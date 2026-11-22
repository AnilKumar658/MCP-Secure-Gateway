"""
gateway/layer2_taint.py
Layer B — Dynamic Taint Engine ("Finding")

Position in pipeline:
  1. Ingestion: Wraps observation return paths from tool calls to record and
     tag untrusted data (source tools: web.fetch_url, mail.read_inbox, PR/issue text).
  2. Propagation & Sink Enforcement: Inspects outgoing tool arguments on subsequent
     calls to detect data flow from tainted sources to sensitive sinks.

Key Capabilities:
-----------------
1. Source Ingestion & Taint Store:
   Stores {id, source, content, hash, timestamp} in session.taint_store.
2. Prompt Injection Scanning:
   Scans incoming tool outputs for prompt injection patterns:
     - "ignore previous instructions", "disregard prior instructions"
     - "system override", "[SYSTEM]:"
     - "send to", "email it to", exfiltration instructions
     - Hidden HTML comments (<!-- ... -->)
3. Provenance & Propagation Tracking:
   Extracts distinctive tokens, n-grams, and entities (e.g. attacker email addresses,
   domains, URLs) from tainted sources. When later tool arguments contain these
   substrings or n-grams, the call is marked as tainted.
4. Sink Enforcement Policy:
   Sensitive sinks (mail.send_mail, file.write_file, git.delete_branch,
   git.force_push, code.run_python) receiving tainted content are escalated or blocked:
     - Tainted with injection payload -> BLOCK (taint_score = 1.0)
     - Tainted with generic external content -> ESCALATE (taint_score = 0.70..0.85)
     - Clean / non-sink calls -> ALLOW (taint_score = 0.0..0.30)
5. Session Taint Accumulator:
   Tracks multi-turn chaining: once untrusted or injected content enters context,
   the session-level taint increases and persists across subsequent turns.

Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from gateway.session import SessionState


# ===========================================================================
# Configuration & Constants
# ===========================================================================

# Default sources of untrusted external content
DEFAULT_TAINT_SOURCES = frozenset({
    ("web", "fetch_url"),
    ("mail", "read_inbox"),
})

# Sinks where data modification, exfiltration, or code execution can occur
DEFAULT_SENSITIVE_SINKS = frozenset({
    ("mail", "send_mail"),
    ("file", "write_file"),
    ("git",  "delete_branch"),
    ("git",  "force_push"),
    ("code", "run_python"),
})

# Prompt injection heuristics
INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r'(?i)\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b'),
        "ignore previous instructions directive",
    ),
    (
        re.compile(r'(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+instructions\b'),
        "disregard instructions directive",
    ),
    (
        re.compile(r'(?i)\bsystem\s+override\b'),
        "system override marker",
    ),
    (
        re.compile(r'<!--\s*(?:HIDDEN\s+INSTRUCTION:?)?.*?(?:ignore|send|email|exfiltrate|system|read).*?-->', re.IGNORECASE | re.DOTALL),
        "hidden HTML comment instruction",
    ),
    (
        re.compile(r'(?i)\[(?:SYSTEM|INSTRUCTION|OVERRIDE)\]\s*:?'),
        "fake system prompt prefix",
    ),
    (
        re.compile(r'(?i)\b(?:send|email|forward|transmit)\s+(?:it\s+to|contents\s+to|all\s+to|data\s+to|to)\s+([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'),
        "exfiltration instruction with email target",
    ),
]

EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b')
URL_REGEX = re.compile(r'https?://[^\s\'"<>]+')


# ===========================================================================
# Data Structures
# ===========================================================================

@dataclass
class TaintRecord:
    """
    Metadata for an observation ingested from an external or untrusted source.
    """
    id: str
    source: str
    content: str
    hash: str
    timestamp: float
    has_injection: bool = False
    injection_matches: list[str] = field(default_factory=list)
    extracted_entities: set[str] = field(default_factory=set)
    ngrams: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "content": self.content[:300] + ("..." if len(self.content) > 300 else ""),
            "hash": self.hash,
            "timestamp": self.timestamp,
            "has_injection": self.has_injection,
            "injection_matches": self.injection_matches,
            "extracted_entities": list(self.extracted_entities),
        }


@dataclass
class TaintFlow:
    """
    Represents an identified flow of tainted information from a source to a sink.
    """
    source: str
    sink: str
    source_record_id: str
    matched_items: list[str]
    propagation_type: str  # "entity_match" | "ngram_match" | "substring_match" | "session_chain"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "sink": self.sink,
            "source_record_id": self.source_record_id,
            "matched_items": self.matched_items,
            "propagation_type": self.propagation_type,
            "timestamp": self.timestamp,
        }


@dataclass
class TaintCheckResult:
    """
    Verdict of the Taint Engine for a proposed action.
    """
    taint_score: float                # 0..1
    is_tainted: bool
    flows: list[TaintFlow]
    action_recommendation: str        # "ALLOW" | "ESCALATE" | "BLOCK"
    session_taint_level: float        # 0..1
    reasons: list[str]
    matched_sources: list[str]

    def has_injection_flow(self) -> bool:
        return any(f.propagation_type in ("entity_match", "ngram_match", "substring_match")
                   for f in self.flows) and self.taint_score >= 0.85

    def __repr__(self) -> str:
        return (
            f"TaintCheckResult(score={self.taint_score:.2f}, "
            f"tainted={self.is_tainted}, "
            f"action={self.action_recommendation}, "
            f"flows={len(self.flows)}, "
            f"session_taint={self.session_taint_level:.2f})"
        )


# ===========================================================================
# TaintEngine
# ===========================================================================

class TaintEngine:
    """
    Dynamic Taint Engine managing observation ingestion, injection scans,
    taint propagation, and sink policy enforcement.
    """

    def __init__(
        self,
        sources: frozenset[tuple[str, str]] = DEFAULT_TAINT_SOURCES,
        sensitive_sinks: frozenset[tuple[str, str]] = DEFAULT_SENSITIVE_SINKS,
    ) -> None:
        self.sources = sources
        self.sensitive_sinks = sensitive_sinks

    # -----------------------------------------------------------------------
    # Ingestion & Injection Scanning
    # -----------------------------------------------------------------------

    def ingest_observation(
        self,
        session: SessionState,
        server: str,
        tool: str,
        observation: Any,
        call_id: str | None = None,
    ) -> TaintRecord | None:
        """
        Ingest an observation returned by an MCP tool. If the tool is a taint
        source (or contains untrusted / injected content), scan it, register
        it in session.taint_store, and raise the session taint level.
        """
        source_key = f"{server}.{tool}"
        is_source = (server, tool) in self.sources

        content_str = self._extract_content_string(observation)
        if not content_str and not is_source:
            return None

        # Check for injection indicators (both regex and meta flag if present)
        injection_matches, has_injection = self._scan_injection(content_str, observation)

        # If it's not a registered source and has no injection, don't taint
        if not is_source and not has_injection:
            return None

        rec_id = call_id or str(uuid.uuid4())
        content_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()

        # Extract entities and n-grams for propagation tracking
        extracted_entities = self._extract_entities(content_str)
        ngrams = self._extract_ngrams(content_str)

        record = TaintRecord(
            id=rec_id,
            source=source_key,
            content=content_str,
            hash=content_hash,
            timestamp=time.time(),
            has_injection=has_injection,
            injection_matches=injection_matches,
            extracted_entities=extracted_entities,
            ngrams=ngrams,
        )

        # Store in session taint store
        session.store_taint(rec_id, record.to_dict())

        # Update session-level taint
        if has_injection:
            session.session_taint_level = max(session.session_taint_level, 0.95)
        else:
            # Baseline external content taint increment
            session.session_taint_level = min(1.0, max(session.session_taint_level, 0.50))

        return record

    def _extract_content_string(self, data: Any) -> str:
        """Flatten structured or string data into searchable text."""
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            parts = []
            for k, val in data.items():
                if val is not None:
                    if isinstance(val, (dict, list)):
                        parts.append(self._extract_content_string(val))
                    else:
                        parts.append(str(val))
            return " ".join(parts)
        if isinstance(data, list):
            return " ".join(self._extract_content_string(item) for item in data)
        return str(data)

    def _scan_injection(self, text: str, raw_observation: Any) -> tuple[list[str], bool]:
        """Scan text for prompt injection patterns."""
        matches: list[str] = []

        # Check explicit meta flag if passed from servers (e.g. web_server)
        if isinstance(raw_observation, dict):
            meta = raw_observation.get("meta", {})
            if isinstance(meta, dict) and meta.get("injected_payload"):
                matches.append("server_metadata_injection_flag")

        for pattern, desc in INJECTION_PATTERNS:
            found = pattern.findall(text)
            if found:
                matches.append(desc)

        return matches, len(matches) > 0

    def _extract_entities(self, text: str) -> set[str]:
        """Extract high-entropy identifiers (emails, URLs, sensitive tokens)."""
        entities: set[str] = set()

        for email in EMAIL_REGEX.findall(text):
            entities.add(email.lower())

        for url in URL_REGEX.findall(text):
            entities.add(url)

        # Detect specific words in prompt injections like malicious recipient addresses or file paths
        for word in re.findall(r'\b[A-Za-z0-9_\-\.\/]{4,}\b', text):
            if word in (".env", "id_rsa", "passwd") or "attacker" in word.lower():
                entities.add(word)

        return entities

    def _extract_ngrams(self, text: str, n: int = 3) -> set[str]:
        """Extract word n-grams (lowercased) of length n."""
        words = re.findall(r'\b[a-zA-Z0-9_\-]+\b', text.lower())
        if len(words) < n:
            return {" ".join(words)} if words else set()
        return {" ".join(words[i:i+n]) for i in range(len(words) - n + 1)}

    # -----------------------------------------------------------------------
    # Propagation & Call Inspection
    # -----------------------------------------------------------------------

    def check_call(
        self,
        session: SessionState,
        server: str,
        tool: str,
        args: dict[str, Any],
        call_id: str | None = None,
    ) -> TaintCheckResult:
        """
        Inspect an outgoing call:
        1. Check if args contain tainted tokens/entities from previous source observations.
        2. Evaluate whether the call targets a sensitive sink.
        3. Determine taint score, flow, and recommendation.
        """
        sink_key = f"{server}.{tool}"
        is_sink = (server, tool) in self.sensitive_sinks
        flows: list[TaintFlow] = []
        reasons: list[str] = []
        matched_sources: list[str] = []

        # Serialize all string arguments to search for taint propagation
        arg_text = self._extract_content_string(args)
        arg_text_lower = arg_text.lower()
        arg_ngrams = self._extract_ngrams(arg_text, n=3)

        direct_taint_hit = False
        injection_taint_hit = False

        # Compare args against all registered taint records in the session
        for rec_id, rec_data in session.taint_store.items():
            source_name = rec_data.get("source", "unknown")
            has_injection = rec_data.get("has_injection", False)
            entities = set(rec_data.get("extracted_entities", []))

            # 1. Entity Matching (e.g. attacker email, specific poisoned tokens)
            matched_entities = [e for e in entities if e.lower() in arg_text_lower]
            if matched_entities:
                flows.append(TaintFlow(
                    source=source_name,
                    sink=sink_key,
                    source_record_id=rec_id,
                    matched_items=matched_entities,
                    propagation_type="entity_match",
                ))
                direct_taint_hit = True
                if has_injection:
                    injection_taint_hit = True
                matched_sources.append(source_name)
                reasons.append(
                    f"Tainted entity {matched_entities} from '{source_name}' "
                    f"propagated to sink '{sink_key}'"
                )

            # 2. N-gram / Substring Matching
            source_content = rec_data.get("content", "")
            source_ngrams = self._extract_ngrams(source_content, n=3)
            ngram_hits = arg_ngrams.intersection(source_ngrams)
            # Ignore common stop-word ngrams
            meaningful_ngrams = [ng for ng in ngram_hits if len(ng) > 10 and not ng.startswith("the ")]

            if meaningful_ngrams and not matched_entities:
                flows.append(TaintFlow(
                    source=source_name,
                    sink=sink_key,
                    source_record_id=rec_id,
                    matched_items=meaningful_ngrams[:3],
                    propagation_type="ngram_match",
                ))
                direct_taint_hit = True
                if has_injection:
                    injection_taint_hit = True
                matched_sources.append(source_name)
                reasons.append(
                    f"Tainted n-grams {meaningful_ngrams[:2]} from '{source_name}' "
                    f"found in arguments of '{sink_key}'"
                )

        # 3. Multi-turn Session Taint Propagation (Context Taint)
        # If no direct argument string match, but session taint is high and tool is a sensitive sink
        if not direct_taint_hit and session.session_taint_level > 0.40 and is_sink:
            flows.append(TaintFlow(
                source="session_context",
                sink=sink_key,
                source_record_id="session",
                matched_items=[f"session_taint_level={session.session_taint_level:.2f}"],
                propagation_type="session_chain",
            ))
            reasons.append(
                f"Sensitive sink '{sink_key}' invoked in a tainted session context "
                f"(taint level: {session.session_taint_level:.2f})"
            )

        # -------------------------------------------------------------------
        # Score & Recommendation Determination
        # -------------------------------------------------------------------
        if injection_taint_hit and is_sink:
            taint_score = 1.0
            recommendation = "BLOCK"
            reasons.append(f"Prompt injection data flowed into sensitive sink '{sink_key}' — HARD BLOCK")
        elif direct_taint_hit and is_sink:
            taint_score = 0.85
            recommendation = "ESCALATE"
            reasons.append(f"Untrusted external data flowed into sensitive sink '{sink_key}' — ESCALATE")
        elif direct_taint_hit and not is_sink:
            taint_score = 0.40
            recommendation = "ALLOW"
            reasons.append(f"Tainted data passed to non-sensitive tool '{sink_key}' — ALLOW with monitoring")
        elif session.session_taint_level > 0.70 and is_sink:
            taint_score = 0.75
            recommendation = "ESCALATE"
            reasons.append(f"High session taint ({session.session_taint_level:.2f}) interacting with sensitive sink '{sink_key}'")
        elif session.session_taint_level > 0.0:
            # Baseline background session taint
            taint_score = round(session.session_taint_level * 0.35, 3)
            recommendation = "ALLOW"
        else:
            taint_score = 0.0
            recommendation = "ALLOW"

        is_tainted = direct_taint_hit or (session.session_taint_level > 0.0 and is_sink)

        # Record flows on the session for dashboard consumption
        for flow in flows:
            session.taint_flows.append(flow.to_dict())

        return TaintCheckResult(
            taint_score=round(taint_score, 3),
            is_tainted=is_tainted,
            flows=flows,
            action_recommendation=recommendation,
            session_taint_level=round(session.session_taint_level, 3),
            reasons=reasons,
            matched_sources=list(set(matched_sources)),
        )
