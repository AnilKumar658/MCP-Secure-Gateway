"""
agent/react_agent.py
ReAct Agent powered by local Ollama (default llama3.1:8b).

Features:
  - Formats user tasks and tool observations into Thought / Action JSON loops.
  - Action JSON schema: {"server": str, "tool": str, "args": dict}
  - Deterministic generation with fixed temperature (0.0) and seed (42).
  - Robust JSON extraction, regex healing (repairs trailing commas, single quotes),
    and retry loops if the model outputs malformed JSON.
  - Clear, user-friendly error guidance if Ollama is unreachable.

Standard library only (uses urllib.request).
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Generator


DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "qwen2.5:3b"


REACT_SYSTEM_PROMPT = """You are an AI assistant that solves tasks by using tools provided by Model Context Protocol (MCP) servers.

Available servers and tools:
- git: list_branches(), create_branch(name), commit_file(path, message, branch), delete_branch(name), force_push(branch), merge_pr(pr_id)
- file: read_file(path), write_file(path, content)
- mail: read_inbox(), send_mail(to, body)
- web: fetch_url(url)
- code: run_python(code)

You MUST respond strictly using the following format:
Thought: <your step-by-step reasoning about what tool to call or whether the task is complete>
Action:
```json
{
  "server": "<server_name>",
  "tool": "<tool_name>",
  "args": { ... }
}
```

When the task is complete and no more tools are needed, answer with:
Final Answer: <your final answer to the user>

IMPORTANT RULES:
1. Always output valid JSON inside the Action code block.
2. Only call tools that exist in the catalog above.
3. If an observation says an action was BLOCKED or requires APPROVAL, adjust your plan safely.
"""


class OllamaConnectionError(Exception):
    """Raised when Ollama local instance cannot be reached."""
    pass


class ReActAgent:
    """
    ReAct Agent communicating with local Ollama instance.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_OLLAMA_URL,
        temperature: float = 0.0,
        seed: int = 42,
        max_retries: int = 3,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.seed = seed
        self.max_retries = max_retries

    # -- Public Agent Step ---------------------------------------------------

    def plan_step(self, task: str, history: list[dict[str, str]]) -> tuple[str, dict[str, Any] | None, str | None]:
        """
        Generate the next ReAct step.

        Returns
        -------
        thought: str
        action: dict | None (if tool call chosen)
        final_answer: str | None (if task finished)
        """
        prompt = self._build_prompt(task, history)

        for attempt in range(self.max_retries):
            raw_response = self._call_ollama(prompt)
            thought, action, final_answer = self._parse_react_response(raw_response)

            if final_answer is not None:
                return thought, None, final_answer

            if action is not None:
                return thought, action, None

            # Retry with repair hint if parsing failed
            prompt += f"\n\n[ERROR: Your previous response did not contain a valid Action JSON block. Please provide valid JSON in Action: ```json ... ``` format.]\n"

        # Fallback if max retries reached without valid action
        return (
            "Failed to parse valid Action JSON from model after multiple retries.",
            None,
            f"Model output format error. Raw: {raw_response[:200]}...",
        )

    # -- Ollama HTTP Call ----------------------------------------------------

    def _call_ollama(self, prompt: str) -> str:
        """Issue HTTP POST to local Ollama API."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "seed": self.seed,
            },
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("response", "")
        except urllib.error.URLError as exc:
            raise OllamaConnectionError(
                f"Could not connect to Ollama at {self.base_url}.\n"
                f"Reason: {exc.reason}\n\n"
                "Please verify that Ollama is running ('ollama serve' or open the Ollama app).\n"
                "To test offline without Ollama, run with --agent simulated."
            ) from exc

    # -- Prompt Formatting ---------------------------------------------------

    def _build_prompt(self, task: str, history: list[dict[str, str]]) -> str:
        lines = [REACT_SYSTEM_PROMPT, f"\nUser Task: {task}\n"]
        for turn in history:
            role = turn.get("role", "")
            content = turn.get("content", "")
            if role == "assistant":
                lines.append(f"{content}\n")
            elif role == "observation":
                lines.append(f"Observation: {content}\n")
        lines.append("Thought:")
        return "\n".join(lines)

    # -- JSON Parsing & Repair -----------------------------------------------

    def _parse_react_response(self, text: str) -> tuple[str, dict[str, Any] | None, str | None]:
        """Extract Thought, Action JSON, or Final Answer."""
        # 1. First check if there is an Action JSON block.
        # Often models include both an Action and a trailing 'Final Answer:' header.
        # If an Action JSON is present, it is an action turn, not final answer.
        json_str = self._extract_json_substring(text)
        action_dict = None
        if json_str:
            action_dict = self._repair_and_parse_json(json_str)

        if action_dict and isinstance(action_dict, dict) and "server" in action_dict and "tool" in action_dict:
            if "args" not in action_dict:
                action_dict["args"] = {}
            # Extract Thought before Action:
            thought = ""
            if "Action:" in text:
                thought = text.split("Action:", 1)[0].replace("Thought:", "").strip()
            else:
                thought = text.split(json_str, 1)[0].replace("Thought:", "").strip()
            return thought, action_dict, None

        # 2. Check for Final Answer when no Action was parsed
        if "Final Answer:" in text:
            parts = text.split("Final Answer:", 1)
            thought = parts[0].replace("Thought:", "").strip()
            final_answer = parts[1].strip()
            if final_answer:
                return thought, None, final_answer

        # 3. Extract Thought only if neither Action nor Final Answer was found
        thought = text.replace("Thought:", "").strip()
        return thought, None, None

    def _extract_json_substring(self, text: str) -> str | None:
        """Find JSON block inside markdown or raw braces."""
        # 1. Look for ```json ... ```
        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if match:
            return match.group(1).strip()

        # 2. Look for Action: { ... }
        match = re.search(r'Action:\s*(\{.*\})', text, re.DOTALL)
        if match:
            # find balanced brace substring
            return self._extract_balanced_braces(match.group(1))

        # 3. Look for first balanced { ... } containing "server" and "tool"
        match = re.search(r'\{[^{}]*"server"[^{}]*"tool"[^{}]*\}', text)
        if match:
            return match.group(0)

        return None

    def _extract_balanced_braces(self, s: str) -> str | None:
        start = s.find("{")
        if start == -1:
            return None
        depth = 0
        for i in range(start, len(s)):
            if s[i] == "{":
                depth += 1
            elif s[i] == "}":
                depth -= 1
                if depth == 0:
                    return s[start:i+1]
        return None

    def _repair_and_parse_json(self, raw: str) -> dict[str, Any] | None:
        """Attempt progressive heuristic repairs on malformed JSON."""
        # Attempt 1: Direct parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Attempt 2: Strip trailing commas
        cleaned = re.sub(r',\s*([}\]])', r'\1', raw)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Attempt 3: Replace single quotes with double quotes
        cleaned_quotes = re.sub(r"'([^']*)'", r'"\1"', cleaned)
        try:
            return json.loads(cleaned_quotes)
        except json.JSONDecodeError:
            pass

        return None
