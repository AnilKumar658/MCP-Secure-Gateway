"""
dashboard/progress_stepper.py
Pure CSS & SVG 5-Stage Security Gateway Progress Ring Stepper for Streamlit.
Zero JavaScript. Sentence case. Self-contained animations with unique SVG IDs per step.
"""
from __future__ import annotations

import html
import re
from typing import Any


STAGE_NAMES = [
    "Scope (L1)",
    "Param and AST (A)",
    "Dynamic taint (B)",
    "Risk engine (C)",
    "MCP server",
]

STAGE_SUBTITLES = {
    "ok": "Passed",
    "warn": "Needs approval",
    "bad": "Blocked",
    "idle": "Not reached",
}


RINGS_CSS = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Sora:wght@400;600;700&display=swap" rel="stylesheet">

<style>
/* CSS Theme Variables for Progress Stepper - Adaptive Light & Dark */
:root {
    --prs-bg: #f8fafc;
    --prs-border: #e2e8f0;
    --prs-shadow: 0 4px 16px -2px rgba(15, 23, 42, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.8);
    --prs-text: #1e293b;
    --prs-chip-bg: #ffffff;
    --prs-chip-border: #cbd5e1;
    --prs-chip-text: #1e40af;
    --prs-overhead-color: #64748b;
    --prs-title-color: #1e293b;
    --prs-idle-title: #94a3b8;
    --prs-time-color: #64748b;
    --prs-reason-bg: #ffffff;
    --prs-reason-border: #e2e8f0;
    --prs-reason-text: #334155;
    --prs-conn-base: #e2e8f0;
    --prs-disc-ok-fill: #dcfce7;
    --prs-disc-warn-fill: #fef3c7;
    --prs-disc-bad-fill: #fee2e2;
    --prs-disc-idle-fill: #f1f5f9;
    --prs-track-stroke: #e2e8f0;
    --prs-tick-stroke: #cbd5e1;
    --prs-check-stroke: #15803d;
    --prs-warn-stroke: #c2410c;
    --prs-bad-stroke: #dc2626;
    --prs-idle-num: #64748b;
}

[data-theme="light"], .stApp[data-theme="light"] {
    --prs-bg: #f8fafc;
    --prs-border: #e2e8f0;
    --prs-shadow: 0 4px 16px -2px rgba(15, 23, 42, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.8);
    --prs-text: #1e293b;
    --prs-chip-bg: #ffffff;
    --prs-chip-border: #cbd5e1;
    --prs-chip-text: #1e40af;
    --prs-overhead-color: #64748b;
    --prs-title-color: #1e293b;
    --prs-idle-title: #94a3b8;
    --prs-time-color: #64748b;
    --prs-reason-bg: #ffffff;
    --prs-reason-border: #e2e8f0;
    --prs-reason-text: #334155;
    --prs-conn-base: #e2e8f0;
    --prs-disc-ok-fill: #dcfce7;
    --prs-disc-warn-fill: #fef3c7;
    --prs-disc-bad-fill: #fee2e2;
    --prs-disc-idle-fill: #f1f5f9;
    --prs-track-stroke: #e2e8f0;
    --prs-tick-stroke: #cbd5e1;
    --prs-check-stroke: #15803d;
    --prs-warn-stroke: #c2410c;
    --prs-bad-stroke: #dc2626;
    --prs-idle-num: #64748b;
}

[data-theme="dark"], .stApp[data-theme="dark"] {
    --prs-bg: radial-gradient(ellipse at 50% 20%, #131c36 0%, #0a0f1e 100%);
    --prs-border: #1f2a47;
    --prs-shadow: 0 18px 36px -10px rgba(5, 10, 25, 0.65), inset 0 1px 0 rgba(255, 255, 255, 0.06);
    --prs-text: #e2e8f0;
    --prs-chip-bg: #0f172a;
    --prs-chip-border: #1e293b;
    --prs-chip-text: #93c5fd;
    --prs-overhead-color: #8794b3;
    --prs-title-color: #cbd5e1;
    --prs-idle-title: #8794b3;
    --prs-time-color: #8794b3;
    --prs-reason-bg: rgba(15, 23, 42, 0.7);
    --prs-reason-border: transparent;
    --prs-reason-text: #cbd5e1;
    --prs-conn-base: #1f2b48;
    --prs-disc-ok-fill: #0e2a20;
    --prs-disc-warn-fill: #2c1f0d;
    --prs-disc-bad-fill: #2b1017;
    --prs-disc-idle-fill: #0c1327;
    --prs-track-stroke: #1d2845;
    --prs-tick-stroke: #2a385c;
    --prs-check-stroke: #bbf7d0;
    --prs-warn-stroke: #fdba74;
    --prs-bad-stroke: #fecdd3;
    --prs-idle-num: #8794b3;
}

@media (prefers-color-scheme: dark) {
    .stApp:not([data-theme="light"]) {
        --prs-bg: radial-gradient(ellipse at 50% 20%, #131c36 0%, #0a0f1e 100%);
        --prs-border: #1f2a47;
        --prs-shadow: 0 18px 36px -10px rgba(5, 10, 25, 0.65), inset 0 1px 0 rgba(255, 255, 255, 0.06);
        --prs-text: #e2e8f0;
        --prs-chip-bg: #0f172a;
        --prs-chip-border: #1e293b;
        --prs-chip-text: #93c5fd;
        --prs-overhead-color: #8794b3;
        --prs-title-color: #cbd5e1;
        --prs-idle-title: #8794b3;
        --prs-time-color: #8794b3;
        --prs-reason-bg: rgba(15, 23, 42, 0.7);
        --prs-reason-border: transparent;
        --prs-reason-text: #cbd5e1;
        --prs-conn-base: #1f2b48;
        --prs-disc-ok-fill: #0e2a20;
        --prs-disc-warn-fill: #2c1f0d;
        --prs-disc-bad-fill: #2b1017;
        --prs-disc-idle-fill: #0c1327;
        --prs-track-stroke: #1d2845;
        --prs-tick-stroke: #2a385c;
        --prs-check-stroke: #bbf7d0;
        --prs-warn-stroke: #fdba74;
        --prs-bad-stroke: #fecdd3;
        --prs-idle-num: #8794b3;
    }
}

/* Base typography & container reset */
.prs-panel {
    background: var(--prs-bg);
    border: 1px solid var(--prs-border);
    border-radius: 20px;
    padding: 22px;
    margin: 14px 0 18px 0;
    box-shadow: var(--prs-shadow);
    font-family: 'Sora', -apple-system, BlinkMacSystemFont, sans-serif;
    color: var(--prs-text);
    overflow-x: auto;
    -webkit-font-smoothing: antialiased;
}

.prs-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
}

.prs-call-chip {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.5px;
    font-weight: 500;
    color: var(--prs-chip-text);
    background: var(--prs-chip-bg);
    border: 1px solid var(--prs-chip-border);
    padding: 6px 12px;
    border-radius: 8px;
    max-width: 60%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.prs-meta-right {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-left: auto;
}

.prs-verdict-pill {
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.03em;
    padding: 4px 11px;
    border-radius: 20px;
    opacity: 0;
    animation: prsFadeIn 0.4s ease-out forwards;
}

.prs-pill-allow {
    background: rgba(22, 163, 74, 0.18);
    border: 1px solid #16a34a;
    color: #16a34a;
    box-shadow: 0 0 12px rgba(34, 197, 94, 0.25);
}

.prs-pill-approval, .prs-pill-downgrade {
    background: rgba(234, 88, 12, 0.18);
    border: 1px solid #ea580c;
    color: #ea580c;
    box-shadow: 0 0 12px rgba(249, 115, 22, 0.25);
}

.prs-pill-block {
    background: rgba(220, 38, 38, 0.18);
    border: 1px solid #dc2626;
    color: #dc2626;
    box-shadow: 0 0 12px rgba(239, 68, 68, 0.28);
}

.prs-overhead {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--prs-overhead-color);
}

/* Stepper Track */
.prs-track {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    min-width: 520px;
    padding: 8px 4px 14px 4px;
}

.prs-node {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    width: 90px;
    flex-shrink: 0;
    position: relative;
}

.prs-svg-box {
    width: 80px;
    height: 80px;
    position: relative;
}

/* Keyframes */
@keyframes prsSpin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

@keyframes prsDrawOk {
    0% { stroke-dashoffset: 100; stroke: #3b82f6; }
    60% { stroke-dashoffset: 0; stroke: #60a5fa; }
    100% { stroke-dashoffset: 0; stroke: url(#prs-grad-ok); }
}

@keyframes prsDrawWarn {
    0% { stroke-dashoffset: 100; stroke: #3b82f6; }
    60% { stroke-dashoffset: 40; stroke: #f59e0b; }
    100% { stroke-dashoffset: 34; stroke: url(#prs-grad-warn); }
}

@keyframes prsDrawBad {
    0% { stroke-dashoffset: 100; stroke: #3b82f6; }
    60% { stroke-dashoffset: 0; stroke: #f43f5e; }
    100% { stroke-dashoffset: 0; stroke: url(#prs-grad-bad); }
}

@keyframes prsCheckIn {
    0% { stroke-dashoffset: 1; opacity: 0; }
    50% { opacity: 1; }
    100% { stroke-dashoffset: 0; opacity: 1; }
}

@keyframes prsShake {
    0%, 100% { transform: translateX(0); }
    20%, 60% { transform: translateX(-3px); }
    40%, 80% { transform: translateX(3px); }
}

@keyframes prsBreathe {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.05); }
}

@keyframes prsFillConn {
    0% { width: 0%; opacity: 0.4; }
    100% { width: 100%; opacity: 1; }
}

@keyframes prsFadeIn {
    0% { opacity: 0; transform: translateY(4px); }
    100% { opacity: 1; transform: translateY(0); }
}

/* Ring Animations */
.prs-spin-tick {
    transform-origin: 40px 40px;
    animation: prsSpin 14s linear infinite;
}

.prs-progress-arc {
    transform-origin: 40px 40px;
    transform: rotate(-90deg);
}

.prs-running-pulse {
    transform-origin: 40px 40px;
}

/* Connectors */
.prs-conn {
    flex-grow: 1;
    height: 4px;
    background: repeating-linear-gradient(90deg, var(--prs-conn-base) 0, var(--prs-conn-base) 6px, transparent 6px, transparent 12px);
    margin: 38px -6px 0 -6px;
    position: relative;
    border-radius: 2px;
}

.prs-conn-fill {
    height: 100%;
    background: linear-gradient(90deg, #16a34a, #4ade80);
    box-shadow: 0 0 10px rgba(74, 222, 128, 0.6);
    border-radius: 2px;
    position: absolute;
    top: 0;
    left: 0;
    width: 0%;
    animation: prsFillConn 0.55s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}

/* Node labels */
.prs-title {
    font-size: 12.5px;
    font-weight: 600;
    margin-top: 10px;
    color: var(--prs-title-color);
    line-height: 1.25;
}

.prs-node-idle .prs-title {
    color: var(--prs-idle-title);
}

.prs-time {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--prs-time-color);
    margin-top: 4px;
}

.prs-sub {
    font-size: 12px;
    font-weight: 500;
    margin-top: 2px;
}

.prs-sub-ok { color: #16a34a; font-weight: 600; }
.prs-sub-warn { color: #ea580c; font-weight: 600; }
.prs-sub-bad { color: #dc2626; font-weight: 600; }
.prs-sub-idle { color: var(--prs-idle-title); }

/* Reason strip */
.prs-reason-strip {
    margin-top: 18px;
    padding: 10px 14px;
    background: var(--prs-reason-bg);
    border: 1px solid var(--prs-reason-border);
    border-radius: 8px;
    font-size: 12px;
    color: var(--prs-reason-text);
    line-height: 1.5;
    opacity: 0;
    animation: prsFadeIn 0.45s ease-out forwards;
}

.prs-reason-allow { border-left: 3px solid #16a34a; }
.prs-reason-approval, .prs-reason-downgrade { border-left: 3px solid #ea580c; }
.prs-reason-block { border-left: 3px solid #dc2626; }

/* Dynamic disc and circle styling */
.prs-disc-ok { fill: var(--prs-disc-ok-fill); }
.prs-disc-warn { fill: var(--prs-disc-warn-fill); }
.prs-disc-bad { fill: var(--prs-disc-bad-fill); }
.prs-disc-idle { fill: var(--prs-disc-idle-fill); }
.prs-spin-tick { stroke: var(--prs-tick-stroke); }
.prs-track-circle { stroke: var(--prs-track-stroke); }

/* Narrow screens under 640px: vertical stacked layout */
@media (max-width: 640px) {
    .prs-track {
        flex-direction: column;
        align-items: center;
        min-width: 0;
        width: 100%;
        padding: 10px 0;
    }
    .prs-node {
        width: 100%;
        margin: 4px 0;
    }
    .prs-conn {
        width: 4px;
        height: 28px;
        flex-grow: 0;
        margin: 6px auto;
        background: repeating-linear-gradient(180deg, var(--prs-conn-base) 0, var(--prs-conn-base) 6px, transparent 6px, transparent 12px);
    }
    .prs-conn-fill {
        width: 100%;
        height: 0%;
        background: linear-gradient(180deg, #16a34a, #4ade80);
        animation: prsFillConnVert 0.55s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }
}

@keyframes prsFillConnVert {
    0% { height: 0%; opacity: 0.4; }
    100% { height: 100%; opacity: 1; }
}

/* Reduced Motion Override */
@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        animation: none !important;
        transition: none !important;
    }
    .prs-verdict-pill, .prs-conn-fill, .prs-reason-strip,
    .prs-spin-tick, .prs-progress-arc, path {
        animation: none !important;
        opacity: 1 !important;
    }
    .prs-conn-fill { width: 100% !important; height: 100% !important; }
}
</style>
"""


def compute_stage_states(decision: Any) -> list[str]:
    """
    Determine the state of each of the 5 gateway stages.
    Returns a list of 5 strings from {"ok", "warn", "bad", "idle"}.
    """
    dec = getattr(decision, "decision", "ALLOW").upper()
    reason = (getattr(decision, "reason", "") or "").lower()

    if dec == "ALLOW":
        return ["ok", "ok", "ok", "ok", "ok"]

    if dec in ("APPROVAL", "DOWNGRADE"):
        return ["ok", "ok", "ok", "warn", "idle"]

    if dec == "BLOCK":
        # Infer the stage that blocked the call
        if "scope" in reason:
            fail_idx = 0
        elif any(k in reason for k in ("path", "branch", "recipient", "param", "ast", "hard")):
            fail_idx = 1
        elif any(k in reason for k in ("taint", "injection")):
            fail_idx = 2
        else:
            fail_idx = 3

        states = []
        for i in range(5):
            if i < fail_idx:
                states.append("ok")
            elif i == fail_idx:
                states.append("bad")
            else:
                states.append("idle")
        return states

    return ["ok", "ok", "ok", "ok", "ok"]


def render_rings(
    states: list[str],
    stage_ms: list[float] | None = None,
    reason: str = "",
    call_str: str = "",
    total_overhead_ms: float = 0.0,
    decision_str: str = "ALLOW",
    step_id: int | str = 1,
) -> str:
    """
    Render the 5-stage Progress Ring Stepper panel as a clean, single-line HTML string.
    """
    dec_upper = decision_str.upper()

    # Determine verdict label and styling class
    if dec_upper == "ALLOW":
        pill_cls = "prs-pill-allow"
        verdict_label = "Allowed"
        reason_cls = "prs-reason-allow"
    elif dec_upper in ("APPROVAL", "DOWNGRADE"):
        pill_cls = "prs-pill-approval"
        verdict_label = "Needs approval" if dec_upper == "APPROVAL" else "Downgraded"
        reason_cls = "prs-reason-approval"
    else:
        pill_cls = "prs-pill-block"
        verdict_label = "Blocked"
        reason_cls = "prs-reason-block"

    # Default proportional stage timing if not provided
    if stage_ms is None or len(stage_ms) != 5:
        q = total_overhead_ms * 0.25
        stage_ms = [round(q, 2), round(q, 2), round(q, 2), round(q, 2), 0.0]

    # Calculate reveal delay for verdict and reason strip
    last_active_idx = max((i for i, st in enumerate(states) if st != "idle"), default=0)
    final_delay_s = round(last_active_idx * 0.9 + 0.65, 2)

    # Unique gradient IDs per step invocation
    uid = f"s{step_id}"
    grad_ok = f"prs_g_ok_{uid}"
    grad_warn = f"prs_g_warn_{uid}"
    grad_bad = f"prs_g_bad_{uid}"
    grad_disc = f"prs_g_disc_{uid}"
    filter_ok = f"prs_f_ok_{uid}"
    filter_bad = f"prs_f_bad_{uid}"

    # SVG Defs block
    defs_html = f"""
    <defs>
        <radialGradient id="{grad_disc}" cx="50%" cy="30%" r="70%">
            <stop offset="0%" stop-color="#26335a"/>
            <stop offset="100%" stop-color="#0c1327"/>
        </radialGradient>
        <linearGradient id="{grad_ok}" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#6ee7a0"/>
            <stop offset="100%" stop-color="#16a34a"/>
        </linearGradient>
        <linearGradient id="{grad_warn}" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#fde047"/>
            <stop offset="100%" stop-color="#ea580c"/>
        </linearGradient>
        <linearGradient id="{grad_bad}" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#fb7185"/>
            <stop offset="100%" stop-color="#dc2626"/>
        </linearGradient>
        <filter id="{filter_ok}" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="0" stdDeviation="3.5" flood-color="#22c55e" flood-opacity="0.6"/>
        </filter>
        <filter id="{filter_bad}" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="0" stdDeviation="4.5" flood-color="#ef4444" flood-opacity="0.75"/>
        </filter>
    </defs>
    """

    nodes_html_list = []

    for i, state in enumerate(states):
        stage_name = STAGE_NAMES[i]
        timing = f"{stage_ms[i]:.2f} ms" if state != "idle" and stage_ms[i] > 0 else "—"
        sub_word = STAGE_SUBTITLES.get(state, "Not reached")
        sub_cls = f"prs-sub-{state}"
        node_cls = f"prs-node prs-node-{state}"

        # Delay for this stage
        delay_s = round(i * 0.9, 2)
        settle_delay_s = round(delay_s + 0.65, 2)

        # Build center mark & ring layers based on state
        if state == "ok":
            disc_color = "#0e2a20"
            filter_attr = f'filter="url(#{filter_ok})"'
            arc_css = f"stroke: url(#{grad_ok}); animation: prsDrawOk 0.65s cubic-bezier(0.16,1,0.3,1) {delay_s}s both;"
            # Checkmark path
            center_mark = f"""
            <path d="M 27 41 L 36 50 L 53 31" fill="none" stroke="var(--prs-check-stroke, #15803d)" stroke-width="3.5"
                  stroke-linecap="round" stroke-linejoin="round" pathLength="1" stroke-dasharray="1" stroke-dashoffset="1"
                  style="animation: prsCheckIn 0.35s ease-out {settle_delay_s}s forwards;"/>
            """
            svg_style = ""
        elif state == "warn":
            disc_color = "#2c1f0d"
            filter_attr = ""
            arc_css = f"stroke: url(#{grad_warn}); animation: prsDrawWarn 0.65s cubic-bezier(0.16,1,0.3,1) {delay_s}s both;"
            # Exclamation mark
            center_mark = f"""
            <g style="animation: prsBreathe 2s ease-in-out {settle_delay_s}s infinite; transform-origin: 40px 40px;">
                <circle cx="40" cy="51" r="2.4" fill="var(--prs-warn-stroke, #c2410c)"/>
                <line x1="40" y1="29" x2="40" y2="44" stroke="var(--prs-warn-stroke, #c2410c)" stroke-width="3.5" stroke-linecap="round"/>
            </g>
            """
            svg_style = ""
        elif state == "bad":
            disc_color = "#2b1017"
            filter_attr = f'filter="url(#{filter_bad})"'
            arc_css = f"stroke: url(#{grad_bad}); animation: prsDrawBad 0.65s cubic-bezier(0.16,1,0.3,1) {delay_s}s both;"
            # X mark
            center_mark = f"""
            <g stroke="var(--prs-bad-stroke, #dc2626)" stroke-width="3.5" stroke-linecap="round">
                <line x1="30" y1="30" x2="50" y2="50"/>
                <line x1="50" y1="30" x2="30" y2="50"/>
            </g>
            """
            svg_style = f"animation: prsShake 0.4s ease-in-out {settle_delay_s}s;"
        else:  # idle
            disc_color = f"url(#{grad_disc})"
            filter_attr = ""
            arc_css = "stroke: #253352; stroke-dashoffset: 100;"
            center_mark = f"""
            <text x="40" y="45" font-family="'JetBrains Mono', monospace" font-size="16" font-weight="700" fill="var(--prs-idle-num, #64748b)" text-anchor="middle">{i + 1}</text>
            """
            svg_style = ""

        svg_content = f"""
        <svg class="prs-svg-box" viewBox="0 0 80 80" role="img" aria-label="{stage_name}: {sub_word.lower()}" style="{svg_style}">
            <!-- Dotted tick circle -->
            <circle class="prs-spin-tick" cx="40" cy="40" r="38" fill="none" stroke="var(--prs-tick-stroke, #cbd5e1)" stroke-width="1.2" stroke-dasharray="1.5 5.2"/>
            <!-- Track circle -->
            <circle class="prs-track-circle" cx="40" cy="40" r="32" fill="none" stroke="var(--prs-track-stroke, #e2e8f0)" stroke-width="5"/>
            <!-- Inner disc -->
            <circle class="prs-disc prs-disc-{state}" cx="40" cy="40" r="28" fill="var(--prs-disc-{state}-fill, {disc_color})"/>
            <!-- Progress Arc -->
            <circle class="prs-progress-arc" cx="40" cy="40" r="32" fill="none" stroke-width="5"
                    stroke-linecap="round" pathLength="100" stroke-dasharray="100" {filter_attr}
                    style="{arc_css}"/>
            <!-- Center Mark -->
            {center_mark}
        </svg>
        """

        node_html = f"""
        <div class="{node_cls}">
            {svg_content}
            <div class="prs-title">{stage_name}</div>
            <div class="prs-time">{timing}</div>
            <div class="prs-sub {sub_cls}">{sub_word}</div>
        </div>
        """
        nodes_html_list.append(node_html)

        # Connector between rings (4 connectors total)
        if i < 4:
            conn_delay_s = round(delay_s + 0.65, 2)
            if state == "ok":
                fill_html = f'<div class="prs-conn-fill" style="animation-delay: {conn_delay_s}s;"></div>'
            else:
                fill_html = ""
            conn_html = f'<div class="prs-conn">{fill_html}</div>'
            nodes_html_list.append(conn_html)

    track_inner = "".join(nodes_html_list)

    # Clean Call string & Reason
    escaped_call = html.escape(call_str or "agent.execute()")
    escaped_reason = html.escape(reason or "Tool call evaluated against dynamic security gateway layers.")

    # Assemble complete component HTML
    raw_html = f"""
<div class="prs-panel">
    <svg style="position: absolute; width: 0; height: 0; overflow: hidden;" version="1.1">
        {defs_html}
    </svg>
    <div class="prs-header">
        <div class="prs-call-chip" title="{escaped_call}">{escaped_call}</div>
        <div class="prs-meta-right">
            <span class="prs-verdict-pill {pill_cls}" style="animation-delay: {final_delay_s}s;">{verdict_label}</span>
            <span class="prs-overhead">Gateway overhead {total_overhead_ms:.2f} ms</span>
        </div>
    </div>
    <div class="prs-track">
        {track_inner}
    </div>
    <div class="prs-reason-strip {reason_cls}" style="animation-delay: {final_delay_s}s;">
        <b>Verdict explanation:</b> {escaped_reason}
    </div>
</div>
"""
    # Streamlit hygiene: Strip comments, newlines, and spaces to avoid markdown turning lines into code blocks
    cleaned = re.sub(r"<!--[\s\S]*?-->", "", raw_html)
    return "".join(line.strip() for line in cleaned.splitlines() if line.strip())
