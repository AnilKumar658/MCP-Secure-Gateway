"""
dashboard/playground_ui.py
Helper module providing HTML flattening, escaping, and progress ring stepper rendering.
"""
from __future__ import annotations

import html
import re
from typing import Any

from dashboard.progress_stepper import RINGS_CSS, compute_stage_states, render_rings


def esc(val: Any) -> str:
    """Safely escape text for HTML embedding."""
    if val is None:
        return ""
    return html.escape(str(val))


def flatten_html(html_str: str) -> str:
    """
    Remove comments, strip indentation and blank lines,
    producing a single-line string to prevent Streamlit Markdown code block parsing.
    """
    if not html_str:
        return ""
    # Strip HTML comments
    cleaned = re.sub(r"<!--[\s\S]*?-->", "", html_str)
    # Strip leading/trailing whitespace and remove blank lines
    return "".join(line.strip() for line in cleaned.splitlines() if line.strip())


def render_reasoning_step(step: int, agent_model: str, elapsed_s: float) -> str:
    """
    Render active agent reasoning status in the exact same 3D workflow card design
    instead of an unstyled alert block.
    """
    card_html = f"""
    <div class="workflow-3d-step workflow-step-running">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.85rem; flex-wrap: wrap; gap: 8px;">
            <div class="workflow-step-badge">
                <span>⚡ STEP {step}</span>
            </div>
            <div class="prs-meta-right">
                <span class="prs-verdict-pill prs-pill-approval prs-pulsing-pill">
                    ● REASONING IN PROGRESS
                </span>
                <span class="prs-overhead">⏱️ {elapsed_s:.1f}s elapsed</span>
            </div>
        </div>
        <div class="thought-box-3d" style="display: flex; align-items: center; gap: 10px; margin-bottom: 0.85rem;">
            <div class="prs-spinner-circle"></div>
            <div>
                <b>Agent Cognitive Reasoning:</b> Executing ReAct loop with <code>{esc(agent_model)}</code>...
            </div>
        </div>
        <div style="font-size: 0.78rem; font-weight: 700; text-transform: uppercase; color: var(--wf-label-color, #64748b); letter-spacing: 0.05em; margin-bottom: 0.35rem;">
            Proposed MCP Tool Action
        </div>
        <div class="action-box-3d" style="font-size: 0.88rem; padding: 0.75rem 1rem;">
            <span>// Awaiting model generation and tool parameter resolution</span><br>
            agent.plan_step(task_prompt, history) &rarr; analyzing observations and planning next action...
        </div>
    </div>
    """
    return flatten_html(card_html)
