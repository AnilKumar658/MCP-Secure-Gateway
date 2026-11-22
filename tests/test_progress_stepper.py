"""
tests/test_progress_stepper.py
Standalone test app to render ALLOW, APPROVAL, and BLOCK progress ring steppers on a single Streamlit page.
Run with: streamlit run tests/test_progress_stepper.py
"""
import streamlit as st
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dashboard.progress_stepper import RINGS_CSS, compute_stage_states, render_rings

st.set_page_config(page_title="Progress Ring Stepper Test", layout="wide")
st.markdown(RINGS_CSS, unsafe_allow_html=True)

st.title("🛡️ 5-Stage Security Gateway Progress Ring Steppers")
st.write("Visual acceptance test for pure-CSS progress rings across all gateway decision bands.")

# Dummy Decision object for testing
class MockDecision:
    def __init__(self, decision: str, reason: str, latency_ms: float = 0.15):
        self.decision = decision
        self.reason = reason
        self.meta = {"latency_ms": latency_ms}

# Scenario 1: ALLOW
st.subheader("1. Scenario: ALLOW (Benign Call Passing All Stages)")
allow_dec = MockDecision("ALLOW", "P123 Allow: Risk score 0.040 < 0.3: operation allowed unconditionally.", latency_ms=0.12)
states_allow = compute_stage_states(allow_dec)
html_allow = render_rings(
    states=states_allow,
    reason=allow_dec.reason,
    call_str="git.list_branches({})",
    total_overhead_ms=allow_dec.meta["latency_ms"],
    decision_str=allow_dec.decision,
    step_id=1,
)
st.markdown(html_allow, unsafe_allow_html=True)

# Scenario 2: APPROVAL
st.subheader("2. Scenario: APPROVAL (High Risk Operation Requiring Human Confirmation)")
appr_dec = MockDecision("APPROVAL", "P123 Approval: Sensitive operation 'force_push' under elevated risk threshold (0.64). Operator confirmation required.", latency_ms=0.28)
states_appr = compute_stage_states(appr_dec)
html_appr = render_rings(
    states=states_appr,
    reason=appr_dec.reason,
    call_str="git.force_push({'branch': 'dev'})",
    total_overhead_ms=appr_dec.meta["latency_ms"],
    decision_str=appr_dec.decision,
    step_id=2,
)
st.markdown(html_appr, unsafe_allow_html=True)

# Scenario 3: BLOCK
st.subheader("3. Scenario: BLOCK (Direct Path Traversal & Taint Injection Halt)")
block_dec = MockDecision("BLOCK", "P123 Block: Hard security rule triggered: Protected path fragment '.env' in arg 'path': '.env'", latency_ms=0.19)
states_block = compute_stage_states(block_dec)
html_block = render_rings(
    states=states_block,
    reason=block_dec.reason,
    call_str="file.read_file({'path': '.env'})",
    total_overhead_ms=block_dec.meta["latency_ms"],
    decision_str=block_dec.decision,
    step_id=3,
)
st.markdown(html_block, unsafe_allow_html=True)
