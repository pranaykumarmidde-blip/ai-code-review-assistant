import ast
import os
import re
import subprocess
import tempfile
from datetime import datetime

import streamlit as st

st.set_page_config(
    page_title="CodeGuard | Python Review",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
.stApp { background: #0b1020; }
.block-container { max-width: 1100px; padding-top: 2rem; }
.hero {
    padding: 24px; border-radius: 18px;
    background: linear-gradient(120deg,#172554,#164e63);
    border: 1px solid #334155; margin-bottom: 20px;
}
.hero h1 { color: #ffffff; margin-bottom: 6px; }
.hero p { color: #cbd5e1; }
div.stButton > button[kind="primary"] {
    width: 100%; min-height: 48px; border-radius: 10px;
}
.metric {
    background: #151d30; padding: 16px;
    border: 1px solid #283449; border-radius: 12px;
}
.small-muted { color: #94a3b8; font-size: 0.9rem; }
</style>
""", unsafe_allow_html=True)

if "source_code" not in st.session_state:
    st.session_state.source_code = ""

if "report" not in st.session_state:
    st.session_state.report = None

st.markdown("""
<div class="hero">
    <h1>🛡️ CodeGuard</h1>
    <p>Python Code Review &amp; Static Analysis Platform</p>
    <p>Find syntax errors, inspect code quality, and get
    practical suggestions before you share your code.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("⚙️ Review settings")
    st.write("**Language:** Python")
    st.write("**Analyzer:** Python AST + Pylint")
    st.write("**Suggestions:** Rule-based")
    st.divider()
    st.caption("Runs on Streamlit Community Cloud.")
    st.caption("Do not upload passwords, API keys, or confidential code.")

st.subheader("1. Add your Python code")

uploaded = st.file_uploader(
    "Upload a Python file (.py)",
    type=["py"],
    help="Alternatively, paste your code into the editor below.",
)

if uploaded is not None:
    uploaded_text = uploaded.getvalue().decode("utf-8", errors="replace")
    if st.session_state.get("last_upload") != uploaded.name:
        st.session_state.source_code = uploaded_text
        st.session_state.last_upload = uploaded.name

source = st.text_area(
    "Code editor",
    key="source_code",
    height=300,
    placeholder="def add(a, b):\n    return a - b",
)

col1, col2 = st.columns(2)
with col1:
    run_review = st.button(
        "🔎 Review Python Code",
        type="primary",
        use_container_width=True,
    )
with col2:
    clear = st.button("Clear editor", use_container_width=True)

if clear:
    st.session_state.source_code = ""
    st.session_state.report = None
    st.session_state.last_upload = None
    st.rerun()


def perform_review(code):
    result = {
        "syntax_ok": False,
        "syntax_message": "",
        "pylint_output": "",
        "errors": 0,
        "warnings": 0,
        "suggestions": [],
        "corrected_code": None,
    }

    try:
        tree = ast.parse(code)
        result["syntax_ok"] = True
        result["syntax_message"] = "No syntax errors found."
    except SyntaxError as exc:
        result["syntax_message"] = (
            f"Line {exc.lineno}, column {exc.offset}: {exc.msg}"
        )
        result["errors"] = 1
        return result

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            encoding="utf-8",
            delete=False,
        ) as temp:
            temp.write(code)
            filename = temp.name

        try:
            process = subprocess.run(
                [
                    "pylint",
                    "--score=no",
                    "--reports=no",
                    "--output-format=text",
                    filename,
                ],
                capture_output=True,
                text=True,
                timeout=25,
            )
            output = (process.stdout + "\n" + process.stderr).strip()

            # Remove temporary machine-specific paths.
            output = output.replace(filename, "your_code.py")
            output = re.sub(
                r"tmp[a-zA-Z0-9_-]+ your_code\.py",
                "your_code.py",
                output,
            )
            result["pylint_output"] = output or "No findings reported."

            for line in output.splitlines():
                if re.search(r":\d+:\d+:\s+E\d+:", line):
                    result["errors"] += 1
                elif re.search(r":\d+:\d+:\s+[CRWIF]\d+:", line):
                    result["warnings"] += 1

        finally:
            os.remove(filename)

    except FileNotFoundError:
        result["pylint_output"] = (
            "Pylint is not installed. Check requirements.txt "
            "and the Streamlit deployment logs."
        )
    except subprocess.TimeoutExpired:
        result["pylint_output"] = "Pylint analysis timed out."

    suggestions = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if ast.get_docstring(node) is None:
                suggestions.append(
                    f"Line {node.lineno}: Add a docstring to "
                    f"function '{node.name}'."
                )

    if re.search(r"\beval\s*\(", code):
        suggestions.append(
            "Avoid eval() on untrusted input because it can "
            "execute arbitrary expressions."
        )

    if re.search(r"\bexcept\s*:", code):
        suggestions.append(
            "Replace a bare except clause with a specific exception."
        )

    if re.search(r"\bdef\s+add\s*\([^)]*\)\s*:\s*\n\s*return\s+\w+\s*-\s*\w+", code):
        suggestions.append(
            "Possible logic issue: add() returns a subtraction. "
            "Check whether addition was intended."
        )
        result["corrected_code"] = re.sub(
            r"(\bdef\s+add\s*\([^)]*\)\s*:\s*\n\s*return\s+)(\w+)\s*-\s*(\w+)",
            r"\1\2 + \3",
            code,
            count=1,
        )

    if not suggestions:
        suggestions.append(
            "No specific rule-based issue was detected. "
            "Test normal inputs, invalid inputs, and edge cases."
        )

    result["suggestions"] = suggestions
    return result


if run_review:
    if not source.strip():
        st.warning("Paste code or upload a Python file first.")
    else:
        with st.spinner("Checking syntax and analyzing code..."):
            st.session_state.report = perform_review(source)

if st.session_state.report:
    report = st.session_state.report
    st.divider()
    st.subheader("2. Review results")

    a, b, c = st.columns(3)
    with a:
        st.metric(
            "Syntax",
            "PASS" if report["syntax_ok"] else "ERROR",
        )
    with b:
        st.metric("Pylint errors", report["errors"])
    with c:
        st.metric("Pylint findings", report["warnings"])

    if report["syntax_ok"]:
        st.success(report["syntax_message"])
    else:
        st.error(report["syntax_message"])

    tab1, tab2, tab3 = st.tabs([
        "Static analysis",
        "Suggestions",
        "Corrected code",
    ])

    with tab1:
        st.markdown("#### Pylint output")
        st.code(report["pylint_output"], language="text")

    with tab2:
        st.markdown("#### Recommendations")
        for item in report["suggestions"]:
            st.markdown(f"- {item}")

    with tab3:
        if report["corrected_code"]:
            st.warning(
                "This is a suggested change, not a guaranteed fix. "
                "Review and test it before using it."
            )
            st.code(report["corrected_code"], language="python")
        else:
            st.info(
                "No automatic correction is available for this code. "
                "Use the findings and suggestions to make changes."
            )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    markdown_report = f"""# CodeGuard Review Report

Generated: {generated}

## Syntax
{report['syntax_message']}

## Pylint findings
{report['pylint_output']}

## Suggestions
""" + "\n".join(
        f"- {item}" for item in report["suggestions"]
    )

    st.download_button(
        "⬇️ Download review report",
        data=markdown_report,
        file_name="codeguard_review.md",
        mime="text/markdown",
        use_container_width=True,
    )

st.divider()
st.markdown(
    '<p class="small-muted">CodeGuard • Static analysis and '
    'rule-based recommendations. Suggestions may be incomplete; '
    'always test your code.</p>',
    unsafe_allow_html=True,
)
