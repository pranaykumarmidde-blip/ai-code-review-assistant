
import ast
import subprocess
import tempfile
import os
from datetime import datetime

import streamlit as st

st.set_page_config(
    page_title="AI Code Review Assistant",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 AI Code Review Assistant")
st.write(
    "Analyze Python code, detect potential problems, "
    "and receive improvement suggestions."
)

st.info(
    "This version uses Python static analysis and "
    "rule-based suggestions."
)

code = st.text_area(
    "Paste your Python code here",
    height=300,
    placeholder="def add(a, b):\n    return a - b"
)


def review_code(source):
    results = []

    try:
        ast.parse(source)
        results.append("✅ Syntax check: No syntax errors found.")
    except SyntaxError as exc:
        results.append(
            f"❌ Syntax error on line {exc.lineno}: {exc.msg}"
        )
        return "\n\n".join(results)

    filename = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            encoding="utf-8",
            delete=False
        ) as temp:
            temp.write(source)
            filename = temp.name

        process = subprocess.run(
            [
                "pylint",
                "--score=no",
                "--reports=no",
                filename
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        output = process.stdout + process.stderr
        output = output.replace(filename, "your_code.py")

        results.append("### Static Analysis Findings")
        results.append(output or "No findings reported.")

    except FileNotFoundError:
        results.append(
            "Pylint is unavailable. Check requirements.txt."
        )
    except subprocess.TimeoutExpired:
        results.append("Static analysis timed out.")
    finally:
        if filename and os.path.exists(filename):
            os.remove(filename)

    suggestions = []

    if "return a - b" in source and "def add" in source:
        suggestions.append(
            "Check add(): it subtracts instead of adding. "
            "If addition is intended, use return a + b."
        )

    if "eval(" in source:
        suggestions.append(
            "Avoid eval() with untrusted input."
        )

    if "except:" in source:
        suggestions.append(
            "Replace bare except clauses with specific exceptions."
        )

    if not suggestions:
        suggestions.append(
            "Add tests for expected behavior and edge cases."
        )

    results.append("### Suggestions")
    results.extend(f"- {item}" for item in suggestions)

    results.append(
        "Report generated: "
        + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    return "\n\n".join(results)


if st.button("🔎 Review Code", type="primary"):
    if not code.strip():
        st.warning("Please paste Python code first.")
    else:
        with st.spinner("Analyzing code..."):
            report = review_code(code)

        st.subheader("Code Review Report")
        st.markdown(report)

        st.download_button(
            "Download Review Report",
            data=report,
            file_name="code_review_report.md",
            mime="text/markdown"
        )

