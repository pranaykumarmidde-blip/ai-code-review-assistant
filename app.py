import ast
import io
import os
import re
import subprocess
import tempfile
import tokenize
from datetime import datetime

import streamlit as st

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------
st.set_page_config(
    page_title="CodeGuard | AI Code Review",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------
# PROFESSIONAL DESIGN
# --------------------------------------------------
st.markdown("""
<style>
.stApp {
    background: #0b1120;
}
.block-container {
    max-width: 1200px;
    padding-top: 1.5rem;
    padding-bottom: 3rem;
}
.hero {
    background: linear-gradient(120deg, #172554, #164e63);
    border: 1px solid #334155;
    border-radius: 18px;
    padding: 25px;
    margin-bottom: 20px;
}
.hero h1 {
    color: white;
    margin-bottom: 6px;
}
.hero p {
    color: #dbeafe;
}
div[data-testid="stMetric"] {
    background: #151e30;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 14px;
}
div.stButton > button {
    border-radius: 10px;
    min-height: 43px;
}
div.stButton > button[kind="primary"] {
    width: 100%;
}
</style>
""", unsafe_allow_html=True)

# --------------------------------------------------
# HEADER
# --------------------------------------------------
st.markdown("""
<div class="hero">
    <h1>🛡️ CodeGuard</h1>
    <p><b>Python Code Review Platform</b></p>
    <p>Detect potential bugs, inspect code quality,
    understand findings, and download a review report.</p>
</div>
""", unsafe_allow_html=True)

# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------
with st.sidebar:
    st.title("⚙️ Review settings")
    st.caption("Choose what to check during analysis.")

    check_pylint = st.checkbox(
        "Enable Pylint analysis", value=True
    )
    check_security = st.checkbox(
        "Enable security checks", value=True
    )
    check_style = st.checkbox(
        "Enable code-quality checks", value=True
    )

    st.divider()
    st.markdown("### About CodeGuard")
    st.write("Language: Python")
    st.write("Engine: AST + Pylint + custom rules")
    st.write("Execution of submitted code: Disabled")
    st.caption(
        "Findings are automated suggestions, not a guarantee "
        "that code is correct or secure."
    )

# --------------------------------------------------
# REVIEW ENGINE
# --------------------------------------------------
def review_python(source, use_pylint, use_security, use_style):
    findings = []
    syntax_error = None
    corrected = source
    fix_available = False

    def add_finding(severity, category, line, message, suggestion=""):
        findings.append({
            "severity": severity,
            "category": category,
            "line": line,
            "message": message,
            "suggestion": suggestion,
        })

    # Syntax and AST checks
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        syntax_error = {
            "line": exc.lineno or 1,
            "column": exc.offset or 1,
            "message": exc.msg,
        }
        return {
            "syntax_error": syntax_error,
            "findings": findings,
            "pylint_output": "",
            "corrected": None,
            "score": 0,
        }

    # Check for suspicious or commonly problematic patterns.
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if use_style and ast.get_docstring(node) is None:
                add_finding(
                    "Low", "Documentation", node.lineno,
                    f"Function '{node.name}' has no docstring.",
                    "Add a short docstring describing its purpose.",
                )

            # Mutable default arguments
            for default in node.args.defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    add_finding(
                        "Medium", "Potential bug", node.lineno,
                        f"Function '{node.name}' uses a mutable default argument.",
                        "Use None as the default and create a new object inside the function.",
                    )
                    break

            for default in node.args.kw_defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    add_finding(
                        "Medium", "Potential bug", node.lineno,
                        f"Function '{node.name}' uses a mutable keyword default.",
                        "Use None as the default and initialize the object inside the function.",
                    )
                    break

        if isinstance(node, ast.Import):
            if use_style:
                for alias in node.names:
                    if alias.name == "os":
                        pass

        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if use_security and func_name == "eval":
                add_finding(
                    "High", "Security", node.lineno,
                    "Use of eval() detected.",
                    "Avoid eval() with untrusted input; use a safer parser or explicit validation.",
                )

            if use_security and func_name == "exec":
                add_finding(
                    "High", "Security", node.lineno,
                    "Use of exec() detected.",
                    "Avoid dynamically executing untrusted code.",
                )

            if use_security and func_name == "pickle":
                add_finding(
                    "Medium", "Security", node.lineno,
                    "Review pickle usage if loading data from untrusted sources.",
                    "Use a safer data format such as JSON for untrusted input.",
                )

    # Common logic error example:
    # Do not assume every function named add must add.
    # Only flag this exact recognizable pattern as a possible issue.
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "add":
            if len(node.args.args) >= 2 and len(node.body) == 1:
                statement = node.body[0]
                if isinstance(statement, ast.Return):
                    value = statement.value
                    if (
                        isinstance(value, ast.BinOp)
                        and isinstance(value.op, ast.Sub)
                        and isinstance(value.left, ast.Name)
                        and isinstance(value.right, ast.Name)
                        and value.left.id == node.args.args[0].arg
                        and value.right.id == node.args.args[1].arg
                    ):
                        add_finding(
                            "Medium", "Possible logic bug", node.lineno,
                            "The add() function subtracts its two parameters.",
                            "If addition is intended, change '-' to '+'.",
                        )
                        corrected = (
                            source[:value.left.end_col_offset]
                            if False else source
                        )
                        # Safe targeted replacement for the recognized return line.
                        lines = source.splitlines()
                        return_line = statement.lineno - 1
                        if 0 <= return_line < len(lines):
                            lines[return_line] = re.sub(
                                r"(\breturn\s+\w+\s*)-\s*(\w+)",
                                r"\1+ \2",
                                lines[return_line],
                                count=1,
                            )
                            corrected = "\n".join(lines)
                            if source.endswith("\n"):
                                corrected += "\n"
                            fix_available = corrected != source

    # Token-based checks for unused imports and bare except.
    if use_style:
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
            imported_names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported_names.add(alias.asname or alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name != "*":
                            imported_names.add(alias.asname or alias.name)

            for name in sorted(imported_names):
                if not re.search(r"\b" + re.escape(name) + r"\b", source):
                    continue
                if len(re.findall(r"\b" + re.escape(name) + r"\b", source)) == 1:
                    add_finding(
                        "Low", "Code quality", 1,
                        f"Imported name '{name}' may be unused.",
                        "Remove the import if it is not needed.",
                    )

            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    add_finding(
                        "Medium", "Code quality", node.lineno,
                        "Bare except clause catches every exception.",
                        "Catch the specific exceptions your code expects.",
                    )
        except (tokenize.TokenError, IndentationError):
            pass

    # Pylint in a temporary file; submitted code is not executed.
    pylint_output = ""
    if use_pylint:
        filename = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".py",
                encoding="utf-8",
                delete=False,
            ) as temp:
                temp.write(source)
                filename = temp.name

            result = subprocess.run(
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
            pylint_output = (
                result.stdout + "\n" + result.stderr
            ).strip()
            pylint_output = pylint_output.replace(
                filename, "your_code.py"
            )
            pylint_output = re.sub(
                r"tmp[a-zA-Z0-9_-]+ your_code\.py",
                "your_code.py",
                pylint_output,
            )
        except FileNotFoundError:
            pylint_output = (
                "Pylint is unavailable. Check requirements.txt."
            )
        except subprocess.TimeoutExpired:
            pylint_output = "Pylint analysis timed out."
        finally:
            if filename and os.path.exists(filename):
                os.remove(filename)

    # Convert Pylint messages into review findings.
    for line in pylint_output.splitlines():
        match = re.search(
            r"your_code\.py:(\d+):\d+:\s+([ECRW]\d+):\s*(.*)",
            line,
        )
        if match:
            line_number = int(match.group(1))
            code = match.group(2)
            message = match.group(3)
            severity = (
                "High" if code.startswith("E")
                else "Medium" if code.startswith("W")
                else "Low"
            )
            add_finding(
                severity, f"Pylint {code}", line_number,
                message, "Review the reported line and update the code if appropriate.",
            )

    # Count findings for a simple quality indicator.
    high_count = sum(f["severity"] == "High" for f in findings)
    medium_count = sum(f["severity"] == "Medium" for f in findings)
    low_count = sum(f["severity"] == "Low" for f in findings)
    score = max(0, 100 - high_count * 20 - medium_count * 10 - low_count * 3)

    return {
        "syntax_error": syntax_error,
        "findings": findings,
        "pylint_output": pylint_output,
        "corrected": corrected if fix_available else None,
        "score": score,
    }


# --------------------------------------------------
# CODE INPUT
# --------------------------------------------------
st.header("1. Submit code")

uploaded_file = st.file_uploader(
    "Upload a Python file",
    type=["py"],
    help="Upload a .py file or paste code below.",
)

default_code = """def add(a, b):
    return a - b
"""

if "code_editor" not in st.session_state:
    st.session_state.code_editor = default_code

if uploaded_file is not None:
    try:
        st.session_state.code_editor = uploaded_file.getvalue().decode(
            "utf-8", errors="replace"
        )
    except Exception:
        st.error("Could not read the uploaded file.")

source_code = st.text_area(
    "Python code editor",
    key="code_editor",
    height=300,
    placeholder="Paste Python code here...",
)

review_button = st.button(
    "🔍 Analyze Code",
    type="primary",
    use_container_width=True,
)

if review_button:
    if not source_code.strip():
        st.warning("Please upload or paste Python code first.")
    elif len(source_code) > 200_000:
        st.error("Please use a Python file smaller than 200 KB.")
    else:
        with st.spinner("Analyzing code..."):
            st.session_state.review_result = review_python(
                source_code,
                check_pylint,
                check_security,
                check_style,
            )
            st.session_state.reviewed_source = source_code

# --------------------------------------------------
# RESULTS
# --------------------------------------------------
if "review_result" in st.session_state:
    result = st.session_state.review_result
    st.divider()
    st.header("2. Review dashboard")

    if result["syntax_error"]:
        error = result["syntax_error"]
        st.error(
            f"Syntax error on line {error['line']}, "
            f"column {error['column']}: {error['message']}"
        )
    else:
        st.success("Syntax check passed. No syntax errors detected.")

    findings = result["findings"]
    high = sum(f["severity"] == "High" for f in findings)
    medium = sum(f["severity"] == "Medium" for f in findings)
    low = sum(f["severity"] == "Low" for f in findings)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Quality indicator", f"{result['score']}/100")
    m2.metric("High", high)
    m3.metric("Medium", medium)
    m4.metric("Low", low)

    tabs = st.tabs([
        "Findings",
        "Suggestions",
        "Corrected code",
        "Pylint output",
    ])

    with tabs[0]:
        if not findings:
            st.success("No custom or parsed Pylint findings were found.")
        else:
            severity_filter = st.selectbox(
                "Filter findings",
                ["All", "High", "Medium", "Low"],
            )
            visible = [
                item for item in findings
                if severity_filter == "All"
                or item["severity"] == severity_filter
            ]

            for item in visible:
                heading = (
                    f"{item['severity']} | {item['category']} "
                    f"| Line {item['line']}"
                )
                with st.expander(heading, expanded=item["severity"] == "High"):
                    st.write(item["message"])
                    if item["suggestion"]:
                        st.info(item["suggestion"])

    with tabs[1]:
        if findings:
            for item in findings:
                st.markdown(
                    f"**Line {item['line']} — {item['category']}**"
                )
                st.write(item["message"])
                if item["suggestion"]:
                    st.write("Suggestion: " + item["suggestion"])
                st.divider()
        else:
            st.info("No suggestions are available for this review.")

    with tabs[2]:
        if result["corrected"]:
            st.warning(
                "This is a targeted example fix, not a guaranteed correction. "
                "Check the intended behavior and run tests before using it."
            )
            st.code(result["corrected"], language="python")
            st.download_button(
                "Download suggested code",
                data=result["corrected"],
                file_name="suggested_code.py",
                mime="text/x-python",
                use_container_width=True,
            )
        else:
            st.info(
                "No automatic fix was generated. Review the findings and "
                "make changes manually."
            )

    with tabs[3]:
        st.code(
            result["pylint_output"] or "Pylint was not run.",
            language="text",
        )

    # Downloadable review report.
    report_lines = [
        "# CodeGuard Review Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Quality indicator: {result['score']}/100",
        "",
        "## Syntax",
        (
            "Passed"
            if not result["syntax_error"]
            else str(result["syntax_error"])
        ),
        "",
        "## Findings",
    ]

    for item in findings:
        report_lines.append(
            f"- [{item['severity']}] Line {item['line']} "
            f"{item['category']}: {item['message']}"
        )
        if item["suggestion"]:
            report_lines.append(f"  Suggestion: {item['suggestion']}")

    report_lines += [
        "",
        "## Pylint output",
        result["pylint_output"] or "Pylint was not run.",
        "",
        "Disclaimer: Automated findings may be incomplete or incorrect.",
        "Review changes and test your program before using it.",
    ]

    report = "\n".join(report_lines)

    st.download_button(
        "⬇️ Download full review report",
        data=report,
        file_name="codeguard_review_report.md",
        mime="text/markdown",
        use_container_width=True,
    )

st.divider()
st.caption(
    "CodeGuard | Static analysis and rule-based review. "
    "No submitted Python code is executed. No LLM is connected in this version."
)
