"""Built-in explanations. Used when no AI provider is configured, or when a provider fails."""
import re

from app.models.schemas import ExplanationContent, Finding

SECRET = {
    "problem": "A secret (password, API key, or token) is written directly in the source code.",
    "why_dangerous": "Anyone who can read the code, including everyone with access to the repository and its history, can use the secret.",
    "impact": "Attackers can access the protected service or data with the stolen credential, and the leak stays in version control history.",
    "how_to_fix": [
        "Treat the secret as compromised: revoke it and create a new one.",
        "Remove it from the code and load it from an environment variable or a secret manager.",
        "Remove it from git history if it was committed (for example with git filter-repo).",
        "Add secret scanning to your pipeline so this is caught early.",
    ],
    "secure_example": 'import os\n\nDB_PASSWORD = os.environ["DB_PASSWORD"]  # set outside the code, never committed',
}

RULES = {
    "sql-injection": {
        "problem": "The SQL query is built by putting values straight into the query text (string formatting, concatenation, or an f-string).",
        "why_dangerous": "Attacker-controlled input becomes part of the SQL command, so it can change what the query does.",
        "impact": "An attacker can read, change, or delete data, bypass login checks, and on some databases run commands on the server.",
        "how_to_fix": [
            "Use parameterized queries: pass the values separately from the SQL text.",
            "Never build SQL with %, +, .format(), or f-strings.",
            "Validate input types and lengths as an extra layer.",
            "Give the database account only the permissions it needs.",
        ],
        "secure_example": '# Unsafe\ncur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n\n# Safe: the driver sends the value separately (use %s instead of ? for MySQL/PostgreSQL)\ncur.execute("SELECT * FROM users WHERE name = ?", (name,))',
    },
    "code-injection-eval": {
        "problem": "eval() or exec() runs text as Python code.",
        "why_dangerous": "If any part of that text comes from a user, the user can run their own code on your server.",
        "impact": "Full compromise of the application: data theft, file access, and running system commands.",
        "how_to_fix": [
            "Remove eval/exec. Parse the data instead of running it.",
            "Use ast.literal_eval for simple values, or json.loads for JSON.",
            "For calculations or commands, map allowed inputs to functions with a dictionary.",
        ],
        "secure_example": "import ast\n\nvalue = ast.literal_eval(user_text)  # accepts only literals: numbers, strings, lists, dicts",
    },
    "command-injection": {
        "problem": "A shell command is built from a value that is not constant and is run through the shell.",
        "why_dangerous": "Special characters in the value (for example ; or &&) can add extra commands.",
        "impact": "An attacker can run arbitrary commands on the server with the application's permissions.",
        "how_to_fix": [
            "Do not use shell=True or os.system with variable input.",
            "Pass the command as a list so each value stays a single argument.",
            "Validate the value against an allow-list (for example a hostname pattern).",
        ],
        "secure_example": 'import subprocess\n\nsubprocess.run(["ping", "-c", "1", host], check=True)  # no shell, host is one argument',
    },
    "hardcoded-credential": SECRET,
    "insecure-deserialization-pickle": {
        "problem": "pickle loads Python objects from data, and a crafted file can run code while it loads.",
        "why_dangerous": "Unpickling is not safe for data that an attacker can influence.",
        "impact": "Remote code execution on the machine that loads the data.",
        "how_to_fix": [
            "Use a data-only format such as JSON.",
            "If you must use pickle, only load data you created yourself and sign it.",
        ],
        "secure_example": "import json\n\ndata = json.loads(text)  # data only, cannot run code",
    },
    "insecure-yaml-load": {
        "problem": "yaml.load() without a safe loader can create arbitrary Python objects from the YAML text.",
        "why_dangerous": "A crafted YAML document can run code while it is parsed.",
        "impact": "Remote code execution when untrusted YAML is loaded.",
        "how_to_fix": ["Use yaml.safe_load instead of yaml.load.", "Keep PyYAML up to date."],
        "secure_example": "import yaml\n\nconfig = yaml.safe_load(text)",
    },
    "weak-hash-algorithm": {
        "problem": "MD5 or SHA-1 is used. Both are considered broken for security purposes.",
        "why_dangerous": "Attackers can find collisions quickly, and fast hashes make stolen password hashes easy to crack.",
        "impact": "Forged data or signatures, and passwords recovered from a leaked database.",
        "how_to_fix": [
            "For checksums, use SHA-256 (hashlib.sha256).",
            "For passwords, use a slow salted function: bcrypt, scrypt, argon2, or PBKDF2.",
        ],
        "secure_example": 'import hashlib, os\n\nsalt = os.urandom(16)\nhash_hex = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()',
    },
    "tls-verification-disabled": {
        "problem": "TLS certificate verification is turned off (verify=False).",
        "why_dangerous": "The program no longer checks who it is talking to, so anyone on the network path can pose as the server.",
        "impact": "Man-in-the-middle attacks: stolen credentials and tampered responses.",
        "how_to_fix": [
            "Remove verify=False so the default certificate check is used.",
            "If you use a private CA, pass its certificate file with verify='/path/to/ca.pem'.",
        ],
        "secure_example": "import requests\n\nresponse = requests.get(url, timeout=10)  # certificate is verified by default",
    },
    "flask-debug-enabled": {
        "problem": "The application runs with debug=True.",
        "why_dangerous": "Debug mode exposes an interactive debugger and detailed errors.",
        "impact": "On a reachable server this can let an attacker run code and see internal details.",
        "how_to_fix": [
            "Turn debug off in production and control it with an environment variable.",
            "Run the app with a production server such as gunicorn.",
        ],
        "secure_example": 'import os\n\napp.run(debug=os.environ.get("FLASK_DEBUG") == "1")',
    },
    "bare-except": {
        "problem": "A bare except: catches every error, including ones you did not expect.",
        "why_dangerous": "It hides bugs and can swallow KeyboardInterrupt and SystemExit.",
        "impact": "Failures pass silently and are hard to debug.",
        "how_to_fix": ["Catch the specific exception types you expect.", "Log or re-raise anything unexpected."],
        "secure_example": "try:\n    value = int(text)\nexcept ValueError:\n    value = 0",
    },
    "mutable-default-argument": {
        "problem": "A function uses a list or dict as a default argument value.",
        "why_dangerous": "The default is created once and shared by every call, so changes leak between calls.",
        "impact": "Hard-to-find bugs where data from earlier calls shows up later.",
        "how_to_fix": ["Use None as the default and create the list inside the function."],
        "secure_example": "def add_item(item, items=None):\n    if items is None:\n        items = []\n    items.append(item)\n    return items",
    },
}


def _where(f: Finding) -> str:
    span = f"line {f.line}" if f.end_line == f.line else f"lines {f.line} to {f.end_line}"
    return f"In {f.file}, {span}."


def _dependency(f: Finding) -> ExplanationContent:
    m = re.match(r"^(\S+) (\S+):", f.title)
    pkg, version = (m.group(1), m.group(2)) if m else ("the package", "")
    fixed_match = re.search(r"Fixed in ([\w.\-+]+?)\.(?:\s|$)", f.message)
    fixed = fixed_match.group(1) if fixed_match else None
    fix_steps = (
        [f"Upgrade {pkg} to {fixed} or later in requirements.txt (for example {pkg}>={fixed})."]
        if fixed
        else [f"No fixed version is listed yet. Check the advisory for {f.rule_id} for a workaround, or replace {pkg}."]
    )
    fix_steps += ["Run your tests after upgrading.", "Use a tool such as pip-audit or Dependabot to catch this earlier."]
    return ExplanationContent(
        problem=f"{pkg} {version} has a publicly known vulnerability ({f.rule_id}).".replace("  ", " "),
        why_dangerous="Known vulnerabilities are documented, and attackers scan for applications that still use affected versions.",
        location=_where(f),
        impact=f"Depends on the flaw, which is rated {f.severity}. Read the advisory for {f.rule_id} to see how it can be exploited.",
        how_to_fix=fix_steps,
        secure_example=f"# requirements.txt\n{pkg}>={fixed}" if fixed else None,
    )


class MockProvider:
    name = "mock"
    model = "built-in-templates"

    def explain(self, f: Finding) -> ExplanationContent:
        if f.tool == "trivy" or f.rule_id.upper().startswith("CVE-"):
            return _dependency(f)
        entry = SECRET if f.category == "Secret" else RULES.get(f.rule_id)
        if entry is None:
            return ExplanationContent(
                problem=f.message or f.title,
                why_dangerous=f"{f.tool} reported this as a {f.severity} {f.category.lower()} issue (rule {f.rule_id}).",
                location=_where(f),
                impact="Depends on how the code is used. Review the flagged code to judge the risk.",
                how_to_fix=["Review the flagged code.", f"Look up the documentation for rule {f.rule_id}.", "Fix it and run the scan again."],
                secure_example=None,
            )
        return ExplanationContent(location=_where(f), **entry)
