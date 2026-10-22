#!/usr/bin/env python3
"""Static checks for the 2H detection queries (no emulator needed).

    python scripts/check_kql.py [file-or-folder ...]      (default: 2h-detection-pack/detections)

For every .kql file it checks:
  * brackets () [] {} are balanced and every quote is closed (comments and strings are ignored);
  * the file has at most MAX_LINES lines (the brief's limit, comments included);
  * every table the query reads (at the start of a pipeline, or after join, lookup or union) is
    SigninLogs or AuditLogs (or a name made with `let`);
  * cluster(), database(), table() and externaldata are not used (no reaching other data);
  * the last statement ends with `| project ...` that includes UserPrincipalName and TimeGenerated.
These are quick sanity checks, not a KQL parser: the emulator tests prove the queries really run.
Exit code 0 = all good, 1 = at least one problem. Standard library only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ALLOWED_TABLES = {"SigninLogs", "AuditLogs"}
REQUIRED_OUTPUT = ("UserPrincipalName", "TimeGenerated")
MAX_LINES = 40
BLOCKED = (
    (re.compile(r"\b(cluster|database|table)\s*\(", re.IGNORECASE), "{0}() is not allowed"),
    (re.compile(r"\bexternaldata\b", re.IGNORECASE), "externaldata is not allowed"),
)
OPTIONS = r"(?:[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s*)*"  # e.g. kind=inner or withsource=Src
PAIRS = {")": "(", "]": "[", "}": "{"}


def strip_comments_and_strings(text: str) -> tuple[str, list[str]]:
    """Return (text with comments removed and every string replaced by ""), plus any problems."""
    problems, out, i, n = [], [], 0, len(text)
    while i < n:
        ch = text[i]
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif ch in "\"'":
            quote, i = ch, i + 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
            if i >= n:
                problems.append("unclosed quote")
            i += 1
            out.append('""')
        else:
            out.append(ch)
            i += 1
    return "".join(out), problems


def check_brackets(clean: str) -> list[str]:
    stack, problems = [], []
    for ch in clean:
        if ch in "([{":
            stack.append(ch)
        elif ch in PAIRS and (not stack or stack.pop() != PAIRS[ch]):
            problems.append(f"unbalanced bracket near '{ch}'")
            return problems
    if stack:
        problems.append(f"unclosed bracket '{stack[-1]}'")
    return problems


def sources(clean: str) -> set[str]:
    """Names used as the start of a pipeline: the first word of a statement, after `let x =`,
    or after '(' when a '|' follows (as in `(AuditLogs | where ...)`)."""
    found = set()
    for match in re.finditer(r"(?:^|;)\s*(?:let\s+\w+\s*=\s*)?([A-Za-z_]\w*)", clean):
        if match.group(1) not in ("let", "union"):
            found.add(match.group(1))
    found.update(re.findall(r"\(\s*([A-Za-z_]\w*)\s*\|", clean))
    return found


def join_union_names(clean: str) -> set[str]:
    """Names right after `join`/`lookup` (with options such as kind=inner, or in parentheses)
    and every item of a `union` list."""
    found = {
        match.group(1)
        for match in re.finditer(
            rf"\b(?:join|lookup)\b\s*{OPTIONS}\(?\s*([A-Za-z_][\w*]*)", clean)
    }
    for match in re.finditer(rf"\bunion\b\s*{OPTIONS}", clean):
        pos = match.end()
        while pos < len(clean):
            while pos < len(clean) and clean[pos].isspace():
                pos += 1
            if pos < len(clean) and clean[pos] == "(":  # (name | ...) is found by sources()
                depth = 0
                while pos < len(clean):
                    depth += (clean[pos] == "(") - (clean[pos] == ")")
                    pos += 1
                    if depth == 0:
                        break
            else:
                name = re.match(r"[A-Za-z_][\w*]*", clean[pos:])
                if not name:
                    break
                found.add(name.group(0))
                pos += name.end()
            while pos < len(clean) and clean[pos].isspace():
                pos += 1
            if pos < len(clean) and clean[pos] == ",":
                pos += 1
            else:
                break
    return found


def last_project_columns(clean: str) -> list[str] | None:
    """Output column names of the final `| project ...`, or None if the query does not end
    with a projection."""
    depth, last_pipe = 0, -1
    for index, ch in enumerate(clean):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "|" and depth == 0:
            last_pipe = index
    segment = clean[last_pipe + 1:].strip().rstrip(";").strip()
    if last_pipe < 0 or not re.match(r"project\b", segment):
        return None
    body, items, depth, current = segment[len("project"):], [], 0, []
    for ch in body:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            items.append("".join(current))
            current = []
        else:
            current.append(ch)
    items.append("".join(current))
    names = []
    for item in items:
        item = item.strip()
        match = re.match(r"([A-Za-z_]\w*)\s*=(?!=)", item)
        names.append(match.group(1) if match else item)
    return names


def check_text(text: str) -> list[str]:
    problems = []
    if len(text.splitlines()) > MAX_LINES:
        problems.append(f"more than {MAX_LINES} lines")
    clean, quote_problems = strip_comments_and_strings(text)
    problems += quote_problems + check_brackets(clean)
    if problems:
        return problems
    for pattern, message in BLOCKED:
        for match in pattern.finditer(clean):
            problems.append(message.format(match.group(1) if match.groups() else ""))
    defined = set(re.findall(r"\blet\s+(\w+)\s*=", clean))
    used = sources(clean) | join_union_names(clean)
    for name in sorted(used - ALLOWED_TABLES - defined - {"union"}):
        problems.append(f"unknown table or name '{name}' (only SigninLogs and AuditLogs allowed)")
    if not (sources(clean) & ALLOWED_TABLES):
        problems.append("query reads neither SigninLogs nor AuditLogs")
    columns = last_project_columns(clean)
    if columns is None:
        problems.append("query does not end with '| project ...'")
    else:
        for needed in REQUIRED_OUTPUT:
            if needed not in columns:
                problems.append(f"final project does not output {needed}")
    return problems


def check_file(path: Path) -> list[str]:
    return check_text(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parent.parent
    targets = [Path(a) for a in argv] or [root / "2h-detection-pack" / "detections"]
    files = []
    for target in targets:
        files += sorted(target.glob("*.kql")) if target.is_dir() else [target]
    if not files:
        print("no .kql files found")
        return 1
    failed = False
    for path in files:
        problems = check_file(path)
        print(f"{'FAIL' if problems else 'ok  '} {path.name}")
        for problem in problems:
            print(f"     - {problem}")
        failed = failed or bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
