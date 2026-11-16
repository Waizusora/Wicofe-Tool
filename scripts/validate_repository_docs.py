#!/usr/bin/env python3
"""Validate local Markdown links and optional forbidden terms in a workspace.

The workspace is a directory containing one or more checked-out repositories.
The command is read-only and uses only the Python standard library.
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

LINK_RE = re.compile(r"!?\\[[^\\]]*\\]\\((<[^>]+>|[^)]+)\\)")
HEADING_RE = re.compile(r"^ {0,3}(#{1,6})\\s+(.+?)\\s*#*\\s*$")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
INLINE_CODE_RE = re.compile(r"\\x60[^\\x60]*\\x60")
FENCE_RE = re.compile(r"^\\s{0,3}(\\x60{3,}|~{3,})")
AUTOLINK_RE = re.compile(r"<((?:https?://|mailto:)[^>]+)>", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    code: str
    message: str


def heading_slug(text: str) -> str:
    text = re.sub(r"\\[([^\\]]+)\\]\\([^)]*\\)", r"\\1", text)
    text = re.sub(r"\\x60([^\\x60]+)\\x60", r"\\1", text)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    text = re.sub(r"[^\\w\\- ]", "", text, flags=re.UNICODE)
    text = re.sub(r"\\s", "-", text)
    return re.sub(r"-+", "-", text)


def markdown_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8-sig").splitlines()


def extract_headings(lines: list[str]) -> set[str]:
    headings: set[str] = set()
    counts: dict[str, int] = {}
    in_fence = False
    fence_marker = ""
    for line in lines:
        fence = FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif marker[0] == fence_marker[0]:
                in_fence = False
            continue
        if in_fence:
            continue
        match = HEADING_RE.match(line)
        if not match:
            continue
        base = heading_slug(match.group(2))
        count = counts.get(base, 0)
        counts[base] = count + 1
        headings.add(base if count == 0 else f"{base}-{count}")
    return headings


def clean_link_target(raw: str) -> str:
    target = raw.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    elif re.search(r"""\\s+["']""", target):
        target = re.split(r"""\\s+(?=["'])""", target, maxsplit=1)[0]
    return unquote(target)


def scan_markdown_file(path: Path, workspace: Path, forbidden_terms: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = markdown_lines(path)
    except (OSError, UnicodeError) as exc:
        return [Finding(path, 1, "READ_ERROR", str(exc))]

    own_headings = extract_headings(lines)
    in_fence = False
    fence_marker = ""
    for number, original in enumerate(lines, start=1):
        fence = FENCE_RE.match(original)
        if fence:
            marker = fence.group(1)
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif marker[0] == fence_marker[0]:
                in_fence = False
            continue
        if in_fence:
            continue

        line = HTML_COMMENT_RE.sub("", original)
        line = INLINE_CODE_RE.sub("", line)
        line = AUTOLINK_RE.sub("", line)

        for term in forbidden_terms:
            if term.casefold() in line.casefold():
                findings.append(Finding(path, number, "FORBIDDEN_TERM",
                                        f"found configured term {term!r}"))

        for match in LINK_RE.finditer(line):
            target = clean_link_target(match.group(1))
            if not target:
                continue
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue

            raw_path = parsed.path
            fragment = parsed.fragment
            if not raw_path:
                destination = path
            elif raw_path.startswith("/"):
                destination = workspace / raw_path.lstrip("/")
            else:
                destination = path.parent / raw_path

            try:
                destination = destination.resolve(strict=False)
                destination.relative_to(workspace)
            except (OSError, ValueError):
                findings.append(Finding(path, number, "PATH_ESCAPE",
                                        f"link leaves workspace: {target}"))
                continue

            if not destination.exists():
                findings.append(Finding(path, number, "BROKEN_LINK",
                                        f"target does not exist: {target}"))
                continue
            if destination.is_dir():
                index_candidates = [destination / "README.md", destination / "INDEX.md",
                                    destination / "index.md"]
                index_file = next((candidate for candidate in index_candidates
                                   if candidate.is_file()), None)
                if index_file is None:
                    findings.append(Finding(path, number, "DIRECTORY_NO_INDEX",
                                            f"directory has no README.md or INDEX.md: {target}"))
                    continue
                destination = index_file

            if fragment and destination.suffix.lower() in {".md", ".markdown"}:
                try:
                    target_headings = extract_headings(markdown_lines(destination))
                except (OSError, UnicodeError) as exc:
                    findings.append(Finding(path, number, "READ_ERROR",
                                            f"cannot inspect anchor target: {exc}"))
                    continue
                if fragment not in target_headings:
                    findings.append(Finding(path, number, "BROKEN_ANCHOR",
                                            f"heading #{fragment} not found in {destination}"))
            elif fragment and destination == path and fragment not in own_headings:
                findings.append(Finding(path, number, "BROKEN_ANCHOR",
                                        f"heading #{fragment} not found in this file"))

    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path,
                        help="directory containing one or more repository checkouts")
    parser.add_argument("--forbid-term", action="append", default=[],
                        help="case-insensitive term forbidden in Markdown; repeatable")
    parser.add_argument("--exclude", action="append", default=[],
                        help="glob relative to workspace to exclude; repeatable")
    args = parser.parse_args(argv)

    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        parser.error(f"workspace is not a directory: {workspace}")

    excluded = set()
    for pattern in args.exclude:
        excluded.update(p.resolve() for p in workspace.glob(pattern))

    markdown_files = sorted(
        p for p in workspace.rglob("*.md")
        if p.is_file() and p.resolve() not in excluded
    )
    findings: list[Finding] = []
    for path in markdown_files:
        findings.extend(scan_markdown_file(path, workspace, args.forbid_term))

    for finding in findings:
        try:
            display_path = finding.path.relative_to(workspace)
        except ValueError:
            display_path = finding.path
        print(f"{display_path}:{finding.line}: {finding.code}: {finding.message}")

    print(f"Scanned {len(markdown_files)} Markdown files; findings: {len(findings)}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
