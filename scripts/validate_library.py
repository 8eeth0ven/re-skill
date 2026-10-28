#!/usr/bin/env python3
"""Validate local RE routes and source syntax without invoking analysis tools.

This is a structural check, not proof that example exploits or live tools work.
Raw data, installed tools, snapshots, and historical logs are not executed.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

# Support direct execution and importlib/spec-based loading from offline tests.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from markdown_routes import extract_routes, prose_lines  # noqa: E402

SKIP_PARTS = {'.git', 'data', 'tools-env', '环境快照', '__pycache__', '输出'}
HISTORICAL = {'自检报告.md', 'radar/发现日志.md'}
REQUIRED_ENTRY_ROUTES = {
    'docs/runner.md', 'pipeline/pipeline.md', 'breach-tables-cve.md',
    'platforms/INDEX.md', 'techniques/INDEX.md', 'corpus/INDEX.md',
    'radar/README.md', 'setup.md', 'device-testing.md', 'unattended.md',
    'test-values.md', 'docs/execution-reference.md',
}


def links(source):
    return extract_routes(source)


def heading_ids(source):
    counts = Counter()
    result = set()
    for _, line in prose_lines(source):
        match = re.match(r'^#{1,6}\s+(.+?)\s*#*$', line)
        if match:
            text = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', match.group(1))
            text = re.sub(r'<[^>]*>', '', text).lower().replace('`', '')
            text = ''.join(c for c in text if c.isalnum() or c in '_- ')
            slug = text.replace(' ', '-')
            suffix = '' if not counts[slug] else f'-{counts[slug]}'
            result.add(slug + suffix)
            counts[slug] += 1
    return result


def validate(root):
    root = Path(root).resolve()
    files = sorted(p for p in root.rglob('*') if p.is_file()
                   and not (set(p.relative_to(root).parts) & SKIP_PARTS))
    errors = []
    warnings = []
    bash = shutil.which("bash")
    texts = {}
    stats = Counter()
    for path in files:
        rel = path.relative_to(root).as_posix()
        if path.suffix == '.md':
            texts[path.resolve()] = path.read_text(encoding='utf-8')
            stats['markdown_files'] += 1
        elif path.suffix == '.py':
            try:
                ast.parse(path.read_text(encoding='utf-8'), filename=rel)
            except (SyntaxError, UnicodeError) as exc:
                errors.append(f'{rel}: {exc}')
            stats['python_files'] += 1
        elif path.suffix == '.sh':
            stats['shell_files'] += 1
            if bash is None:
                stats['shell_files_unchecked'] += 1
                continue
            try:
                proc = subprocess.run([bash, '-n', path.relative_to(root).as_posix()],
                                      cwd=root, capture_output=True, text=True)
                if proc.returncode:
                    errors.append(f'{rel}: {proc.stderr.strip()}')
            except OSError as exc:
                errors.append(f'{rel}: Bash syntax check unavailable: {exc}')

    for path, source in texts.items():
        rel = path.relative_to(root).as_posix()
        if rel in HISTORICAL:
            continue
        for number, target in links(source):
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            destination = (path.parent / unquote(url.path)).resolve() if url.path else path
            stats['local_links'] += 1
            if not destination.exists():
                errors.append(f'{rel}:{number}: missing link {target}')
            elif url.fragment and destination.suffix == '.md':
                content = texts.get(destination)
                if content is not None and unquote(url.fragment) not in heading_ids(content):
                    errors.append(f'{rel}:{number}: missing heading {target}')

    # Root-relative library routes also appear as plain prose or inline code. Do not
    # treat generated outputs, external source trees (namespace:path), or raw data
    # as bundled files. Markdown links and anchors are validated separately above.
    route_pattern = re.compile(
        r'(?<![\w/.:~-])((?:platforms|techniques|corpus|docs|pipeline|radar)/'
        r'[A-Za-z0-9_./-]+\.md)(?![\w/-]|\.\w)'
    )
    for path, source in texts.items():
        rel = path.relative_to(root).as_posix()
        if rel in HISTORICAL:
            continue
        for number, line in prose_lines(source):
            for match in route_pattern.finditer(line):
                target = match.group(1)
                stats['literal_routes'] += 1
                if not (root / target).exists() and not (path.parent / target).exists():
                    errors.append(f'{rel}:{number}: missing literal library route {target}')

    for branch in ('platforms', 'techniques', 'corpus'):
        folder = root / branch
        index = folder / 'INDEX.md'
        source = texts.get(index.resolve(), '')
        targets = {(index.parent / unquote(urlsplit(t).path)).resolve()
                   for _, t in links(source) if not urlsplit(t).scheme}
        missing = [p.relative_to(root).as_posix() for p in sorted(folder.rglob('*.md'))
                   if p != index and p.resolve() not in targets]
        if missing:
            errors.append(f'{branch}/INDEX.md: articles missing from index: {", ".join(missing)}')
        for number, line in prose_lines(source):
            if line.lstrip().startswith('|'):
                row = re.sub(r'(`+).*?\1', '', line.strip())
                row = re.sub(r'\\\|', '', row)
                if row.count('|') != 3:
                    errors.append(f'{branch}/INDEX.md:{number}: expected a two-column route table')
        stats[f'{branch}_articles'] = len(list(folder.rglob('*.md'))) - 1

    skill = texts.get((root / 'SKILL.md').resolve(), '')
    front = re.match(r'\A---\n(.*?)\n---\n', skill, re.S)
    if not front:
        errors.append('SKILL.md: missing standard YAML frontmatter')
    else:
        desc = front.group(1)
        if not re.search(r'^name:\s*re\s*$', desc, re.M):
            errors.append('SKILL.md: expected name: re')
        description = re.search(r'^description:\s*>-?\n((?:[ \t]+[^\n]*\n?)*)', desc, re.M)
        normalized = ' '.join(description.group(1).split()) if description else ''
        if not normalized or len(normalized) > 500:
            errors.append('SKILL.md: expected a nonempty folded description of at most 500 characters')
        if 'reverse engineering' not in normalized.lower():
            errors.append('SKILL.md: description must identify its reverse-engineering domain')
        if re.search(r'[\u3400-\u9fff]', normalized):
            errors.append('SKILL.md: discovery description must be English')
        entry_targets = {unquote(urlsplit(target).path) for _, target in links(skill)
                         if not urlsplit(target).scheme}
        for route in sorted(REQUIRED_ENTRY_ROUTES - entry_targets):
            errors.append(f'SKILL.md: missing essential workflow route: {route}')
    if stats['shell_files_unchecked']:
        warnings.append('Bash is unavailable; optional shell-script syntax was not checked. Python entry points remain independently validated.')
    return {'root': str(root), 'passed': not errors, 'stats': dict(stats), 'errors': errors, 'warnings': warnings}


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--json', action='store_true', help='Emit the report as JSON.')
    args = parser.parse_args()
    report = validate(args.root.resolve())
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(('PASS' if report['passed'] else 'FAIL') + ': local RE library structural checks')
        print(json.dumps(report['stats'], sort_keys=True))
        for error in report['errors']:
            print(f'  {error}')
        for warning in report['warnings']:
            print(f'  WARNING: {warning}')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
