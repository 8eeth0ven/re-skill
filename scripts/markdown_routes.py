"""Extract local-route candidates from a bounded, standard-library Markdown subset.

Supported: inline links/images, single-line reference definitions and their
explicit/collapsed/defined-shortcut uses, HTML a[href]/img[src], and simple
non-data img[srcset]. Fenced code, line-local code spans, and HTML comments are
ignored. This is not a complete CommonMark parser, HTML renderer, or CSS parser.
Targets are returned without fetching or resolving them; callers own scope,
existence, and anchor checks. Line numbers are one-based.
"""
from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser


INLINE_LINK = re.compile(
    r'(?<!\\)!?\[(?:\\.|[^\]\\])*\]\(\s*'
    r'(?P<target><[^>\n]+>|(?:[^\s()]|\([^()\n]*\))+?)'
    r'(?:\s+(?:"[^"\n]*"|\x27[^\x27\n]*\x27|\([^()\n]*\)))?\s*\)'
)
DEFINITION = re.compile(
    r'^ {0,3}\[(?P<label>[^\]\n]+)\]:\s*'
    r'(?P<target><[^>\n]+>|\S+)'
    r'(?:\s+(?:"[^"\n]*"|\x27[^\x27\n]*\x27|\([^()\n]*\)))?\s*$'
)
REFERENCE = re.compile(r'(?<!\\)!?\[(?P<text>[^\]\n]+)\]\s*\[(?P<label>[^\]\n]*)\]')
SHORTCUT = re.compile(r'(?<![\\\w])!?\[(?P<label>[^\]\n]+)\](?![\[:(])')
CODE_SPAN = re.compile(r'(`+).*?\1')


def prose_lines(source):
    """Yield original numbered lines outside fenced code; retain inline-code text."""
    marker = None
    for number, line in enumerate(source.splitlines(), 1):
        fence = re.match(r'^\s*(`{3,}|~{3,})(.*)$', line)
        if fence:
            token, suffix = fence.groups()
            if marker is None:
                marker = token
            elif token[0] == marker[0] and len(token) >= len(marker) and not suffix.strip():
                marker = None
            continue
        if marker is None:
            yield number, line


def _blank(value):
    return ''.join('\n' if char == '\n' else ' ' for char in value)


def _label(value):
    return ' '.join(unescape(value).split()).casefold()


def _target(value):
    value = value[1:-1] if value.startswith('<') and value.endswith('>') else value
    return unescape(re.sub(r'\\([\\`*{}\[\]()#+.!_> -])', r'\1', value))


class _HtmlRoutes(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.routes = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        line, _ = self.getpos()
        field = 'href' if tag == 'a' else 'src' if tag == 'img' else None
        if field and attrs.get(field):
            self.routes.append((line, attrs[field]))
        srcset = attrs.get('srcset') if tag == 'img' else None
        # Data URLs can contain commas; do not invent relative paths from them.
        if srcset and 'data:' not in srcset.lower():
            for candidate in srcset.split(','):
                parts = candidate.strip().split()
                if parts:
                    self.routes.append((line, parts[0]))


def extract_routes(source):
    """Return (line, target) pairs, including reference definitions and used links.

    Undefined reference labels remain ordinary bracketed text. A definition's
    target is checked even when unused, so stale maintained routes stay visible.
    """
    lines = [''] * len(source.splitlines())
    for number, line in prose_lines(source):
        lines[number - 1] = CODE_SPAN.sub(lambda match: _blank(match.group()), line)
    visible = '\n'.join(lines)
    visible = re.sub(r'<!--.*?-->', lambda match: _blank(match.group()), visible, flags=re.S)
    lines = visible.splitlines()
    definitions = {}
    definition_lines = set()
    routes = []
    for number, line in enumerate(lines, 1):
        match = DEFINITION.match(line)
        if match:
            target = _target(match['target'])
            definitions.setdefault(_label(match['label']), target)
            definition_lines.add(number)
            routes.append((number, target))
    for number, line in enumerate(lines, 1):
        if number in definition_lines:
            continue
        occupied = []
        for match in INLINE_LINK.finditer(line):
            routes.append((number, _target(match['target'])))
            occupied.append(match.span())
        for match in REFERENCE.finditer(line):
            if any(start <= match.start() < end for start, end in occupied):
                continue
            label = _label(match['label'] or match['text'])
            if label in definitions:
                routes.append((number, definitions[label]))
            occupied.append(match.span())
        for match in SHORTCUT.finditer(line):
            if any(start <= match.start() < end for start, end in occupied):
                continue
            label = _label(match['label'])
            if label in definitions:
                routes.append((number, definitions[label]))
    html = _HtmlRoutes()
    html.feed(visible)
    html.close()
    routes.extend(html.routes)
    return sorted(routes, key=lambda item: item[0])
