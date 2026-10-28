#!/usr/bin/env python3
"""Stalker call events -> call tree and hotspot statistics(previously tested locally).

Input: JSONL produced by stalker_trace.py --out, one event per line:
  {"type":"call","from":"Python!0x...","to":"Python!0x...","depth":N}
  (block/ret records are ignored)

Usage:
  ./calltree.py events.jsonl [--top 15] [--children 3] [--depth-max 8]

Output:
  1) Aggregated call tree(target symbol and call count per node; display capped by count)
  2) Top hotspots: most frequently called targets
  3) Deduplication: unique from->to edges versus total events, showing trace compression
"""
import argparse
import json
from collections import defaultdict


class Node:
    __slots__ = ('count', 'children')

    def __init__(self):
        self.count = 0
        self.children = defaultdict(Node)

    def add(self, path):
        n = self
        n.count += 1
        for p in path:
            n = n.children[p]
            n.count += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('jsonl')
    ap.add_argument('--top', type=int, default=15)
    ap.add_argument('--children', type=int, default=3)
    ap.add_argument('--depth-max', type=int, default=8)
    a = ap.parse_args()

    root = Node()
    edges = defaultdict(int)     # (from,to) -> count
    targets = defaultdict(int)   # to -> count
    total = 0
    stack = []                   # Current call stack(target chain)

    with open(a.jsonl) as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get('type') != 'call':
                continue
            total += 1
            src, dst, d = e['from'], e['to'], e['depth']
            edges[(src, dst)] += 1
            targets[dst] += 1
            # Relative depth: increase -> push, decrease -> pop, equal -> sibling
            if not stack:
                stack = [(d, dst)]
                root.add([dst])
                continue
            last_d = stack[-1][0]
            if d > last_d:
                stack.append((d, dst))
            else:
                while stack and stack[-1][0] >= d:
                    stack.pop()
                stack.append((d, dst))
            root.add([x[1] for x in stack][:a.depth_max])

    def render(n, prefix, depth):
        if depth > a.depth_max:
            return
        kids = sorted(n.children.items(), key=lambda kv: -kv[1].count)[:a.children]
        for i, (name, c) in enumerate(kids):
            last = (i == len(kids) - 1)
            print('%s%s%s x%d' % (prefix, '`- ' if last else '|- ', name, c.count))
            render(c, prefix + ('   ' if last else '|  '), depth + 1)

    print('== Call tree(top %d children/level, depth<=%d) ==' % (a.children, a.depth_max))
    render(root, '', 0)

    print('\n== Top %d hotspot targets ==' % a.top)
    for k, v in sorted(targets.items(), key=lambda kv: -kv[1])[:a.top]:
        print('  %6d  %s' % (v, k))

    uniq = len(edges)
    print('\n== Deduplication statistics ==')
    print('  Total call events: %d' % total)
    print('  Unique from->to edges: %d (reduction %.1f%%)' % (uniq, 100.0 * (1 - uniq / total) if total else 0))
    print('  Unique target symbols: %d' % len(targets))


if __name__ == '__main__':
    main()
