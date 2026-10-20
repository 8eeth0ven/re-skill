#!/usr/bin/env python3
"""Stalker call 事件 → 调用树 + 热点统计(本机实测通过)。

输入:stalker_trace.py --out 产出的 JSONL,每行
  {"type":"call","from":"Python!0x...","to":"Python!0x...","depth":N}
  (block/ret 行会被忽略)

用法:
  ./calltree.py events.jsonl [--top 15] [--children 3] [--depth-max 8]

输出:
  1) 聚合调用树(每个节点:目标符号 + 调用次数;按次数截断展示)
  2) 热点 top:被调最多次的目标
  3) 去重率:唯一 from->to 边 / 总事件数(trace 数据大爆炸的压缩证据)
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
    edges = defaultdict(int)     # (from,to) -> 次数
    targets = defaultdict(int)   # to -> 次数
    total = 0
    stack = []                   # 当前调用栈(to 链)

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
            # depth 相对值:增→入栈,减→弹栈,平→同级
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

    print('== 调用树(top %d children/层, 深度<=%d) ==' % (a.children, a.depth_max))
    render(root, '', 0)

    print('\n== 热点目标 top %d ==' % a.top)
    for k, v in sorted(targets.items(), key=lambda kv: -kv[1])[:a.top]:
        print('  %6d  %s' % (v, k))

    uniq = len(edges)
    print('\n== 去重统计 ==')
    print('  call 事件总数 : %d' % total)
    print('  唯一 from->to 边: %d (去重率 %.1f%%)' % (uniq, 100.0 * (1 - uniq / total) if total else 0))
    print('  唯一目标符号  : %d' % len(targets))


if __name__ == '__main__':
    main()
