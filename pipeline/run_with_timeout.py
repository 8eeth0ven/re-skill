#!/usr/bin/env python3
"""Run an argv command within its timeout and an optional monotonic workflow deadline.

Exit 124 means timeout/budget exhaustion; 127 means the executable is unavailable.
Only the process tree created by this invocation is terminated on timeout.
"""
import argparse
import os
import signal
import subprocess
import sys
import time


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deadline', type=float)
    parser.add_argument('--reserve', type=float, default=0)
    parser.add_argument('seconds', type=float)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not args.command or args.seconds <= 0 or args.reserve < 0:
        parser.error('supply a positive timeout, nonnegative reserve, and a command')
    timeout = args.seconds
    if args.deadline is not None:
        timeout = min(timeout, args.deadline - time.monotonic() - args.reserve)
    if timeout <= 0:
        print('DEGRADED: pipeline budget exhausted; reserve the report window', file=sys.stderr)
        return 124
    try:
        process = subprocess.Popen(args.command, start_new_session=(os.name == 'posix'))
    except OSError as exc:
        print(f'DEGRADED: cannot start command: {exc}', file=sys.stderr)
        return 127
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == 'posix':
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            try:
                subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               check=False, timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                pass
            if process.poll() is None:
                process.kill()
        process.wait()
        print('DEGRADED: command timed out (rc=124)', file=sys.stderr)
        return 124


if __name__ == '__main__':
    raise SystemExit(main())
