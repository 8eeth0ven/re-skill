#!/usr/bin/env python3
"""Run an argv command within its timeout and an optional monotonic workflow deadline.

Exit 124 means timeout/budget exhaustion; 127 means the executable is unavailable.
Exit 126 rejects Windows batch launchers; use a native executable/Java entry instead.
Only the process tree created by this invocation is terminated on timeout.
"""
import argparse
import os
import signal
import shutil
import subprocess
import sys
import time


def main(argv=None):
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
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
    command = list(args.command)
    if os.name == 'nt':
        executable = shutil.which(command[0]) or command[0]
        # CreateProcess can involve cmd.exe for batch launchers even with
        # shell=False. An arbitrary vendor launcher cannot safely carry asset
        # paths containing cmd metacharacters; do not synthesize a shell string.
        if os.path.splitext(executable.rstrip(' .'))[1].lower() in {'.bat', '.cmd'}:
            print('DEGRADED: Windows batch launcher is unsupported (rc=126); '
                  'use a native executable or Java entry, or the re-run Android profile', file=sys.stderr)
            return 126
        command[0] = executable
    try:
        process = subprocess.Popen(command, start_new_session=(os.name == 'posix'))
    except OSError as exc:
        print(f'DEGRADED: cannot start command: {exc}', file=sys.stderr)
        return 127
    try:
        return process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        interrupted = isinstance(exc, KeyboardInterrupt)
        stop_tree(process)
        message = 'command interrupted (rc=130)' if interrupted else 'command timed out (rc=124)'
        print(f'DEGRADED: {message}', file=sys.stderr)
        return 130 if interrupted else 124


def stop_tree(process):
    """Reap this invocation's child; never terminate an attached/user process."""
    if os.name == 'posix':
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            if process.poll() is None:
                process.kill()
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



if __name__ == '__main__':
    raise SystemExit(main())
