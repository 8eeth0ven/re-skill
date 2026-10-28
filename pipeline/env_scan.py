#!/usr/bin/env python3
"""Read-only tool/device inventory and companion guidance; snapshots use the legacy directory name."""
import datetime
import glob
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAP_DIR = ROOT / '环境快照'
IS_WIN = platform.system() == 'Windows'
_sdk_default = Path.home() / ('Library/Android/sdk' if platform.system() == 'Darwin' else
                              'AppData/Local/Android/Sdk' if IS_WIN else 'Android/Sdk')
SDK = Path(os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME') or _sdk_default)
ADB = shutil.which('adb') or str(SDK / 'platform-tools' / ('adb.exe' if IS_WIN else 'adb'))
VENV_PY = str(ROOT / 'tools-env' / '.venv' / ('Scripts/python.exe' if IS_WIN else 'bin/python'))
ABI_TO_ARCH = {'arm64-v8a': 'arm64', 'armeabi-v7a': 'arm', 'armeabi': 'arm',
               'x86': 'x86', 'x86_64': 'x86_64'}


def run(cmd, timeout=20):
    """Pass an argv list directly; paths/serials are never interpreted by a host shell."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=timeout)
        output = (result.stdout or '') + (result.stderr or '')
        return output if result.returncode == 0 else f'[err rc={result.returncode}] {output}'
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f'[err {type(exc).__name__}]'


def sec(lines, title):
    lines.extend(['', f'## {title}', ''])


def serial_ports():
    if platform.system() == 'Darwin':
        return sorted(glob.glob('/dev/cu.*'))
    if IS_WIN:
        output = run(['powershell', '-NoProfile', '-Command',
                      '[System.IO.Ports.SerialPort]::GetPortNames()'])
        return [p.strip() for p in output.splitlines() if re.fullmatch(r'COM\d+', p.strip())]
    return sorted(set(glob.glob('/dev/ttyUSB*') + glob.glob('/dev/ttyACM*')))


def main():
    now = datetime.datetime.now()
    out = [f'# Environment snapshot {now:%Y-%m-%d %H:%M}',
           f'> host {platform.system()} {platform.release()} | scanner env_scan.py | '
           'read-only observations; companion guidance requires the device-testing discipline', '']
    sec(out, '1. Available software')
    tools = [('jadx', ['jadx', '--version']), ('apktool', ['apktool', '--version']),
             ('radare2', ['r2', '-v']), ('adb', [ADB, 'version']), ('7z', ['7z']),
             ('java', ['java', '-version']), ('node', ['node', '-v']),
             ('uv', ['uv', '--version']), ('python3', [shutil.which('python3') or 'python', '--version'])]
    out.extend(['| tool | version |', '|------|------|'])
    for name, cmd in tools:
        lines = run(cmd).strip().splitlines()
        version = lines[0][:80] if lines else 'not installed/no version output'
        out.append(f'| {name} | {version} |')
    libs = run([VENV_PY, '-c', 'import frida,unicorn,capstone,androguard;print(frida.__version__)']).strip()
    esptool = run([VENV_PY, '-m', 'esptool', 'version']).strip()
    out.extend(['', f'- venv (tools-env): {"error: " if libs.startswith("[err") else "OK frida "}{libs}',
                f'- esptool: {esptool.splitlines()[0] if esptool else "not installed"}'])
    fs_dir = ROOT / 'tools-env/frida-server'
    if fs_dir.is_dir():
        out.append('- frida-server spares: ' + ', '.join(sorted(p.name for p in fs_dir.iterdir())))

    sec(out, '2. External devices')
    if platform.system() == 'Darwin':
        usb = run(['system_profiler', 'SPUSBDataType'], timeout=40)
        selected = [line for line in usb.splitlines() if re.search(r'Product Name|Product ID|Manufacturer', line)]
        usb = '\n'.join(selected) or (usb if usb.startswith('[err') else '')
    elif IS_WIN:
        usb = run(['powershell', '-NoProfile', '-Command',
                   'Get-PnpDevice -PresentOnly | Where-Object InstanceId -Like "USB*" | Select-Object Status,Class,FriendlyName'])
    else:
        usb = run(['lsusb'])
    out.extend(['USB devices:', usb.strip() or '(none)'])
    ttys = serial_ports()
    patterns = [value for value in os.environ.get('BT_PATTERNS', '').split(',') if value]
    is_bluetooth = lambda port: 'Bluetooth' in port or any(value in port for value in patterns)
    normal_ports = [port for port in ttys if not is_bluetooth(port)]
    bluetooth_ports = [port for port in ttys if is_bluetooth(port)]
    out.extend(['', 'Serial ports:', *(normal_ports or ['(none)']), '',
                'Bluetooth SPP ports (not counted as new devices): ' + (', '.join(bluetooth_ports) or '(none)')])

    sec(out, '3. Android device details')
    devs = run([ADB, 'devices'])
    online = [line.split()[0] for line in devs.splitlines() if re.fullmatch(r'\S+\s+device', line.strip())]
    if not online:
        out.append('No online phone/emulator connected. Physical connection/debugging authorization may be required; '
                   'rerun the scan after that action. Do not poll. See device-testing.md.')
    for device in online:
        adb = [ADB, '-s', device]
        out.append(f'### Device {device}')
        props = {key: run(adb + ['shell', 'getprop', key]).strip() for key in
                 ['ro.product.model', 'ro.product.brand', 'ro.build.version.release', 'ro.build.version.sdk',
                  'ro.product.cpu.abi', 'ro.build.fingerprint', 'ro.build.display.id', 'ro.build.type', 'ro.debuggable']}
        out.extend(['| item | value |', '|------|------|'])
        out.extend(f'| {key} | {value} |' for key, value in props.items())
        su = run(adb + ['shell', 'which', 'su']).strip()
        magisk = run(adb + ['shell', 'pm', 'path', 'com.topjohnwu.magisk']).strip()
        ksu = run(adb + ['shell', 'pm', 'path', 'me.weishu.kernelsu']).strip()
        uid = run(adb + ['shell', 'id']).strip()
        uid0 = bool(re.search(r'\buid=0\b', uid))
        evidence = ((su and not su.startswith('[err')) or magisk.startswith('package:') or ksu.startswith('package:'))
        verdict = 'confirmed: current adb shell uid=0' if uid0 else ('unverified root evidence; su/adbd capability must be checked' if evidence else 'no root evidence; standard-user route')
        out.append(f'**root verdict: {verdict}**')
        out.extend(['- which su: ' + (su or 'none'), '- Magisk package: ' + (magisk or 'none'),
                    '- KernelSU package: ' + (ksu or 'none'), '- adb shell id: ' + (uid or '?')])
        packages = run(adb + ['shell', 'pm', 'list', 'packages', '-3'])
        pkgs3 = sorted(line.removeprefix('package:').strip() for line in packages.splitlines() if line.startswith('package:'))
        pkgs_system = [line for line in run(adb + ['shell', 'pm', 'list', 'packages', '-s']).splitlines() if line.startswith('package:')]
        out.append(f'- third-party apps {len(pkgs3)} / system apps {len(pkgs_system)}; third-party list:')
        out.append('  ' + ' '.join(pkgs3[:200]) + (' ...' if len(pkgs3) > 200 else ''))
        processes = run(adb + ['shell', 'ps', '-A'])
        fs_processes = [line for line in processes.splitlines() if re.search(r'(?:^|[/\s])(?:re_fs(?:_[\w-]+)?|fs|frida-server)\s*$', line)]
        out.append('- frida-server process observations (including legacy names): ' + ('; '.join(fs_processes) or 'none'))
        out.append('- adb_enabled: ' + run(adb + ['shell', 'settings', 'get', 'global', 'adb_enabled']).strip())
        abi = props.get('ro.product.cpu.abi', '')
        arch = ABI_TO_ARCH.get(abi)
        server = fs_dir / ('frida-server-android-' + arch) if arch else None
        out.extend(['', '**Companion actions (guidance only; this scan deploys nothing)**:'])
        if uid0 or evidence:
            out.append('  - Verify existing root access without obtaining root; su evidence does not imply `adb root` support. '
                       'Use only the selected test device, matching server/client version, and a new /data/local/tmp/re_fs; '
                       'record the copied file and spawned PID. See device-testing.md §I.')
            out.append('  - Active-invocation unpacking/FART and detection work remain available when their prerequisites hold; '
                       'see techniques/03-unpacking/ and techniques/12-bypass/.')
        else:
            out.append('  - Use gadget injection in a self-installed test APK or a test emulator; do not force root. '
                       'The objection patchapk route is in techniques/05-toolbox/.')
        out.append(f'  - abi={abi}; release architecture={arch or "unknown (do not guess)"}; spare server=' +
                   (str(server.relative_to(ROOT)) if server and server.is_file() else 'not available; select a matching binary first'))
        out.append(f'  - SDK {props.get("ro.build.version.sdk", "?")}: check the ART symbol-version table in techniques/11-syscall-chain/dex-load-exec-chain.md.')
        out.append('  - Self-installed test APKs only; preserve existing applications/services and restore task-owned changes per device-testing.md §I.4.')

    sec(out, '4. Firmware / microcontrollers')
    if normal_ports:
        out.append(f'Serial ports found: {normal_ports}; identity requires read-only identification/listening. No flashing or reset-line control.')
    else:
        out.append('No candidate microcontroller serial ports found. Recheck after physical connection; see device-testing.md §II.')
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    path = SNAP_DIR / f'snapshot-{now:%Y%m%d-%H%M%S}.md'
    content = '\n'.join(out)
    path.write_text(content, encoding='utf-8')
    (SNAP_DIR / 'latest.md').write_text(content, encoding='utf-8')
    print(content)
    print(f'\n[snapshot saved] {path}')


if __name__ == '__main__':
    main()
