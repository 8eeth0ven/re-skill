#!/usr/bin/env python3
"""Full environment inventory: tools / external devices / phone details (root · software list) / companion actions → snapshot written to re/环境快照/"""
import subprocess, sys, os, datetime, platform, shutil, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP_DIR = os.path.join(ROOT, '环境快照')
ADB = shutil.which('adb') or os.path.expanduser('~/Library/Android/sdk/platform-tools/adb')
VENV_PY = os.path.join(ROOT, 'tools-env/.venv/bin/python')

def run(cmd, timeout=20, shell=False):
    try:
        r = subprocess.run(cmd if shell else cmd.split(), capture_output=True, text=True, timeout=timeout,
                           shell=shell) if not shell else subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=True)
        return (r.stdout or '') + (r.stderr or '')
    except Exception as e:
        return f'[err {type(e).__name__}]'

def sec(lines, title): lines += ['', f'## {title}', '']

def main():
    now = datetime.datetime.now()
    out = [f'# Environment snapshot {now:%Y-%m-%d %H:%M}', f'> host {platform.system()} {platform.release()} | scanner env_scan.py | companion actions auto-generated from the verdicts', '']

    # 1 available software
    sec(out, '1. Available software')
    tools = [('jadx','jadx --version'),('apktool','apktool --version'),('radare2','r2 -v'),
             ('adb', f'{ADB} version'), ('7z','7z | head -2'),('java','java -version 2>&1 | head -1'),
             ('node','node -v'),('uv','uv --version'),('python3','python3 --version')]
    out.append('| tool | version |')
    out.append('|------|------|')
    for name, cmd in tools:
        v = run(cmd, shell=True).strip().splitlines()
        v = v[0][:60] if v else 'not installed'
        out.append(f'| {name} | {v} |')
    libs = run(f'{VENV_PY} -c "import frida,unicorn,capstone,androguard;print(frida.__version__)"', shell=True).strip()
    out.append('')
    out.append(f'- venv (tools-env): {"OK frida "+libs if libs and not libs.startswith("[") else "error: "+libs}; esptool: {run(VENV_PY+" -m esptool version", shell=True).splitlines()[0] if run(VENV_PY+" -m esptool version", shell=True) else "not installed"}')
    fs_dir = os.path.join(ROOT, 'tools-env/frida-server')
    if os.path.isdir(fs_dir):
        out.append(f'- frida-server spares: {", ".join(sorted(os.listdir(fs_dir)))}')

    # 2 external devices (USB/serial)
    sec(out, '2. External devices')
    usb = run('system_profiler SPUSBDataType | grep -E "Product Name|Product ID|Manufacturer"', shell=True, timeout=40)
    out.append('USB devices:'); out.append(usb.strip() or '(none)')
    if platform.system() == 'Darwin':
        ttys = run("ls /dev/cu.* 2>/dev/null | grep -v Bluetooth", shell=True).strip().splitlines()
        out.append(''); out.append('Serial ports:')
        out.extend(ttys or ['(none)'])
        out.append(''); out.append('Bluetooth SPP ports (not counted as new devices): ' + ', '.join(t for t in ttys if 'Bluetooth' in t or any(x and x in t for x in os.environ.get('BT_PATTERNS','').split(','))) or '(none)')

    # 3 phone details
    sec(out, '3. Android device details')
    devs = run(f'{ADB} devices', shell=True)
    online = [l.split('\t')[0] for l in devs.splitlines() if '\tdevice' in l]
    if not online:
        out.append('No phone connected. Companion action: plug one in (with USB debugging enabled) and rerun this scan; the physical-device chain is in device-testing.md.')
    for d in online:
        out.append(f'### Device {d}')
        props = {}
        for key in ['ro.product.model','ro.product.brand','ro.build.version.release','ro.build.version.sdk',
                    'ro.product.cpu.abi','ro.build.fingerprint','ro.build.display.id','ro.build.type','ro.debuggable']:
            props[key] = run(f'{ADB} -s {d} shell getprop {key}', shell=True).strip()
        out.append('| item | value |'); out.append('|------|------|')
        for k, v in props.items(): out.append(f'| {k} | {v} |')
        # root detection (read-only)
        root_evidence = []
        root_evidence.append('which su: ' + (run(f'{ADB} -s {d} shell which su', shell=True).strip() or 'none'))
        magisk = run(f'{ADB} -s {d} shell pm path com.topjohnwu.magisk', shell=True).strip()
        root_evidence.append('magisk package: ' + (magisk or 'none'))
        ksu = run(f'{ADB} -s {d} shell pm path me.weishu.kernelsu', shell=True).strip()
        root_evidence.append('KernelSU package: ' + (ksu or 'none'))
        adbroot = 'id=0' in run(f'{ADB} -s {d} shell id', shell=True) and 'adb root output: ' + run(f'{ADB} -s {d} root', shell=True).strip().splitlines()[0] if False else ''
        uid0 = run(f'{ADB} -s {d} shell id', shell=True).strip()
        root_evidence.append('adb shell id: ' + (uid0 or '?'))
        rooted = ('su' in root_evidence[0] and root_evidence[0] != 'which su: none') or magisk or ksu or 'uid=0' in uid0
        out.append(f'**root verdict: {"yes (root available)" if rooted else "no (standard user)"}**')
        out.extend('- ' + r for r in root_evidence)
        # installed software
        pkg3 = run(f'{ADB} -s {d} shell pm list packages -3', shell=True)
        pkgs3 = sorted(p.replace('package:','').strip() for p in pkg3.splitlines() if p.strip())
        pkgs_s = run(f'{ADB} -s {d} shell pm list packages -s', shell=True).splitlines()
        out.append(f'- third-party apps {len(pkgs3)} / system apps {len(pkgs_s)}; third-party list:')
        out.append('  ' + ' '.join(pkgs3[:200]) + (' ...' if len(pkgs3) > 200 else ''))
        # runtime environment
        out.append('- frida-server processes: ' + (run(f'{ADB} -s {d} shell ps -A | grep -c " fs$"', shell=True).strip() or '0') + ' (0=not running)')
        out.append('- debug/dev option adb_enabled: ' + run(f'{ADB} -s {d} shell settings get global adb_enabled', shell=True).strip())
        # companion actions (state → action)
        out.append(''); out.append('**Companion actions**:')
        abi = props.get('ro.product.cpu.abi','arm64')
        sdk = props.get('ro.build.version.sdk','?')
        if rooted:
            out.append(f'  - root available → start frida-server directly: adb push tools-env/frida-server/frida-server-android-{abi} /data/local/tmp/fs && chmod 755 && start in the background; full hook surface (java/native/unpacking chain, see techniques/02-frida)')
            out.append('  - unpacking can use the active-invocation family (FART approach); detection-countermeasure deep dives in techniques/12-bypass')
        else:
            out.append('  - no root → frida via gadget injection (repackaged test APK) or the emulator layer only; OberON: the objection patchapk route is in techniques/05-toolbox')
        out.append(f'  - abi={abi} → use the spare frida-server-android-{abi}; SDK {sdk} → mind the ART symbol version (version table in techniques/11-syscall-chain/dex-load-exec-chain.md)')
        out.append('  - test targets must be self-installed test APKs only; restore discipline at wrap-up in device-testing.md §1.4')

    # 4 firmware / microcontrollers
    sec(out, '4. Firmware / microcontrollers')
    new_tty = [t for t in (ttys if platform.system()=='Darwin' else []) if 'Bluetooth' not in t and not any(x and x in t for x in os.environ.get('BT_PATTERNS','').split(','))]
    if new_tty:
        out.append(f'Serial ports found: {new_tty} (identity pending read-only esptool identification; no flashing)')
    else:
        out.append('No suspicious microcontroller serial ports. If a device gets plugged in, rerun this scan; identification and monitoring flow in device-testing.md §2.')

    # persist
    os.makedirs(SNAP_DIR, exist_ok=True)
    path = os.path.join(SNAP_DIR, f'snapshot-{now:%Y%m%d-%H%M}.md')
    open(path, 'w', encoding='utf-8').write('\n'.join(out))
    open(os.path.join(SNAP_DIR, 'latest.md'), 'w', encoding='utf-8').write('\n'.join(out))
    print('\n'.join(out))
    print(f'\n[snapshot saved] {path}')

if __name__ == '__main__':
    main()
