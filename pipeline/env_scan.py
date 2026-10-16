#!/usr/bin/env python3
"""环境全量盘点:工具/外部设备/手机详情(root·软件清单)/配套操作 → 快照落盘 re/环境快照/"""
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
    out = [f'# 环境快照 {now:%Y-%m-%d %H:%M}', f'> 主机 {platform.system()} {platform.release()} | 扫描器 env_scan.py | 配套操作判定自动生成', '']

    # 1 可用软件
    sec(out, '一、可用软件')
    tools = [('jadx','jadx --version'),('apktool','apktool --version'),('radare2','r2 -v'),
             ('adb', f'{ADB} version'), ('7z','7z | head -2'),('java','java -version 2>&1 | head -1'),
             ('node','node -v'),('uv','uv --version'),('python3','python3 --version')]
    out.append('| 工具 | 版本 |')
    out.append('|------|------|')
    for name, cmd in tools:
        v = run(cmd, shell=True).strip().splitlines()
        v = v[0][:60] if v else '未装'
        out.append(f'| {name} | {v} |')
    libs = run(f'{VENV_PY} -c "import frida,unicorn,capstone,androguard;print(frida.__version__)"', shell=True).strip()
    out.append('')
    out.append(f'- venv(tools-env): {"OK frida "+libs if libs and not libs.startswith("[") else "异常:"+libs};esptool: {run(VENV_PY+" -m esptool version", shell=True).splitlines()[0] if run(VENV_PY+" -m esptool version", shell=True) else "未装"}')
    fs_dir = os.path.join(ROOT, 'tools-env/frida-server')
    if os.path.isdir(fs_dir):
        out.append(f'- frida-server 备件: {", ".join(sorted(os.listdir(fs_dir)))}')

    # 2 外部设备(USB/串口)
    sec(out, '二、外部设备')
    usb = run('system_profiler SPUSBDataType | grep -E "Product Name|Product ID|Manufacturer"', shell=True, timeout=40)
    out.append('USB 设备:'); out.append(usb.strip() or '(无)')
    if platform.system() == 'Darwin':
        ttys = run("ls /dev/cu.* 2>/dev/null | grep -v Bluetooth", shell=True).strip().splitlines()
        out.append(''); out.append('串口:')
        out.extend(ttys or ['(无)'])
        out.append(''); out.append('蓝牙 SPP 口(不算新设备): ' + ', '.join(t for t in ttys if 'Bluetooth' in t or any(x and x in t for x in os.environ.get('BT_PATTERNS','').split(','))) or '(无)')

    # 3 手机详情
    sec(out, '三、Android 设备详情')
    devs = run(f'{ADB} devices', shell=True)
    online = [l.split('\t')[0] for l in devs.splitlines() if '\tdevice' in l]
    if not online:
        out.append('未连接手机。配套操作:插入(开 USB 调试)后重跑本扫描;真机链见 真机测试.md。')
    for d in online:
        out.append(f'### 设备 {d}')
        props = {}
        for key in ['ro.product.model','ro.product.brand','ro.build.version.release','ro.build.version.sdk',
                    'ro.product.cpu.abi','ro.build.fingerprint','ro.build.display.id','ro.build.type','ro.debuggable']:
            props[key] = run(f'{ADB} -s {d} shell getprop {key}', shell=True).strip()
        out.append('| 项 | 值 |'); out.append('|------|------|')
        for k, v in props.items(): out.append(f'| {k} | {v} |')
        # root 检测(只读)
        root_evidence = []
        root_evidence.append('which su: ' + (run(f'{ADB} -s {d} shell which su', shell=True).strip() or '无'))
        magisk = run(f'{ADB} -s {d} shell pm path com.topjohnwu.magisk', shell=True).strip()
        root_evidence.append('magisk 包: ' + (magisk or '无'))
        ksu = run(f'{ADB} -s {d} shell pm path me.weishu.kernelsu', shell=True).strip()
        root_evidence.append('KernelSU 包: ' + (ksu or '无'))
        adbroot = 'id=0' in run(f'{ADB} -s {d} shell id', shell=True) and 'adb root 输出: ' + run(f'{ADB} -s {d} root', shell=True).strip().splitlines()[0] if False else ''
        uid0 = run(f'{ADB} -s {d} shell id', shell=True).strip()
        root_evidence.append('adb shell id: ' + (uid0 or '?'))
        rooted = ('su' in root_evidence[0] and root_evidence[0] != 'which su: 无') or magisk or ksu or 'uid=0' in uid0
        out.append(f'**root 判定: {"是(root 可用)" if rooted else "否(标准用户)"}**')
        out.extend('- ' + r for r in root_evidence)
        # 已装软件
        pkg3 = run(f'{ADB} -s {d} shell pm list packages -3', shell=True)
        pkgs3 = sorted(p.replace('package:','').strip() for p in pkg3.splitlines() if p.strip())
        pkgs_s = run(f'{ADB} -s {d} shell pm list packages -s', shell=True).splitlines()
        out.append(f'- 第三方应用 {len(pkgs3)} 个 / 系统应用 {len(pkgs_s)} 个;第三方清单:')
        out.append('  ' + ' '.join(pkgs3[:200]) + (' …' if len(pkgs3) > 200 else ''))
        # 运行环境
        out.append('- frida-server 进程: ' + (run(f'{ADB} -s {d} shell ps -A | grep -c " fs$"', shell=True).strip() or '0') + ' (0=未跑)')
        out.append('- 调试/开发选项 adb_enabled: ' + run(f'{ADB} -s {d} shell settings get global adb_enabled', shell=True).strip())
        # 配套操作(状态→行动)
        out.append(''); out.append('**配套操作**:')
        abi = props.get('ro.product.cpu.abi','arm64')
        sdk = props.get('ro.build.version.sdk','?')
        if rooted:
            out.append(f'  - root 可用 → frida-server 直起:adb push tools-env/frida-server/frida-server-android-{abi} /data/local/tmp/fs && chmod 755 && 后台起;hook 面全开(java/native/脱壳全链,见 手法/02-frida)')
            out.append('  - 脱壳可用主动调用系(FART 思路);检测对抗深挖见 手法/12-绕过决策')
        else:
            out.append('  - 非 root → frida 用 gadget 注入(重打包测试 APK)或仅模拟器层; OberON:objection patchapk 路线见 手法/05-工具矩阵')
        out.append(f'  - abi={abi} → 用备件 frida-server-android-{abi};SDK {sdk} → ART 符号版注意(手法/11/dex加载与执行链路 版本表)')
        out.append('  - 测试对象只用自装测试 APK;收尾恢复纪律见 真机测试.md §一.4')

    # 4 固件/单片机
    sec(out, '四、固件/单片机')
    new_tty = [t for t in (ttys if platform.system()=='Darwin' else []) if 'Bluetooth' not in t and not any(x and x in t for x in os.environ.get('BT_PATTERNS','').split(','))]
    if new_tty:
        out.append(f'发现串口: {new_tty}(身份待 esptool 只读识别,禁烧录)')
    else:
        out.append('无可疑单片机串口。若有设备插入,重跑本扫描;识别与监听流程见 真机测试.md §二。')

    # 落盘
    os.makedirs(SNAP_DIR, exist_ok=True)
    path = os.path.join(SNAP_DIR, f'snapshot-{now:%Y%m%d-%H%M}.md')
    open(path, 'w', encoding='utf-8').write('\n'.join(out))
    open(os.path.join(SNAP_DIR, 'latest.md'), 'w', encoding='utf-8').write('\n'.join(out))
    print('\n'.join(out))
    print(f'\n[快照已留存] {path}')

if __name__ == '__main__':
    main()
