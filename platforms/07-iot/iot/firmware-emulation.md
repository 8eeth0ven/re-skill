# Firmware Emulation


The default kit for the no-real-hardware era. Three tiers of solutions, heavy to light; the selection mnemonic: **if full-system emulation comes up, use FirmAE; if it doesn't, hang the single process in user mode; if even the processes won't run, slice functions with Unicorn/Qiling**.

## 1. Firmadyne / FAT (full-system level)

```
FAT (firmware-analysis-toolkit) = Firmadyne kernel + QEMU full-system emulation
Flow: extract FS → identify architecture → create disk image → InferNetwork infers network interfaces → boot in qemu-system
```

Pain points: devices with non-standard kernels / private drivers won't come up; the `nvram_daemon` hangs forever waiting for a pid file (the classic pit).

## 2. FirmAE (automatic workarounds)

FirmAE, built on Firmadyne, automatically handles most of the hang points (nvram hijack, block-device redirection); its five arbitration techniques lift the emulation success rate from Firmadyne's 16.28% to 79.36% (Docker-parallel per-image emulation). The command surface: `./init.sh` for one-time initialization; `sudo ./run.sh -c <brand> <fw>` (check emulation) -> `-a` (the FirmAE analyzer) -> `-r` (run / test network services) -> `-d` (user-level debugging) -> `-b` (kernel-level boot debugging); after `-c` completes, pick 2 in debug mode to drop into a shell.

Representative posts:
- "Practicing Zyxel Router Firmware Emulation with FirmAE"
- "Vigor3900 Firmware Emulation" (CVE-2024-44844/44845)
- "A Xiaomi Router Firmware Emulation Scheme" (customized emulation for Xiaomi's private nvram / data-center calls)
- "A Generic Approach to Emulating OpenWrt Secondary-Development Firmware" (NepCTF2024; the generic "swap the kernel, keep userland" method for when the secondary-development kernel mismatches)
- "Reproducing CVE-2023-26315 on the Xiaomi AX9000 Router" (QEMU emulation + vulnerability reproduction strung into one line)

### 2.1 Hands-on: FirmAE-emulating Zyxel — manually reviving the device when auto-emulation fails

The practical case of the Zyxel NWA1100-NH 2.12 (the logs say "success" but the Web never comes up):
1. Root cause: the filesystem holds **two** http services; FirmAE started httpd while the real one is mini_httpd.
2. `/etc/default/mini_httpd.conf` points at `/tmp/mini_httpd.conf` (which does not exist); booting directly with mini_httpd.cnf (the SSL config) fails.
3. Open mini_httpd in IDA, search for the error string `unknown config option`, locate the config-parsing logic, probe the required fields, then hand-write the minimal config:
   ```
   dir=/usr/www
   cgipat=cgi-bin/*
   user=root
   port=8081
   ```
4. Once up, logging in with `admin/admin` errors `log_maintain: not found` -> that program lives in `/etc/scripts/`: `export PATH=/etc/scripts/:$PATH`.
5. Login verification is delegated to `chkpwd` (apparently the system credentials), and changing the system password does nothing -> **patch the login logic**: flip the `bnez` to `beqz` at the strncmp `"Access granted"` judgment (a one-instruction edit right in IDA) and you are in.
6. Captured `POST /cgi-bin/ip` (AP_IPADDR=...&EXECUTE=ip); the string `/cgi-bin/ip` is nowhere in the firmware — it is generated at runtime: in the emulated system `ip` is a symlink pointing at `/sbin/cgiMain`, and **the real request handler is cgiMain** — reverse it / gdb it to keep hunting.

Pitfalls: "the pipeline succeeded" is not "the service is up" — port reachability is the only truth; when one firmware holds several same-type services, first pin down which one is real.

## 3. QEMU user mode + Qiling/Unicorn (single-process level)

- `qemu-mipsel -L squashfs-root/ ./httpd` (paired with a multi-arch `gdbserver` for IDA remote debugging): "Remote-Debugging MIPS Executables with QEMU+IDA", "Building a MIPS64 Debug Environment with buildroot".
- **Qiling**: a user-mode emulation framework that can hook syscalls and fake nvram returns — well suited to standing up a single cgi/algorithm: "Emulating Firmware with the Qiling Framework for IDA Dynamic Debugging", "QilingLab, from Details to Source Analysis".
- Debug-environment companions: "A Router Firmware Debugging Scheme", "Installing the Router Environment's Basic Tools", "Getting a Local Shell on an IoT Device and Debugging Software", the DVRF range (a router-pwn practice ground).

## 4. Full-system QEMU, a hands-on whole-machine emulation: the Cisco RV340 unauthenticated file upload CVE-2023-20073

RV340/RV340W/RV345/RV345P unauthenticated arbitrary file upload to `/tmp/upload` -> the upload.cgi bug -> stored XSS.

The emulation chain (Ubuntu18.04+QEMU7.2+binwalk2.3.3, ARM little-endian):
1. `binwalk -Me RV34X-v1.0.03.29...img` fails: missing tools for the UBI filesystem -> `apt install liblzo2-dev && pip3 install python-lzo ubi_reader`.
2. binwalk nulls the symlinks pointing outside the extraction dir (var->/tmp) -> subsequent emulation inevitably breaks. Three fixes: patch binwalk's `extractor.py`, changing `if not` to `if 0 and not`, and reinstall; or run `ubireader_extract_files 0.ubi` directly; or `python3 ubidump.py -s . 0.ubi`.
3. The bridge: `brctl addbr br0` + ens33 into the bridge + `tunctl -t tap0` into the bridge (br0 gets its IP via dhclient).
4. `qemu-system-arm -M vexpress-a9 -kernel vmlinuz-3.2.0-4-vexpress -initrd initrd.img-... -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 -append "root=/dev/mmcblk0p2" -net nic -net tap,ifname=tap0,script=no`; on SD-card errors first run `qemu-img resize ... 32G`; login root/root.
5. **scp the archive across** (tar.gz), not the directory (files get lost — the author burned a week on this); `mount --bind /proc proc; mount --bind /dev dev; chroot . /bin/sh`.
6. The service start order (the correct sequence after debugging):
   ```
   /etc/init.d/boot boot        # Create /tmp directories and resolve "uci: Entry not found"
   generate_default_cert        # Generate /etc/ssl/private/Default.pem
   /etc/init.d/confd start      # Lightweight configuration management required by nginx
   /etc/init.d/nginx start
   ```

Exploitation (the key upload.cgi logic):
- `multipart_parser_execute` parses the POST fields; `jsonutil_get_string(dword_2348C, &v26, "\"file.path\"", -1)` fetches file.path.
- `match_regex` validates that file.path must look like `/tmp/upload/NNNNNNNNNN`, otherwise the return branch runs (with a system `rm /tmp/upload/*` thrown in on the way).
- **Method one**: freeze the upload.cgi process and watch the actual filename under /tmp/upload, then hand-write `file.path=/tmp/upload/0000000001` in the request to pass the regex -> system performs the `mv` into the Portal directory to replace login.html.
- **Method two (the elegant one)**: the nginx directive `upload_set_form_field $upload_field_name.path "$upload_tmp_path"` **automatically** generates the `<name>.path` field — name the field `file` in the request and it carries a correct file.path, no need to know the upload path.

The three debugging chops (the special bane of fork-type cgi):
1. Brute force: `while true; do PID=$(pidof upload.cgi); [ -n "$PID" ] && ./gdbserver 0.0.0.0:9999 --attach $PID; done` (a one-in-three shot).
2. **Infinite loop (the most reliable)**: with keypatch, change main's first BL to `B <its own address>` (e.g. at 0x10E0C, `BL getenv` -> `B 0x10E0C`), chmod 777 (www-data uid33 executing a root-owned file), attach, then `set *0x10e0c=0xebffffaa` to restore the little-endian machine code, and `gdb-multiarch` + `set architecture arm` to debug remotely.
3. `catch exec` on the parent (theoretically viable, failed in practice). Also: the uwsgi config carries a harakiri timeout that drops long debug sessions — raise it.
