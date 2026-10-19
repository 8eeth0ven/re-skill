# Router Practice: The Web Vulnerability Matrix


## 1. Command injection (the #1 hotspot)

The pattern: front-end parameter -> cgi -> `sprintf` assembles the shell string -> `system()/popen()/execve("/bin/sh")`. Take **CVE-2018-17066** (D-Link, the time-settings page) as the example: the front-end time parameter is unfiltered and gets concatenated into the `system` argument, so `;`/backticks escape straight out. Same-type posts by the handful:

| Vendor/Model | CVE |
|-----------|-----|
| D-Link | CVE-2018-17066 (the time-settings page) |
| Huawei HG532 | CVE-2017-17215 (TR-064 command injection; ATLAS counted 400k units affected) |
| D-Link Go-RT-AC750 | — |
| D-Link | CVE-2021-45382 / CVE-2022-34527 / CVE-2022-26258 |
| DrayTek Vigor3900 | CVE-2021-43118 / CVE-2024-44844-45 |
| GL-iNet | CVE-2024-39226 (plus a full GL-iNet security-analysis post) |
| D-Link DIR-823G | CVE-2022-44201 (DIR-823G v1.02B05 command injection, CWE-78, CVSS 9.8) |
| Tenda | CVE-2023-27216 |
| Cisco | CVE-2023-20073 (arbitrary file upload; plus a compiled-kernel reproduction post) |

Hunting recipe (community consensus): (1) `strings` the cgi binary for `iptables|reboot|ping|wget` command templates; (2) walk the xrefs back from `system` to find the unfiltered parameters; (3) fire the packet in the emulated environment to verify.

## 2. Stack overflow (MIPS/ARM)

- "An Instance Analysis of Home-Router Bug Hunting: D-Link DIR-815" (the classic intro: from cookie length to ROP)
- "D-Link DIR-645 stack overflow" / "an overlong-cookie stack overflow" / "DIR-645 RCE"
- Tenda CVE-2018-18708, Tenda AC15 CVE-2018-16333
- MIPS exploit chains: CVE-2019-10892, "the CVE-2017-13772 analysis with an MIPS stack-overflow exploitation summary", "the TP-LINK CVE-2017-13772 RCE"
- MIPS exploitation essentials: cache coherence needs a `sleep` gadget to flush the cache; pull general gadgets from busybox/libc; the libc version decides the `system` address (on ASLR-less devices, once is forever).
- Heap: the Netgear WNR2200 heap overflow.

## 3. Backdoors / information disclosure / auth bypass

- "Those Backdoors in Wireless Routers" (the D-Link edition; a vendor-backdoor-account special — an old post whose methodology has not aged)
- The TP-Link WR740 backdoor reproduction, the CVE-2020-22253 backdoor
- "A Brief Talk on Netgear Router Information-Disclosure Hunting" (0day included)
- "The TOTOLink Login-Skip Analysis", "TOTOLink Bug Hunting"
- "An Analysis of a Router SQL-Injection Bug" (a rare IoT-side SQLi specimen)
- "The Phicomm K1 Bugs and User-Data Collection"
- 1day->0day: "the Cisco RV160W series from 1day to 0day", "the Cisco RV110W CVE-2020-3331 + an IoT practice range"
- Gateway pwn: "Pwning a Gateway Device"; WRT54G; PSV-2020-0437; the portable WiFi dongle
- Tutorial series: the HG533 router analysis tutorials (5 parts); tooling: "Using RouterSploit"

## 4. Fuzz

- "A Simple Use of boofuzz in Binary IoT Bug Hunting" (template-driven fuzzing against cgi/Web services)
- "Firm-AFL firmware grey-box fuzzing" (an AFL user-mode + full-system hybrid)
- "The CVE-2024-44337 go-fuzz hunt" (a fuzzing framework written in Go)

## 5. Hands-on: the Huawei HG532 CVE-2017-17215 command injection (QEMU whole-machine emulation + call chain)

Per the Check Point report, Mirai variants were already using it; the bug sits in `/bin/mic`, reached over UPnP (SOAP) on port 37215 -> `system()`.

- Environment: qemu-system-mips malta + debian_squeeze_mips_standard.qcow2, bridge Virbr0+tap0 (192.168.10.x), scp squashfs-root in, `mount -o bind /dev`, `chroot`, then start `./bin/upnp` + `./bin/mic`; note that once upnp/mic come up they rewrite the NIC's IP — when ssh drops, go back to the console and reconfigure.
- Pit: QEMU won't come up on newer Ubuntu (firmadyne hardcodes the loop device; firmware-analysis-plus issue#40) -> switch to 16.04.
- EXP core: POST `http://IP:37215/ctrlt/DeviceUpgrade_1`, Digest header username=dslf-config (realm=HuaweiHomeGateway), with `<NewStatusURL>;/bin/busybox ls;</NewStatusURL>` inside the SOAP body as the injection point; a 200 back = executed.
- Analysis method: tcpdump `-i tap0 -w result.cap` (tap0 is no different from a physical NIC at the upper layers); `grep -r "DeviceUpgrade_1\|37215"` pinpoints the two files upnp+mic; chase the xref from XML parsing to system inside mic.

## 6. The meta-method

Every router CVE post shares one meta-method: **get the firmware -> emulate -> find system/xref in the cgi -> verify with packets**; switching vendors only changes the structure, never the method (the full learning route is in [attack-surface-recon.md](attack-surface-recon.md) §4).
