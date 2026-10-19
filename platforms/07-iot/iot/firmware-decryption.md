# Firmware Decryption


## 1. Why encryption exists, and three extraction ideas

To block the "download straight off the vendor site" route, vendors encrypt the whole upgrade package (AES/RC4/custom stream ciphers) and put the decryption logic in the boot program / an encrypted bootloader (e.g. D-Link's `alpha/alphad` family, some DIR units), decrypting only at boot when writing to flash. It follows that **the key must exist on the device side**; three extraction ideas:

1. **Pull the algorithm + key out of the encrypted bootloader**: the bootloader itself is unencrypted (it must be executable at the U-Boot stage); use binwalk/IDA to find the AES tables (S-box/Te0) or the TEA/XTEA round loops, then pin the key/iv constants.
2. **Runtime dump**: once the real device is up, read the plaintext straight out of memory / the decrypted flash partition (combined with the U-Boot/SPI punches of firmware-extraction.md).
3. **Byte-by-byte relation inference**: run a chosen-plaintext comparison against a known plaintext header (e.g. the squashfs magic `hsqs`) to derive the stream cipher's xor sequence.

Representative posts (the direction has become a series):
- "Common Firmware Encryption/Decryption Schemes and a D-Link Firmware Decryption Practice" (a systematic rundown of the four schemes: XOR/RC4/AES-CBC/custom xor transforms)
- "Reverse Analysis of an Encrypted DLINK Router Firmware" (the decryptor was introduced by the vendor later; reverse its decryption flow)
- "An IoT Security X-Ray: A Full Reverse of the D-Link DWR-932B Firmware" (hardcoded credentials / a weak root password / update-flow defects)
- "A Firmware-Decryption Session on an RTEMS System" (the same topic on the VxWorks/RTOS side)
- "The Boot Flow and Firmware Decryption of a Certain Well-Known (Animal-Named) Domestic Camera"
- "Ideas for HMI Firmware Decryption" (industrial touch panels)
- "Firmware Decryption" (a beginner discussion thread)

## 2. Telling whether it is encrypted: the entropy plot

`binwalk -E fw.bin` for the entropy profile: constantly-high entropy >0.9 ~ encrypted; low up front then fluctuating ~ code + compression mixed; high-entropy regions = encrypted/compressed, low-entropy = the firmware body — **step one of judging "is it encrypted"**.

## 3. Hands-on: decrypting D-Link encrypted firmware (the transitional-version diff method)

DIR-822-US (AC1200, MIPS R3000), the approach from the Payatu original:
1. **Find the transitional version**: dig through the FTP release history; two packages shipped the same day (`middle` and the official one), where `middle` is the transitional build that introduced encryption/decryption (plaintext); from then on, binwalk shows no squashfs signature on later versions (fully encrypted). The release-notes PDF corroborates.
2. **Confirm encryption with the entropy plot**: `binwalk -E` / a firmware-audit tool (see §2).
3. kdiff3-diff the old filesystem against middle's, locking onto `/etc/templates/hnap/StartFirmwareDownload.php`:
   ```php
   setattr("/runtime/tmpdevdata/image_sign","get","cat /etc/config/image_sign");
   fwrite("a",$ShellPath,"encimg -d -i ".$fw_path." -s ".$image_sign." > /dev/console\n");
   ```
4. The key = the contents of `/etc/config/image_sign`: `wrgac43s_dlink.2015dir822c1`; `qemu-mips -L . ./usr/sbin/encimg -d -i <fw> -s <key>` decrypts it directly; `-strace` shows `/lib/libcrypto.so.0.9.8` being loaded -> a hint of symmetric encryption.
5. IDA: main -> build, importing `AES_set_encrypt_key/AES_set_decrypt_key/AES_cbc_encrypt` = **AES-CBC, mmap-map -> set the key -> CBC encrypt/decrypt -> munmap write-back**.
6. Attack-surface extension: if the decryption flow has no integrity check -> use firmware-mod-kit to modify the firmware, repack, re-encrypt, and upload = a malicious firmware update (only a signature mechanism prevents this).

Methodology: encryption was introduced later -> **dig the release history for the transitional package, and diff out the decryption call site and where the key is stored** — the universal playbook for encrypted-firmware analysis.

## 4. The RTOS side and related cross-links

- The same topic for RTEMS/VxWorks firmware (see the §1 representative posts); if the decrypted artifact is a filesystem-less bare firmware, the load-address / symbol-recovery methods are in [firmware-extraction.md](firmware-extraction.md) §6.3.
- For the password-protected ZIP image class (the Zyxel extraction) see [firmware-extraction.md](firmware-extraction.md) §4.
