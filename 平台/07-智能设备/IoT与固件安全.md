# IoT 与固件安全(已多级拆分 · 导航页)

> 本篇已按多级专项拆分至 `iot/` 子目录,本文件保留为入口导航。姊妹篇 [硬件与无线.md](硬件与无线.md)(拆分至 `无线硬件/`);CTF 套路见 [CTF-writeup方法论.md](CTF-writeup方法论.md)。

## 拆分去向

| 子篇 | 内容 |
|------|------|
| [iot/攻击面与信息收集.md](iot/攻击面与信息收集.md) | 攻击面全景图/标准工作流/设备研究(手表/门锁/摄像头/楼宇/前沿交互面)/学习路线 |
| [iot/固件提取.md](iot/固件提取.md) | 五路提取/U-Boot 操控实战/SPI 摘读/Zyxel/十法总表/binwalk 解包/静态分析/RTOS 加载地址与符号恢复 |
| [iot/固件解密.md](iot/固件解密.md) | 加密体系与三条思路/熵图/D-Link 过渡版本 diff 法/AES-CBC 实案 |
| [iot/固件仿真.md](iot/固件仿真.md) | Firmadyne·FAT/FirmAE(含 Zyxel 手动救活)/QEMU user·Qiling/思科 RV340 整机仿真全流程与 fork 型 cgi 调试三板斧 |
| [iot/路由器实战.md](iot/路由器实战.md) | 命令注入 CVE 矩阵/MIPS·ARM 栈溢出/后门与认证绕过/Fuzz/华为 HG532 CVE-2017-17215 实战 |
| [iot/协议与服务.md](iot/协议与服务.md) | MQTT/CoAP/Mirai 系恶意软件/工控(S7comm·PLC 蠕虫·Modbus) |
