# Network Chains: Java -> libc -> syscall -> kernel, the full expansion

> Positioning: **splits one Android network action end-to-end from the Java API down to the kernel driver**, providing per-function grounds for "at which layer to observe/intercept".
> Division of labor: "[../09-function-map/android-function-layers.md](../09-function-map/android-function-layers.md)" sec.2's network-domain five-layer table is the **index**; this piece is the **sequence expansion**; user-space capture scenarios (CA/pinning/proxies/QUIC fallback) belong to "[../04-evasion/capture-all-scenarios.md](../04-evasion/capture-all-scenarios.md)" - this piece covers **the kernel side and the boundary** only, cross-referenced without duplication.
> Baseline: linux torvalds master (net/socket.c, af_inet.c, tcp_ipv4.c, tcp.c, tcp_output.c, ip_output.c, ip_input.c, ip_forward.c, udp.c, dev.c, af_packet.c, tun.c, netfilter.h) + AOSP master (VpnService.java, Vpn.java, com_android_server_connectivity_Vpn.cpp, bionic ifaddrs.cpp/getaddrinfo.c). **Line numbers follow master; Android common/GKI (5.15/6.1) naming drift is flagged where known**; uncertain items marked `[unverified]`.

## 0. Overview: the six-leg journey of one TCP payload

```
[Java/Kotlin]      Socket/OkHttp/Cronet → libcore SocketImpl → libcore.io.Posix(libjavacore.so)
[L3 bionic]         socket/connect/sendto/recvfrom (libc.so exports)
[L4 svc]            svc #0,x8=198/203/206/207/211/212(arm64)
[L5 generic kernel] net/socket.c: sys_socket/__sys_connect/__sys_sendto/sock_sendmsg/sock_recvmsg
[Protocol layer]    proto_ops(inet_stream_ops)→ proto(tcp_prot)→ tcp_sendmsg/tcp_recvmsg/tcp_v4_connect
[IP/netfilter]      ip_queue_xmit → __ip_local_out(NF_INET_LOCAL_OUT)→ ip_output(POST_ROUTING)
[Device layer]      dev_queue_xmit → qdisc → dev_hard_start_xmit → driver ndo_start_xmit
Receive direction: NIC interrupt/NAPI → __netif_receive_skb_core (AF_PACKET capture taps first) → ip_rcv(PRE_ROUTING)
           → ip_local_deliver(LOCAL_IN)→ tcp_v4_rcv → sk_receive_queue → user read copies data out
```

| Chain | Contents | Main battleground files | Relation to capture/confrontation |
|---|---|---|---|
| Chain 1 | TCP connection setup (socket+connect+handshake) | socket.c/af_inet.c/tcp_ipv4.c/tcp_output.c | frida port-probe detection happens here |
| Chain 2 | Send/receive (send/recv + the capture tap) | tcp.c/tcp_output.c/dev.c/af_packet.c | the landing-point differences of r0capture/ecapture/tcpdump |
| Chain 3 | netfilter's five hooks + iptables + VpnService/tun | ip_*.c/netfilter.h/tun.c | the underpinning of transparent-proxy and VPN-detection confrontation |
| Chain 4 | UDP/QUIC | udp.c | the kernel-side explanation of why QUIC can't be captured |
| Chain 5 | Certificate/CA loading (file side) | conscrypt/TrustedCertificateStore | observing and intervening in the network trust chain |
| Chain 6 | getaddrinfo/DNS | bionic getaddrinfo.c + netd | the blue-team observation point for C2 domain resolution |
The arm64 syscall numbers (socket=198, bind=200, connect=203, sendto=206, recvfrom=207, sendmsg=211, recvmsg=212) were checked against kernel headers in area 09's layer panorama sec.0.1 and are not repeated here.

## Chain 1: the full TCP connection-setup chain

### 1.1 Sequence diagram (socket + connect + three-way handshake)

```
── socket() ────────────────────────────────────────────────────────────
new Socket()                            [Java,libcore]
  → SocketImpl (libcore; historically the PlainSocketImpl family; current Android class names need verification,
     but all converge on libcore.io.Posix natives)
  → Java_libcore_io_Posix_socket        [libjavacore.so export, L2]
  → socket()                            [bionic libc,L3]
  → svc #0, x8=198(__NR_socket)        [L4 instruction level]
  → SYSCALL_DEFINE3(socket)             [net/socket.c:1830; L5 begins]
     → __sys_socket()                   [socket.c:1813]
        → sock_create() → __sock_create()   [socket.c:1732/1605]
           → net_families[AF_INET]->create = inet_create()   [af_inet.c:259]
              ① Look up inetsw_array by type: SOCK_STREAM+TCP → answer->ops=&inet_stream_ops
              ② sk_alloc(..., &tcp_prot)  → sock->sk = sk
              ③ sk->sk_prot->init(sk) = tcp_v4_init_sock()   [tcp_ipv4.c:2396,
                 Internally calls tcp_init_sock(tcp.c) to initialize tcp_sock fields/timers]
        → sock_map_fd()                 [socket.c:578; installs fd in the process fdtable]
  ← Return fd

── connect() ───────────────────────────────────────────────────────────
socket.connect(addr) → Posix.connect → libc connect() → svc #0, x8=203
  → SYSCALL_DEFINE3(connect) → __sys_connect()            [socket.c:2170]
     → move_addr_to_kernel(user sockaddr → kernel)
     → __sys_connect_file() → connect_socket()            [socket.c:2157; newer master refactor;
        older kernels call sock->ops->connect here directly; version-dependent]
        → sock->ops->connect = inet_stream_connect()      [af_inet.c:749]
           → __inet_stream_connect()
              → sk->sk_prot->connect = tcp_v4_connect()  [tcp_ipv4.c:221]
                 ① Route lookup (ip_route_output_flow); cache result in sk for subsequent sends
                 ② Set inet_daddr/inet_dport/inet_saddr (bind outgoing-interface address)
                 ③ sk_state = TCP_SYN_SENT
                 ④ tcp_connect()                         [tcp_output.c:4301]
                    → tcp_connect_init() initializes sequence/window state [tcp_output.c:4363]
                    → Construct SYN sk_buff
                    → __tcp_transmit_skb()               [tcp_output.c:1536]
                       → icsk->icsk_af_ops->queue_xmit   [tcp_output.c:1716]
                         = ip_queue_xmit()               [ip_output.c:545; registered in tcp_ipv4.c:2359]
                          → __ip_local_out()             [ip_output.c:102]
                             → nf_hook(NF_INET_LOCAL_OUT) [ip_output.c:120 ← iptables OUTPUT hook]
                          → dst_output → ip_output() → NF_INET_POST_ROUTING → dev_queue_xmit → driver
              (Blocking socket: wait for sk_state to leave TCP_SYN_SENT; implementation varies by version:
               inet_wait_for_connect/sock_wait_event; verify on the target)

── SYN-ACK return path (asynchronous, interrupt/NAPI context)──────────────────
NIC receives packet → ip_rcv() NF_HOOK(NF_INET_PRE_ROUTING)  [ip_input.c:612]
  → ip_rcv_finish → route selects local delivery → ip_local_deliver() NF_HOOK(NF_INET_LOCAL_IN) [ip_input.c:262]
  → ip_local_deliver_finish → tcp_v4_rcv()        [tcp_ipv4.c:2070]
     → __inet_lookup_skb(find sock by four-tuple hash)
     → tcp_v4_do_rcv()                            [tcp_ipv4.c:1830]
        → (sk_state=TCP_SYN_SENT) tcp_rcv_state_process()
          → Send ACK, set sk_state=TCP_ESTABLISHED, wake connect waiters
  → connect() returns 0; the kernel sends the third-handshake ACK with the next send/timer event
```

### 1.2 Key structures (fields drift slightly across kernel versions)

| Structure | Key members | Role |
|---|---|---|
| `struct socket` | `state` (SS_UNCONNECTED/SS_CONNECTED), `ops` (proto_ops*), `sk` (struct sock*), `file` | the socket as VFS sees it; the syscall layer operates on it |
| `struct proto_ops` (inet_stream_ops) | `.connect=inet_stream_connect`, `.sendmsg=inet_sendmsg`, `.recvmsg=inet_recvmsg` (af_inet.c:1060-1086) | the trampoline table from the generic layer to the protocol layer |
| `struct proto` (tcp_prot) | `.init=tcp_v4_init_sock`, `.connect=tcp_v4_connect`, `.sendmsg=tcp_sendmsg`, `.recvmsg=tcp_recvmsg`, `.backlog_rcv=tcp_v4_do_rcv` (tcp_ipv4.c:3348+) | the TCP protocol implementation table |
| `struct sock` | `__sk_common.skc_state` (TCP_SYN_SENT/ESTABLISHED), `sk_receive_queue`, `sk_write_queue`, `sk_prot`, `sk_socket`, `sk_dst` (cached route) | the socket core; the four-tuple lives in skc_daddr/skc_dport |
| `struct inet_sock` | `inet_saddr/inet_daddr/inet_sport/inet_dport`, `inet_num` | the IP-layer parameters embedded in sock |
| `struct tcp_sock` | `snd_nxt/rcv_nxt/copied_seq`, `out_of_order_queue`, the cwnd family | the TCP state machine and send/receive sequence numbers |
| `struct inet_connection_sock` | `icsk_af_ops->queue_xmit (=ip_queue_xmit)`, the retransmit timer | the TCP<->IP operations table |
| `struct rtable/dst_entry` | the output route | cached at connect, reused at send; re-looked-up when routes change |

### 1.3 Observation point table

| Observation point | Layer | What you see | Means | Pitfalls |
|---|---|---|---|---|
| `Socket.connect` | L1 | target host:port (Java side) | frida Java.use | RASP scans call stacks; Native/Cronet traffic completely invisible |
| `Java_libcore_io_Posix_connect` | L2 | fd, sockaddr | frida attach on the exported symbol | nobody guards it - great value |
| libc `connect` | L3 | same as above | Interceptor/GOT | **bypassed by direct svc calls**; CRC-checked function heads |
| svc x8=203 | L4 | every connect (direct calls included) | Stalker/memory svc scan | costly; see "hook-fallback playbook" sec.3 |
| kprobe `tcp_v4_connect` | L5 | the `struct sock*` parameter - read daddr/dport directly, covering every user-space path | kprobe/KPM (root needed) | on GKI the symbol is extractable from boot.img (kernel-symbol-locating.md) |
| kprobe `__sys_connect`/`connect_socket` | L5 | fd+sockaddr (user address already copied into the kernel) | same as above | function names drifted after the master refactor |
| tracepoint `sock:inet_sock_set_state` | L5 | global TCP state transitions (SYN_SENT->ESTABLISHED), 4.16+ | bpftrace/eBPF | state only, no payload; GKI needs BTF |

### 1.4 Practical tips

- **frida port-probe detection happens on this chain**: the app connect()s to 127.0.0.1:27042 to test for frida-server. Three tiers of countermeasures compared:
 1. User-space hook of libc `connect` (return -ECONNREFUSED) - misses apps that call svc directly;
 2. Change the frida-server port + rename (symptomatic; pair with the frida anti-detection piece);
 3. **Kernel layer**: kprobe `tcp_v4_connect`; when daddr=127.0.0.1 && dport in {27042,27043} matches, use a kretprobe to set retval=-ECONNREFUSED (the app sees the port as closed) - covers every user-space direct call; alternatively hook after `tcp_v4_init_sock` and pre-check dport in `tcp_connect` to return early. The landing toolchain is in "[../07-kernel/kernel-hook-stealth.md](../07-kernel/kernel-hook-stealth.md)" sec.2 (KernelPatch/KPM). The full fallback narrative is in "[hook fallback playbook](../09-function-map/hook-fallback-playbook.md)" case 2.
- Capturing "which targets were connected": from the blue-team view, eBPF `inet_sock_set_state` + kprobe tcp_v4_connect reading sock yields a global list - with root, steadier than injecting app-by-app.
- Java-side `SocketChannel` (NIO) and `Socket` (BIO) are **entirely the same path below L2** (both converge on Posix natives->libc); hooking one spot at L2/L3 covers both APIs.

## Chain 2: the send/receive chain

### 2.1 Send sequence

```
out.write(buf)                          [Java OutputStream]
  → SocketImpl → Posix.write(fd)        [libjavacore]
  → write() → svc x8=64(__NR_write)     [L4; similarly send/sendto/sendmsg: x8=64/206/211]
  → ksys_write → vfs_write → file->f_op->write_iter
     = sock_write_iter()                [socket.c:1247,socket_file_ops:159]
     → sock_sendmsg()                   [socket.c:826]
        → sock->ops->sendmsg = inet_sendmsg()   [af_inet.c:856]
           → sk->sk_prot->sendmsg = tcp_sendmsg()  [tcp.c:1446]
              → tcp_sendmsg_locked()    [tcp.c:1116]
                 ① lock_sock (mutual exclusion with receive/timer processing)
                 ② Optional tcp_sendmsg_fastopen(TFO) fast path
                 ③ Loop: wait for send-buffer space with sk_stream_wait_memory(tcp.c:1404)
                    → tcp_stream_alloc_skb allocates sk_buff (page-fragment mode)
                    → Copy user data into skb (copy_from_iter family)
                 ④ tcp_push()            [tcp.c:740]
                    → __tcp_push_pending_frames → tcp_write_xmit()  [tcp_output.c:2964]
                       (cwnd/congestion-control/Nagle checks determine which segments to send)
                    → tcp_transmit_skb → __tcp_transmit_skb()  [tcp_output.c:1536]
                       → ip_queue_xmit()  [ip_output.c:545; reuse the route cached by connect]
                          → __ip_local_out() → **nf_hook(NF_INET_LOCAL_OUT)**  [ip_output.c:120]
                          → dst_output → ip_output() → NF_HOOK(POST_ROUTING) [ip_output.c:400-437]
                          → ip_finish_output2 → neigh_output(ARP resolution)  [ip_output.c:199/236]
             → dev_queue_xmit()          [net/core/dev.c]
                → __dev_xmit_skb         [dev.c:4248; qdisc enqueue, or direct send without qdisc]
                → dev_hard_start_xmit()  [dev.c:3959]
                → driver ndo_start_xmit → DMA → NIC transmits
```

Note: the TCP-layer skb is not sent to completion inside `tcp_sendmsg` - data first queues onto `sk_write_queue`, and `tcp_write_xmit` decides segmentation and sending per the window; retransmits also pull from this queue.

### 2.2 Receive sequence (with tcpdump's kernel path)

```
NIC interrupt → NAPI polling → napi_gro_receive(GRO aggregation)
  → netif_receive_skb_internal → __netif_receive_skb → __netif_receive_skb_core  [dev.c:~2511-2630]
     ① **Traverse ptype_all first: deliver_skb() delivers to AF_PACKET sockets** [dev.c:2533/2594]
        → packet_rcv() / tpacket_rcv()     [af_packet.c:2136/2249]
           = tcpdump/pcap kernel receive point; tpacket_rcv fills the TPACKET_V3 mmap ring
     ② Then hand to ip_rcv() in ptype_base
  → ip_rcv() → **NF_HOOK(NF_INET_PRE_ROUTING)**  [ip_input.c:612]
  → ip_rcv_finish → ip_route_input_noref route lookup → local host
  → ip_local_deliver() → **NF_HOOK(NF_INET_LOCAL_IN)**  [ip_input.c:262]
  → ip_local_deliver_finish → tcp_v4_rcv()      [tcp_ipv4.c:2070; protocol registered by af_inet.c inet_init]
     → __inet_lookup_skb(find sock by four-tuple; SYN uses listen hash → server-side three-way handshake)
     → tcp_v4_do_rcv()                          [tcp_ipv4.c:1830]
        → ESTABLISHED: tcp_rcv_established → tcp_queue_rcv enqueues in sk_receive_queue
        → Other states: tcp_rcv_state_process(handshake/close state machine)
     → sk->sk_data_ready wakes the waiting reader thread

User read:
in.read(buf) → Posix.read → svc x8=63 → ksys_read → vfs_read
  → file->f_op->read_iter = sock_read_iter()    [socket.c:1226]
     → sock_recvmsg()                           [socket.c:1169]
        → sock->ops->recvmsg = inet_recvmsg()   [af_inet.c:884]
           → tcp_recvmsg() → tcp_recvmsg_locked()  [tcp.c:1974/1996]
              → skb_copy_datagram_msg(): copy receive-queue skb data to user buffer [tcp.c:2028]
              (Handle URG, PEEK, window probes, and out-of-order queue merging)
```

### 2.3 Observation point table

| Observation point | Side | What you see | Means | Notes |
|---|---|---|---|---|
| libc `send/sendto/write/recv` | send/recv | **below TLS it's ciphertext** (if the upper layer encrypts); the plaintext boundary is at user-space SSL_write/read | frida Interceptor | r0capture's Java/native send/receive hooks sit around this layer (cross-ref "[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.2.13) |
| kprobe `tcp_sendmsg/tcp_recvmsg` | send/recv | all TCP payloads (ciphertext) + `struct sock*` correlating the target | root+kprobe | covers every direct call; eBPF kprobe reading iov needs helpers |
| tracepoint `net:net_dev_queue`/`net_dev_xmit` | send | dev/len of each dequeued skb | bpftrace | no payload detail; for traffic profiling |
| `SO_ATTACH_FILTER` (cBPF)/`SO_ATTACH_BPF` | recv | **per-socket** filters (socket option, 208) | setsockopt | classic BPF capture (libpcap's kernel filtering shares this origin); the app can attach one to its own socket |
| AF_PACKET socket (packet_rcv/tpacket_rcv) | recv (send can inject) | all NIC link-layer frames (non-local traffic included, promisc) | tcpdump/pcap | **needs CAP_NET_RAW+root** (neither shell nor app has it on Android user builds); SELinux adds restrictions |
| eBPF/ecapture | user-space boundary | SSL_read/SSL_write plaintext (uprobe) | ecapture | the no-MITM solution; details in "[../07-kernel/android-kernel-ebpf.md](../07-kernel/android-kernel-ebpf.md)" |

### 2.4 Practical tips

- **The plaintext/ciphertext boundary**: what kernel sendmsg/tcp_sendmsg sees is "post-TLS-encryption" bytes; for plaintext you must sit at the user-space encryption boundary (SSL_write/SSL_read, Cipher.doFinal, QUIC callbacks) - exactly the principle behind r0capture/ecapture's point selection; the scenario matrix is in "[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.2.
- tcpdump's full kernel path on Android: `socket(AF_PACKET)` -> `packet_create` (af_packet.c) -> bind(ETH_P_ALL) + promisc -> received packets are cloned by `packet_rcv` at the ptype_all dispatch point in `__netif_receive_skb_core` (`deliver_skb` clones before handing to the IP layer, so capture doesn't disturb normal reception). **Not usable without root**: the app's SELinux domain (untrusted_app) has no packet-socket permission and shell lacks CAP_NET_RAW; from Android 10 the app can't even read `/proc/net/*` (cross-ref "[detection landscape](../04-evasion/detection-landscape.md)").
- When the send buffer fills, `tcp_sendmsg_locked` blocks in `sk_stream_wait_memory` - a hook that never returns fakes a dead network thread; preserve original semantics when frida rewrites send functions.
- `MSG_FASTOPEN`/TCP Fast Open merges connect with the first packet - a missing connect observation doesn't mean no connection; the `inet_sock_set_state` tracepair is more reliable.

## Chain 3: netfilter/iptables and transparent proxies + VpnService/tun

### 3.1 The five hook positions (verified file by file)

```
                       ┌── NF_INET_PRE_ROUTING ──┐
Receive ip_rcv ───────▶│ ip_input.c:612          │──▶ ip_rcv_finish ──route──┐
                       └─────────────────────────┘                          │
   Local host ▼                                                      Forward ▼
  ip_local_deliver                                              ip_forward
  NF_INET_LOCAL_IN                                             NF_INET_FORWARD
  [ip_input.c:262]                                             [ip_forward.c:162]
       │                                                            │
       ▼                                                            ▼
  tcp_v4_rcv/udp_rcv                                      ip_output → NF_INET_POST_ROUTING
                                                          [ip_output.c:400-437] → dev_queue_xmit

Send __ip_local_out ─▶ NF_INET_LOCAL_OUT [ip_output.c:120] ─▶ ip_output → POST_ROUTING → ...
```
- NF_HOOK is a static inline in `include/linux/netfilter.h` (netfilter.h:319/425, two versions by CONFIG); internally it walks `nf_hook`->`nf_hook_slow` (net/netfilter/core.c) over the tables/chains registered on that hook; each iptables table (raw/mangle/nat/filter) mounts on the matching hooks by permission.
- The nat table only looks up a flow's first round (after conntrack is established the fast path applies); the filter table mounts INPUT/OUTPUT/FORWARD, mangle mounts all five hooks. **REDIRECT is a nat-table OUTPUT/PREROUTING target** (rewriting the destination to local 127.0.0.1:port); TPROXY sits in mangle PREROUTING (needs policy routing to cooperate).

### 3.2 iptables/netlink usability on Android

| Item | Fact | Source |
|---|---|---|
| The iptables binary | /system/bin/iptables exists; rules go down via `setsockopt(IPT_SO_SET_REPLACE)` | shipped with the system |
| Permissions | **root required (CAP_NET_ADMIN)**; an ordinary app's SELinux domain refuses outright | behavioral fact |
| Root transparent proxy | `iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner X -j REDIRECT --to-port 8080`; the app is unaware, no proxy settings, no tun | "[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.2.5 |
| REDIRECT and UDP | nat REDIRECT handles only TCP reliably; UDP needs TPROXY (mangle)+`ip rule`, both root operations on Android | same |
| The app's netlink restrictions | bionic `getifaddrs` source comment: **"SELinux policy only allows RTM_GETLINK messages to be sent by system apps"**; bionic also skips RTM_GETLINK outright when `getuid < FIRST_APPLICATION_UID`, falling back to `if_indextoname` + `ioctl(SIOCGIFFLAGS)` to backfill names and flags | bionic/libc/bionic/ifaddrs.cpp:280-334 (pulled from master). **The introducing version is commonly cited as Android 12, exact version `[unverified]`; RTM_GETADDR is still allowed today** |
Note: the netlink tightening **does not affect the app's VPN detection** - interface names/addresses still arrive via getifaddrs (the RTM_GETADDR path), so `tun0` enumeration detection still works; what got cut is link-layer detail (the source of part of the MAC/flags).

### 3.3 The VpnService -> /dev/tun chain

```
app: VpnService.Builder.establish()                     [framework,VpnService.java:971]
  → getService().establishVpn(mConfig)                  [binder → system_server,:976]
     → Vpn.establish(config)                            [services/.../connectivity/Vpn.java:1722]
        → vpn.jniCreate(mtu)                            [Vpn.java:2423 native]
           → create()                                   [com_android_server_connectivity_Vpn.cpp]
              ① open("/dev/tun", O_RDWR|O_NONBLOCK|O_CLOEXEC)   [:61; Android uses /dev/tun;
                 desktop Linux /dev/net/tun is not created on Android]
              ② ioctl(tun, TUNSETIFF, &ifr4)            [:68]
                 → kernel tun_chr_ioctl → __tun_chr_ioctl [tun.c:3196]
                    → tun_set_iff()                     [tun.c:2845]
                       → alloc_netdev_mqs(tun_setup) → register_netdevice  [tun.c:2932/2961]
                       = net_device "tun0" (kernel-assigned name; Vpn.java:1764 reads it via jniGetName)
        → jniSetAddresses(interfaze, ...)               [Vpn.java:2425 sets interface addresses]
        → Install routes through netd (write Builder routes to the routing table, default route → tun0;
          old jniSetRoutes is absent from master; details require verification)
        → Return tun fd to app over binder (ParcelFileDescriptor)
  → app protect(socket): binder asks netd to apply fwmark to its upstream socket,
     preventing the VPN process's own traffic from routing back to tun in a loop

── Each subsequent VPN packet (kernel side)─────────────────────────────────
App packet route matches tun0 → dev_queue_xmit
  → tun_net_xmit()                          [tun.c:1059 = net_device ndo_start_xmit; :1272]
     → skb enters tun_file ptr_ring (tx_ring initialized in tun_chr_open:3549) → wake reader
app read(fd):tun_chr_read_iter              [tun.c:2338]
  → tun_do_read()                            [tun.c:2301] → pop a complete IP packet from ring
App processes packet (encryption/decryption/forwarding to proxy server)
app write(fd):tun_chr_write_iter            [tun.c:2080]
  → tun_get_user()                           [tun.c:1779: user buffer→skb; ends with netif_rx(skb), :2050]
     → netif_rx → __netif_receive_skb → ip_rcv(NF_INET_PRE_ROUTING)
     → route → ip_forward(NF_INET_FORWARD)→ POST_ROUTING → transmit through physical NIC wlan0
```

Postern/Clash/Surge's "VPN mode" is exactly this: a user-space process acts as the router while the kernel merely hauls bidirectional packets between the tun device and the fd. **The read/write direction is easy to mix up**: `tun_get_user` is the "app writes the fd to inject into the kernel" path; "app reads the fd to fetch packets" is `tun_chr_read_iter/tun_do_read`.

### 3.4 Observation/confrontation table

| Surface | Location | Fact | Confrontation/observation ideas |
|---|---|---|---|
| VPN detection (user space) | `getifaddrs`/`NetworkInterface` | enumerating tun0/tunX = VPN verdict; `ConnectivityManager.hasTransport(TRANSPORT_VPN)` goes over binder | bypass and counter-move matrices in "[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.4 and "[detection landscape](../04-evasion/detection-landscape.md)" sec.5.1 |
| VPN detection (kernel view) | enumerate `struct net_device` names with the `tun` prefix | same origin as user space (getifaddrs ultimately enumerates net_device via netlink/ioctl) | a kernel hook rewriting the returned interface name fools it globally (root needed, costly) |
| tun fd side-channel dump | inside the VPN app process | the tun fd is an ordinary fd; read/write are hookable | **hooking read/write(fd) inside the Postern/Clash process yields full plaintext IP packets** (one observation point each before/after encryption) - better than grabbing ciphertext on the Wi-Fi side |
| iptables traces | `/proc/net/ip_tables_names` etc. | root can read; apps (Android 10+) are restricted from /proc/net | an iptables-based capture setup is less visible to the app than the VPN setup |

### 3.5 Practical tips

- Only one VpnService can take over per device (the system's single VPN); the mutual exclusion of Postern and HttpCanary is rooted in system_server's Vpn state lock, not in the kernel.
- The tun MTU comes from `jniCreate(mtu)` (Vpn.java:1550 has a "Stop setting the MTU in jniCreate" TODO; details vary by version); large packets go through `ip_fragment` - mind reassembly when side-channel dumping.
- After grabbing the tun fd with frida you can also just `dup` it and run your own reader thread to eavesdrop without altering the app's behavior (stealthier than hooking write to change returns).

## Chain 4: the UDP/QUIC chain

### 4.1 UDP send/receive (checked against udp.c)

```
Send: udp_sendmsg()                          [udp.c:1255]
  → (cork/non-cork branch)ip_make_skb()      [udp.c:1460; assemble skb including IP header]
  → udp_send_skb()                          [udp.c:1113; checksum + statistics]
  → ip_send_skb → __ip_local_out(NF_INET_LOCAL_OUT)→ POST_ROUTING → dev_queue_xmit
     (Shares the entire egress path after LOCAL_OUT with TCP)
Receive: udp_rcv()                           [udp.c:2634; registered by inet_init]
  → __udp4_lib_rcv(look up sock by four-tuple hash; early demux possible)
  → udp_unicast_rcv_skb()                   [udp.c:2612]
  → udp_queue_rcv_skb() → __udp_queue_rcv_skb()  [udp.c:2466/2351; validate/enqueue in sk_receive_queue]
Read: udp_recvmsg()                          [udp.c:2053]
  → skb_recv_datagram pops queue → copy to user
```

The key UDP-vs-TCP difference: no `sk_write_queue` retransmit logic - udp_sendmsg does "app data -> IP packet" in one step, fire and forget; reception has no state machine, just enqueues by four-tuple.

### 4.2 What QUIC looks like to the kernel

- QUIC (HTTP/3) on Android is a **pure user-space implementation**: Cronet (quiche), Chromium-line WebViews, Flutter's custom stack. The TLS 1.3 handshake and record encryption complete in user space, then hand the payload to `udp_sendmsg` as UDP (typically dport 443).
- **The kernel sees only UDP ciphertext**: QUIC traffic observed at the tcp_sendmsg/udp_sendmsg layer is fully encrypted; the Connection ID header is plaintext (sessions can be clustered), and parts of Initial-packet headers are plaintext. This is not "can't capture the packet" but "captured but can't decrypt" - hence fallback (dropping UDP 443 to force HTTP/2 over TCP) is the mainstream; the full matrix is in "[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.2.6.
- The plaintext boundary is in user space: Cronet's `Cronet_UrlRequest` callback layer, or the in-library TLS/quiche send/receive functions; ecapture's QUIC key-extraction capability evolves by version (support scope per its repo notes).

### 4.3 Observation point table

| Observation point | What you see | Notes |
|---|---|---|
| kprobe `udp_sendmsg/udp_recvmsg` | QUIC ciphertext + sock (port pair) | traffic profiling / cert SNI invisible (encrypted) |
| User-space hook of Cronet callbacks | request/response plaintext | "[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.2.11; mind the so-load timing |
| iptables `-p udp --dport 443 -j DROP` | makes QUIC unusable -> client self-downgrades | root; use DROP for UDP, not REDIRECT |
| TPROXY (mangle PREROUTING) + ip rule | UDP transparent proxy | root; feasible on Android but fiddly - see "[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.2.5 pitfalls |

## Chain 5: the certificate chain and CA loading (the file side of the network trust chain)

### 5.1 The chain

```
app manifest: android:networkSecurityConfig=@xml/nsc
  → NetworkSecurityConfigProvider.install(context)   [framework installs provider at startup]
     → Parse trust-anchors(system/user/pin-set)→ build TrustManager policy
TLS handshake (conscrypt OpenSSLSocketImpl; Conscrypt in APEX com.android.conscrypt, modularized on Android 10+)
  → TrustManagerImpl.checkServerTrusted(chain, authType)
     → X509TrustManagerExtensions.checkServerTrusted → anchor lookup + chain validation + OCSP/pinning
Anchor data comes from TrustedCertificateStore file reads (file-attr-chain.md, §1):
  System CA:openat("/system/etc/security/cacerts/<hash>.0")        [Android 13-]
          openat("/apex/com.android.conscrypt/cacerts/...")       [Android 14+, read-only APEX]
  User CA:openat("/data/misc/user/0/cacerts-added/...")
  → read → BoringSSL X509 parsing → process cache (later handshakes avoid disk; first read is observable)
```

Certificate storage, the naming rule (`<subject_hash_old>.0`), and the Android 14 APEX-ification and bind-mount scheme are already written up in "[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.2.3/sec.3; only the kernel view is added here, without repetition.

### 5.2 Observation points

| Surface | Location | Use |
|---|---|---|
| hook `TrustManagerImpl.checkServerTrusted` (and `checkTrustedRecursive`) | L1 (conscrypt) | unpinning/trust-chain intervention; ready-made scripts in "[SSL pinning bypass](../04-evasion/ssl-pinning-bypass.md)" sec.3.1 and "[Java certificate snippets](../02-frida/java-layer/sslpinning-and-certificates.md)" |
| openat filtering `cacerts` paths | L3/L5 | kernel/strace observation of "which CA files the app read on first handshake"; blue teams can kprobe `sys_enter_openat` filtering this path to spot certificate-loading behavior; red teams use it to verify whether a Magisk certificate module was actually read by the target process (old directory vs apex directory is a single glance) |
| APEX mount point | the mount table | on Android 14+, to size up the target's certificate surface, `ls /apex/com.android.conscrypt/cacerts` first, then pick the plan |

### 5.3 Practical tips

- Apps that detect "whether a capture tool's CA is in the certificate directory" walk this same file chain (enumerating the cacerts directory comparing CNs) - the confrontation (changing CN/custom CA) and the detection live at the same layer; see the table in "[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.4.
- WebView/Chromium-line certificate logic is independent of libcore's TrustManagerImpl; hooking the Java layer occasionally fails for WebView ("[capture scenarios](../04-evasion/capture-all-scenarios.md)" sec.2.12) - when going deeper, openat observation first confirms which directory it actually reads.

## Chain 6: the getaddrinfo / DNS chain

### 6.1 The chain (checked against bionic master)

```
Java InetAddress.getAllByName/getByName
  → libcore Inet6AddressImpl.lookupAllHostAddr   [libjavacore native]
  → bionic getaddrinfo / android_getaddrinfofornetcontext   [libc.so,L3]
     → __netdClientDispatch.dnsOpenProxy()       [getaddrinfo.c:425; libnetdclient hook]
        = connect to netd DNS proxy socket (Unix socket; historical name dnsproxyd; verify path)
     → netid = __netdClientDispatch.netIdForResolv(netid)  [:429; tag by current network]
     → fprintf(proxy, "getaddrinfo %s %s <hints...> %u", hostname, ...) + NUL
        [:431; FrameworkListener text protocol]
netd (system_server-side daemon):
  → DnsProxyListener parses request → resolver (DNS resolver inside netd; consolidated there on Android 8+)
  → Private DNS enabled (DoT, Android 9+): netd connects to resolver:853 over TLS (ciphertext)
     Disabled: standard UDP 53 query (egress via chain 4; network capture can observe plaintext query)
  → Write text result to proxy socket → bionic parses addrinfo → Java receives InetAddress[]
```

Key points: **the app process never sends DNS packets itself** (Android 8+ everything is proxied through netd, tagged with a netId to distinguish networks); with DoT on, even plaintext UDP 53 queries vanish from the wire - a traffic fingerprint for judging the target's private-DNS state.

### 6.2 Observation point table

| Observation point | Layer | What you see | Notes |
|---|---|---|---|
| `InetAddress.getByName` | L1 | domain (the Java caller) | visible to RASP; native self-resolvers are invisible |
| libc `getaddrinfo` | L3 | every name resolution (native so calling libc directly included) | hooking the return enables DNS hijacking/sanitizing; apps bundling their own static resolver bypass it |
| netd proxy socket traffic | L3 (root) | the plaintext query text from app->netd | under root, strace/hook netd or tap the unix socket |
| Network-side UDP 53 | chain 4 | plaintext queries when private DNS is off | tcpdump/router side; disappears with DoT |
| kprobe (eBPF) | L5 | global DNS queries (attached at udp_sendmsg with dport=53, or on the netd process) | the blue team's stable point for monitoring C2 domains; with DoT you only see 853 ciphertext + the target IP |

### 6.3 Practical tips

- Blue-team view: the steadiest observation point for C2 domain resolution is **the netd side** (all apps converge there, root-controllable, logs enable-able); per-app user-space getaddrinfo hooks miss static resolvers and DoT.
- Red-team view: hooking `getaddrinfo` only affects the Java/native paths through bionic; if the target bundles DoH (resolution embedded in HTTPS), the DNS chain degenerates into ordinary HTTPS traffic and the observation points merge into chains 2/5.
- The legacy `gethostbyname` interface converges into the same netd proxy path in bionic (internally shared inside getaddrinfo.c); hooking one spot covers both entrances.

## Appendix A: version notes (2026-10 snapshot)

- This document's kernel line numbers come from torvalds **master**; known Android common/GKI (5.15/6.1/6.6) differences: the `connect_socket` split out of `__sys_connect` is a new master refactor, `tcp_stream_alloc_skb` coexisted with the old name `sk_stream_alloc_skb`, and the `net_hotdata` series is a recent cleanup - **align old kernels by function name, not line number**; for symbol extraction use the six-step method of 07-kernel/kernel-symbol-locating.md.
- The concrete Android Java SocketImpl class evolves with libcore versions (PlainSocketImpl line -> ?); OpenJDK 13+ desktop JVM's `sun.nio.ch.NioSocketImpl` is unrelated to Android; on the Android side both IO models converge on `.Posix` natives - the hooked layer is unaffected (class-name details).
- VpnService route provisioning migrated from jniSetRoutes to the netd pipe (timing point), but tun creation stays fixed in system_server's `jniCreate`.
- bionic getifaddrs' RTM_GETLINK uid gate (10000) and the SELinux comment are the master status quo; the introducing version is commonly cited as Android 12 - the sepolicy change commit was not obtained.

## Appendix B: checklist

- [ ] The exact introducing version and the sepolicy commit of the Android 12 netlink (RTM_GETLINK) restriction.
- [ ] The current path of the dnsproxyd socket (/dev/socket/dnsproxyd) and whether the protocol is still FrameworkListener text.
- [ ] The concrete class name of the current libcore .Socket's SocketImpl and the version switch point.
- [ ] The current netd interface name for VpnService route provisioning; whether any tun-interface naming version adds random suffixes.
- [ ] ecapture's support scope for QUIC (Cronet/quiche) key export.
- [ ] Whether GKI versions export the `sock:inet_sock_set_state`/`net:net_dev_queue` tracepoints (BTF availability varies by device).

## Appendix C: source anchors

- Kernel: linux torvalds master: net/socket.c, net/ipv4/{af_inet.c,tcp_ipv4.c,tcp.c,tcp_output.c,ip_output.c,ip_input.c,ip_forward.c,udp.c}, net/core/dev.c, net/packet/af_packet.c, drivers/net/tun.c, include/linux/netfilter.h.
- AOSP master: frameworks/base core/java/android/net/VpnService.java (establish:971-980), services/core/java/com/android/server/connectivity/Vpn.java (establish:1722, jniCreate:2423), services/core/jni/com_android_server_connectivity_Vpn.cpp (create:61/68), bionic libc/bionic/ifaddrs.cpp (getifaddrs gate:303-334), libc/dns/net/getaddrinfo.c (netd proxy:425-445).
- In-library cross-references: "../09-function-map/android-function-layers.md" sec.2/sec.0.1, "../09-function-map/hook-fallback-playbook.md" case 2/sec.3, "../04-evasion/capture-all-scenarios.md" sec.2/sec.3/sec.4, "../04-evasion/ssl-pinning-bypass.md", "../07-kernel/android-kernel-ebpf.md", "../07-kernel/kernel-hook-stealth.md".
