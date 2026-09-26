= BOR-BOX: eBPF/XDP DNS Rate-Limiting Middlebox

A high-performance Linux kernel middlebox built with eBPF/XDP and Python that enforces operator-defined structural DNS filtering rules at line rate. BOR-BOX acts as an interim defensive layer deployed directly in front of recursive resolvers to mitigate newly disclosed vulnerabilities during the vendor patch gap without requiring resolver restarts or risking false-positive outages[cite: 1].

'''

== Core Architecture

BOR-BOX implements a hybrid two-plane architecture consisting of a high-speed in-kernel packet filter and an asynchronous user-space rate-limiting and re-injection pipeline[cite: 1]:

[source,text]
----
[ Ingress Network Interface (e.g., lo, eth0) ]
                      │
                      ▼
            [ XDP Hook: ebpf-probe.c ]
                      │
         ┌────────────┴──────────────────────────┐
         │ Magic MAC (00:de:ad:be:ef:00)?        │
         └────────────┬──────────────────────────┘
             YES ─────┼──────────────────────────────┐
                      │ NO                           │
         ┌────────────┴──────────────────────────┐   │
         │ Header Parser & DSL Rule Evaluation   │   │
         └────────────┬──────────────────────────┘   │
             ALLOW ───┼──────────┐                   │
                      │ LIMIT    │                   │
                      ▼          ▼                   ▼
                [ perf_buffer ] [ XDP_PASS ] ──> [ Linux Kernel Network Stack ]
                      │                                    │
                      ▼ (events.perf_submit_skb)           ▼
         [ User Space Queue: ebpf_runner.py ]      [ Local / Upstream DNS Resolver ]
                      │
                      ▼ (10 packets/sec throttled)
         [ Scapy Worker: Magic MAC Tagging ]
                      │
                      └─ sendp() ──> Re-inject to Interface
----

=== 1. In-Kernel Fast Path (`ebpf-probe.c`)
Attaches directly to the network driver via Generic or Native XDP (`flags=2`). It validates L2–L4 protocol boundaries, parses the raw DNS fixed header into host-byte order, derives logical subflags, and executes user-defined rule branches. Packets matching an `ALLOW` rule or falling through unmatched return `XDP_PASS` immediately, traversing the Linux networking stack with zero memory allocation or IPC penalty.

=== 2. IPC Telemetry & Rate-Limiting Channel
Packets matching a `LIMIT` condition are shunted off the fast path. The probe captures the frame using BCC's `events.perf_submit_skb()` helper to copy the payload directly into a per-CPU perf ring buffer, returning `XDP_DROP` to halt further execution down the kernel stack.

=== 3. User-Space Queue & Re-Injection Engine (`ebpf_runner.py`)
A Python daemon continuously polls the perf buffer and enqueues intercepted frames into a bounded queue (`maxsize=1000`). A dedicated rate-limiter worker releases frames onto the wire at a strictly capped throughput (10 packets/second), guaranteeing delivery while suppressing denial-of-service pressure against downstream resolver worker threads.

=== 4. Interactive Control Plane (`bor_box_gui.py`)
A desktop GUI providing real-time telemetry streaming, active interface configuration, rule syntax checking, and dynamic eBPF recompilation and re-attachment without dropping application state.

'''

== Rule Engine & DSL Specification

BOR-BOX compiles a Domain Specific Language (DSL) into native C branch statements evaluated in order inside the XDP probe.

=== Rule Grammar
[source,text]
----
IF IN <field> <operator> <value> <ACTION>
----

* *Semantics:* *First-match wins*. The first rule whose condition evaluates to `true` executes its terminal action. Packets matching no rules default to *`ALLOW`*.
* *Supported Operators:* `<`, `>`, `<=`, `>=`, `==`, `=` (normalized to `==` in C).
* *Values:* Supports decimal integers (`10`, `0`) and hexadecimal literals (`0x8400`, `0x01`).

=== Supported Fields

[cols="1,1,2,2", options="header"]
|===
| Field Name | Source | Description | Supported Values

| `id`
| Fixed Header
| DNS 16-bit Transaction ID
| `0` – `65535` (`0x0000`–`0xFFFF`)

| `flags`
| Fixed Header
| Full 16-bit Header Flags & Codes
| `0` – `65535` (`0x0000`–`0xFFFF`)

| `qdcount`
| Fixed Header
| Number of Question entries
| `0` – `65535`

| `ancount`
| Fixed Header
| Number of Answer Resource Records
| `0` – `65535`

| `nscount`
| Fixed Header
| Number of Authority Nameserver Records
| `0` – `65535`

| `arcount`
| Fixed Header
| Number of Additional Resource Records
| `0` – `65535`

| `qr`
| Bitfield (`flags[15]`)
| Query (0) or Response (1) Indicator
| `0` or `1`

| `opcode`
| Bitfield (`flags[11:14]`)
| Operation Code (Standard=0, Inverse=1, Status=2)
| `0` – `15`

| `aa`
| Bitfield (`flags[10]`)
| Authoritative Answer Flag
| `0` or `1`

| `tc`
| Bitfield (`flags[9]`)
| Truncation Flag
| `0` or `1`

| `rd`
| Bitfield (`flags[8]`)
| Recursion Desired Flag
| `0` or `1`

| `ra`
| Bitfield (`flags[7]`)
| Recursion Available Flag
| `0` or `1`

| `rcode`
| Bitfield (`flags[0:3]`)
| Response Return Code (NOERROR=0, SERVFAIL=2, NXDOMAIN=3)
| `0` – `15`
|===

=== Actions
* *`ALLOW`*: Generates `return XDP_PASS;` immediately upon matching. The packet bypasses all remaining checks and enters the OS network stack.
* *`LIMIT`*: Generates `goto limit_packet;`, which serializes the frame into the perf ring buffer and drops the original packet via `XDP_DROP`.

'''

== The Magic MAC Bypass

Re-injecting throttled frames from user space back onto the same network interface causes the packets to encounter the ingress XDP hook a second time, resulting in an infinite interception loop.

To bypass this without recalculating IP and UDP transport checksums:

1. When `ebpf_runner.py` pops a packet from the queue, Scapy rewrites the Ethernet source address to the Magic MAC: `00:de:ad:be:ef:00`.
2. The packet is placed on the wire via `sendp()`.
3. In `ebpf-probe.c`, the very first branch executed after validating Ethernet boundary safety checks `eth->h_source`:
+
[source,c]
----
if (eth->h_source[0] == 0x00 && eth->h_source[1] == 0xDE &&
    eth->h_source[2] == 0xAD && eth->h_source[3] == 0xBE &&
    eth->h_source[4] == 0xEF && eth->h_source[5] == 0x00) {
    return XDP_PASS;
}
----
4. Re-injected packets execute an $O(1)$ fast exit directly into the system networking stack without undergoing rule re-evaluation.

'''

== Project Structure

[source,text]
----
ebpf-bor-box/
├── ebpf-probe.c       # C kernel source containing XDP logic and parsing anchors
├── ebpf_runner.py     # Core engine: rule compilation, BCC interface, and rate limiter
├── bor_box_gui.py     # Graphical control panel with live telemetry and rule editor
├── rules.txt          # (Optional) Standalone plain-text rule definitions
└── README.md          # Technical documentation and deployment guide
----

'''

== Environment & Prerequisites

This system is tested on *Ubuntu 20.04 LTS (Linux Kernel 5.4)*.

Install the required LLVM toolchain, kernel development headers, BCC libraries, and Scapy via `apt` (do *not* install BCC via `pip`):

[source,bash]
----
sudo apt-get update
sudo apt-get install -y \
    bpfcc-tools \
    linux-headers-$(uname -r) \
    python3-bpfcc \
    python3-scapy \
    python3-tk
----

'''

== Deployment & Usage

=== Option 1: Running via the Graphical Control Plane (Recommended)

. *Clear Existing Hooks:*
+
Ensure no orphaned XDP hooks remain on the target interface:
+
[source,bash]
----
sudo ip link set dev lo xdpgeneric off 2>/dev/null
----

. *Launch the Interface:*
+
Launch the control panel with root privileges (required by the kernel to load BPF bytecode):
+
[source,bash]
----
sudo python3 bor_box_gui.py
----

. *Configure & Deploy:*
* Select the target network interface from the dropdown (e.g., `lo` for local testing).
* Review or modify the DSL rules inside the *Active Rule Specification* editor.
* Click *Compile & Install*. The status indicator will transition to `● RUNNING`, and compile logs will appear in the system telemetry window.

=== Option 2: Running Headless via CLI

Create a custom rule file (e.g., `rules.txt`):

[source,text]
----
# Mitigate TuDoor: Throttle multi-question queries[cite: 1]
IF IN qdcount > 1 LIMIT

# Mitigate NXNSAttack: Throttle excessive delegations[cite: 1]
IF IN nscount > 10 LIMIT

# Mitigate KeyTrap: Throttle excessive resource records[cite: 1]
IF IN ancount > 15 LIMIT
----

Run the engine module directly:

[source,bash]
----
sudo python3 ebpf_runner.py lo rules.txt
----

'''

== Testing & Validation

=== 1. Fast-Path Verification (`ALLOW`)
Transmit a standard query matching no limiting rules. The query will pass cleanly through the kernel hook:

[source,bash]
----
dig @127.0.0.1 www.example.com
----

*Telemetry Output:* No trap events generated; packet passes transparently to the resolver.

=== 2. Rate-Limiting Verification (`LIMIT`)
Send an attack packet crafted to trigger a structural mitigation (e.g., a TuDoor logic panic query containing `qdcount = 2`)[cite: 1]:

[source,bash]
----
sudo python3 -c '
from scapy.all import IP, UDP, DNS, DNSQR, send
pkt = IP(dst="127.0.0.1")/UDP(dport=53)/DNS(qdcount=2, qd=DNSQR(qname="test1.com")/DNSQR(qname="test2.com"))
send(pkt, verbose=False)
'
----

*Expected Telemetry Output in GUI/Terminal:*
[source,text]
----
[XDP Trap] Packet intercepted (81 bytes). Queued.
[User Space] Re-injected packet with Magic MAC.
----

=== 3. Observing the Magic MAC on the Wire
Monitor L2 frames in real time to observe the source MAC address transform during re-injection:

[source,bash]
----
sudo tcpdump -i lo -n -e udp port 53
----

*Output will display the re-injected packet bearing the bypass hardware address `00:de:ad:be:ef:00`.*
