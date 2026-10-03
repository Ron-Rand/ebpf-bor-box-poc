# Mini BOR-BOX: eBPF/XDP DNS Rate-Limiting Middlebox

Mini BOR-BOX is a high-performance DNS middlebox proof of concept built on Linux eBPF and XDP (eXpress Data Path). It dynamically compiles human-readable filtering rules into in-kernel bytecode to inspect DNS header fields at the driver/generic network layer, diverting suspicious or malformed traffic into a throttled user-space queue while letting legitimate queries traverse the fast path unhindered.

---

## Architecture Overview

The system operates across three coordinated layers:

### 1. In-Kernel Fast Path (XDP)
The C program (`ebpf-probe.c`) attaches directly to the network interface at the XDP layer. When a packet arrives:
* It verifies Ethernet, IPv4, and UDP encapsulations destined for or originating from port 53.
* It checks the source MAC address. If the packet carries the designated Magic MAC (`00:de:ad:be:ef:00`), it is immediately passed (`XDP_PASS`) to avoid infinite inspection loops upon re-injection.
* It parses the DNS fixed header, extracting all 6 standard fields and unpacking flag bits into local variables in host byte order.
* It executes a dynamically compiled chain of rule conditions. If a packet matches an `ALLOW` rule, it continues to the resolver via `XDP_PASS`. If it matches a `LIMIT` rule, it jumps to the rate-limiter branch.
* If no rules match, the default policy is `ALLOW` (`XDP_PASS`).

### 2. IPC Telemetry Channel (Perf Event Ring Buffer)
When a packet matches a `LIMIT` condition:
* A metadata struct containing the packet length is prepared.
* The kernel calls `events.perf_submit_skb()` to push the metadata and raw packet payload into a per-CPU BPF perf ring buffer.
* The XDP hook immediately returns `XDP_DROP`, halting the packet from reaching the socket buffer of the vulnerable resolver.

### 3. User-Space Control Plane & Rate Limiter
The Python orchestrator (`ebpf_runner.py` / `bor_box_gui.py`):
* Polls the perf ring buffer asynchronously.
* Places intercepted packets into a thread-safe queue.
* A background rate-limiting worker pulls packets from the queue and enforces a release ceiling of 10 packets per second.
* Before re-injecting each throttled packet back onto the interface using Scapy, the worker rewrites its Ethernet source MAC to `00:de:ad:be:ef:00` (the Magic MAC).
* When the packet re-enters the XDP hook, the O(1) Magic MAC check passes it directly to the host network stack, allowing eventual resolution without re-triggering the rate limiter.

---

## Rule Domain-Specific Language (DSL)

Mini BOR-BOX provides a declarative syntax for expressing DNS header filtering rules.

### Rule Syntax
```text
IF IN <field> <operator> <value> <ACTION>
```

### Evaluation Semantics
* **First-match wins:** Rules are evaluated sequentially from top to bottom. The first rule whose condition evaluates to true executes its action and terminates further evaluation for that packet.
* **Default policy:** Packets that do not match any rule evaluate to `ALLOW` (`XDP_PASS`).
* **Comments and blank lines:** Empty lines and lines starting with `#` are ignored.

### Supported DNS Header Fields
* `id`: 16-bit DNS Transaction ID.
* `flags`: Full 16-bit raw flags word.
* `qdcount`: Number of entries in the Question section.
* `ancount`: Number of Resource Records in the Answer section.
* `nscount`: Number of Name Server Resource Records in the Authority section.
* `arcount`: Number of Resource Records in the Additional section.

### Supported Virtual Subflag Fields
Extracted automatically from the `flags` word:
* `qr`: Query (0) or Response (1) indicator (1 bit).
* `opcode`: Operation code (4 bits, standard query is 0).
* `aa`: Authoritative Answer bit (1 bit).
* `tc`: Truncation flag (1 bit).
* `rd`: Recursion Desired bit (1 bit).
* `ra`: Recursion Available bit (1 bit).
* `rcode`: Response code (4 bits, e.g., 0 for NoError, 3 for NXDOMAIN).

### Supported Comparison Operators
* `<`: Less than
* `>`: Greater than
* `=`: Equal to (normalized to C `==`)
* `==`: Equal to
* `<=`: Less than or equal to
* `>=`: Greater than or equal to

### Supported Actions
* `ALLOW`: Immediately pass the packet via `XDP_PASS`.
* `LIMIT`: Trap the packet, drop it from the kernel path, and route it to the 10 pkts/sec rate-limited re-injection queue.

### Example Policy
```text
# Mitigate TuDoor: Throttle multi-question queries
IF IN qdcount > 1 LIMIT

# Mitigate NXNSAttack / NRDelegation: Throttle excessive authority delegations
IF IN nscount > 10 LIMIT

# Mitigate KeyTrap: Throttle excessive answer records
IF IN ancount > 15 LIMIT

# Explicitly fast-path standard queries
IF IN qr == 0 ALLOW
```

---

## Repository Structure

* `ebpf-probe.c`: The C source template for the XDP probe containing Ethernet/IP/UDP/DNS parsing, the Magic MAC bypass hook, and the `/* %RULES_CODE% */` code-generation placeholder.
* `ebpf_runner.py`: The core engine module. Parses the DSL, replaces the placeholder with synthesized C branches, compiles bytecode via BCC/LLVM, attaches/detaches XDP hooks, and runs the Scapy re-injection thread. Can be run standalone from the CLI.
* `bor_box_gui.py`: The Tkinter-based desktop GUI control plane. Provides a DSL code editor, network interface selection, compilation status tracking, and a live telemetry terminal.
* `README.md`: System documentation and deployment instructions.

---

## Dependencies & Environment Setup

Tested on **Ubuntu 20.04 LTS (Linux Kernel 5.4)**.

Install the required kernel headers, LLVM/Clang compiler toolchain, BCC packages, Scapy, and Tkinter via the system package manager (do not install BCC via pip):

```bash
sudo apt-get update
sudo apt-get install -y \
    bpfcc-tools \
    linux-headers-$(uname -r) \
    python3-bpfcc \
    python3-scapy \
    python3-tk
```

---

## Operating Instructions

### 1. Clear Existing Interface Hooks
Ensure no orphaned XDP hooks remain on your target interface (e.g., `lo`):
```bash
sudo ip link set dev lo xdpgeneric off 2>/dev/null
```

### 2. Option A: Run via the GUI Control Plane
Launch the GUI application with root privileges:
```bash
sudo python3 bor_box_gui.py
```
* Select the target network interface from the dropdown (default: `lo`).
* Edit or add rules in the **Active Rule Specification** panel.
* Click **Compile & Install**. The status indicator will switch to `RUNNING`, and compilation/attachment logs will stream into the telemetry view.
* Click **Update Rules** to hot-recompile and reload updated rule sets at runtime.
* Click **Detach XDP** to cleanly remove the probe from the interface.

### 3. Option B: Run Headless via CLI
You can run the engine directly from the command line without the GUI:
```bash
sudo python3 ebpf_runner.py <interface> [path/to/rules.txt]
```
Example:
```bash
sudo python3 ebpf_runner.py lo
```

---

## Verification & Testing

### 1. Monitor Interface Traffic
In a separate terminal, monitor traffic on the target interface with L2 header display enabled:
```bash
sudo tcpdump -i lo -n -e udp port 53
```

### 2. Test the Fast Path (Legitimate Query)
Send a standard DNS query:
```bash
dig @127.0.0.1 [www.example.com](https://www.example.com)
```
The packet matches no `LIMIT` rules, traverses the XDP hook via `XDP_PASS`, and resolves immediately without triggering logging in the telemetry panel.

### 3. Test the Rate-Limited Path (Malformed Query)
Using Python and Scapy, forge a malformed query with `qdcount = 2` to trigger the TuDoor mitigation rule:
```bash
sudo python3 -c '
from scapy.all import IP, UDP, DNS, DNSQR, send
malformed_pkt = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(qdcount=2, qd=DNSQR(qname="test1.com") / DNSQR(qname="test2.com"))
send(malformed_pkt, verbose=False)
'
```
* The kernel drops the packet from the normal stack path (`XDP_DROP`) and submits it to the perf buffer.
* The runner logs: `[XDP Trap] Packet intercepted (<len> bytes). Queued.`
* After the rate-limiting delay, Scapy re-injects the packet with source MAC `00:de:ad:be:ef:00`.
* The runner logs: `[User Space] Re-injected packet with Magic MAC.`
* In `tcpdump`, the re-injected packet appears on the wire bearing the `00:de:ad:be:ef:00` MAC address.

---

## Technical Notes & Operational Boundaries

* **Generic XDP Mode:** The runner attaches using `flags=2` (`XDP_FLAGS_SKB_MODE`). This enables compatibility across standard virtual interfaces, veth pairs, and loopback devices without requiring specialized hardware driver support.
* **Payload Truncation Boundary:** The probe caps captured packet slices sent through the perf ring buffer at 256 bytes (`pkt_len = 256`). For packets requiring full L7 re-injection when payload exceeds 256 bytes, adjust `pkt_len` up to the network MTU to ensure IP/UDP length fields remain valid.
* **Encrypted DNS:** The XDP probe operates on cleartext DNS over UDP (Do53). It does not inspect DNS over TLS (DoT) or DNS over HTTPS (DoH) sessions.
