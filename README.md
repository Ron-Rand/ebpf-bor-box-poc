# BOR-BOX eBPF Proof of Concept

This repository contains a high-performance eBPF middlebox implementation of the BOR-BOX DNS rate-limiting engine. It demonstrates the ability to inspect structural DNS logic directly inside the Linux kernel via XDP (eXpress Data Path), rate-limit malformed queries in user space, and re-inject them without trapping the packets in an infinite XDP drop loop.

## Core Architecture

The architecture is divided into three distinct stages:

1. **The XDP Fast Path (Kernel Space):** 
   The C program (`ebpf-probe.c`) attaches to the network interface at the lowest possible level. It parses the packet headers (`ETH` -> `IP` -> `UDP` -> `DNS`). If a packet violates a defined structural rule (e.g., `QDCOUNT > 1` indicating a TuDoor logic panic attack), the packet is rejected from the fast path.
2. **The IPC Channel (Perf Buffer):**
   When a packet triggers a rule limit, the kernel utilizes `bpf_perf_event_output` (via the BCC `perf_submit_skb` macro) to push a metadata struct and the raw packet bytes directly into a user-space Perf Buffer, instantly returning `XDP_DROP` to prevent the packet from reaching the vulnerable DNS resolver.
3. **The Control Plane & Rate Limiter (User Space):**
   The Python orchestrator (`ebpf-runner.py`) continuously polls the Perf Buffer. Caught packets are placed in an asynchronous queue where a background thread releases exactly 10 packets per second.

## The Magic MAC Bypass (Re-injection)

When the Python user-space queue releases a rate-limited packet, it must be sent back onto the network so the original client eventually receives a response. However, re-injecting the packet means it will hit the XDP kernel hook a second time, potentially causing an infinite loop.

To bypass this without forcing the eBPF kernel code to recalculate complex IP and UDP checksums, this PoC uses a **Magic MAC Address**. 
Before Scapy re-injects the throttled packet, it alters the Ethernet source MAC to `00:de:ad:be:ef:00`. The first instruction in the XDP C code checks for this exact MAC address. If found, it executes an $O(1)$ `XDP_PASS`, allowing the packet to traverse standard Linux networking completely untouched at L3/L4.

## Environment & Dependencies

This PoC was built for **Ubuntu 20.04 (Kernel 5.4)**. 
Do not use `pip` to install eBPF bindings. You must use the system package manager to install the LLVM compilers and BCC tools:
* `sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3-scapy`

## Deployment & Testing Guide

**1. Clean the Interface**
Ensure no orphaned XDP hooks remain on the loopback interface from previous crashed runs:
`sudo ip link set dev lo xdpgeneric off`

**2. Start the Engine**
Launch the orchestrator on the loopback interface:
`sudo python3 ebpf-runner.py lo`

**3. Monitor the Wire**
In a separate terminal, watch the raw L2 traffic (the `-e` flag exposes the MAC addresses):
`sudo tcpdump -i lo -n -e udp port 53`

**4. Test the Fast Path**
In a third terminal, send a standard query. It should pass through the XDP hook silently and immediately appear in the `tcpdump` logs:
`dig @127.0.0.1 www.example.com`

**5. Trigger the Defense**
Create an `attack.py` script to forge a malformed TuDoor query (`QDCOUNT = 2`):
```python
#!/usr/bin/env python3
from scapy.all import IP, UDP, DNS, DNSQR, send
malformed_pkt = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(qdcount=2, qd=DNSQR(qname="test1.com") / DNSQR(qname="test2.com"))
send(malformed_pkt, verbose=True)
Run sudo python3 attack.py. The Python runner will log the capture, sleep to enforce the rate limit, and re-inject the packet using the Magic MAC.
