#!/usr/bin/env python3
import threading
import queue
import ctypes as ct
import sys
import time
from bcc import BPF
from scapy.all import Ether, sendp, conf

# We only define the metadata; the raw bytes follow dynamically in memory
class PacketMeta(ct.Structure):
    _fields_ = [("len", ct.c_uint32)]

device = sys.argv[1] if len(sys.argv) > 1 else "lo"
conf.iface = device

print(f"[*] Compiling eBPF C code via BCC and attaching to {device}...")
with open("ebpf-probe.c", "r") as f:
    b = BPF(text=f.read())

fn = b.load_func("xdp_prog", BPF.XDP)
b.attach_xdp(dev=device, fn=fn, flags=2)

pkt_queue = queue.Queue()

def process_event(cpu, data, size):
    # 1. Cast the start of the memory to our Metadata struct
    meta = ct.cast(data, ct.POINTER(PacketMeta)).contents
    
    # 2. Calculate the memory address where the raw packet bytes actually begin
    packet_base = ct.cast(data, ct.c_void_p).value + ct.sizeof(PacketMeta)
    
    # 3. Read exactly 'meta.len' bytes natively from that memory pointer
    raw_bytes = ct.string_at(packet_base, meta.len)
    
    pkt_queue.put(raw_bytes)
    print(f"[XDP Hook] Captured malformed TuDoor packet. Length: {meta.len} bytes")

def scapy_worker():
    print("[*] Rate limiter worker started. Throttling to 2 pkts/sec.")
    while True:
        raw_bytes = pkt_queue.get() 
        time.sleep(0.5) 
        
        try:
            pkt = Ether(raw_bytes)
            pkt.src = "00:de:ad:be:ef:00"
            
            sendp(pkt, iface=device, verbose=False)
            print("[User Space] Re-injected throttled packet with Magic MAC.")
        except Exception as e:
            print(f"[!] Scapy error during re-injection: {e}")
        finally:
            pkt_queue.task_done()

worker = threading.Thread(target=scapy_worker, daemon=True)
worker.start()

b["events"].open_perf_buffer(process_event)

print("[*] BOR-BOX eBPF Engine Active. Press Ctrl+C to exit.")
try:
    while True:
        b.perf_buffer_poll() 
except KeyboardInterrupt:
    print("\n[*] Detaching XDP probe and shutting down...")
finally:
    b.remove_xdp(device, flags=2)
