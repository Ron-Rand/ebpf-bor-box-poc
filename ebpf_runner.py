#!/usr/bin/env python3
import ctypes as ct
import os
import queue
import re
import sys
import threading
import time
from bcc import BPF
from scapy.all import Ether, conf, sendp

VALID_FIELDS = {
    "id", "flags", "qdcount", "ancount", "nscount", "arcount",
    "qr", "opcode", "aa", "tc", "rd", "ra", "rcode"
}

RULE_PATTERN = re.compile(
    r"^\s*IF\s+IN\s+([a-zA-Z_]+)\s*(<=|>=|==|=|<|>)\s*([0-9a-fA-FxX]+)\s+(ALLOW|LIMIT)\s*$",
    re.IGNORECASE
)

class PacketMeta(ct.Structure):
    _fields_ = [("len", ct.c_uint32)]

def parse_rules_to_c(rules_text: str) -> str:
    c_lines = []
    lines = rules_text.strip().splitlines()
    
    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        
        match = RULE_PATTERN.match(line)
        if not match:
            raise ValueError(f"Line {idx}: Syntax error -> '{raw_line}'")
        
        field, op, val_str, action = match.groups()
        field = field.lower()
        action = action.upper()
        
        if field not in VALID_FIELDS:
            raise ValueError(f"Line {idx}: Unknown DNS field '{field}'")
        
        try:
            val = int(val_str, 0)
        except ValueError:
            raise ValueError(f"Line {idx}: Invalid numeric value '{val_str}'")
        
        if op == "=":
            op = "=="
            
        if action == "LIMIT":
            action_code = "goto limit_packet;"
        else:
            action_code = "return XDP_PASS;"
            
        c_lines.append(f"    if ({field} {op} {val}) {{ {action_code} }}")
    
    return "\n".join(c_lines)

class BorBoxEngine:
    def __init__(self, probe_template_path="ebpf-probe.c", log_fn=print):
        self.probe_path = probe_template_path
        self.log = log_fn
        self.bpf = None
        self.device = None
        self.pkt_queue = queue.Queue(maxsize=1000)
        self.running = False
        self.worker_thread = None
        self.poll_thread = None

    def start(self, rules_text: str, device: str = "lo"):
        if self.running:
            self.stop()

        self.device = device
        conf.iface = device
        self.log(f"[*] Parsing rules for interface '{device}'...")
        
        rules_c = parse_rules_to_c(rules_text)
        
        if not os.path.exists(self.probe_path):
            raise FileNotFoundError(f"Missing probe template: {self.probe_path}")
            
        with open(self.probe_path, "r") as f:
            code = f.read()

        if "/* %RULES_CODE% */" not in code:
            raise ValueError("Template anchor '/* %RULES_CODE% */' missing from probe C file.")

        injected_c = code.replace("/* %RULES_CODE% */", rules_c)

        self.log("[*] Compiling eBPF bytecode via Clang/BCC...")
        self.bpf = BPF(text=injected_c)
        fn = self.bpf.load_func("xdp_prog", BPF.XDP)
        
        self.log(f"[*] Attaching XDP hook (flags=2) on {device}...")
        self.bpf.attach_xdp(dev=device, fn=fn, flags=2)
        
        self.running = True

        self.worker_thread = threading.Thread(target=self._scapy_worker, daemon=True)
        self.worker_thread.start()

        def _perf_handler(cpu, data, size):
            meta = ct.cast(data, ct.POINTER(PacketMeta)).contents
            packet_base = ct.cast(data, ct.c_void_p).value + ct.sizeof(PacketMeta)
            raw_bytes = ct.string_at(packet_base, meta.len)
            try:
                self.pkt_queue.put_nowait(raw_bytes)
                self.log(f"[XDP Trap] Packet intercepted ({meta.len} bytes). Queued.")
            except queue.Full:
                self.log("[!] Queue full: throttled packet dropped.")

        self.bpf["events"].open_perf_buffer(_perf_handler)

        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()
        self.log("[+] BOR-BOX engine running successfully.")

    def _poll_loop(self):
        while self.running and self.bpf:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception:
                break

    def _scapy_worker(self):
        while self.running:
            try:
                raw_bytes = self.pkt_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            time.sleep(0.1)  # 10 packets per second ceiling
            try:
                pkt = Ether(raw_bytes)
                pkt.src = "00:de:ad:be:ef:00"
                sendp(pkt, iface=self.device, verbose=False)
                self.log("[User Space] Re-injected packet with Magic MAC.")
            except Exception as e:
                self.log(f"[!] Scapy re-injection error: {e}")
            finally:
                self.pkt_queue.task_done()

    def stop(self):
        if not self.running:
            return
        self.log("[*] Detaching XDP hook and halting engine...")
        self.running = False

        if self.bpf and self.device:
            try:
                self.bpf.remove_xdp(self.device, flags=2)
            except Exception as e:
                self.log(f"[!] Error removing XDP hook: {e}")
            self.bpf = None

        self.log("[-] Engine detached and stopped.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 ebpf_runner.py <interface> [rules.txt]")
        sys.exit(1)
        
    dev = sys.argv[1]
    rule_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if rule_file:
        with open(rule_file, "r") as rf:
            rules = rf.read()
    else:
        rules = "IF IN qdcount > 1 LIMIT\n"
        
    engine = BorBoxEngine(log_fn=print)
    try:
        engine.start(rules, dev)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop()
