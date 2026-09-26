#!/usr/bin/env python3
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from ebpf_runner import BorBoxEngine

DEFAULT_RULES = """# Mini BOR-BOX Rule Definitions
# Syntax: IF IN <field> <op> <value> <ALLOW|LIMIT>
# Fields: id, flags, qdcount, ancount, nscount, arcount, qr, opcode, aa, tc, rd, ra, rcode
# Ops:    <, >, =, ==, <=, >=
# First-match wins. Unmatched queries default to ALLOW.

# Mitigate TuDoor: Throttle multi-question queries
IF IN qdcount > 1 LIMIT

# Mitigate NXNSAttack: Throttle excessive nameserver delegations
IF IN nscount > 10 LIMIT

# Mitigate KeyTrap: Throttle excessive resource records
IF IN ancount > 15 LIMIT
"""

class ModernBorBoxUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BOR-BOX // Mini DNS Firewall & Rate-Limiter")
        self.root.geometry("880x740")
        self.root.minsize(760, 600)
        self.root.configure(bg="#11111b")

        self.log_queue = queue.Queue()
        self.engine = BorBoxEngine(probe_template_path="ebpf-probe.c", log_fn=self.enqueue_log)

        self._configure_styles()
        self._build_layout()
        self._detect_interfaces()

        self.root.after(100, self._process_log_queue)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure(".", background="#11111b", foreground="#cdd6f4", font=("Segoe UI", 10))
        style.configure("TCombobox", fieldbackground="#1e1e2e", background="#313244", foreground="#cdd6f4")
        style.map("TCombobox", fieldbackground=[("readonly", "#1e1e2e")], selectbackground=[("readonly", "#313244")])

    def _build_layout(self):
        # Header Frame
        header = tk.Frame(self.root, bg="#181825", height=60, padx=20, pady=10)
        header.pack(fill=tk.X, side=tk.TOP)

        title_lbl = tk.Label(header, text="BOR-BOX", font=("Consolas", 18, "bold"), fg="#89b4fa", bg="#181825")
        title_lbl.pack(side=tk.LEFT)

        subtitle_lbl = tk.Label(header, text="  eBPF/XDP Rate-Limited Queue Engine", font=("Segoe UI", 10), fg="#6c7086", bg="#181825")
        subtitle_lbl.pack(side=tk.LEFT, pady=(6, 0))

        self.status_pill = tk.Label(header, text="● INACTIVE", font=("Segoe UI", 9, "bold"), fg="#f38ba8", bg="#313244", padx=10, pady=4)
        self.status_pill.pack(side=tk.RIGHT)

        # Control Bar
        ctrl_bar = tk.Frame(self.root, bg="#11111b", padx=20, pady=12)
        ctrl_bar.pack(fill=tk.X)

        iface_lbl = tk.Label(ctrl_bar, text="Target Interface:", fg="#a6adc8", bg="#11111b", font=("Segoe UI", 10, "bold"))
        iface_lbl.pack(side=tk.LEFT, padx=(0, 8))

        self.iface_combo = ttk.Combobox(ctrl_bar, width=12, state="readonly")
        self.iface_combo.pack(side=tk.LEFT, padx=(0, 20))

        self.btn_compile = tk.Button(
            ctrl_bar, text="Compile & Install", bg="#a6e3a1", fg="#11111b",
            font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=14, pady=4,
            activebackground="#94e2d5", cursor="hand2", command=self.action_start
        )
        self.btn_compile.pack(side=tk.LEFT, padx=6)

        self.btn_stop = tk.Button(
            ctrl_bar, text="Detach XDP", bg="#313244", fg="#cdd6f4",
            font=("Segoe UI", 10), relief=tk.FLAT, padx=14, pady=4,
            activebackground="#45475a", state=tk.DISABLED, cursor="hand2", command=self.action_stop
        )
        self.btn_stop.pack(side=tk.LEFT, padx=6)

        btn_clear = tk.Button(
            ctrl_bar, text="Clear Log", bg="#181825", fg="#6c7086",
            font=("Segoe UI", 9), relief=tk.FLAT, padx=8, pady=4,
            activebackground="#313244", cursor="hand2", command=self.action_clear_log
        )
        btn_clear.pack(side=tk.RIGHT)

        # Main Workspace Splitter
        paned = tk.PanedWindow(self.root, orient=tk.VERTICAL, bg="#313244", sashrelief=tk.FLAT, sashwidth=4)
        paned.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

        # Rule Editor Frame
        editor_frame = tk.Frame(paned, bg="#181825")
        paned.add(editor_frame, minsize=180, height=260)

        editor_hdr = tk.Frame(editor_frame, bg="#1e1e2e", padx=10, pady=4)
        editor_hdr.pack(fill=tk.X)
        tk.Label(editor_hdr, text="ACTIVE RULE SPECIFICATION (DSL)", font=("Consolas", 9, "bold"), fg="#fab387", bg="#1e1e2e").pack(side=tk.LEFT)

        self.rules_text = tk.Text(
            editor_frame, bg="#181825", fg="#cdd6f4", insertbackground="#cdd6f4",
            font=("Consolas", 10), wrap=tk.NONE, relief=tk.FLAT, padx=10, pady=8
        )
        self.rules_text.pack(fill=tk.BOTH, expand=True)
        self.rules_text.insert(tk.END, DEFAULT_RULES)

        # Terminal Log Frame
        log_frame = tk.Frame(paned, bg="#181825")
        paned.add(log_frame, minsize=200, height=280)

        log_hdr = tk.Frame(log_frame, bg="#1e1e2e", padx=10, pady=4)
        log_hdr.pack(fill=tk.X)
        tk.Label(log_hdr, text="MIDDLEBOX SYSTEM TELEMETRY", font=("Consolas", 9, "bold"), fg="#89dceb", bg="#1e1e2e").pack(side=tk.LEFT)

        self.log_text = tk.Text(
            log_frame, bg="#11111b", fg="#a6adc8", font=("Consolas", 9),
            wrap=tk.WORD, relief=tk.FLAT, state=tk.DISABLED, padx=10, pady=8
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Text Tag Palette
        self.log_text.tag_config("TRAP", foreground="#f38ba8")
        self.log_text.tag_config("USER", foreground="#89dceb")
        self.log_text.tag_config("SUCCESS", foreground="#a6e3a1")
        self.log_text.tag_config("WARN", foreground="#fab387")
        self.log_text.tag_config("INFO", foreground="#6c7086")

    def _detect_interfaces(self):
        try:
            ifaces = os.listdir('/sys/class/net/')
            if "lo" in ifaces:
                ifaces.remove("lo")
                ifaces.insert(0, "lo")
        except Exception:
            ifaces = ["lo", "eth0"]
        self.iface_combo['values'] = ifaces
        self.iface_combo.current(0)

    def enqueue_log(self, msg: str):
        self.log_queue.put(msg)

    def _process_log_queue(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get_nowait()
            self.log_text.config(state=tk.NORMAL)
            
            tag = "INFO"
            if "[XDP Trap]" in msg:
                tag = "TRAP"
            elif "[User Space]" in msg:
                tag = "USER"
            elif "[+]" in msg:
                tag = "SUCCESS"
            elif "[!]" in msg:
                tag = "WARN"

            self.log_text.insert(tk.END, msg + "\n", tag)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)

        self.root.after(80, self._process_log_queue)

    def action_start(self):
        iface = self.iface_combo.get()
        rules = self.rules_text.get("1.0", tk.END)

        self.btn_compile.config(state=tk.DISABLED, bg="#313244")
        self.status_pill.config(text="● COMPILING", fg="#fab387")

        def _worker():
            try:
                self.engine.start(rules, device=iface)
                self.root.after(0, self._ui_state_running)
            except Exception as e:
                self.enqueue_log(f"[!] Compilation / Load Failure: {e}")
                self.root.after(0, lambda: messagebox.showerror("Execution Error", str(e)))
                self.root.after(0, self._ui_state_stopped)

        threading.Thread(target=_worker, daemon=True).start()

    def action_stop(self):
        self.engine.stop()
        self._ui_state_stopped()

    def action_clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _ui_state_running(self):
        self.status_pill.config(text="● RUNNING", fg="#a6e3a1")
        self.btn_compile.config(state=tk.NORMAL, bg="#89b4fa", text="Update Rules")
        self.btn_stop.config(state=tk.NORMAL, bg="#f38ba8", fg="#11111b")

    def _ui_state_stopped(self):
        self.status_pill.config(text="● INACTIVE", fg="#f38ba8")
        self.btn_compile.config(state=tk.NORMAL, bg="#a6e3a1", fg="#11111b", text="Compile & Install")
        self.btn_stop.config(state=tk.DISABLED, bg="#313244", fg="#cdd6f4")

    def on_close(self):
        if self.engine.running:
            self.engine.stop()
        self.root.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Root privileges required to load eBPF programs. Re-run with sudo.")
        sys.exit(1)

    root = tk.Tk()
    app = ModernBorBoxUI(root)
    root.mainloop()
