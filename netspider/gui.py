#!/usr/bin/env python3
"""NetSpider-Max v3 GUI — tkinter-based scanner interface."""
from __future__ import annotations
import sys, os, time, json, threading, queue, logging
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from datetime import datetime
from ipaddress import ip_network

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

logger = logging.getLogger(__name__)


class ScannerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("NetSpider-Max v3 — Weak Password Scanner")
        self.root.geometry("1100x650")
        self.root.minsize(900, 500)

        self.engine = None
        self.thread = None
        self._found: list[dict] = []
        self._port_rows: set[str] = set()
        self._scan_start_time: float = 0.0

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding="10")
        top.pack(fill=tk.X)

        ttk.Label(top, text="Target CIDR:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.cidr_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(top, textvariable=self.cidr_var, width=22).grid(row=0, column=1, sticky=tk.W, padx=(0, 15))

        ttk.Label(top, text="Ports:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.ports_var = tk.StringVar(
            value="21,22,23,80,443,161,445,1433,1521,3306,3389,5432,5900,6379,"
                  "8000,8080,8443,8888,9090,9200,27017")
        ttk.Entry(top, textvariable=self.ports_var, width=55).grid(row=0, column=3, sticky=tk.W, padx=(0, 5))

        btn_row0 = ttk.Frame(top)
        btn_row0.grid(row=0, column=4, sticky=tk.W)
        ttk.Button(btn_row0, text="Common", command=self._fill_default).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row0, text="Web", command=self._fill_web).pack(side=tk.LEFT)

        ttk.Label(top, text="Threads:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(8, 0))
        self.threads_var = tk.IntVar(value=100)
        ttk.Spinbox(top, from_=5, to=500, textvariable=self.threads_var, width=8).grid(
            row=1, column=1, sticky=tk.W, padx=(0, 15), pady=(8, 0))

        ttk.Label(top, text="Timeout(s):").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(8, 0))
        self.timeout_var = tk.DoubleVar(value=2.0)
        ttk.Spinbox(top, from_=0.5, to=10.0, increment=0.5, textvariable=self.timeout_var, width=8).grid(
            row=1, column=3, sticky=tk.W, padx=(0, 15), pady=(8, 0))

        self.nmap_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Use Nmap", variable=self.nmap_var).grid(
            row=1, column=4, sticky=tk.W, pady=(8, 0))

        ttk.Label(top, text="Max creds/svc:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5), pady=(8, 0))
        self.max_creds_var = tk.StringVar(value="100")
        ttk.Combobox(top, textvariable=self.max_creds_var,
            values=["50", "100", "300", "500", "All"], width=6, state='readonly').grid(
            row=2, column=1, sticky=tk.W, padx=(0, 15), pady=(8, 0))

        self.mask_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Mask passwords", variable=self.mask_var).grid(
            row=2, column=3, sticky=tk.W, padx=(0, 10), pady=(8, 0))

        btn_frame = ttk.Frame(self.root, padding="10 5")
        btn_frame.pack(fill=tk.X)

        self.start_btn = ttk.Button(btn_frame, text="Start", command=self._start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self._stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 20))
        self.export_btn = ttk.Button(btn_frame, text="Export", command=self._export_dialog, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT)

        self._nmap_label = ttk.Label(btn_frame, text="", foreground="gray")
        self._nmap_label.pack(side=tk.RIGHT, padx=(10, 0))
        self._update_nmap_label()

        from netspider.protocols.network import HAS_PARAMIKO
        if not HAS_PARAMIKO:
            ttk.Label(btn_frame, text="[SSH: pip install paramiko]", foreground="gray").pack(side=tk.RIGHT)

        self.status_var = tk.StringVar(value="Ready — enter target CIDR and click Start")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN,
                  anchor=tk.W, padding="3 2").pack(fill=tk.X, padx=10)

        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=10, pady=(5, 0))

        tree_frame = ttk.Frame(self.root, padding="10 5")
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('ip', 'port', 'service', 'product', 'finding_type', 'username', 'password')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        col_config = [
            ('ip', 'IP', 125), ('port', 'Port', 50), ('service', 'Service', 85),
            ('product', 'Product', 110), ('finding_type', 'Risk', 85),
            ('username', 'Username', 100), ('password', 'Password', 110),
        ]
        for cid, ctext, cwidth in col_config:
            self.tree.heading(cid, text=ctext, command=lambda c=cid: self._sort_column(c))
            self.tree.column(cid, width=cwidth, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.tag_configure('port', background='#f0f0f0')
        self.tree.tag_configure('hit', background='#ffcccc')
        self.tree.tag_configure('noauth', background='#fff3cd')
        self.tree.tag_configure('default', background='#ffe0f0')

        self._sort_col = None
        self._sort_reverse = False

        self._poll_queue()

    def _fill_default(self):
        self.ports_var.set(
            "21,22,23,80,443,161,445,554,1080,1433,1521,3306,3389,5432,5900,6379,"
            "8000,8008,8080,8443,8888,9090,9200,27017")

    def _fill_web(self):
        self.ports_var.set("80,443,1080,8000,8008,8080,8443,8888,9090")

    def _sort_column(self, col):
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col; self._sort_reverse = False
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        if col == 'port':
            items.sort(key=lambda x: int(x[0]) if x[0].lstrip('-').isdigit() else 0, reverse=self._sort_reverse)
        else:
            items.sort(key=lambda x: x[0].lower(), reverse=self._sort_reverse)
        for idx, (_, k) in enumerate(items):
            self.tree.move(k, '', idx)

    def _update_nmap_label(self):
        from netspider.discovery.nmap import check_nmap
        ok, ver = check_nmap()
        if ok:
            self._nmap_label.config(text=f"[Nmap: {ver[:30]}]", foreground="green")
        else:
            self._nmap_label.config(text="[Nmap: unavailable]", foreground="orange")

    def _parse_ports(self):
        ports = []
        for p in self.ports_var.get().split(','):
            p = p.strip()
            if p.isdigit():
                ports.append(int(p))
            elif '-' in p:
                a, b = p.split('-', 1)
                ports.extend(range(int(a.strip()), int(b.strip()) + 1))
        return sorted(set(p for p in ports if 1 <= p <= 65535))

    def _start_scan(self):
        cidr = self.cidr_var.get().strip()
        ports = self._parse_ports()
        if not cidr or not ports:
            messagebox.showwarning("Input Error", "Enter valid CIDR and ports")
            return
        try:
            net = ip_network(cidr, strict=False)
        except ValueError as e:
            messagebox.showerror("CIDR Error", f"Invalid CIDR: {e}")
            return
        host_count = net.num_addresses - 2
        if host_count > 65536:
            if not messagebox.askyesno("Large Range", f"Scan {host_count} IPs. Continue?"):
                return

        for item in self.tree.get_children():
            self.tree.delete(item)
        self._found.clear()
        self._port_rows.clear()
        self.progress['mode'] = 'indeterminate'
        self.progress.start(10)

        max_creds_str = self.max_creds_var.get()
        max_creds = 999999 if max_creds_str == "All" else int(max_creds_str)

        from netspider.engine.scheduler import ScanEngineV3
        self.engine = ScanEngineV3(
            target_cidr=cidr, ports=ports,
            threads=self.threads_var.get(),
            timeout=self.timeout_var.get(),
            use_nmap=self.nmap_var.get(),
            max_creds_per_svc=max_creds,
        )

        self._scan_start_time = time.time()
        self.status_var.set("Scanning...")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.DISABLED)

        self.thread = threading.Thread(target=self.engine.run, daemon=True)
        self.thread.start()

    def _stop_scan(self):
        if self.engine:
            self.engine.stop()
        self.status_var.set("Stopping...")

    def _scan_done(self):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.NORMAL if self._found else tk.DISABLED)
        self.progress.stop()
        self.progress['mode'] = 'determinate'
        self.progress['value'] = self.progress['maximum']

    def _poll_queue(self):
        if self.engine:
            try:
                while True:
                    mtype, payload = self.engine.result_queue.get_nowait()
                    if mtype == 'port':
                        key = f"{payload['ip']}:{payload['port']}"
                        if key not in self._port_rows:
                            self._port_rows.add(key)
                            product = payload.get('product', '') or ''
                            if payload.get('version', ''):
                                product += ' ' + payload['version']
                            self.tree.insert('', tk.END,
                                values=(payload['ip'], payload['port'],
                                        payload['service'], product.strip(), '', '', ''),
                                tags=('port',))
                    elif mtype == 'info_port':
                        self.tree.insert('', tk.END,
                            values=(payload['ip'], payload['port'],
                                    payload['service'], '', '(manual)', '', ''),
                            tags=('port',))
                    elif mtype == 'found':
                        ft = payload.get('finding_type', 'weak_password')
                        self._found.append(payload)
                        tag = {'weak_password': 'hit', 'no_auth': 'noauth',
                               'default_password': 'default'}.get(ft, 'hit')
                        self.tree.insert('', tk.END,
                            values=(payload['ip'], payload['port'],
                                    payload['service'], '',
                                    ft, payload['username'], payload['password']),
                            tags=(tag,))
            except queue.Empty:
                pass

            try:
                while True:
                    msg = self.engine.status_queue.get_nowait()
                    mtype = msg[0]
                    if mtype in ('info', 'progress'):
                        self.status_var.set(msg[1])
                    elif mtype == 'phase2_start':
                        total = msg[1]
                        self.progress['mode'] = 'determinate'
                        self.progress['maximum'] = total
                        self.progress['value'] = 0
                    elif mtype == 'progress_val':
                        self.status_var.set(msg[1])
                        self.progress['value'] = msg[2]
                    elif mtype == 'done':
                        self._scan_done()
                        elapsed = time.time() - self._scan_start_time
                        self.status_var.set(f"Done | {elapsed:.0f}s | Hits: {len(self._found)}")
            except queue.Empty:
                pass

        self.root.after(250, self._poll_queue)

    def _export_dialog(self):
        if not self._found:
            messagebox.showinfo("No Data", "No results to export")
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="HTML", command=lambda: self._export('html'))
        menu.add_command(label="CSV", command=lambda: self._export('csv'))
        menu.add_command(label="JSON", command=lambda: self._export('json'))
        menu.add_command(label="TXT", command=lambda: self._export('txt'))
        menu.add_command(label="All Formats", command=self._export_all)
        menu.post(self.export_btn.winfo_rootx(), self.export_btn.winfo_rooty() + 25)

    def _mask_pwd(self, pwd):
        if not self.mask_var.get(): return pwd
        if not pwd: return ''
        if len(pwd) == 1: return '*'
        return pwd[0] + '*' * (len(pwd) - 2) + pwd[-1]

    def _build_export_data(self):
        return {
            'target': self.cidr_var.get(), 'ports': self.ports_var.get(),
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'stats': self.engine.stats if self.engine else {},
            'found': self._found,
            'open_ports': [{'ip': k.split(':')[0], 'port': k.split(':')[1]} for k in self._port_rows],
        }

    def _export(self, fmt, filepath=None):
        ext_map = {'html': '.html', 'csv': '.csv', 'json': '.json', 'txt': '.txt'}
        if filepath:
            path = filepath
        else:
            path = filedialog.asksaveasfilename(
                title=f"Export {fmt.upper()}",
                defaultextension=ext_map[fmt],
                filetypes=[(f"{fmt.upper()} files", f"*{ext_map[fmt]}")])
            if not path: return

        data = self._build_export_data()

        if fmt == 'json':
            from netspider.output.exporters import export_json
            export_json(data, path)
        elif fmt == 'csv':
            from netspider.output.exporters import export_csv
            export_csv(self._found, path, self._mask_pwd)
        elif fmt == 'txt':
            from netspider.output.exporters import export_txt
            export_txt(self._found, path, {'target': data['target'], 'ports': data['ports']}, self._mask_pwd)
        elif fmt == 'html':
            from netspider.output.exporters import export_html
            export_html(data, self._found, path, self._mask_pwd)

        if not filepath:
            messagebox.showinfo("Export OK", f"Exported to:\n{path}")

    def _export_all(self):
        folder = filedialog.askdirectory(title="Select export directory")
        if not folder: return
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = str(Path(folder) / f"scan_{ts}")
        for fmt in ('html', 'csv', 'json', 'txt'):
            self._export(fmt, filepath=base + {'html':'.html','csv':'.csv','json':'.json','txt':'.txt'}[fmt])
        messagebox.showinfo("Export OK", f"Exported all 4 formats to:\n{folder}")

    def run(self):
        self.root.mainloop()
