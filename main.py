import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import dns.resolver
import whois
import subprocess
import requests
import socket
import ssl
from datetime import datetime
from urllib.request import urlopen
import json
import os
import webbrowser
from io import StringIO
import threading
import queue

# Dark theme configuration
DARK_BG = "#23272e"
DARK_FG = "#e0e0e0"
ENTRY_BG = "#2c313c"
ENTRY_FG = "#e0e0e0"
BTN_BG = "#444857"
BTN_FG = "#e0e0e0"
HIGHLIGHT = "#3a3f4b"
TAB_BG = "#2c313c"
TEXT_BG = "#1e2227"
LOADING_COLOR = "#4a6baf"
FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")

HISTORY_FILE = "full_history.txt"
HISTORY_LIMIT = 100
HISTORY_SEPARATOR = "\n" + "=" * 60 + "\n"

class DNSAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced DNS Analyzer")
        self.root.configure(bg=DARK_BG)
        self.root.geometry("900x650")
        self.root.minsize(800, 500)
        self.history = []
        self.task_queue = queue.Queue()
        self.running = True
        self.setup_ui()
        self.setup_global_context_menu()
        self.start_task_processor()

    def start_task_processor(self):
        def process_tasks():
            while self.running:
                try:
                    task = self.task_queue.get(timeout=0.1)
                    task()
                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"Error processing task: {e}")
        self.task_thread = threading.Thread(target=process_tasks, daemon=True)
        self.task_thread.start()

    def stop_task_processor(self):
        self.running = False
        if self.task_thread.is_alive():
            self.task_thread.join()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background=DARK_BG, foreground=DARK_FG, font=FONT)
        style.configure('TNotebook', background=DARK_BG)
        style.configure('TNotebook.Tab', background=TAB_BG, foreground=DARK_FG, font=FONT_BOLD)
        style.map('TNotebook.Tab', background=[('selected', HIGHLIGHT)])
        style.configure('TFrame', background=DARK_BG)
        style.configure('TLabel', background=DARK_BG, foreground=DARK_FG, font=FONT)
        style.configure('TButton', background=BTN_BG, foreground=BTN_FG, font=FONT_BOLD)
        style.map('TButton', background=[('active', HIGHLIGHT)])
        style.configure('TEntry', fieldbackground=ENTRY_BG, foreground=ENTRY_FG)
        style.configure('TCombobox', fieldbackground=ENTRY_BG, foreground=ENTRY_FG)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=8, pady=8)

        self.dns_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dns_tab, text='DNS Analysis')
        self.setup_dns_tab()

        self.tools_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.tools_tab, text='Network Tools')
        self.setup_tools_tab()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        self.stop_task_processor()
        self.root.destroy()

    def setup_dns_tab(self):
        frame = ttk.Frame(self.dns_tab)
        frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Input section
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', pady=5)

        ttk.Label(input_frame, text="Domain/IP:").pack(side='left', padx=(0, 5))

        domain_entry_frame = ttk.Frame(input_frame)
        domain_entry_frame.pack(side='left', expand=True, fill='x')

        self.domain_entry = ttk.Entry(domain_entry_frame, width=30)
        self.domain_entry.pack(side='left', expand=True, fill='x')
        self.domain_entry.bind('<Return>', lambda e: self.run_full_analysis())
        self.create_context_menu(self.domain_entry)
        self.domain_entry.focus_set()

        self.dns_server_entry = ttk.Entry(domain_entry_frame, width=10)
        self.dns_server_entry.pack(side='left', padx=5)
        self.dns_server_entry.insert(0, "")
        self.dns_server_entry.tooltip = self.create_tooltip(self.dns_server_entry, "Custom DNS server (e.g. @8.8.8.8)")
        self.create_context_menu(self.dns_server_entry)

        ttk.Button(input_frame, text="Analyze", command=self.run_full_analysis).pack(side='left', padx=5)
        ttk.Button(input_frame, text="Open in Browser", command=self.open_in_browser).pack(side='left', padx=5)

        # History and DKIM/DMARC selector
        history_frame = ttk.Frame(frame)
        history_frame.pack(fill='x', pady=5)

        ttk.Label(history_frame, text="History:").pack(side='left')
        self.history_combo = ttk.Combobox(history_frame, values=self.history, width=15, state="readonly")
        self.history_combo.pack(side='left', padx=5)
        self.history_combo.bind('<<ComboboxSelected>>', self.select_from_history)
        self.history_combo.bind('<Button-1>', lambda e: self.history_combo.event_generate('<Down>'))
        self.create_context_menu(self.history_combo)

        ttk.Label(history_frame, text="DKIM Selector:").pack(side='left', padx=(10, 0))
        self.dkim_selector_entry = ttk.Entry(history_frame, width=15)
        self.dkim_selector_entry.pack(side='left')
        self.dkim_selector_entry.insert(0, "selector1")
        self.dkim_selector_entry.tooltip = self.create_tooltip(self.dkim_selector_entry, "DKIM selector (e.g. selector1)")
        self.create_context_menu(self.dkim_selector_entry)

        ttk.Label(history_frame, text="DMARC Selector:").pack(side='left', padx=(10, 0))
        self.dmarc_selector_entry = ttk.Entry(history_frame, width=15)
        self.dmarc_selector_entry.pack(side='left')
        self.dmarc_selector_entry.insert(0, "_dmarc")
        self.dmarc_selector_entry.tooltip = self.create_tooltip(self.dmarc_selector_entry, "DMARC selector (e.g. _dmarc)")
        self.create_context_menu(self.dmarc_selector_entry)

        # Results
        self.result_text = scrolledtext.ScrolledText(
            frame, wrap=tk.WORD, width=80, height=22,
            bg=TEXT_BG, fg=DARK_FG, insertbackground=DARK_FG, font=FONT
        )
        self.result_text.pack(fill='both', expand=True, pady=5)
        self.result_text.config(state=tk.DISABLED)
        self.create_context_menu(self.result_text)

        # Export buttons
        export_frame = ttk.Frame(frame)
        export_frame.pack(fill='x', pady=5)
        ttk.Button(export_frame, text="Export to TXT", command=lambda: self.export_results('txt')).pack(side='left')
        ttk.Button(export_frame, text="Export to JSON", command=lambda: self.export_results('json')).pack(side='left', padx=5)
        ttk.Button(export_frame, text="Show dig format", command=self.show_dig_format).pack(side='left', padx=5)
        ttk.Button(export_frame, text="Полная история", command=self.show_full_history).pack(side='left', padx=5)

    def setup_tools_tab(self):
        frame = ttk.Frame(self.tools_tab)
        frame.pack(fill='both', expand=True, padx=10, pady=10)

        tools = [
            ("Ping Tool", "Host:", "ping_entry", "Ping", self.run_ping, "ping_result"),
            ("Traceroute", "Host:", "traceroute_entry", "Traceroute", self.run_traceroute, "traceroute_result"),
            ("NSLookup", "Host/IP:", "nslookup_entry", "NSLookup", self.run_nslookup, "nslookup_result"),
            ("Curl (HTTP Headers)", "URL:", "curl_entry", "Fetch Headers", self.run_curl, "curl_result"),
        ]

        for idx, (tool_name, label_text, entry_attr, btn_text, command, result_attr) in enumerate(tools):
            lf = ttk.LabelFrame(frame, text=tool_name)
            lf.grid(row=idx, column=0, sticky='ew', pady=6, padx=0)
            lf.columnconfigure(1, weight=1)

            ttk.Label(lf, text=label_text).grid(row=0, column=0, sticky='w', padx=(4, 5), pady=2)

            entry_frame = ttk.Frame(lf)
            entry_frame.grid(row=0, column=1, sticky='ew', padx=(0, 5), pady=2)
            entry_frame.columnconfigure(0, weight=1)

            entry = ttk.Entry(entry_frame)
            entry.grid(row=0, column=0, sticky='ew')
            self.create_context_menu(entry)

            if tool_name == "Curl (HTTP Headers)":
                self.curl_keys_entry = ttk.Entry(entry_frame, width=10)
                self.curl_keys_entry.grid(row=0, column=1, padx=5)
                self.curl_keys_entry.insert(0, "-IL")
                self.curl_keys_entry.tooltip = self.create_tooltip(self.curl_keys_entry, "Curl keys (e.g. -IL)")
                self.create_context_menu(self.curl_keys_entry)
                entry.bind('<Return>', lambda e: self.run_curl())
            else:
                entry.bind('<Return>', lambda e, cmd=command: cmd())

            btn = ttk.Button(lf, text=btn_text, command=command)
            btn.grid(row=0, column=2, padx=5, pady=2)

            result = scrolledtext.ScrolledText(
                lf, wrap=tk.WORD, width=80, height=5,
                bg=TEXT_BG, fg=DARK_FG, insertbackground=DARK_FG, font=FONT
            )
            result.grid(row=1, column=0, columnspan=3, sticky='ew', padx=2, pady=(4, 2))
            result.config(state=tk.DISABLED)
            self.create_context_menu(result)

            setattr(self, entry_attr, entry)
            setattr(self, result_attr, result)

        frame.columnconfigure(0, weight=1)

    def flash_result(self, widget_name):
        result_widget = getattr(self, f"{widget_name}_result", None)
        if result_widget:
            original_bg = result_widget.cget("bg")
            result_widget.config(bg=LOADING_COLOR)
            self.root.after(100, lambda: result_widget.config(bg=original_bg))
        if widget_name == 'dns':
            original_bg = self.result_text.cget("bg")
            self.result_text.config(bg=LOADING_COLOR)
            self.root.after(100, lambda: self.result_text.config(bg=original_bg))

    def setup_global_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0, bg=ENTRY_BG, fg=DARK_FG)
        self.context_menu.add_command(label="Copy", command=lambda: self.root.focus_get().event_generate("<<Copy>>"))
        self.context_menu.add_command(label="Paste", command=lambda: self.root.focus_get().event_generate("<<Paste>>"))
        self.context_menu.add_command(label="Cut", command=lambda: self.root.focus_get().event_generate("<<Cut>>"))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Select All", command=lambda: self.root.focus_get().tag_add('sel', '1.0', 'end')
                                    if hasattr(self.root.focus_get(), 'tag_add') else self.root.focus_get().select_range(0, tk.END))
        def show_menu(e):
            widget = e.widget
            widget.focus()
            try:
                self.context_menu.tk_popup(e.x_root, e.y_root)
            finally:
                self.context_menu.grab_release()
        self.root.bind("<Button-3>", show_menu)

    def create_context_menu(self, widget):
        widget.bind("<Button-3>", self.on_right_click)
        widget.bind("<Control-c>", lambda e: widget.event_generate("<<Copy>>") or "break")
        widget.bind("<Control-v>", lambda e: widget.event_generate("<<Paste>>") or "break")
        widget.bind("<Control-x>", lambda e: widget.event_generate("<<Cut>>"))
        widget.bind("<Control-a>", self.select_all)

    def on_right_click(self, event):
        widget = event.widget
        widget.focus()
        menu = tk.Menu(widget, tearoff=0, bg=ENTRY_BG, fg=DARK_FG)
        menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
        if isinstance(widget, (tk.Entry, ttk.Entry, tk.Text, scrolledtext.ScrolledText)):
            menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
            menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
            menu.add_separator()
            menu.add_command(label="Select All", command=self.select_all)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def select_all(self, event=None):
        widget = self.root.focus_get()
        if isinstance(widget, (tk.Text, scrolledtext.ScrolledText)):
            widget.tag_add('sel', '1.0', 'end')
        elif isinstance(widget, (tk.Entry, ttk.Entry)):
            widget.select_range(0, tk.END)

    def run_in_thread(self, func, callback=None, widget_name=None):
        def thread_wrapper():
            try:
                result = func()
                if callback:
                    self.task_queue.put(lambda: callback(result))
            except Exception as e:
                self.task_queue.put(lambda: messagebox.showerror("Error", f"Operation failed: {str(e)}"))
            finally:
                if widget_name:
                    self.task_queue.put(lambda: self.flash_result(widget_name))
        threading.Thread(target=thread_wrapper, daemon=True).start()

    def run_command(self, command, entry_attr, result_attr, encoding='utf-8', widget_name=None):
        host = getattr(self, entry_attr).get().strip()
        if not host:
            messagebox.showerror("Error", "Please enter a value")
            return
        def execute():
            result = subprocess.run(
                command + [host],
                capture_output=True,
                text=True,
                encoding=encoding,
                errors='replace'
            )
            return result.stdout or result.stderr
        def update_result(output):
            result_widget = getattr(self, result_attr)
            result_widget.config(state=tk.NORMAL)
            result_widget.delete(1.0, tk.END)
            result_widget.insert(tk.END, output)
            result_widget.config(state=tk.DISABLED)
        self.run_in_thread(execute, update_result, widget_name)

    def run_ping(self):
        param = ['-n', '4'] if os.name == 'nt' else ['-c', '4']
        self.run_command(
            ['ping'] + param,
            'ping_entry',
            'ping_result',
            'cp866' if os.name == 'nt' else 'utf-8',
            'ping'
        )

    def run_nslookup(self):
        host = self.nslookup_entry.get().strip()
        if not host:
            messagebox.showerror("Error", "Please enter a host or IP")
            return
        def execute():
            if os.name == 'nt':
                result = subprocess.run(
                    ['cmd', '/c', 'chcp 65001 >nul && nslookup', host],
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
            else:
                result = subprocess.run(
                    ['nslookup', host],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
            return result.stdout or result.stderr
        def update_result(output):
            self.nslookup_result.config(state=tk.NORMAL)
            self.nslookup_result.delete(1.0, tk.END)
            self.nslookup_result.insert(tk.END, output)
            self.nslookup_result.config(state=tk.DISABLED)
        self.run_in_thread(execute, update_result, 'nslookup')

    def run_traceroute(self):
        host = self.traceroute_entry.get().strip()
        if not host:
            messagebox.showerror("Error", "Please enter a host")
            return
        def execute():
            if os.name == 'nt':
                cmd = ['tracert', host]
                encoding = 'cp866'
            else:
                cmd = ['traceroute', host]
                encoding = 'utf-8'
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding=encoding,
                errors='replace'
            )
            return result.stdout or result.stderr
        def update_result(output):
            self.traceroute_result.config(state=tk.NORMAL)
            self.traceroute_result.delete(1.0, tk.END)
            self.traceroute_result.insert(tk.END, output)
            self.traceroute_result.config(state=tk.DISABLED)
        self.run_in_thread(execute, update_result, 'traceroute')

    def run_curl(self):
        url = self.curl_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        keys = self.curl_keys_entry.get().strip()
        def execute():
            result = subprocess.run(
                ['curl'] + keys.split() + [url],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            return result.stdout or result.stderr
        def update_result(output):
            self.curl_result.config(state=tk.NORMAL)
            self.curl_result.delete(1.0, tk.END)
            self.curl_result.insert(tk.END, output)
            self.curl_result.config(state=tk.DISABLED)
        self.run_in_thread(execute, update_result, 'curl')

    def run_full_analysis(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain or IP")
            return
        self.add_to_history(domain)
        def analyze():
            output = StringIO()
            is_ip = False
            try:
                socket.inet_aton(domain)
                is_ip = True
            except socket.error:
                pass
            if not is_ip:
                output.write("=== DNS RECORDS ===\n")
                try:
                    dns_server = self.dns_server_entry.get().strip()
                    resolver = dns.resolver.Resolver()
                    if dns_server.startswith('@'):
                        nameserver = dns_server[1:]
                        resolver.nameservers = [socket.gethostbyname(nameserver)]
                    dns_records = self.get_dns_records(domain, resolver)
                    if not any(records != ["Not found"] for records in dns_records.values()):
                        output.write("DNS server not responding or domain not found\n")
                    else:
                        for rtype, values in dns_records.items():
                            output.write(f"{rtype}:\n")
                            for val in values:
                                output.write(f"  {val}\n")
                    output.write("\n=== EMAIL SECURITY RECORDS ===\n")
                    try:
                        dkim_selector = self.dkim_selector_entry.get().strip() or "selector1"
                        dkim_domain = f"{dkim_selector}._domainkey.{domain}"
                        dkim_records = resolver.resolve(dkim_domain, 'TXT')
                        output.write(f"DKIM ({dkim_selector}):\n")
                        for r in dkim_records:
                            output.write(f"  {r}\n")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        output.write(f"DKIM record not found (tried {dkim_selector}._domainkey)\n")
                    except Exception as e:
                        output.write(f"DKIM lookup error: {str(e)}\n")
                    try:
                        dmarc_selector = self.dmarc_selector_entry.get().strip() or "_dmarc"
                        dmarc_domain = f"{dmarc_selector}.{domain}"
                        dmarc_records = resolver.resolve(dmarc_domain, 'TXT')
                        output.write(f"DMARC ({dmarc_selector}):\n")
                        for r in dmarc_records:
                            output.write(f"  {r}\n")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        output.write("DMARC record not found\n")
                    except Exception as e:
                        output.write(f"DMARC lookup error: {str(e)}\n")
                except dns.resolver.NoNameservers:
                    output.write("DNS server not responding\n")
                except Exception as e:
                    output.write(f"DNS lookup error: {str(e)}\n")
            output.write("\n=== WHOIS ===\n")
            try:
                whois_info = self.get_whois_info(domain)
                output.write(whois_info)
            except Exception as e:
                output.write(f"WHOIS lookup error: {str(e)}\n")
            if not is_ip:
                output.write("\n=== HTTP STATUS ===\n")
                try:
                    http_status = self.check_http_status(domain)
                    output.write(http_status)
                except Exception as e:
                    output.write(f"HTTP check error: {str(e)}\n")
                output.write("\n=== SSL CERTIFICATE ===\n")
                try:
                    ssl_info = self.check_ssl(domain)
                    output.write(ssl_info)
                except Exception as e:
                    output.write(f"SSL check error: {str(e)}\n")
            else:
                output.write("\n=== GEOIP INFO ===\n")
                try:
                    geoip_info = self.get_ip_geo(domain)
                    output.write(geoip_info)
                except Exception as e:
                    output.write(f"GeoIP lookup error: {str(e)}\n")
            result_str = output.getvalue()
            self.save_full_history(domain, result_str)
            return result_str
        def update_result(result):
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, result)
            self.result_text.config(state=tk.DISABLED)
        self.run_in_thread(analyze, update_result, 'dns')

    def save_full_history(self, domain, result):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {domain}\n{result.strip()}{HISTORY_SEPARATOR}"
        # Read existing history
        entries = []
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    content = f.read()
                # Split by separator, remove empty
                raw_entries = content.split(HISTORY_SEPARATOR)
                entries = [e.strip() for e in raw_entries if e.strip()]
            except Exception:
                entries = []
        # Insert new entry at the top
        entries.insert(0, entry.strip())
        # Limit to HISTORY_LIMIT
        entries = entries[:HISTORY_LIMIT]
        # Write back
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                f.write(HISTORY_SEPARATOR.join(entries) + HISTORY_SEPARATOR)
        except Exception as e:
            print(f"Error saving history: {e}")

    def show_full_history(self):
        # Read and show history in a new window
        if not os.path.exists(HISTORY_FILE):
            messagebox.showinfo("История пуста", "Нет сохранённой истории.")
            return
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось прочитать историю: {e}")
            return
        win = tk.Toplevel(self.root)
        win.title("Полная история анализов")
        win.configure(bg=DARK_BG)
        win.geometry("900x600")
        win.minsize(500, 300)
        text = scrolledtext.ScrolledText(
            win, wrap=tk.WORD, width=100, height=35,
            bg=TEXT_BG, fg=DARK_FG, insertbackground=DARK_FG, font=FONT
        )
        text.pack(fill='both', expand=True, padx=10, pady=10)
        text.insert(tk.END, content)
        text.config(state=tk.NORMAL)
        self.create_context_menu(text)
        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill='x', padx=10, pady=(0,10))
        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Copied", "Вся история скопирована в буфер обмена.")
        ttk.Button(btn_frame, text="Copy to clipboard", command=copy_to_clipboard).pack(side='right')
        def clear_history():
            if messagebox.askyesno("Очистить историю", "Вы уверены, что хотите очистить всю историю?"):
                try:
                    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                        f.write("")
                    text.config(state=tk.NORMAL)
                    text.delete(1.0, tk.END)
                    text.insert(tk.END, "")
                    text.config(state=tk.DISABLED)
                    messagebox.showinfo("Готово", "История очищена.")
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось очистить историю: {e}")
        ttk.Button(btn_frame, text="Очистить историю", command=clear_history).pack(side='left')

    def get_dns_records(self, domain, resolver=None):
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        if resolver is None:
            resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                records[rtype] = ["Not found"]
            except dns.resolver.NoNameservers:
                records[rtype] = ["DNS server not responding"]
            except Exception as e:
                records[rtype] = [f"Error: {str(e)}"]
        return records

    def get_whois_info(self, domain):
        try:
            whois_data = whois.whois(domain)
            return str(whois_data)
        except Exception as e:
            return f"WHOIS Error: {e}"

    def check_http_status(self, url):
        try:
            response = requests.get(f"https://{url}", timeout=5)
            return f"HTTP Status: {response.status_code}\nFinal URL: {response.url}"
        except requests.exceptions.SSLError:
            try:
                response = requests.get(f"http://{url}", timeout=5)
                return f"HTTP Status: {response.status_code}\nFinal URL: {response.url} (no HTTPS)"
            except Exception as e:
                return f"Error: {e}"
        except Exception as e:
            return f"Error: {e}"

    def check_ssl(self, domain):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
            expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.now()).days
            return f"SSL Certificate:\nExpires: {expire_date}\nDays left: {days_left}"
        except Exception as e:
            return f"SSL Error: {e}"

    def get_ip_geo(self, ip):
        try:
            url = f"http://ip-api.com/json/{ip}?fields=country,city,isp,lat,lon"
            with urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
            return (f"Country: {data.get('country', 'N/A')}\n"
                    f"City: {data.get('city', 'N/A')}\n"
                    f"ISP: {data.get('isp', 'N/A')}\n"
                    f"Coordinates: {data.get('lat', '?')}, {data.get('lon', '?')}")
        except Exception as e:
            return f"GeoIP Error: {e}"

    def add_to_history(self, domain):
        if domain not in self.history:
            self.history.append(domain)
            if len(self.history) > 10:
                self.history.pop(0)
            self.history_combo['values'] = self.history

    def select_from_history(self, event):
        selected = self.history_combo.get()
        self.domain_entry.delete(0, tk.END)
        self.domain_entry.insert(0, selected)
        self.run_full_analysis()

    def export_results(self, format_type):
        data = self.result_text.get("1.0", tk.END)
        domain = self.domain_entry.get().strip() or "results"
        filename = f"dns_analysis_{domain}.{format_type}"
        try:
            with open(filename, "w", encoding='utf-8') as f:
                if format_type == "json":
                    json.dump({"domain": domain, "results": data}, f, indent=2, ensure_ascii=False)
                else:
                    f.write(data)
            messagebox.showinfo("Success", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def open_in_browser(self):
        domain = self.domain_entry.get().strip()
        if domain:
            try:
                webbrowser.open(f"https://{domain}")
            except Exception:
                try:
                    webbrowser.open(f"http://{domain}")
                except Exception as e:
                    messagebox.showerror("Error", f"Cannot open browser: {e}")

    def create_tooltip(self, widget, text):
        tooltip = tk.Toplevel(widget)
        tooltip.withdraw()
        tooltip.overrideredirect(True)
        label = tk.Label(tooltip, text=text, background="#333", foreground="#fff", font=("Segoe UI", 9), padx=6, pady=2)
        label.pack()
        def show(event):
            x = widget.winfo_rootx() + 20
            y = widget.winfo_rooty() + widget.winfo_height() + 2
            tooltip.geometry(f"+{x}+{y}")
            tooltip.deiconify()
        def hide(event):
            tooltip.withdraw()
        widget.bind("<Enter>", show)
        widget.bind("<Leave>", hide)
        return tooltip

    def show_dig_format(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return
        dns_server = self.dns_server_entry.get().strip()
        dig_server = ""
        if dns_server.startswith('@'):
            dig_server = dns_server + " "
        resolver = dns.resolver.Resolver()
        if dns_server.startswith('@'):
            nameserver = dns_server[1:]
            try:
                resolver.nameservers = [socket.gethostbyname(nameserver)]
            except Exception:
                pass
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        dig_outputs = {}

        # Основные записи
        for rtype in record_types:
            dig_cmd = f"dig {dig_server}{domain} {rtype} +short"
            try:
                answers = resolver.resolve(domain, rtype)
                values = [str(r).replace('"', '') for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                values = []
            except Exception:
                values = []
            if dig_cmd not in dig_outputs:
                dig_outputs[dig_cmd] = []
            if values:
                dig_outputs[dig_cmd].extend(values)
            else:
                dig_outputs[dig_cmd].append("; no answer")

        # DKIM
        dkim_selector = self.dkim_selector_entry.get().strip() or "selector1"
        dkim_domain = f"{dkim_selector}._domainkey.{domain}"
        dig_cmd = f"dig {dig_server}{dkim_domain} TXT +short"
        try:
            dkim_answers = resolver.resolve(dkim_domain, 'TXT')
            dkim_values = [str(r).replace('"', '') for r in dkim_answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dkim_values = []
        except Exception:
            dkim_values = []
        if dig_cmd not in dig_outputs:
            dig_outputs[dig_cmd] = []
        if dkim_values:
            dig_outputs[dig_cmd].extend(dkim_values)
        else:
            dig_outputs[dig_cmd].append("; no answer")

        # DMARC
        dmarc_selector = self.dmarc_selector_entry.get().strip() or "_dmarc"
        dmarc_domain = f"{dmarc_selector}.{domain}"
        dig_cmd = f"dig {dig_server}{dmarc_domain} TXT +short"
        try:
            dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
            dmarc_values = [str(r).replace('"', '') for r in dmarc_answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dmarc_values = []
        except Exception:
            dmarc_values = []
        if dig_cmd not in dig_outputs:
            dig_outputs[dig_cmd] = []
        if dmarc_values:
            dig_outputs[dig_cmd].extend(dmarc_values)
        else:
            dig_outputs[dig_cmd].append("; no answer")

        # Формируем текст для окна
        result = ""
        for cmd, vals in dig_outputs.items():
            result += f"{cmd}\n"
            for val in vals:
                result += f"{val}\n"
            result += "\n"

        # Окно с результатом
        dig_win = tk.Toplevel(self.root)
        dig_win.title("dig format output")
        dig_win.configure(bg=DARK_BG)
        dig_win.geometry("700x500")
        dig_win.minsize(400, 200)
        text = scrolledtext.ScrolledText(
            dig_win, wrap=tk.WORD, width=80, height=30,
            bg=TEXT_BG, fg=DARK_FG, insertbackground=DARK_FG, font=FONT
        )
        text.pack(fill='both', expand=True, padx=10, pady=10)
        text.insert(tk.END, result)
        text.config(state=tk.NORMAL)
        self.create_context_menu(text)
        # Кнопка копирования
        btn_frame = ttk.Frame(dig_win)
        btn_frame.pack(fill='x', padx=10, pady=(0,10))
        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Copied", "dig-formatted DNS records copied to clipboard.")
        ttk.Button(btn_frame, text="Copy to clipboard", command=copy_to_clipboard).pack(side='right')

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSAnalyzerApp(root)
    root.mainloop()
