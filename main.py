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

# Конфигурация тёмной темы
DARK_BG = "#23272e"
DARK_FG = "#e0e0e0"
ENTRY_BG = "#2c313c"
ENTRY_FG = "#e0e0e0"
BTN_BG = "#444857"
BTN_FG = "#e0e0e0"
HIGHLIGHT = "#3a3f4b"
TAB_BG = "#2c313c"
TEXT_BG = "#1e2227"

class DNSAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced DNS Analyzer")
        self.root.configure(bg=DARK_BG)
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
        
        style.configure('.', background=DARK_BG, foreground=DARK_FG)
        style.configure('TNotebook', background=DARK_BG)
        style.configure('TNotebook.Tab', background=TAB_BG, foreground=DARK_FG)
        style.map('TNotebook.Tab', background=[('selected', HIGHLIGHT)])
        style.configure('TFrame', background=DARK_BG)
        style.configure('TLabel', background=DARK_BG, foreground=DARK_FG)
        style.configure('TButton', background=BTN_BG, foreground=BTN_FG)
        style.map('TButton', background=[('active', HIGHLIGHT)])
        style.configure('TEntry', fieldbackground=ENTRY_BG, foreground=ENTRY_FG)
        style.configure('TCombobox', fieldbackground=ENTRY_BG, foreground=ENTRY_FG)
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
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
        
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', pady=5)
        
        ttk.Label(input_frame, text="Domain/IP:").pack(side='left')
        self.domain_entry = ttk.Entry(input_frame, width=40)
        self.domain_entry.pack(side='left', expand=True, fill='x', padx=5)
        self.domain_entry.bind('<Return>', lambda e: self.run_full_analysis())
        self.create_context_menu(self.domain_entry)
        
        ttk.Button(input_frame, text="Analyze", command=self.run_full_analysis).pack(side='left')
        ttk.Button(input_frame, text="Open in Browser", command=self.open_in_browser).pack(side='left', padx=5)
        
        history_frame = ttk.Frame(frame)
        history_frame.pack(fill='x', pady=5)
        
        ttk.Label(history_frame, text="History:").pack(side='left')
        self.history_combo = ttk.Combobox(history_frame, values=self.history, width=30)
        self.history_combo.pack(side='left', expand=True, fill='x', padx=5)
        self.history_combo.bind('<<ComboboxSelected>>', self.select_from_history)
        self.create_context_menu(self.history_combo)
        
        self.result_text = scrolledtext.ScrolledText(
            frame, wrap=tk.WORD, width=80, height=20,
            bg=TEXT_BG, fg=DARK_FG, insertbackground=DARK_FG
        )
        self.result_text.pack(fill='both', expand=True)
        self.create_context_menu(self.result_text)
        
        export_frame = ttk.Frame(frame)
        export_frame.pack(fill='x', pady=5)
        
        ttk.Button(export_frame, text="Export to TXT", command=lambda: self.export_results('txt')).pack(side='left')
        ttk.Button(export_frame, text="Export to JSON", command=lambda: self.export_results('json')).pack(side='left', padx=5)
    
    def setup_tools_tab(self):
        self.tools_paned = tk.PanedWindow(self.tools_tab, orient=tk.VERTICAL, bg=DARK_BG, sashrelief=tk.RAISED, sashwidth=5)
        self.tools_paned.pack(fill='both', expand=True)
        
        tools = [
            ("Ping Tool", "Host:", self.run_ping),
            ("Traceroute", "Destination:", self.run_traceroute),
            ("NSLookup", "Host/IP:", self.run_nslookup),
            ("Curl (HTTP Headers)", "URL:", self.run_curl)
        ]
        
        for tool_name, label_text, command in tools:
            frame = ttk.LabelFrame(self.tools_paned, text=tool_name)
            
            ttk.Label(frame, text=label_text).pack(side='left')
            entry = ttk.Entry(frame, width=30)
            entry.pack(side='left', expand=True, fill='x', padx=5)
            entry.bind('<Return>', lambda e, cmd=command: cmd())
            self.create_context_menu(entry)
            
            btn_text = tool_name.split()[0] if tool_name != "Curl (HTTP Headers)" else "Fetch Headers"
            ttk.Button(frame, text=btn_text, command=command).pack(side='left')
            
            result = scrolledtext.ScrolledText(
                frame, wrap=tk.WORD, width=80, height=5,
                bg=TEXT_BG, fg=DARK_FG, insertbackground=DARK_FG
            )
            result.pack(fill='both', expand=True)
            self.create_context_menu(result)
            
            setattr(self, f"{tool_name.split()[0].lower()}_entry", entry)
            setattr(self, f"{tool_name.split()[0].lower()}_result", result)
            
            self.tools_paned.add(frame)
    
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
        widget.bind("<Control-c>", lambda e: widget.event_generate("<<Copy>>"))
        widget.bind("<Control-v>", lambda e: widget.event_generate("<<Paste>>"))
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
    
    def run_in_thread(self, func, callback=None):
        def thread_wrapper():
            try:
                result = func()
                if callback:
                    self.task_queue.put(lambda: callback(result))
            except Exception as e:
                self.task_queue.put(lambda: messagebox.showerror("Error", f"Operation failed: {str(e)}"))
        
        threading.Thread(target=thread_wrapper, daemon=True).start()
    
    def run_command(self, command, entry_attr, result_attr, encoding='utf-8'):
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
        
        self.run_in_thread(execute, update_result)
    
    def run_ping(self):
        param = ['-n', '4'] if os.name == 'nt' else ['-c', '4']
        self.run_command(
            ['ping'] + param,
            'ping_entry',
            'ping_result',
            'cp866' if os.name == 'nt' else 'utf-8'
        )
    
    def run_traceroute(self):
        command = ['tracert', '-d'] if os.name == 'nt' else ['traceroute']
        self.run_command(
            command,
            'trace_entry',
            'trace_result',
            'cp866' if os.name == 'nt' else 'utf-8'
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
        
        self.run_in_thread(execute, update_result)
    
    def run_curl(self):
        url = self.curl_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        
        def execute():
            result = subprocess.run(
                ['curl', '-IL', url],
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
        
        self.run_in_thread(execute, update_result)
    
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
            
            # DNS Records
            if not is_ip:
                output.write("=== DNS RECORDS ===\n")
                try:
                    dns_records = self.get_dns_records(domain)
                    if not any(records != ["Not found"] for records in dns_records.values()):
                        output.write("DNS server not responding or domain not found\n")
                    else:
                        for rtype, values in dns_records.items():
                            output.write(f"{rtype}:\n")
                            for val in values:
                                output.write(f"  {val}\n")
                except dns.resolver.NoNameservers:
                    output.write("DNS server not responding\n")
                except Exception as e:
                    output.write(f"DNS lookup error: {str(e)}\n")
            
            # WHOIS
            output.write("\n=== WHOIS ===\n")
            try:
                whois_info = self.get_whois_info(domain)
                output.write(whois_info)
            except Exception as e:
                output.write(f"WHOIS lookup error: {str(e)}\n")
            
            # HTTP/SSL or GeoIP
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
            
            return output.getvalue()
        
        def update_result(result):
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, result)
            self.result_text.config(state=tk.DISABLED)
        
        self.run_in_thread(analyze, update_result)
    
    def get_dns_records(self, domain):
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
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

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSAnalyzerApp(root)
    root.mainloop()
