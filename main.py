import sys
import os
import socket
import ssl
import subprocess
import json
import threading
import queue
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QFileDialog,
    QMessageBox, QSplitter, QFrame, QScrollArea, QPlainTextEdit, QAction, QMenu,
    QGridLayout, QSizePolicy, QDialog
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject

import dns.resolver
import whois
import requests
from urllib.request import urlopen

HISTORY_FILE = "full_history.txt"
HISTORY_LIMIT = 100
HISTORY_SEPARATOR = "\n" + "=" * 60 + "\n"

DARK_BG = "#23272e"
DARK_FG = "#e0e0e0"
ENTRY_BG = "#f3f3f3"
ENTRY_FG = "#252525"
BTN_BG = "#444857"
BTN_FG = "#b9b9b9"
BTN_PRESSED_BG = "#2a2d36"
HIGHLIGHT = "#3a3f4b"
TAB_BG = "#2c313c"
TEXT_BG = "#1e2227"
LOADING_COLOR = "#4a6baf"
FONT = "Segoe UI"

class ResultEvent(QObject):
    resultReady = pyqtSignal(str, object, object)  # result, widget, button

class DNSAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced DNS Analyzer (Qt)")
        self.setMinimumSize(900, 650)
        self.setStyleSheet(f"""
            QWidget {{ background: {DARK_BG}; color: {DARK_FG}; font-family: {FONT}; font-size: 10pt; }}
            QLineEdit, QComboBox {{ background: {ENTRY_BG}; color: {ENTRY_FG}; border: 1px solid {HIGHLIGHT}; }}
            QPushButton {{
                background: {BTN_BG}; color: {BTN_FG}; border: 1px solid {HIGHLIGHT}; padding: 4px 10px;
            }}
            QPushButton:pressed {{
                background: {BTN_PRESSED_BG};
            }}
            QTextEdit, QPlainTextEdit {{ background: {TEXT_BG}; color: {DARK_FG}; border: 1px solid {HIGHLIGHT}; }}
            QTabWidget::pane {{ border: 1px solid {HIGHLIGHT}; }}
            QTabBar::tab {{ background: {TAB_BG}; color: {DARK_FG}; padding: 8px; }}
            QTabBar::tab:selected {{ background: {HIGHLIGHT}; }}
        """)
        self.history = []
        self.task_queue = queue.Queue()
        self.running = True
        self.result_event = ResultEvent()
        self.result_event.resultReady.connect(self._handle_result)
        self.history_window = None
        self._setup_ui()
        self._start_task_processor()

    def closeEvent(self, event):
        self.running = False
        event.accept()

    def _setup_ui(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.dns_tab = QWidget()
        self.tools_tab = QWidget()
        self.tabs.addTab(self.dns_tab, "DNS Analysis")
        self.tabs.addTab(self.tools_tab, "Network Tools")
        self._setup_dns_tab()
        self._setup_tools_tab()
        self._setup_menu()

    def _setup_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        export_txt = QAction("Export to TXT", self)
        export_txt.triggered.connect(lambda: self.export_results('txt'))
        export_json = QAction("Export to JSON", self)
        export_json.triggered.connect(lambda: self.export_results('json'))
        file_menu.addAction(export_txt)
        file_menu.addAction(export_json)
        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def _setup_dns_tab(self):
        layout = QVBoxLayout()
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Domain/IP:"))
        self.domain_entry = QLineEdit()
        self.domain_entry.setPlaceholderText("example.com or 8.8.8.8")
        input_layout.addWidget(self.domain_entry)
        self.dns_server_entry = QLineEdit()
        self.dns_server_entry.setPlaceholderText("@8.8.8.8")
        self.dns_server_entry.setFixedWidth(100)
        input_layout.addWidget(self.dns_server_entry)
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.run_full_analysis)
        input_layout.addWidget(self.analyze_btn)
        self.open_browser_btn = QPushButton("Open in Browser")
        self.open_browser_btn.clicked.connect(self.open_in_browser)
        input_layout.addWidget(self.open_browser_btn)
        layout.addLayout(input_layout)

        self.domain_entry.returnPressed.connect(self.analyze_btn.animateClick)
        self.dns_server_entry.returnPressed.connect(self.analyze_btn.animateClick)

        hist_layout = QHBoxLayout()
        hist_layout.addWidget(QLabel("History:"))
        self.history_combo = QComboBox()
        self.history_combo.setEditable(False)
        self.history_combo.activated.connect(self.select_from_history)
        hist_layout.addWidget(self.history_combo)
        hist_layout.addWidget(QLabel("DKIM Selector:"))
        self.dkim_selector_entry = QLineEdit("selector1")
        self.dkim_selector_entry.setFixedWidth(100)
        hist_layout.addWidget(self.dkim_selector_entry)
        hist_layout.addWidget(QLabel("DMARC Selector:"))
        self.dmarc_selector_entry = QLineEdit("_dmarc")
        self.dmarc_selector_entry.setFixedWidth(100)
        hist_layout.addWidget(self.dmarc_selector_entry)
        layout.addLayout(hist_layout)

        self.result_text = QPlainTextEdit()
        self.result_text.setReadOnly(False)
        layout.addWidget(self.result_text)

        export_layout = QHBoxLayout()
        export_txt_btn = QPushButton("Export to TXT")
        export_txt_btn.clicked.connect(lambda: self.export_results('txt'))
        export_json_btn = QPushButton("Export to JSON")
        export_json_btn.clicked.connect(lambda: self.export_results('json'))
        dig_btn = QPushButton("Show dig format")
        dig_btn.clicked.connect(self.show_dig_format)
        full_hist_btn = QPushButton("Полная история")
        full_hist_btn.clicked.connect(self.show_full_history)
        export_layout.addWidget(export_txt_btn)
        export_layout.addWidget(export_json_btn)
        export_layout.addWidget(dig_btn)
        export_layout.addWidget(full_hist_btn)
        export_layout.addStretch()
        layout.addLayout(export_layout)

        self.dns_tab.setLayout(layout)

    def _setup_tools_tab(self):
        grid = QGridLayout()
        grid.setSpacing(10)

        curl_widget = QWidget()
        curl_layout = QVBoxLayout()
        curl_label = QLabel("Curl (HTTP Headers)")
        curl_layout.addWidget(curl_label)
        curl_input_layout = QHBoxLayout()
        self.curl_entry = QLineEdit()
        self.curl_entry.setPlaceholderText("URL")
        self.curl_keys_entry = QLineEdit("-IL")
        self.curl_keys_entry.setFixedWidth(60)
        curl_input_layout.addWidget(self.curl_entry)
        curl_input_layout.addWidget(self.curl_keys_entry)
        self.curl_btn = QPushButton("Fetch Headers")
        self.curl_btn.clicked.connect(self.run_curl)
        curl_input_layout.addWidget(self.curl_btn)
        curl_layout.addLayout(curl_input_layout)
        self.curl_result = QPlainTextEdit()
        self.curl_result.setReadOnly(True)
        curl_layout.addWidget(self.curl_result)
        curl_widget.setLayout(curl_layout)

        self.curl_entry.returnPressed.connect(self.curl_btn.animateClick)
        self.curl_keys_entry.returnPressed.connect(self.curl_btn.animateClick)

        nslookup_widget = QWidget()
        nslookup_layout = QVBoxLayout()
        nslookup_label = QLabel("NSLookup")
        nslookup_layout.addWidget(nslookup_label)
        nslookup_input_layout = QHBoxLayout()
        self.nslookup_entry = QLineEdit()
        self.nslookup_entry.setPlaceholderText("Host/IP")
        nslookup_input_layout.addWidget(self.nslookup_entry)
        self.nslookup_btn = QPushButton("NSLookup")
        self.nslookup_btn.clicked.connect(self.run_nslookup)
        nslookup_input_layout.addWidget(self.nslookup_btn)
        nslookup_layout.addLayout(nslookup_input_layout)
        self.nslookup_result = QPlainTextEdit()
        self.nslookup_result.setReadOnly(True)
        nslookup_layout.addWidget(self.nslookup_result)
        nslookup_widget.setLayout(nslookup_layout)

        self.nslookup_entry.returnPressed.connect(self.nslookup_btn.animateClick)

        ping_widget = QWidget()
        ping_layout = QVBoxLayout()
        ping_label = QLabel("Ping Tool")
        ping_layout.addWidget(ping_label)
        ping_input_layout = QHBoxLayout()
        self.ping_entry = QLineEdit()
        self.ping_entry.setPlaceholderText("Host")
        ping_input_layout.addWidget(self.ping_entry)
        self.ping_btn = QPushButton("Ping")
        self.ping_btn.clicked.connect(self.run_ping)
        ping_input_layout.addWidget(self.ping_btn)
        ping_layout.addLayout(ping_input_layout)
        self.ping_result = QPlainTextEdit()
        self.ping_result.setReadOnly(True)
        ping_layout.addWidget(self.ping_result)
        ping_widget.setLayout(ping_layout)

        self.ping_entry.returnPressed.connect(self.ping_btn.animateClick)

        traceroute_widget = QWidget()
        traceroute_layout = QVBoxLayout()
        traceroute_label = QLabel("Traceroute")
        traceroute_layout.addWidget(traceroute_label)
        traceroute_input_layout = QHBoxLayout()
        self.traceroute_entry = QLineEdit()
        self.traceroute_entry.setPlaceholderText("Host")
        traceroute_input_layout.addWidget(self.traceroute_entry)
        self.traceroute_btn = QPushButton("Traceroute")
        self.traceroute_btn.clicked.connect(self.run_traceroute)
        traceroute_input_layout.addWidget(self.traceroute_btn)
        traceroute_layout.addLayout(traceroute_input_layout)
        self.traceroute_result = QPlainTextEdit()
        self.traceroute_result.setReadOnly(True)
        traceroute_layout.addWidget(self.traceroute_result)
        traceroute_widget.setLayout(traceroute_layout)

        self.traceroute_entry.returnPressed.connect(self.traceroute_btn.animateClick)

        grid.addWidget(nslookup_widget, 0, 0)
        grid.addWidget(curl_widget, 0, 1)
        grid.addWidget(ping_widget, 1, 0)
        grid.addWidget(traceroute_widget, 1, 1)

        for i in range(2):
            grid.setRowStretch(i, 1)
            grid.setColumnStretch(i, 1)

        self.tools_tab.setLayout(grid)

    def _start_task_processor(self):
        def process_tasks():
            while self.running:
                try:
                    func, widget, button = self.task_queue.get(timeout=0.1)
                    # Show loading in widget and button (in main thread via signal)
                    self.result_event.resultReady.emit("Loading...", widget, button)
                    result = func()
                    self.result_event.resultReady.emit(result, widget, button)
                except queue.Empty:
                    continue
                except Exception as e:
                    self.result_event.resultReady.emit(f"Error: {e}", widget, button)
        threading.Thread(target=process_tasks, daemon=True).start()

    def _handle_result(self, result, widget, button):
        # This runs in the main thread!
        if isinstance(widget, (QPlainTextEdit, QTextEdit)):
            widget.setPlainText(str(result))
        if button is not None:
            button.setEnabled(True)
            orig_text = getattr(button, "_orig_text", None)
            if orig_text:
                button.setText(orig_text)
            else:
                button.setText(button.text().replace("Working...", "").strip() or "Run")

    def run_in_thread(self, func, widget=None, button=None):
        if button is not None and not hasattr(button, "_orig_text"):
            button._orig_text = button.text()
        if button is not None:
            button.setEnabled(False)
            button.setText("Working...")
        self.task_queue.put((func, widget, button))

    # --- DNS Analysis ---
    def run_full_analysis(self):
        domain = self.domain_entry.text().strip()
        if not domain:
            QMessageBox.critical(self, "Error", "Please enter a domain or IP")
            return
        self.add_to_history(domain)
        def analyze():
            output = []
            is_ip = False
            try:
                socket.inet_aton(domain)
                is_ip = True
            except socket.error:
                pass
            if not is_ip:
                output.append("=== DNS RECORDS ===")
                try:
                    dns_server = self.dns_server_entry.text().strip()
                    resolver = dns.resolver.Resolver()
                    if dns_server.startswith('@'):
                        nameserver = dns_server[1:]
                        resolver.nameservers = [socket.gethostbyname(nameserver)]
                    dns_records = self.get_dns_records(domain, resolver)
                    if not any(records != ["Not found"] for records in dns_records.values()):
                        output.append("DNS server not responding or domain not found")
                    else:
                        for rtype, values in dns_records.items():
                            output.append(f"{rtype}:")
                            for val in values:
                                output.append(f"  {val}")
                    output.append("\n=== EMAIL SECURITY RECORDS ===")
                    try:
                        dkim_selector = self.dkim_selector_entry.text().strip() or "selector1"
                        dkim_domain = f"{dkim_selector}._domainkey.{domain}"
                        dkim_records = resolver.resolve(dkim_domain, 'TXT')
                        output.append(f"DKIM ({dkim_selector}):")
                        for r in dkim_records:
                            output.append(f"  {r}")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        output.append(f"DKIM record not found (tried {dkim_selector}._domainkey)")
                    except Exception as e:
                        output.append(f"DKIM lookup error: {str(e)}")
                    try:
                        dmarc_selector = self.dmarc_selector_entry.text().strip() or "_dmarc"
                        dmarc_domain = f"{dmarc_selector}.{domain}"
                        dmarc_records = resolver.resolve(dmarc_domain, 'TXT')
                        output.append(f"DMARC ({dmarc_selector}):")
                        for r in dmarc_records:
                            output.append(f"  {r}")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        output.append("DMARC record not found")
                    except Exception as e:
                        output.append(f"DMARC lookup error: {str(e)}")
                except dns.resolver.NoNameservers:
                    output.append("DNS server not responding")
                except Exception as e:
                    output.append(f"DNS lookup error: {str(e)}")
            output.append("\n=== WHOIS ===")
            try:
                whois_info = self.get_whois_info(domain)
                output.append(whois_info)
            except Exception as e:
                output.append(f"WHOIS lookup error: {str(e)}")
            if not is_ip:
                output.append("\n=== HTTP STATUS ===")
                try:
                    http_status = self.check_http_status(domain)
                    output.append(http_status)
                except Exception as e:
                    output.append(f"HTTP check error: {str(e)}")
                output.append("\n=== SSL CERTIFICATE ===")
                try:
                    ssl_info = self.check_ssl(domain)
                    output.append(ssl_info)
                except Exception as e:
                    output.append(f"SSL check error: {str(e)}")
            else:
                output.append("\n=== GEOIP INFO ===")
                try:
                    geoip_info = self.get_ip_geo(domain)
                    output.append(geoip_info)
                except Exception as e:
                    output.append(f"GeoIP lookup error: {str(e)}")
            result_str = "\n".join(output)
            self.save_full_history(domain, result_str)
            return result_str
        self.run_in_thread(analyze, self.result_text, button=self.analyze_btn)

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

    def save_full_history(self, domain, result):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {domain}\n{result.strip()}{HISTORY_SEPARATOR}"
        entries = []
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    content = f.read()
                raw_entries = content.split(HISTORY_SEPARATOR)
                entries = [e.strip() for e in raw_entries if e.strip()]
            except Exception:
                entries = []
        entries.insert(0, entry.strip())
        entries = entries[:HISTORY_LIMIT]
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                f.write(HISTORY_SEPARATOR.join(entries) + HISTORY_SEPARATOR)
        except Exception as e:
            print(f"Error saving history: {e}")

    def show_full_history(self):
        if not os.path.exists(HISTORY_FILE):
            QMessageBox.information(self, "История пуста", "Нет сохранённой истории.")
            return
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать историю: {e}")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Полная история анализов")
        dlg.setMinimumSize(900, 600)
        layout = QVBoxLayout()

        # --- Search bar ---
        search_layout = QHBoxLayout()
        search_label = QLabel("Поиск:")
        search_edit = QLineEdit()
        search_edit.setPlaceholderText("Введите строку для поиска...")
        search_btn = QPushButton("Найти")
        search_layout.addWidget(search_label)
        search_layout.addWidget(search_edit)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)

        text = QPlainTextEdit()
        text.setPlainText(content)
        text.setReadOnly(True)
        layout.addWidget(text)

        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy to clipboard")
        clear_btn = QPushButton("Очистить историю")
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(copy_btn)
        layout.addLayout(btn_layout)
        dlg.setLayout(layout)

        def copy_to_clipboard():
            QApplication.clipboard().setText(content)
            QMessageBox.information(self, "Copied", "Вся история скопирована в буфер обмена.")

        def clear_history():
            if QMessageBox.question(self, "Очистить историю", "Вы уверены, что хотите очистить всю историю?") == QMessageBox.Yes:
                try:
                    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                        f.write("")
                    text.setPlainText("")
                    QMessageBox.information(self, "Готово", "История очищена.")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось очистить историю: {e}")

        copy_btn.clicked.connect(copy_to_clipboard)
        clear_btn.clicked.connect(clear_history)

        # --- Search logic ---
        def do_search():
            query = search_edit.text()
            if not query:
                return
            doc = text.document()
            cursor = text.textCursor()
            # Start search from current position + 1 char
            start_pos = cursor.position() + 1 if cursor.hasSelection() else 0
            found = doc.find(query, start_pos)
            if not found.isNull():
                text.setTextCursor(found)
                text.centerCursor()
            else:
                # Try from the top if not found after current
                found = doc.find(query, 0)
                if not found.isNull():
                    text.setTextCursor(found)
                    text.centerCursor()
                else:
                    QMessageBox.information(dlg, "Поиск", "Строка не найдена.")

        search_btn.clicked.connect(do_search)
        search_edit.returnPressed.connect(do_search)

        # --- Ctrl+F shortcut ---
        def focus_search():
            search_edit.setFocus()
            search_edit.selectAll()
        search_shortcut = QAction(dlg)
        search_shortcut.setShortcut("Ctrl+F")
        search_shortcut.triggered.connect(focus_search)
        dlg.addAction(search_shortcut)

        self.history_window = dlg
        dlg.exec_()

    def add_to_history(self, domain):
        if domain not in self.history:
            self.history.append(domain)
            if len(self.history) > 10:
                self.history.pop(0)
            self.history_combo.clear()
            self.history_combo.addItems(self.history)

    def select_from_history(self, idx):
        selected = self.history_combo.currentText()
        self.domain_entry.setText(selected)
        self.run_full_analysis()

    def export_results(self, format_type):
        data = self.result_text.toPlainText()
        domain = self.domain_entry.text().strip() or "results"
        filename = f"dns_analysis_{domain}.{format_type}"
        try:
            if format_type == "json":
                with open(filename, "w", encoding='utf-8') as f:
                    json.dump({"domain": domain, "results": data}, f, indent=2, ensure_ascii=False)
            else:
                with open(filename, "w", encoding='utf-8') as f:
                    f.write(data)
            QMessageBox.information(self, "Success", f"Results exported to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {e}")

    def open_in_browser(self):
        import webbrowser
        domain = self.domain_entry.text().strip()
        if domain:
            try:
                webbrowser.open(f"https://{domain}")
            except Exception:
                try:
                    webbrowser.open(f"http://{domain}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Cannot open browser: {e}")

    def show_dig_format(self):
        domain = self.domain_entry.text().strip()
        if not domain:
            QMessageBox.critical(self, "Error", "Please enter a domain")
            return
        dns_server = self.dns_server_entry.text().strip()
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
        dkim_selector = self.dkim_selector_entry.text().strip() or "selector1"
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
        dmarc_selector = self.dmarc_selector_entry.text().strip() or "_dmarc"
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
        result = ""
        for cmd, vals in dig_outputs.items():
            result += f"{cmd}\n"
            for val in vals:
                result += f"{val}\n"
            result += "\n"

        dlg = QDialog(self)
        dlg.setWindowTitle("dig format output")
        dlg.setMinimumSize(700, 500)
        layout = QVBoxLayout()
        text = QPlainTextEdit()
        text.setPlainText(result)
        text.setReadOnly(True)
        layout.addWidget(text)
        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy to clipboard")
        btn_layout.addStretch()
        btn_layout.addWidget(copy_btn)
        layout.addLayout(btn_layout)
        dlg.setLayout(layout)
        def copy_to_clipboard():
            QApplication.clipboard().setText(result)
            QMessageBox.information(self, "Copied", "dig-formatted DNS records copied to clipboard.")
        copy_btn.clicked.connect(copy_to_clipboard)
        dlg.exec_()

    # --- Network Tools ---
    def run_command(self, command, entry_widget, result_widget, encoding='utf-8', button=None):
        host = entry_widget.text().strip()
        if not host:
            QMessageBox.critical(self, "Error", "Please enter a value")
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
        self.run_in_thread(execute, result_widget, button=button)

    def run_ping(self):
        param = ['-n', '4'] if os.name == 'nt' else ['-c', '4']
        encoding = 'cp866' if os.name == 'nt' else 'utf-8'
        self.run_command(['ping'] + param, self.ping_entry, self.ping_result, encoding, button=self.ping_btn)

    def run_nslookup(self):
        host = self.nslookup_entry.text().strip()
        if not host:
            QMessageBox.critical(self, "Error", "Please enter a host or IP")
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
        self.run_in_thread(execute, self.nslookup_result, button=self.nslookup_btn)

    def run_traceroute(self):
        host = self.traceroute_entry.text().strip()
        if not host:
            QMessageBox.critical(self, "Error", "Please enter a host")
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
        self.run_in_thread(execute, self.traceroute_result, button=self.traceroute_btn)

    def run_curl(self):
        url = self.curl_entry.text().strip()
        if not url:
            QMessageBox.critical(self, "Error", "Please enter a URL")
            return
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        keys = self.curl_keys_entry.text().strip()
        def execute():
            result = subprocess.run(
                ['curl'] + keys.split() + [url],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            return result.stdout or result.stderr
        self.run_in_thread(execute, self.curl_result, button=self.curl_btn)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = DNSAnalyzerApp()
    win.show()
    sys.exit(app.exec_())
