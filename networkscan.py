import tkinter as tk
from tkinter import ttk, filedialog
import socket
from tkinter import messagebox
import threading

# Define the scanning process status
is_scanning = False
is_paused = False

def create_gui():
    # Create the main window
    root = tk.Tk()
    root.title("Port Scanner with Toolbar")

    # Define a toolbar frame
    toolbar = tk.Frame(root, bd=1, relief=tk.RAISED)
    toolbar.pack(side="top", fill="x")

    # Add toolbar buttons
    start_btn = tk.Button(toolbar, text="Start", command=lambda: start_scan(entry_target, entry_ports, result_text, progress_bar, root))
    start_btn.pack(side="left", padx=2, pady=2)

    stop_btn = tk.Button(toolbar, text="Stop", command=stop_scan)
    stop_btn.pack(side="left", padx=2, pady=2)

    restart_btn = tk.Button(toolbar, text="Restart", command=lambda: start_scan(entry_target, entry_ports, result_text, progress_bar, root))
    restart_btn.pack(side="left", padx=2, pady=2)

    pause_btn = tk.Button(toolbar, text="Pause", command=pause_scan)
    pause_btn.pack(side="left", padx=2, pady=2)

    save_btn = tk.Button(toolbar, text="Save to File", command=lambda: save_to_file(result_text))
    save_btn.pack(side="left", padx=2, pady=2)

    service_btn = tk.Button(toolbar, text="Service Scan", command=lambda: start_service_scan(entry_target.get(), result_text, progress_bar, root))
    service_btn.pack(side="left", padx=2, pady=2)

    # Frame for input fields
    input_frame = tk.Frame(root)
    input_frame.pack(pady=5)

    # Entry widget for target input
    tk.Label(input_frame, text="Target IP or Hostname:").pack(side="left", padx=5)
    entry_target = tk.Entry(input_frame, width=20)
    entry_target.pack(side="left", padx=5)

    # Entry widget for port range input
    tk.Label(input_frame, text="Port Range (start-end):").pack(side="left", padx=5)
    entry_ports = tk.Entry(input_frame, width=20)
    entry_ports.pack(side="left", padx=5)

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

    return root

def detect_service(port):
    services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
    }
    return services.get(port, 'Unknown Service')

def banner_grab(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((target, port))
        sock.send(b'Hello\r\n')
        banner = sock.recv(1024).decode().strip()
        return banner
    except:
        return None

def scan_ports(target, port_range, result_text, progress_bar, root):
    global is_scanning, is_paused
    start_port, end_port = map(int, port_range.split('-'))
    total_ports = end_port - start_port + 1
    progress_bar["maximum"] = total_ports
    result_text.delete("1.0", tk.END)

    try:
        for i, port in enumerate(range(start_port, end_port + 1)):
            if not is_scanning:
                break
            while is_paused:
                root.update_idletasks()
            progress_bar["value"] = i + 1
            root.update_idletasks()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = detect_service(port)
                banner = banner_grab(target, port)
                result_text.insert(tk.END, f"Port {port}: OPEN ({service})\n")
                if banner:
                    result_text.insert(tk.END, f" - Banner: {banner}\n")
            else:
                result_text.insert(tk.END, f"Port {port}: CLOSED\n")
            sock.close()
    except Exception as e:
        messagebox.showerror("Error", str(e))

def start_scan(entry_target, entry_ports, result_text, progress_bar, root):
    global is_scanning, is_paused
    is_scanning = True
    is_paused = False
    target = entry_target.get()
    port_range = entry_ports.get()
    threading.Thread(target=scan_ports, args=(target, port_range, result_text, progress_bar, root)).start()

def stop_scan():
    global is_scanning
    is_scanning = False

def pause_scan():
    global is_paused
    is_paused = not is_paused

def save_to_file(result_text):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(result_text.get("1.0", tk.END))

def start_service_scan(target, result_text, progress_bar, root):
    global is_scanning
    is_scanning = True
    result_text.delete("1.0", tk.END)
    threading.Thread(target=service_scan, args=(target, result_text, progress_bar, root)).start()

def service_scan(target, result_text, progress_bar, root):
    global is_scanning
    services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
    }
    progress_bar["maximum"] = len(services)
    result_text.insert(tk.END, "Scanning for active services...\n")
    try:
        for i, (port, service) in enumerate(services.items()):
            if not is_scanning:
                break
            progress_bar["value"] = i + 1
            root.update_idletasks()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                result_text.insert(tk.END, f"Port {port}: OPEN ({service})\n")
                banner = banner_grab(target, port)
                if banner:
                    result_text.insert(tk.END, f" - Banner: {banner}\n")
            else:
                result_text.insert(tk.END, f"Port {port}: CLOSED ({service})\n")
            sock.close()
    except Exception as e:
        messagebox.showerror("Error", str(e))
    result_text.insert(tk.END, "Service scan completed.\n")

if __name__ == "__main__":
    gui = create_gui()
    gui.mainloop()
