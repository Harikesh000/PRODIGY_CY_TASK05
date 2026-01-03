import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import queue
from datetime import datetime
import ttkbootstrap as tb
import sys
import ctypes
from scapy.all import sniff, IP, TCP, UDP

app = tb.Window(themename="cosmo")
app.title("Real-Time Traffic Analyzer")
app.geometry("1100x650")

traffic_summary = {}
packet_queue = queue.Queue()
domain_queue = queue.Queue()
lock = threading.Lock()
domain_cache = {}

current_proto = "TCP/UDP"
capture_thread = None
capture_running = False
resolver_running = True

def resolve_domain(ip):
    if ip in domain_cache:
        return domain_cache[ip]
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except Exception:
        domain = "N/A"
    domain_cache[ip] = domain
    return domain

def current_time_str():
    return datetime.now().strftime("%I:%M:%S %p")

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        proto = None

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            # Detect protocols by ports
            if sport == 80 or dport == 80:
                proto = "HTTP"
            elif sport == 443 or dport == 443:
                proto = "HTTPS"
            else:
                proto = "TCP"

        elif UDP in packet:
            proto = "UDP"

        if proto:
            packet_queue.put((src_ip, dst_ip, proto))

def capture_packets():
    try:
        sniff(filter="tcp or udp", prn=packet_handler, store=False,
              stop_filter=lambda pkt: not capture_running)
    except Exception as e:
        print("Error in sniff:", e)

def domain_resolver_worker():
    while resolver_running:
        try:
            ip = domain_queue.get(timeout=1)
        except queue.Empty:
            continue
        resolve_domain(ip)
        domain_queue.task_done()

def toggle_capture():
    global capture_running, capture_thread
    if not capture_running:
        capture_running = True
        start_btn.configure(text="⛔ Stop Capture", bootstyle="danger")
        # Start capture thread immediately to have quick response
        capture_thread = threading.Thread(target=capture_packets, daemon=True)
        capture_thread.start()
        messagebox.showinfo("Started", "Packet capture started.")
    else:
        capture_running = False
        start_btn.configure(text="▶ Start Capture", bootstyle="success")
        messagebox.showinfo("Stopped", "Packet capture stopped.")

def process_queue():
    updated = False

    if not traffic_summary:
        for row in tree.get_children():
            tree.delete(row)
        tree.insert("", "end", values=("", "Waiting for traffic...", "", "", "", ""))

    while not packet_queue.empty():
        src_ip, dst_ip, proto = packet_queue.get()
        key = (src_ip, dst_ip)
        with lock:
            if key not in traffic_summary:
                traffic_summary[key] = {
                    "src_domain": None,
                    "dst_domain": None,
                    "protocols": {proto},
                    "count": 1,
                    "last_seen": current_time_str()
                }
                if src_ip not in domain_cache:
                    domain_queue.put(src_ip)
                else:
                    traffic_summary[key]["src_domain"] = domain_cache[src_ip]
                if dst_ip not in domain_cache:
                    domain_queue.put(dst_ip)
                else:
                    traffic_summary[key]["dst_domain"] = domain_cache[dst_ip]
            else:
                traffic_summary[key]["protocols"].add(proto)
                traffic_summary[key]["count"] += 1
                traffic_summary[key]["last_seen"] = current_time_str()
        updated = True

    with lock:
        for (src_ip, dst_ip), info in traffic_summary.items():
            if info["src_domain"] is None and src_ip in domain_cache:
                info["src_domain"] = domain_cache[src_ip]
                updated = True
            if info["dst_domain"] is None and dst_ip in domain_cache:
                info["dst_domain"] = domain_cache[dst_ip]
                updated = True

    if updated:
        refresh_table()
    app.after(300, process_queue)

def format_addr(ip, domain):
    return f"{ip}\n{domain if domain else 'Resolving...'}"

def refresh_table():
    for row in tree.get_children():
        tree.delete(row)
    with lock:
        items = list(traffic_summary.items())
    filtered = []
    for (src_ip, dst_ip), info in items:
        # Filter based on current_proto selection
        if current_proto == "TCP/UDP":
            # Show TCP and/or UDP only (exclude HTTP/HTTPS)
            protos = sorted(p for p in info["protocols"] if p in ("TCP", "UDP"))
            if protos:
                filtered.append((format_addr(src_ip, info['src_domain']),
                                 format_addr(dst_ip, info['dst_domain']),
                                 ", ".join(protos),
                                 info["count"],
                                 info["last_seen"]))
        elif current_proto in ("HTTP", "HTTPS"):
            # Show entries that contain the selected protocol
            if current_proto in info["protocols"]:
                filtered.append((format_addr(src_ip, info['src_domain']),
                                 format_addr(dst_ip, info['dst_domain']),
                                 current_proto,
                                 info["count"],
                                 info["last_seen"]))
        else:
            # For TCP or UDP individually
            if current_proto in info["protocols"]:
                filtered.append((format_addr(src_ip, info['src_domain']),
                                 format_addr(dst_ip, info['dst_domain']),
                                 current_proto,
                                 info["count"],
                                 info["last_seen"]))
    for i, (from_addr, to_addr, protos, count, last_seen) in enumerate(filtered, start=1):
        tree.insert("", "end", values=(i, from_addr, to_addr, protos, count, last_seen))

def on_radio_change():
    global current_proto
    current_proto = proto_var.get()
    refresh_table()

def search_traffic():
    query = search_var.get().strip().lower()
    if not query or query == "ipv4/domain name":
        messagebox.showinfo("Info", "Please enter an IPv4 or Domain Name to search.")
        return
    with lock:
        results = [
            (i + 1,
             format_addr(src, info['src_domain']),
             format_addr(dst, info['dst_domain']),
             ", ".join(sorted(info["protocols"])), info["count"], info["last_seen"])
            for i, ((src, dst), info) in enumerate(traffic_summary.items())
            if query in src.lower() or query in dst.lower()
            or (info['src_domain'] and query in info['src_domain'].lower())
            or (info['dst_domain'] and query in info['dst_domain'].lower())
        ]
    new_window(f"Search Results for '{query}'", results)

def new_window(title, data):
    new_win = tb.Toplevel(app)
    new_win.title(title)
    new_win.geometry("1100x500")
    cols = ("SNo", "From", "To", "Protocols", "Packet Count", "Last Seen")
    table = ttk.Treeview(new_win, columns=cols, show="headings")
    col_widths = {
        "SNo": 5, "From": 290, "To": 290,
        "Protocols": 70, "Packet Count": 110, "Last Seen": 130
    }
    for col in cols:
        table.heading(col, text=col)
        table.column(col, anchor="center", width=col_widths[col])
    style = ttk.Style(new_win)
    style.configure("Treeview", rowheight=50)
    table.pack(expand=True, fill="both", padx=20, pady=20)
    if data:
        for item in data:
            table.insert("", "end", values=item)
    else:
        messagebox.showinfo("Info", "No Traffic Found")

# GUI setup

top_frame = tb.Frame(app)
top_frame.pack(pady=10, fill="x")

center_frame = tb.Frame(top_frame)
center_frame.pack(expand=True)

start_btn = tb.Button(center_frame, text="▶ Start Capture", bootstyle="success", width=20, command=toggle_capture)
start_btn.pack(side="left", padx=10)

proto_var = tk.StringVar(value="TCP/UDP")

for text, val in [("TCP/UDP", "TCP/UDP"), ("TCP", "TCP"), ("UDP", "UDP"), ("HTTP", "HTTP"), ("HTTPS", "HTTPS")]:
    tb.Radiobutton(center_frame, text=text, variable=proto_var, value=val,
                   bootstyle="info-toolbutton", command=on_radio_change).pack(side="left", padx=5)

search_frame = tb.Frame(app)
search_frame.pack(pady=10)
search_var = tk.StringVar()
search_entry = tb.Entry(search_frame, textvariable=search_var, width=40, bootstyle="info")
search_entry.insert(0, "IPv4/Domain Name")
search_entry.configure(foreground="Black")

def clear_hint(event):
    if search_entry.get() == "IPv4/Domain Name":
        search_entry.delete(0, tk.END)
        search_entry.configure(foreground="Black")

def restore_hint(event):
    if search_entry.get() == "":
        search_entry.insert(0, "IPv4/Domain Name")
        search_entry.configure(foreground="Black")

search_entry.bind("<FocusIn>", clear_hint)
search_entry.bind("<FocusOut>", restore_hint)
search_entry.grid(row=0, column=0, padx=10)
search_btn = tb.Button(search_frame, text="🔍 Search", bootstyle="primary", command=search_traffic)
search_btn.grid(row=0, column=1, padx=5)

tree_frame = tb.Frame(app)
tree_frame.pack(expand=True, fill="both", padx=20, pady=20)

cols = ("SNo", "From", "To", "Protocols", "Packet Count", "Last Seen")
tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=15)
col_widths = {
      "SNo": 5, "From": 290, "To": 290,
        "Protocols": 70, "Packet Count": 110, "Last Seen": 130
}
for col in cols:
    tree.heading(col, text=col)
    tree.column(col, anchor="center", width=col_widths[col])
style = ttk.Style(app)
style.configure("Treeview", rowheight=50)
tree.pack(expand=True, fill="both")

domain_resolver_thread = threading.Thread(target=domain_resolver_worker, daemon=True)
domain_resolver_thread.start()

app.after(300, process_queue)

def on_closing():
    global capture_running, resolver_running
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        capture_running = False
        resolver_running = False
        app.destroy()

app.protocol("WM_DELETE_WINDOW", on_closing)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()
else:
    app.mainloop()