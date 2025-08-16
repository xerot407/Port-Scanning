import tkinter as tk
import socket
import threading

def scan_port(ip, port):
    """
    Checks if a specific port on the given IP is open or closed.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Timeout in seconds
    result = sock.connect_ex((ip, port))
    sock.close()
    if result == 0:
        return f"Port {port}: Open"
    else:
        return f"Port {port}: Closed"

def start_scan():
    """
    Starts the port scanning process in a separate thread to avoid freezing the GUI.
    """
    ip = ip_entry.get()
    if not ip:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Please enter a valid IP address.\n")
        return

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Scanning {ip} for common ports...\n")

    def scan():
        # List of common ports to scan (you can add more if needed)
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 465, 993, 995, 3389]
        
        for port in common_ports:
            result = scan_port(ip, port)
            # Use root.after to safely update the GUI from another thread
            root.after(0, lambda r=result: result_text.insert(tk.END, r + "\n"))
        
        root.after(0, lambda: result_text.insert(tk.END, "Scan complete.\n"))

    # Run the scan in a background thread
    threading.Thread(target=scan).start()

# Set up the Tkinter GUI
root = tk.Tk()
root.title("Simple Port Scanner")
root.geometry("400x400")

# IP input label and entry
tk.Label(root, text="Enter IP Address:").pack(pady=10)
ip_entry = tk.Entry(root, width=30)
ip_entry.pack()

# Scan button
tk.Button(root, text="Scan Ports", command=start_scan).pack(pady=10)

# Result display area
result_text = tk.Text(root, height=15, width=50, wrap=tk.WORD)
result_text.pack(pady=10)

root.mainloop()