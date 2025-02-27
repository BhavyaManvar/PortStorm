import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox

class PortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Automated Port Scanner")
        self.root.geometry("500x450")

        # Target IP Input
        tk.Label(root, text="Target IP:").pack()
        self.target_ip = tk.Entry(root)
        self.target_ip.pack()

        # Scan Type (TCP or UDP)
        tk.Label(root, text="Scan Type:").pack()
        self.scan_type = tk.StringVar(value="TCP")
        scan_options = ttk.Combobox(root, textvariable=self.scan_type, values=["TCP", "UDP"])
        scan_options.pack()

        # Port Range Input
        tk.Label(root, text="Port(s): (e.g., 80, 443 or 1-100)").pack()
        self.ports_entry = tk.Entry(root)
        self.ports_entry.pack()

        # Output Filtering (Show only open or all)
        tk.Label(root, text="Show Results:").pack()
        self.output_choice = tk.StringVar(value="open")
        output_options = ttk.Combobox(root, textvariable=self.output_choice, values=["open", "all"])
        output_options.pack()

        # Scan Button
        self.scan_button = tk.Button(root, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.pack()

        # Output Box
        self.output_box = tk.Text(root, height=15, width=60)
        self.output_box.pack()

    def start_scan_thread(self):
        """ Runs the scan in a separate thread to keep the GUI responsive. """
        threading.Thread(target=self.start_scan, daemon=True).start()

    def start_scan(self):
        """ Start the scanning process """
        target = self.target_ip.get().strip()
        port_input = self.ports_entry.get().strip()

        # Validate IP
        if not target:
            messagebox.showerror("Error", "Please enter a target IP.")
            return

        # Get ports
        ports = self.parse_ports(port_input)
        if not ports:
            messagebox.showerror("Error", "Invalid port range. Enter like 80,443 or 1-100.")
            return

        scan_method = self.scan_tcp if self.scan_type.get() == "TCP" else self.scan_udp

        # Clear output box
        self.output_box.delete(1.0, tk.END)

        # Multi-threaded Scanning
        threads = []
        for port in ports:
            thread = threading.Thread(target=self.scan_and_display, args=(scan_method, port), daemon=True)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def scan_and_display(self, scan_method, port):
        """ Scan and update GUI safely """
        result = scan_method(port)
        user_choice = self.output_choice.get()  # Get user selection ("open" or "all")

        if user_choice == "all" or ("[+]" in result):  # Show all or only open ports
            self.output_box.insert(tk.END, result + "\n")
            self.output_box.see(tk.END)

    def scan_tcp(self, port):
        """ Scan TCP port """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((self.target_ip.get(), port))

            if result == 0:
                return f"[+] TCP Port {port} ({self.get_port_name(port)}) is open"
            else:
                return f"[-] TCP Port {port} is closed"

    def scan_udp(self, port):
        """ Scan UDP port """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            try:
                s.sendto(b"", (self.target_ip.get(), port))
                s.recvfrom(1024)  # If response comes, port is open
                return f"[+] UDP Port {port} ({self.get_port_name(port)}) is open or filtered"
            except socket.timeout:
                return f"[?] UDP Port {port} is filtered (no response)"
            except Exception as e:
                return f"[!] Error scanning UDP port {port}: {e}"

    def parse_ports(self, port_input):
        """ Parse port input (single port or range) """
        ports = set()
        try:
            for part in port_input.split(","):
                if "-" in part:  # Handle port range (e.g., 1-100)
                    start, end = map(int, part.split("-"))
                    ports.update(range(start, end + 1))
                else:  # Handle single port (e.g., 80)
                    ports.add(int(part))
            return sorted(ports)
        except ValueError:
            return None

    def get_port_name(self, port):
        """ Get common port names """
        return {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 3306: "mysql",
            3389: "rdp", 8080: "http-proxy"
        }.get(port, "unknown")

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PortScanner(root)
    root.mainloop()
