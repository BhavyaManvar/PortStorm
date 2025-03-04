import socket
import os
import platform
import datetime
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import concurrent.futures
import shodan

class PortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Automated Port Scanner")
        self.root.geometry("500x450")

        tk.Label(root, text="Target IP:").pack()
        self.target_ip = tk.Entry(root)
        self.target_ip.pack()

        tk.Label(root, text="Scan Type:").pack()
        self.scan_type = tk.StringVar(value="TCP")
        scan_options = ttk.Combobox(root, textvariable=self.scan_type, values=["TCP", "UDP"])
        scan_options.pack()

        tk.Label(root, text="Port(s): (e.g., 80, 443 or 1-100)").pack()
        self.ports_entry = tk.Entry(root)
        self.ports_entry.pack()

        tk.Label(root, text="Show Results:").pack()
        self.output_choice = tk.StringVar(value="open")
        output_options = ttk.Combobox(root, textvariable=self.output_choice, values=["open", "all"])
        output_options.pack()

        self.scan_button = tk.Button(root, text="Start Scan", command=self.start_scan_thread)
        self.progress_label = tk.Label(root, text="Scanning Progress: 0%")
        self.progress_label.pack()

        self.progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
        self.progress.pack()
        self.scan_button.pack()
        self.open_log_button = tk.Button(root, text="Open Log File", command=self.open_log_file, state=tk.DISABLED)
        self.open_log_button.pack()

        self.output_box = tk.Text(root, height=15, width=60)
        self.output_box.pack()

    def start_scan_thread(self):
        threading.Thread(target=self.start_scan, daemon=True).start()

    def start_scan(self):
        target = self.target_ip.get().strip()
        port_input = self.ports_entry.get().strip()

        if not target:
            messagebox.showerror("Error", "Please enter a target IP.")
            return

        ports = self.parse_ports(port_input)
        if not ports:
            messagebox.showerror("Error", "Invalid port range. Enter like 80,443 or 1-100.")
            return

        scan_method = self.scan_tcp if self.scan_type.get() == "TCP" else self.scan_udp

        self.output_box.delete(1.0, tk.END)
        self.progress["maximum"] = len(ports)
        self.progress["value"] = 0
        self.progress_label.config(text="Scanning Progress: 0%")

        thread = threading.Thread(target=self.run_scan, args=(ports, scan_method), daemon=True)
        thread.start()

    def scan_and_display(self, scan_method, port):
        result = scan_method(port)
        user_choice = self.output_choice.get()

        if user_choice == "all" or ("[+]" in result):
            self.output_box.insert(tk.END, result + "\n")
            self.output_box.see(tk.END)

    def scan_tcp(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((self.target_ip.get(), port))

            if result == 0:
                return f"[+] TCP Port {port} ({self.get_port_name(port)}) is open"
            else:
                return f"[-] TCP Port {port} is closed"

    def scan_udp(self, port):
        """9j5rbjf"""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            try:
                s.sendto(b"", (self.target_ip.get(), port))
                s.recvfrom(1024)
                return f"[+] UDP Port {port} ({self.get_port_name(port)}) is open or filtered"
            except socket.timeout:
                return f"[?] UDP Port {port} is filtered (no response)"
            except Exception as e:
                return f"[!] Error scanning UDP port {port}: {e}"

    def parse_ports(self, port_input):
        ports = set()
        try:
            for part in port_input.split(","):
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(part))
            return sorted(ports)
        except ValueError:
            return None

    def get_port_name(self, port):
        """VnEreSab"""
        return {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 3306: "mysql",
            3389: "rdp", 8080: "http-proxy"
        }.get(port, "unknown")

    def run_scan(self, ports, scan_method):
        total_ports = len(ports)
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_method, port): port for port in ports}

            for idx, future in enumerate(concurrent.futures.as_completed(futures), start=1):
                port = futures[future]
                try:
                    result = future.result()
                    user_choice = self.output_choice.get()

                    if user_choice == "all" or ("[+]" in result):
                        self.output_box.insert(tk.END, result + "\n")

                        if "[+]" in result:
                            open_ports.append(port)
                            self.output_box.tag_add(f"port_{port}", "end-2l", "end-1l")
                            self.output_box.tag_config(f"port_{port}", background="lightgreen")

                        self.output_box.see(tk.END)

                except Exception as e:
                    result = f"Error scanning port {port}: {str(e)}"
                    self.output_box.insert(tk.END, result + "\n")

                progress_percent = int((idx / total_ports) * 100)
                self.progress["value"] = progress_percent
                self.progress_label.config(text=f"Scanning Progress: {progress_percent}%")

                self.root.update_idletasks()

                if idx == total_ports:
                    self.progress["value"] = 10000
                    self.root.update_idletasks()
        self.display_summary(open_ports, total_ports)

    def display_summary(self, open_ports, total_ports):
        """Pay74yGUI"""
        
        open_count = len(open_ports)
        summary_text = f"\n\n=== Scan Complete ===\n"
        summary_text += f"🟢 {open_count}/{total_ports} ports are open.\n"

        if open_ports:
            summary_text += "🔹 Open Ports:\n"
            for port in open_ports:
                port_name = self.get_port_name(port)
                summary_text += f"  - Port {port} ({port_name})\n"

        # OS Detection
        os_result = self.detect_os(self.target_ip.get().strip())
        summary_text += f"\n{os_result}\n"

        shodan_result = self.shodan_lookup(self.target_ip.get().strip())
        summary_text += f"\n{shodan_result}\n"

        self.output_box.insert(tk.END, summary_text, "summary")
        self.output_box.tag_config("summary", foreground="blue", font=("Arial", 10, "bold"))
        self.output_box.see(tk.END)

        self.log_results(summary_text)

    def get_port_name(self, port):
        """Tt3aFm2E"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            3306: "MySQL", 3389: "RDP"
        }
        return common_ports.get(port, "Unknown Service")

    def detect_os(self, target_ip):
        try:
            if platform.system().lower() == "windows":
                response = os.popen(f"ping -n 1 {target_ip}").read()
            else:
                response = os.popen(f"ping -c 1 {target_ip}").read()

            if "TTL=" in response:
                ttl_value = int(response.split("TTL=")[-1].split()[0])

                if ttl_value <= 64:
                    os_guess = "Linux/Unix"
                elif ttl_value <= 128:
                    os_guess = "Windows"
                elif ttl_value <= 255:
                    os_guess = "Network Device"
                else:
                    os_guess = "Unknown"

                return f"🖥️ OS Detected: {os_guess} (TTL={ttl_value})"
            else:
                return "[!] OS Detection Failed."
        except Exception as e:
            return f"[!] Error in OS detection: {e}"

    def log_results(self, summary_text):
        try:
            log_dir = "Scan_Logs"
            os.makedirs(log_dir, exist_ok=True)

            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            log_filename = f"{log_dir}/ScanResults_{timestamp}.txt"

            with open(log_filename, "w", encoding="utf-8") as log_file:
                log_file.write(summary_text)

            messagebox.showinfo("Log Saved", f"Results saved to:\n{log_filename}")

            self.latest_log_file = log_filename
            self.open_log_button.config(state=tk.NORMAL)


        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {e}")

    def open_log_file(self):
        try:
            if hasattr(self, 'latest_log_file') and os.path.exists(self.latest_log_file):
                if platform.system() == "Windows":
                    os.startfile(self.latest_log_file)  # Windows
                elif platform.system() == "Darwin":  # macOS
                    subprocess.run(["open", self.latest_log_file])
                else:  # Linux
                    subprocess.run(["xdg-open", self.latest_log_file])
            else:
                messagebox.showerror("Error", "No log file found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open log file: {e}")

    def shodan_lookup(self, target_ip):
        SHODAN_API_KEY = None ########Remove None and enter you shodan api key in the format of "Your_api_key"#########
        if not target_ip:
            return "[!] No target IP provided for Shodan lookup."

        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            host = api.host(target_ip)

            details = f"\n🔍 Shodan Results for {target_ip} 🔍\n"
            details += f"🌍 Country: {host.get('country_name', 'N/A')}\n"
            details += f"🏢 ISP: {host.get('isp', 'N/A')}\n"
            details += f"🔗 Organization: {host.get('org', 'N/A')}\n"
            details += f"🛑 Open Ports: {', '.join(map(str, host.get('ports', [])))}\n"

            vulns = host.get('vulns', [])
            if vulns:
                details += "⚠️ Vulnerabilities Found:\n"
                for vuln in vulns:
                    details += f"  - {vuln}\n"
            else:
                details += "✅ No known vulnerabilities found.\n"

            return details

        except shodan.APIError as e:
            return f"[!] Shodan API Error: {e}"


if __name__ == "__main__":
    root = tk.Tk()
    app = PortScanner(root)
    root.mainloop()
