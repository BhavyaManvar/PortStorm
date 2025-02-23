import socket
import threading


class PortScanner:
    def __init__(self, target, ports, scan_type, timeout=1):
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.timeout = timeout
    
    def scan_tcp(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                return f"[+] TCP Port {port} is open"
            return f"[-] TCP Port {port} is closed"

    def scan_udp(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            try:
                s.sendto(b"", (self.target, port))
                s.recvfrom(1024)
                return f"[+] UDP Port {port} is open or filtered"
            except socket.timeout:
                return f"[-] UDP Port {port} is closed or filtered"
            except Exception as e:
                return f"[!] Error scanning UDP port {port}: {e}"
    
    def run_scan(self, output_box):
        threads = []
        for port in self.ports:
            if self.scan_type == "TCP":
                t = threading.Thread(target=self.scan_and_display, args=(self.scan_tcp, port, output_box))
            elif self.scan_type == "UDP":
                t = threading.Thread(target=self.scan_and_display, args=(self.scan_udp, port, output_box))
            else:
                output_box.insert(tk.END, "[!] Invalid scan type. Use TCP or UDP.\n")
                return
            
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
    
    def scan_and_display(self, scan_method, port, output_box):
        result = scan_method(port)
        output_box.insert(tk.END, result + "\n")
        output_box.see(tk.END)

def start_scan():
    target_ip = ip_entry.get()
    scan_type = scan_type_var.get()
    port_input = port_entry.get()
    
    if "-" in port_input:
        start, end = map(int, port_input.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = [int(port_input)]
    
    output_box.delete(1.0, tk.END)
    scanner = PortScanner(target_ip, ports, scan_type)
    threading.Thread(target=scanner.run_scan, args=(output_box,), daemon=True).start()
