
# ⚡ PortStorm – Advanced Port Scanner

🚀 **PortStorm** is a fully featured **port scanning tool** designed for **network security professionals, ethical hackers, and penetration testers**.  
It includes **TCP & UDP scanning, OS detection, Shodan integration, and vulnerability detection**, making it a powerful tool for **cybersecurity analysis**.  

💻 **It supports both GUI and Web-based interfaces**, allowing you to run scans seamlessly from **desktop or browser**.  

---

## **⚡ Features**
✅ **TCP & UDP Port Scanning** – Scan individual or a range of ports  
✅ **Only Open Ports or All Ports Output** – Filter results as needed  
✅ **OS Detection** – Identify the target OS using TTL values  
✅ **Shodan Integration** – Fetch ISP, organization, open ports, and vulnerabilities  
✅ **Save Scan Results** – Automatically logs results in a timestamped text file  
✅ **Web-Based GUI** – Run the scanner from your browser using Flask  
✅ **Fast Multi-Threading Support** – Ensures rapid and efficient scanning  

---

## **🛠️ Installation**
### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/yourusername/PortStorm.git
cd PortStorm
```
Ensure you have Python 3.8+ installed. Then, install the required libraries:

```bash
pip install -r requirements.txt
```

in terminal 
```bash
python portstorm.py
```

**If you want the best vulnerabilities detection them add you shodan key from shodan website**
add this code in the shodan_API_key in code **line 260**


🖥️ Web Interface Features
Enter Target IP Address
Choose TCP or UDP Scanning
Select Ports (e.g., 22,80,443 or 1-1000)
Choose to display only open ports or all results
Save results automatically
Shodan Lookup for extra details
Download scan logs



💻 Libraries Used
PortStorm is built using the following Python libraries:

tkinter → For the desktop GUI
shodan → Fetching internet-connected device details
os, platform, datetime → OS detection and system operations
threading, subprocess → Multithreading & process management
