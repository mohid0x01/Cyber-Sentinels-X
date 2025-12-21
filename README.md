# 🚀 Sentinel-X | Elite Network Security Framework

Sentinel-X is an advanced, automated network exploitation and OSINT framework. It bridges the gap between high-level reconnaissance and low-level network interception by orchestrating industry-standard tools like Bettercap and Mitmproxy into a single, unified interface.
🛡️ Key Modules
Module	Description	Engine
OSINT Tracker	Scans 30+ social platforms for target profiles.	Custom Requests
MITM Elite	Automated ARP Spoofing, SSLStrip, and Traffic Sniffing.	Bettercap + Mitmproxy
Network Discovery	Live ARP scanning to map all devices on a LAN.	Scapy
Web Recon	Fingerprinting servers and finding hidden admin panels.	HTTP Probes
Port Scanner	Multi-threaded stealth scanning for open services.	Socket
📸 MITM Workflow

Sentinel-X automates the entire "Man-in-the-Middle" lifecycle:

    Auto-Discovery: Scans the LAN for targets.

    Redirection: Configures Iptables to route traffic through the system.

    Interception: Uses Mitmproxy to capture flows while Bettercap handles ARP poisoning.

    Archiving: Automatically saves every session to the sentinel_vault/.

⚙️ Installation & Requirements

Ensure you are running a Linux-based system (Kali, Parrot, or Ubuntu).
1. Install System Dependencies

`sudo apt update && sudo apt install bettercap mitmproxy iptables python3-pip -y`

2. Install Python Packages

    `pip install -r requirements.txt`

Requirements: scapy, requests, colorama, pyttsx3

3. Run the Tool

`sudo python3 main.py`

    Note: Root privileges are required for MITM and Network Sniffing operations.

📂 Project Structure

Sentinel-X/
├── main.py         
└── README.md          

⚠️ Disclaimer

This tool is developed for educational and ethical security testing purposes only. Usage of Sentinel-X for attacking targets without prior mutual consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
🤝 Contributing

Feel free to fork this project, report bugs, or submit pull requests to enhance the automation engines!
