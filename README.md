# **Network & Security Toolkit** 🛠️

A multi-functional Python script for network reconnaissance and security testing. This toolkit includes **10 powerful features** to help you analyze and secure networks.

---

## **Features** ✨

1. **Port Scanner**: Scan a target IP for open ports.
2. **Ping Sweeper**: Ping a range of IPs to identify live hosts.
3. **Subdomain Enumerator**: Discover subdomains of a target domain.
4. **WHOIS Lookup**: Retrieve WHOIS information for a domain.
5. **DNS Resolver**: Resolve a domain name to its IP address.
6. **HTTP Header Checker**: Fetch and display HTTP headers of a website.
7. **MAC Address Lookup**: Look up the vendor of a MAC address.
8. **Geolocation Lookup**: Get the geolocation of an IP address.
9. **Packet Sniffer**: Capture and analyze network packets.
10. **Advanced Packet Analysis**: Perform advanced analysis on captured packets (e.g., TCP/UDP payload inspection).

---

## **How to Use** 🚀

1. **Install Python**: Ensure you have [Python 3.x](https://www.python.org/downloads/) installed.
2. **Install Dependencies**:
   ```bash
   pip install requests scapy python-whois
   ```
3. **Run the Script**:
   ```bash
   python network_toolkit.py
   ```
4. **Choose an Option**:
   - Select one of the 10 features from the menu and follow the prompts.

---

## **Example Output** 📊

### **Port Scanner**:
```
Enter the target IP address: 192.168.1.1
Enter the starting port (default: 1): 1
Enter the ending port (default: 1024): 1024

Scanning 192.168.1.1 from port 1 to 1024...
Port 22 (SSH) is open.
Port 80 (HTTP) is open.
Port 443 (HTTPS) is open.
Scan complete!
```

### **Advanced Packet Analysis**:
```
Starting advanced packet analysis... Press Ctrl+C to stop.

Packet: 192.168.1.100 -> 192.168.1.1 | Protocol: TCP
TCP: Source Port: 54321 -> Destination Port: 80
Payload: b'GET / HTTP/1.1\r\nHost: example.com\r\n...'
```

---

## **TBA** 🛠️

- **Add More Features**: Extend the toolkit with additional tools like vulnerability scanning, brute-forcing, or SSL/TLS analysis.
- **Improve Performance**: Use asynchronous programming or multi-threading for faster scans and operations.
- **Export Results**: Save results to a file (e.g., CSV, JSON) for further analysis.
- **GUI Integration**: Develop a graphical user interface (GUI) for easier interaction.
- **Cross-Platform Compatibility**: Ensure full compatibility with Windows, macOS, and Linux.
- **API Integration**: Add support for more APIs (e.g., Shodan, VirusTotal) for enhanced functionality.

---

## **Contributing** 🤝

Feel free to contribute to this project by opening issues or submitting pull requests. Your feedback and improvements are welcome!

---

Your all-in-one network and security toolkit! 🚀
