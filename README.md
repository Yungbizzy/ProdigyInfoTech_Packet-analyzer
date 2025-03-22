# ProdigyInfoTech_Packet-analyzer
## Introduction
A **Network Packet Analyzer** (also known as a **Packet Sniffer**) is a tool used to **capture and analyze network traffic**. It helps in monitoring data packets, diagnosing network issues, and enhancing security. This project provides a Python-based packet sniffer using the **Scapy** library to inspect network packets in real-time.

## Overview
A **Network Packet Analyzer** captures and analyzes data transmitted over a network. It can be useful for **troubleshooting network issues, detecting intrusions, and monitoring data flows**. However, network sniffing should only be performed in authorized environments to maintain ethical and legal compliance.

## Features
- Captures and analyzes network packets in real-time.
- Extracts **source and destination IP addresses**.
- Identifies the **protocol** used (TCP, UDP, ICMP, etc.).
- Displays **packet payload** 
- Allows **filtering** by protocol or IP address.
- Can be modified to **log captured packets** to a file.

## Installation
### 1. Install Scapy
Run the following command to install **Scapy**:

sudo apt update
sudo apt install python3-scapy

### 2. Verify Installation
Ensure `scapy` is installed correctly:

python3 -c "import scapy"

If there are no errors, **Scapy** is installed successfully.
![image](https://github.com/user-attachments/assets/6e2e790f-ba12-483b-8cf6-78c5b8f228ad)

## Usage
### 1. Clone the Repository

git clone https://github.com/your-username/network-packet-analyzer.git
cd network-packet-analyzer

### 2. Create and Edit the Packet Sniffer Script
Create a new Python script:
`
nano packet_sniffer.py
Copy and paste the following code:
import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        
        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"Payload: {payload}")
        
        print("-" * 50)

def start_sniffing():
    print("Starting packet sniffer...")
    scapy.sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()
![image](https://github.com/user-attachments/assets/aa40f5d0-4fd9-4b17-8420-e297d0c217fc)



### 3. Run the Packet Sniffer
Run the script with **sudo** privileges:

sudo python3 packet_sniffer.py

### 4.Output
![image](https://github.com/user-attachments/assets/a9e856c0-6ed5-4810-a7b4-59d499f5eaad)


## Enhancements
### 1. Filter Specific Protocols (HTTP - Port 80)
def packet_callback(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].dport == 80 or packet[scapy.TCP].sport == 80:
            print(f"HTTP Packet: {packet.summary()}")


### 2. Save Captured Packets to a File
```python
with open("packets.log", "a") as log_file:
    log_file.write(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}\n")
```

### 3. Capture Only Specific IP Addresses
TARGET_IP = "192.168.1.100"

def packet_callback(packet):
    if packet.haslayer(scapy.IP) and (packet[scapy.IP].src == TARGET_IP or packet[scapy.IP].dst == TARGET_IP):
        print(f"Packet from/to {TARGET_IP}: {packet.summary()}")
![image](https://github.com/user-attachments/assets/2eef7065-1280-456b-9c2e-049c6dc2d79f)

## Ethical Considerations
⚠️ **Use this tool responsibly and legally. Unauthorized network sniffing is illegal in many regions.** Ensure you:
- Only monitor networks you own or have **explicit permission** to analyze.
- Do not capture sensitive information **without consent**.
- Comply with **privacy laws** and **ethical hacking principles**.

## Recommendations
- **Enhance Security Measures**: Use this tool in a controlled environment for **penetration testing** and **network analysis**.
- **Implement Logging**: Store packet logs for future analysis to identify trends and potential threats.
- **Use with Firewalls and IDS**: Combine with **Intrusion Detection Systems (IDS)** to improve network security monitoring.
- **Expand Filtering Capabilities**: Implement advanced filters to capture only relevant traffic based on protocol, IP, or keywords.

## Conclusion
The **Network Packet Analyzer** is a powerful tool for network monitoring, security auditing, and debugging. By using Python and **Scapy**, this script enables users to **capture, analyze, and log network traffic efficiently**.
However, ethical and legal considerations must always be followed when using this tool. Further improvements, such as **log storage, filtering mechanisms, and integration with IDS systems**, can enhance its functionality and effectiveness.

.


