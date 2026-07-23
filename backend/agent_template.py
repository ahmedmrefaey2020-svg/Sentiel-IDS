import requests
import time
import sys

TOKEN = "REPLACE_WITH_USER_TOKEN"
SERVER_URL = "REPLACE_WITH_YOUR_SITE_URL"

HAS_SCAPY = False
try:
    from scapy.all import sniff, IP, TCP, UDP
    HAS_SCAPY = True
except ImportError:
    pass

def send_traffic(traffic_data):
    headers = {"token": TOKEN, "Content-Type": "application/json"}
    try:
        response = requests.post(f"{SERVER_URL}/api/external-data-ingest", json=traffic_data, headers=headers, timeout=5)
        print(f"Data sent. Response: {response.status_code}")
    except Exception as e:
        print(f"Failed to transmit telemetry: {e}")

scapy_failed = False
if HAS_SCAPY:
    print("Scapy detected. Starting live network packet capture...")
    def packet_callback(packet):
        if packet.haslayer(IP):
            src_bytes = len(packet)
            protocol = "tcp" if packet.haslayer(TCP) else ("udp" if packet.haslayer(UDP) else "other")
            port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)
            service = "http" if port == 80 else ("https" if port == 443 else "other")
            
            data = {
                "duration": 0.0,
                "protocol_type": protocol,
                "service": service,
                "src_bytes": src_bytes,
                "dst_bytes": 0,
                "count": 1
            }
            send_traffic(data)
    try:
        sniff(prn=packet_callback, store=False)
    except Exception as e:
        print(f"Scapy capture error: {e}. Falling back to simulation mode.")
        scapy_failed = True

if not HAS_SCAPY or scapy_failed:
    print("Simulating traffic logs telemetry...")
    while True:
        simulated_data = {
            "duration": 0.0,
            "protocol_type": "tcp",
            "service": "https",
            "src_bytes": 1024,
            "dst_bytes": 512,
            "count": 1
        }
        send_traffic(simulated_data)
        time.sleep(2)