import pyshark
import pandas as pd
import numpy as np
from collections import defaultdict
import time

# Define the network interface (use "Wi-Fi" or "eth0" based on your system)
INTERFACE = "Wi-Fi"  # Change to your active network interface
CAPTURE_DURATION = 200  # Capture traffic for 200 seconds
OUTPUT_CSV = "captured_traffic.csv"

# Initialize flow statistics storage
flow_stats = defaultdict(lambda: {
    "Source IP": "",
    "Source Port": 0,
    "Destination IP": "",
    "Destination Port": 0,
    "Protocol": "",
    "Timestamp": 0,
    "Flow Duration": 0,
    "Total Fwd Packets": 0,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 0,
    "Total Length of Bwd Packets": 0,
    "Fwd Packet Length Max": 0,
    "Fwd Packet Length Min": np.inf,
    "Fwd Packet Length Mean": [],
    "Fwd Packet Length Std": [],
    "Bwd Packet Length Max": 0,
    "Bwd Packet Length Min": np.inf,
    "Bwd Packet Length Mean": [],
    "Bwd Packet Length Std": [],
    "Flow Bytes/s": 0,
    "Flow Packets/s": 0,
    "Flow IAT Mean": [],
    "Flow IAT Std": [],
    "Flow IAT Max": 0,
    "Flow IAT Min": np.inf,
    "Fwd IAT Total": 0,
    "Fwd IAT Mean": [],
    "Fwd IAT Std": [],
    "Fwd IAT Max": 0,
    "Fwd IAT Min": np.inf,
    "Bwd IAT Total": 0,
    "Bwd IAT Mean": [],
    "Bwd IAT Std": [],
    "Bwd IAT Max": 0,
    "Bwd IAT Min": np.inf,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 0,
    "Bwd Header Length": 0,
    "Fwd Packets/s": 0,
    "Bwd Packets/s": 0,
    "Min Packet Length": np.inf,
    "Max Packet Length": 0,
    "Packet Length Mean": [],
    "Packet Length Std": [],
    "Packet Lengths": [],
    "FIN Flag Count": 0,
    "SYN Flag Count": 0,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 0,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 0,
    "Start Time": None
})

# Function to process captured packets
def process_packet(packet):
    try:
        if "IP" in packet and ("TCP" in packet or "UDP" in packet):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer  # TCP/UDP
            timestamp = float(packet.sniff_time.timestamp())

            src_port = int(packet[protocol].srcport)
            dst_port = int(packet[protocol].dstport)
            pkt_length = int(packet.length)
            
            flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)

            # Initialize flow start time
            if flow_stats[flow_key]["Start Time"] is None:
                flow_stats[flow_key]["Start Time"] = timestamp
                flow_stats[flow_key]["Timestamp"] = timestamp

            # Compute flow duration
            flow_stats[flow_key]["Flow Duration"] = timestamp - flow_stats[flow_key]["Start Time"]

            # Update flow statistics
            flow_stats[flow_key]["Source IP"] = src_ip
            flow_stats[flow_key]["Source Port"] = src_port
            flow_stats[flow_key]["Destination IP"] = dst_ip
            flow_stats[flow_key]["Destination Port"] = dst_port
            flow_stats[flow_key]["Protocol"] = protocol

            # Update packet count
            flow_stats[flow_key]["Total Fwd Packets"] += 1
            flow_stats[flow_key]["Total Length of Fwd Packets"] += pkt_length
            
            # Store packet lengths
            flow_stats[flow_key]["Packet Lengths"].append(pkt_length)
            
            # Update Min/Max statistics
            flow_stats[flow_key]["Fwd Packet Length Min"] = min(flow_stats[flow_key]["Fwd Packet Length Min"], pkt_length)
            flow_stats[flow_key]["Fwd Packet Length Max"] = max(flow_stats[flow_key]["Fwd Packet Length Max"], pkt_length)
            flow_stats[flow_key]["Max Packet Length"] = max(flow_stats[flow_key]["Max Packet Length"], pkt_length)
            flow_stats[flow_key]["Min Packet Length"] = min(flow_stats[flow_key]["Min Packet Length"], pkt_length)
            
            # Calculate Flow Bytes/sec
            if flow_stats[flow_key]["Flow Duration"] > 0:
                flow_stats[flow_key]["Flow Bytes/s"] = flow_stats[flow_key]["Total Length of Fwd Packets"] / flow_stats[flow_key]["Flow Duration"]

            # Count packets per second
            flow_stats[flow_key]["Flow Packets/s"] += 1
            flow_stats[flow_key]["Fwd Packets/s"] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start live capture
print(f"Starting packet capture on interface {INTERFACE} for {CAPTURE_DURATION} seconds...")
capture = pyshark.LiveCapture(interface=INTERFACE)

# Capture packets for a fixed duration
start_time = time.time()
for packet in capture.sniff_continuously():
    if time.time() - start_time > CAPTURE_DURATION:
        break
    process_packet(packet)

# Convert statistics into a DataFrame
data = []
for flow_key, stats in flow_stats.items():
    stats["Packet Length Mean"] = np.mean(stats["Packet Lengths"]) if stats["Packet Lengths"] else 0
    stats["Packet Length Std"] = np.std(stats["Packet Lengths"]) if stats["Packet Lengths"] else 0
    data.append(stats)

df = pd.DataFrame(data)
df.to_csv(OUTPUT_CSV, index=False)

print(f"Packet capture completed. Data saved to {OUTPUT_CSV}")
