import pyshark
import pandas as pd
import numpy as np
from collections import defaultdict
import time

# Define network interface
INTERFACE = "Wi-Fi 2"  # Change this to your active interface
CAPTURE_DURATION = 60  # Capture time in seconds
OUTPUT_CSV = "captured_traffic.csv"

# Initialize flow statistics storage
flow_stats = defaultdict(lambda: {
    "Source IP": "",
    "Source Port": 0,
    "Flow Duration": 0,
    "Total Length of Fwd Packets": 0,
    "Fwd Packet Lengths": [],
    "Flow IATs": [],
    "Fwd IATs": [],
    "Flow Bytes/s": 0,
    "Flow Packets/s": 0,
    "Fwd Packets/s": 0,
    "Start Time": None,
    "Last Packet Time": None
})

# Function to process packets
def process_packet(packet):
    try:
        if "IP" in packet and ("TCP" in packet or "UDP" in packet):
            src_ip = packet.ip.src
            protocol = packet.transport_layer  # TCP/UDP
            timestamp = float(packet.sniff_time.timestamp())

            src_port = int(packet[protocol].srcport)
            pkt_length = int(packet.length)
            
            # Identify the flow key
            flow_key = (src_ip, src_port, protocol)
            
            # Initialize flow start time
            if flow_stats[flow_key]["Start Time"] is None:
                flow_stats[flow_key]["Start Time"] = timestamp
            
            # Compute flow duration
            flow_stats[flow_key]["Flow Duration"] = timestamp - flow_stats[flow_key]["Start Time"]

            # Update flow statistics
            flow_stats[flow_key]["Source IP"] = src_ip
            flow_stats[flow_key]["Source Port"] = src_port

            # Compute Inter-Arrival Time (IAT)
            if flow_stats[flow_key]["Last Packet Time"] is not None:
                iat = timestamp - flow_stats[flow_key]["Last Packet Time"]
                flow_stats[flow_key]["Flow IATs"].append(iat)
                flow_stats[flow_key]["Fwd IATs"].append(iat)

            # Update packet lengths
            flow_stats[flow_key]["Total Length of Fwd Packets"] += pkt_length
            flow_stats[flow_key]["Fwd Packet Lengths"].append(pkt_length)

            # Compute Flow Bytes/sec
            if flow_stats[flow_key]["Flow Duration"] > 0:
                flow_stats[flow_key]["Flow Bytes/s"] = flow_stats[flow_key]["Total Length of Fwd Packets"] / flow_stats[flow_key]["Flow Duration"]
            
            # Update last packet time
            flow_stats[flow_key]["Last Packet Time"] = timestamp

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start packet capture
print(f"Starting packet capture on interface {INTERFACE} for {CAPTURE_DURATION} seconds...")
capture = pyshark.LiveCapture(interface=INTERFACE)

# Capture packets for a fixed duration
start_time = time.time()
for packet in capture.sniff_continuously():
    if time.time() - start_time > CAPTURE_DURATION:
        break
    process_packet(packet)

# Convert statistics into DataFrame
data = []
for flow_key, stats in flow_stats.items():
    stats["Packet Length Mean"] = np.mean(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0
    stats["Fwd Packet Length Min"] = np.min(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0
    stats["Fwd Packet Length Max"] = np.max(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0
    stats["Max Packet Length"] = stats["Fwd Packet Length Max"]
    stats["Min Packet Length"] = stats["Fwd Packet Length Min"]
    stats["Avg Fwd Segment Size"] = stats["Packet Length Mean"]
    stats["Subflow Fwd Bytes"] = stats["Total Length of Fwd Packets"]
    stats["Fwd Packet Length Mean"] = stats["Packet Length Mean"]
    
    stats["Flow IAT Mean"] = np.mean(stats["Flow IATs"]) if stats["Flow IATs"] else 0
    stats["Flow IAT Min"] = np.min(stats["Flow IATs"]) if stats["Flow IATs"] else 0
    stats["Flow IAT Max"] = np.max(stats["Flow IATs"]) if stats["Flow IATs"] else 0

    stats["Fwd IAT Mean"] = np.mean(stats["Fwd IATs"]) if stats["Fwd IATs"] else 0
    stats["Fwd IAT Min"] = np.min(stats["Fwd IATs"]) if stats["Fwd IATs"] else 0
    stats["Fwd IAT Max"] = np.max(stats["Fwd IATs"]) if stats["Fwd IATs"] else 0
    
    stats["Flow Packets/s"] = len(stats["Fwd Packet Lengths"]) / stats["Flow Duration"] if stats["Flow Duration"] > 0 else 0
    stats["Fwd Packets/s"] = stats["Flow Packets/s"]
    
    data.append(stats)

df = pd.DataFrame(data)

# Select only required columns
columns = [
    "Source IP", "Source Port", "Packet Length Mean", "Fwd Packet Length Min", "Subflow Fwd Bytes",
    "Fwd Packet Length Mean", "Total Length of Fwd Packets", "Fwd Packet Length Max",
    "Max Packet Length", "Min Packet Length", "Avg Fwd Segment Size", "Fwd IAT Mean", "Flow IAT Mean",
    "Flow Bytes/s", "Fwd IAT Min", "Fwd IAT Max", "Flow IAT Min", "Flow IAT Max", "Flow Packets/s",
    "Flow Duration", "Fwd Packets/s"
]

df = df[columns]
df.to_csv(OUTPUT_CSV, index=False)

print(f"Packet capture completed. Data saved to {OUTPUT_CSV}")


