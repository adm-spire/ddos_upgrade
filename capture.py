import pyshark
import pandas as pd
import numpy as np
from collections import defaultdict
import time

# Define the network interface (use "Wi-Fi" or "eth0" based on your system)
INTERFACE = "Wi-Fi"  # Change to your active network interface
CAPTURE_DURATION = 60  # Capture traffic for 60 seconds
OUTPUT_CSV = "captured_traffic.csv"

# Initialize flow statistics storage
flow_stats = defaultdict(lambda: {
    "Source IP": "",
    "Source Port": 0,
    "Average Packet Size": [],
    "Fwd Packet Length Min": np.inf,
    "Packet Length Mean": [],
    "Subflow Fwd Bytes": 0,
    "Fwd Packet Length Mean": [],
    "Total Length of Fwd Packets": 0,
    "Fwd Packet Length Max": 0,
    "Max Packet Length": 0,
    "Min Packet Length": np.inf,
    "Avg Fwd Segment Size": [],
    "Fwd IAT Mean": [],
    "Flow IAT Mean": [],
    "Flow Bytes/s": 0,
    "Fwd IAT Min": np.inf,
    "Fwd IAT Max": 0,
    "Flow IAT Min": np.inf,
    "Flow IAT Max": 0,
    "Flow Packets/s": 0,
    "Flow Duration": 0,
    "Fwd Packets/s": 0,
    "Start Time": None
})

# Function to process captured packets
def process_packet(packet):
    try:
        if "IP" in packet and "TCP" in packet:  # Consider only TCP/IP packets
            src_ip = packet.ip.src
            src_port = packet.tcp.srcport
            pkt_length = int(packet.length)
            timestamp = float(packet.sniff_time.timestamp())  # Get packet timestamp

            flow_key = (src_ip, src_port)  # Unique key for each flow

            # Initialize flow start time
            if flow_stats[flow_key]["Start Time"] is None:
                flow_stats[flow_key]["Start Time"] = timestamp

            # Compute flow duration
            flow_stats[flow_key]["Flow Duration"] = timestamp - flow_stats[flow_key]["Start Time"]

            # Update flow statistics
            flow_stats[flow_key]["Source IP"] = src_ip
            flow_stats[flow_key]["Source Port"] = src_port
            flow_stats[flow_key]["Average Packet Size"].append(pkt_length)
            flow_stats[flow_key]["Packet Length Mean"].append(pkt_length)
            flow_stats[flow_key]["Fwd Packet Length Mean"].append(pkt_length)
            flow_stats[flow_key]["Avg Fwd Segment Size"].append(pkt_length)
            flow_stats[flow_key]["Total Length of Fwd Packets"] += pkt_length
            flow_stats[flow_key]["Subflow Fwd Bytes"] += pkt_length

            # Update Min/Max statistics
            flow_stats[flow_key]["Fwd Packet Length Min"] = min(flow_stats[flow_key]["Fwd Packet Length Min"], pkt_length)
            flow_stats[flow_key]["Fwd Packet Length Max"] = max(flow_stats[flow_key]["Fwd Packet Length Max"], pkt_length)
            flow_stats[flow_key]["Max Packet Length"] = max(flow_stats[flow_key]["Max Packet Length"], pkt_length)
            flow_stats[flow_key]["Min Packet Length"] = min(flow_stats[flow_key]["Min Packet Length"], pkt_length)
            flow_stats[flow_key]["Fwd IAT Min"] = min(flow_stats[flow_key]["Fwd IAT Min"], timestamp)
            flow_stats[flow_key]["Fwd IAT Max"] = max(flow_stats[flow_key]["Fwd IAT Max"], timestamp)
            flow_stats[flow_key]["Flow IAT Min"] = min(flow_stats[flow_key]["Flow IAT Min"], timestamp)
            flow_stats[flow_key]["Flow IAT Max"] = max(flow_stats[flow_key]["Flow IAT Max"], timestamp)

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
    data.append({
        "Source IP": stats["Source IP"],
        "Source Port": stats["Source Port"],
        "Average Packet Size": np.mean(stats["Average Packet Size"]) if stats["Average Packet Size"] else 0,
        "Fwd Packet Length Min": stats["Fwd Packet Length Min"],
        "Packet Length Mean": np.mean(stats["Packet Length Mean"]) if stats["Packet Length Mean"] else 0,
        "Subflow Fwd Bytes": stats["Subflow Fwd Bytes"],
        "Fwd Packet Length Mean": np.mean(stats["Fwd Packet Length Mean"]) if stats["Fwd Packet Length Mean"] else 0,
        "Total Length of Fwd Packets": stats["Total Length of Fwd Packets"],
        "Fwd Packet Length Max": stats["Fwd Packet Length Max"],
        "Max Packet Length": stats["Max Packet Length"],
        "Min Packet Length": stats["Min Packet Length"],
        "Avg Fwd Segment Size": np.mean(stats["Avg Fwd Segment Size"]) if stats["Avg Fwd Segment Size"] else 0,
        "Fwd IAT Mean": np.mean(stats["Fwd IAT Mean"]) if stats["Fwd IAT Mean"] else 0,
        "Flow IAT Mean": np.mean(stats["Flow IAT Mean"]) if stats["Flow IAT Mean"] else 0,
        "Flow Bytes/s": stats["Flow Bytes/s"],
        "Fwd IAT Min": stats["Fwd IAT Min"],
        "Fwd IAT Max": stats["Fwd IAT Max"],
        "Flow IAT Min": stats["Flow IAT Min"],
        "Flow IAT Max": stats["Flow IAT Max"],
        "Flow Packets/s": stats["Flow Packets/s"],
        "Flow Duration": stats["Flow Duration"],
        "Fwd Packets/s": stats["Fwd Packets/s"]
    })

# Save to CSV
df = pd.DataFrame(data)
df.to_csv(OUTPUT_CSV, index=False)
print(f"\n Captured traffic saved to {OUTPUT_CSV}")
