import pandas as pd
import glob
from scapy.all import rdpcap, IP, UDP
import os

rows = []
files = glob.glob("Session_1/Match_1/Server/*.pcap")
for file in files:
    packets = rdpcap(file)
    for i, pkt in enumerate(packets):
        row = {
            "file": os.path.basename(file),
            "packet_no": i + 1,
            "timestamp": float(pkt.time),
            "packet_length": len(pkt),
        }
        if IP in pkt:
            row["src_ip"] = pkt[IP].src
            row["dst_ip"] = pkt[IP].dst
            row["ttl"] = pkt[IP].ttl
            row["protocol"] = pkt[IP].proto
        elif UDP in pkt:
            row["transport"] = "UDP"
            row["src_port"] = pkt[UDP].sport
            row["dst_port"] = pkt[UDP].dport
            row["payload_size"] = len(pkt[UDP].payload)
        rows.append(row)
df = pd.DataFrame(rows)
df["iat"] = df["timestamp"].diff()
df["iat"] = df["iat"].fillna(0)
df["std_size_20"] = df["packet_length"].rolling(window=20, min_periods=0).std()
df["rolling_rate"] = 5 / df["timestamp"].diff(5)
df["rolling_rate"] = df["rolling_rate"].fillna(0)
df["jitter"] = df["iat"].rolling(window=5, min_periods=1).std()
df = df.fillna(0)
df.to_csv("packets.csv", index=False)
print(df.head())
print(df.shape)
