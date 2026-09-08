from tqdm import trange
import pandas as pd
from pathlib import Path
from scapy.all import PcapReader, rdpcap
from scapy.layers.inet import IP, UDP


file_paths = list(Path("./dataset").rglob("**/*.pcap"))
files = list(str(f) for f in file_paths)


def extract_udp_payloads(pcap_path):
    packet_list = []
    with trange(1, desc=f"Processing {pcap_path}", unit="packet") as pbar:
        with PcapReader(pcap_path) as packets:
            for pkt in packets:
                if IP in pkt and UDP in pkt:
                    # 1. Get raw bytes
                    raw_payload = bytes(pkt[UDP].payload)

                    # 2. Safely attempt to decode text (or fallback to hex representation)
                    try:
                        decoded_payload = raw_payload.decode("utf-8", errors="ignore")
                    except Exception:
                        decoded_payload = None

                    packet_list.append(
                        {
                            "time": float(pkt.time),
                            "src_ip": pkt[IP].src,
                            "dst_ip": pkt[IP].dst,
                            "src_port": pkt[UDP].sport,
                            "dst_port": pkt[UDP].dport,
                            "payload_bytes": raw_payload,  # Raw bytes object
                            "payload_hex": raw_payload.hex(),  # Readable hex string
                            "payload_text": decoded_payload,  # UTF-8 text string
                        }
                    )
                    pbar.update(1)

    return pd.DataFrame(packet_list)


def sample(pcap_path):
    packets = rdpcap(pcap_path)

    count = 0

    for pkt in packets:
        if UDP not in pkt:
            continue

        if pkt[UDP].sport != 7777 and pkt[UDP].dport != 7777:
            continue

        data = bytes(pkt[UDP].payload)

        if not data:
            continue

        print(
            f"{count:06d} "
            f"{pkt[UDP].sport} -> {pkt[UDP].dport} "
            f"len={len(data):4d} "
            f"{data[:16].hex(' ')}"
        )

        count += 1

        if count >= 100:
            break


def decode_payloads(pcap_path):
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if UDP in pkt and pkt[UDP].dport == 7777:
            payload = bytes(pkt[UDP].payload)
        payload = bytes(pkt[UDP].payload)
        handler = decode_handler_header(payload)
        if handler["handshake"]:
            result = decode_handshake(payload)
        else:
            result = decode_ue_packet(payload)
        print(result)


class BitReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read_bits(self, n):
        value = 0

        for i in range(n):
            byte_index = self.pos // 8
            bit_index = self.pos % 8

            bit = (self.data[byte_index] >> bit_index) & 1
            value |= bit << i

            self.pos += 1

        return value

    def remaining(self):
        return len(self.data) * 8 - self.pos


def decode_handler_header(data):
    r = BitReader(data)

    session_id = r.read_bits(2)
    client_id = r.read_bits(3)
    handshake = r.read_bits(1)

    return {
        "session_id": session_id,
        "client_id": client_id,
        "handshake": handshake,
        "bit_position": r.pos,
    }


def decode_handshake(data):
    r = BitReader(data)

    session_id = r.read_bits(2)
    client_id = r.read_bits(3)
    handshake = r.read_bits(1)

    if not handshake:
        return None

    restart = r.read_bits(1)

    min_version = r.read_bits(8)
    current_version = r.read_bits(8)

    packet_type = r.read_bits(8)
    packet_count = r.read_bits(8)

    network_version = r.read_bits(32)
    runtime_features = r.read_bits(16)

    return {
        "session_id": session_id,
        "client_id": client_id,
        "handshake": handshake,
        "restart": restart,
        "min_version": min_version,
        "current_version": current_version,
        "packet_type": packet_type,
        "packet_count": packet_count,
        "network_version": network_version,
        "runtime_features": runtime_features,
        "bits_consumed": r.pos,
    }


def decode_ue_packet(data):
    r = BitReader(data)

    # StatelessConnect handler
    session_id = r.read_bits(2)
    client_id = r.read_bits(3)
    handshake = r.read_bits(1)

    if handshake:
        return {
            "type": "handshake",
            "session_id": session_id,
            "client_id": client_id,
        }

    # Normal UE packet
    # Continue into packet-notify header...

    return {
        "type": "normal",
        "session_id": session_id,
        "client_id": client_id,
    }


def decode_packet_notify(r):
    history_count = r.read_bits(4)
    acked_seq = r.read_bits(14)
    seq = r.read_bits(14)

    return {
        "history_count": history_count,
        "acked_seq": acked_seq,
        "seq": seq,
    }


sample(files[0])
# decode_payloads(files[0])
# df = extract_udp_payloads(files[0])
# print(df.head())
# df.to_csv("raw_payload.csv", index=False)
# print(f"First record payload bytes: {df.iloc[0]['payload_bytes']}")
# print(f"First record payload hex: {df.iloc[0]['payload_hex']}")
# print(f"First record payload text: {df.iloc[0]['payload_text']}")
