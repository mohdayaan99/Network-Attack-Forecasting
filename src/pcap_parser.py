"""
PCAP Parser & Low-level Packet Feature Extractor
"""
import logging
import numpy as np
import pandas as pd
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def parse_pcap_to_flow_records(packets_stream) -> pd.DataFrame:
    """
    Simulated/Scapy packet stream reader to aggregate packets into flow-level records
    with TTL variance, TCP window sizes, and flag distributions.
    """
    logger.info("Extracting flow records from packet stream...")
    flows = defaultdict(lambda: {
        "timestamps": [],
        "packet_lengths": [],
        "ttls": [],
        "tcp_windows": [],
        "syn_flags": 0,
        "ack_flags": 0,
        "rst_flags": 0,
        "src_ports": set(),
        "dst_ports": set()
    })

    # Flow key format: (src_ip, dst_ip, proto)
    for pkt in packets_stream:
        key = (pkt.get("src_ip"), pkt.get("dst_ip"), pkt.get("protocol"))
        flow = flows[key]
        
        flow["timestamps"].append(pkt.get("timestamp", 0))
        flow["packet_lengths"].append(pkt.get("length", 0))
        flow["ttls"].append(pkt.get("ttl", 64))
        flow["tcp_windows"].append(pkt.get("window_size", 0))
        flow["src_ports"].add(pkt.get("src_port"))
        flow["dst_ports"].add(pkt.get("dst_port"))
        
        if pkt.get("is_syn"): flow["syn_flags"] += 1
        if pkt.get("is_ack"): flow["ack_flags"] += 1
        if pkt.get("is_rst"): flow["rst_flags"] += 1

    extracted_records = []
    for (src_ip, dst_ip, proto), metrics in flows.items():
        ts = np.array(metrics["timestamps"])
        lens = np.array(metrics["packet_lengths"])
        ttls = np.array(metrics["ttls"])
        wins = np.array(metrics["tcp_windows"])

        duration = (ts.max() - ts.min()) if len(ts) > 1 else 0.0
        iats = np.diff(np.sort(ts)) if len(ts) > 1 else np.array([0.0])

        extracted_records.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "flow_duration": duration,
            "total_packets": len(lens),
            "total_bytes": int(lens.sum()),
            "packet_length_std": float(np.std(lens)) if len(lens) > 1 else 0.0,
            "iat_mean": float(np.mean(iats)),
            "iat_std": float(np.std(iats)) if len(iats) > 1 else 0.0,
            "syn_flag_count": metrics["syn_flags"],
            "ack_flag_count": metrics["ack_flags"],
            "rst_flag_count": metrics["rst_flags"],
            "ttl_variance": float(np.var(ttls)) if len(ttls) > 1 else 0.0,
            "tcp_window_mean": float(np.mean(wins)) if len(wins) > 0 else 0.0,
            "unique_dst_ports": len(metrics["dst_ports"])
        })

    logger.info(f"Processed {len(extracted_records)} unique flows from packet stream.")
    return pd.DataFrame(extracted_records)