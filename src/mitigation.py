def analyze_attacker_path(traffic_features: dict, attack_prob: float):
    packets = traffic_features.get("total_packets", 0)
    bytes_cnt = traffic_features.get("total_bytes", 0)
    
    if attack_prob < 0.4:
        return {
            "detected_stage": "Normal Traffic",
            "predicted_next_move": "No immediate threat detected",
            "action_required": "None",
            "firewall_rule": "N/A"
        }

    if packets > 100 and bytes_cnt < 2000:
        return {
            "detected_stage": "Port Scanning / Reconnaissance",
            "predicted_next_move": "Brute Force attempt on SSH/FTP ports (Port 22/21)",
            "action_required": "Block IP & Enable Rate Limiting",
            "firewall_rule": "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set"
        }
    elif packets > 300 and bytes_cnt > 10000:
        return {
            "detected_stage": "Volume-based DDoS Attack",
            "predicted_next_move": "Targeting Main Server Availability / Crash Internal Gateway",
            "action_required": "Activate Cloudflare Scrubbing & Throttling",
            "firewall_rule": "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT"
        }
    else:
        return {
            "detected_stage": "Lateral Probing & Exploitation",
            "predicted_next_move": "Targeting Internal Database Server (Port 3306)",
            "action_required": "Isolate Subnet & Reroute Attacker to Decoy Honeypot",
            "firewall_rule": "iptables -A FORWARD -d 10.0.1.50 -j DROP"
        }
