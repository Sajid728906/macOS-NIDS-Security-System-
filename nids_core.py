import os
import sys
import socket 
from scapy.all import sniff, IP, TCP, Raw
from collections import defaultdict
import time 
from datetime import datetime

LOG_FILE_PATH = "/Users/Shared/nids_blocked_ips.txt"

packet_count_buffer = defaultdict(int)
port_scan_buffer = defaultdict(set)
blacklist_ips = set()

def get_mac_own_ip():
    """this for identify your own ip """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        own_ip = s.getsockname()[0]
        s.close()
        return own_ip
    except Exception:
        return "192.168.1.108" # 

MAC_OWN_IP = get_mac_own_ip()

# 
whitelist_ips = {
    "127.0.0.1",   # Localhost
    "8.8.8.8",     # Google Primary DNS
    "8.8.4.4",     # Google Secondary DNS
    "1.1.1.1",     # Cloudflare DNS
    MAC_OWN_IP     # 
}

DDOS_THRESHOLD = 20
PORT_SCAN_THRESHOLD = 5

def log_blocked_ip_to_file(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    try:
        with open(LOG_FILE_PATH, "a") as f:
            f.write(log_entry)
            f.flush()
    except Exception:
        pass

def load_existing_blacklist():
    """your data does not erase after restart"""
    if os.path.exists(LOG_FILE_PATH):
        try:
            with open(LOG_FILE_PATH, "r") as f:
                for line in f:
                    if "BLOCKED ATTACKER IP:" in line:
                        # 
                        parts = line.split("BLOCKED ATTACKER IP:")
                        if len(parts) > 1:
                            ip_part = parts[1].split("|")[0].strip()
                            if ip_part not in whitelist_ips:
                                blacklist_ips.add(ip_part)
        except Exception:
            pass

def isolate_attacker_ip_mac(ip_to_block, reason):
    # 
    if ip_to_block in whitelist_ips or ip_to_block == MAC_OWN_IP:
        return

    rule = f"block drop from {ip_to_block} to any"
    try:
        command = f'echo "{rule}" | pfctl -a nids_block_{ip_to_block} -f -'
        exit_code = os.system(command)
        os.system("pfctl -e > /dev/null 2>&1")
        
        if exit_code == 0:
            log_blocked_ip_to_file(f"BLOCKED ATTACKER IP: {ip_to_block} | Reason: {reason} | Status: Success")
        else:
            log_blocked_ip_to_file(f"ERROR: Failed to block {ip_to_block}. Code: {exit_code}")
    except Exception as e:
        log_blocked_ip_to_file(f"FIREWALL ERROR for {ip_to_block}: {str(e)}")

def packet_analysis_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src

        # 
        if src_ip in blacklist_ips or src_ip in whitelist_ips:
            return

        # 1. DDoS Detection Logic
        packet_count_buffer[src_ip] += 1
        if packet_count_buffer[src_ip] > DDOS_THRESHOLD:
            blacklist_ips.add(src_ip)
            isolate_attacker_ip_mac(src_ip, "DDoS Attack Vector (High Burst Rates)")
            return

        # 2. Port Scan Detection Logic
        if packet.haslayer(TCP):
            target_port = packet[TCP].dport
            port_scan_buffer[src_ip].add(target_port)

            if len(port_scan_buffer[src_ip]) > PORT_SCAN_THRESHOLD:
                blacklist_ips.add(src_ip)
                isolate_attacker_ip_mac(src_ip, f"Port Scan Detected (Ports: {list(port_scan_buffer[src_ip])})")
                return

        # 3. Malicious Injection Logic
        if packet.haslayer(Raw):
            try:
                raw_payload_data = packet[Raw].load.decode('utf-8', errors='ignore')
                threat_signatures = ["<script>", "union select", "admin'--", "exec("]

                for pattern in threat_signatures:
                    if pattern in raw_payload_data.lower():
                        blacklist_ips.add(src_ip)
                        isolate_attacker_ip_mac(src_ip, f"Malicious Injection Attempt ({pattern})")
                        return
            except Exception:
                pass

if __name__ == "__main__":
    log_blocked_ip_to_file(f"NIDS Fully Loaded. Mac IP ({MAC_OWN_IP}) Whitelisted.")
    
    #
    load_existing_blacklist()
    
    try:
        sniff(iface="en0", prn=packet_analysis_callback, store=0)
    except Exception as e:
        log_blocked_ip_to_file(f"CRITICAL RUNTIME ERROR: {str(e)}")
