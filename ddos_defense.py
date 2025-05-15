import os
import json
import psutil
import socket
import time
import threading
import subprocess
import requests
from scapy.all import sniff, IP
from rich.console import Console
from rich.table import Table

# === CONFIG SETUP ===
CONFIG_DIR = "config"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

DEFAULT_CONFIG = {
    "ip_detection": {
        "ip_method": "src"
    },
    "firewall": {
        "firewall_system": "iptables"
    },
    "notification": {
        "webhook_url": ""
    },
    "triggers": {
        "detection_threshold": 1000,
        "pps_threshold": 500,
        "trigger_mode": "auto",
        "mitigation_pause": 60,
        "mbps_threshold": 100,
        "packet_count": 1000
    },
    "capture": {
        "network_interface": "eth0",
        "filter_arguments": ""
    },
    "whitelist": {
        "trusted_ips": "127.0.0.1, localhost"
    },
    "advanced_mitigation": {
        "enable_fallback_blocking": True,
        "block_other_attack_contributors": False,
        "enable_pattern_detection": True,
        "block_autodetected_patterns": True,
        "contributor_threshold": 30,
        "max_pcap_files": 10
    },
    "external_firewall": {
        "sending_mode": "batch",
        "max_ips_per_batch": 10
    }
}

# Ensure config directory and file
if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)
    print(f"✅ Created config directory at {CONFIG_DIR}")

if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)
    print(f"✅ Created default config file at {CONFIG_FILE}")

# Load configuration
with open(CONFIG_FILE) as f:
    config = json.load(f)

# === SYSTEM SETUP ===
ip_method = config["ip_detection"]["ip_method"]
firewall_system = config["firewall"]["firewall_system"]
webhook_url = config["notification"]["webhook_url"]
detection_threshold = int(config["triggers"]["detection_threshold"])
pps_threshold = int(config["triggers"]["pps_threshold"])
trigger_mode = config["triggers"]["trigger_mode"]
mitigation_pause = int(config["triggers"]["mitigation_pause"])
mbps_threshold = int(config["triggers"]["mbps_threshold"])
packet_count_threshold = int(config["triggers"]["packet_count"])
network_interface = config["capture"]["network_interface"]
filter_arguments = config["capture"]["filter_arguments"]
trusted_ips = set(config["whitelist"]["trusted_ips"].split(", "))

# Advanced mitigation
advanced = config.get("advanced_mitigation", {})
enable_fallback_blocking = advanced.get("enable_fallback_blocking", True)
block_other_attack_contributors = advanced.get("block_other_attack_contributors", False)
enable_pattern_detection = advanced.get("enable_pattern_detection", True)
block_autodetected_patterns = advanced.get("block_autodetected_patterns", True)
contributor_threshold = int(advanced.get("contributor_threshold", 30))
max_pcap_files = int(advanced.get("max_pcap_files", 10))

# External firewall
external_fw = config.get("external_firewall", {})
sending_mode = external_fw.get("sending_mode", "batch")
max_ips_per_batch = int(external_fw.get("max_ips_per_batch", 10))

VPS_IP = socket.gethostbyname(socket.gethostname())

# === TRACKERS ===
ip_packet_counts = {}
blocked_ips = {}
attack_patterns = {}
batch_queue = []

console = Console()

def block_ip(ip):
    if ip not in blocked_ips and ip not in trusted_ips:
        console.print(f"[red]🚫 Blocking IP: {ip}[/red]")
        if firewall_system == "iptables":
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        blocked_ips[ip] = time.time()
        batch_queue.append(ip)
        send_webhook(f"Blocked IP: {ip} due to DDoS detection.")

def unblock_ip(ip):
    console.print(f"[green]✅ Unblocking IP: {ip}[/green]")
    if firewall_system == "iptables":
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    del blocked_ips[ip]

def send_webhook(message):
    if not webhook_url:
        return
    try:
        requests.post(webhook_url, json={"text": message})
    except Exception as e:
        console.print(f"[yellow]⚠️ Webhook send failed: {e}[/yellow]")

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src if ip_method == "src" else packet[IP].dst
        if src_ip not in trusted_ips:
            ip_packet_counts[src_ip] = ip_packet_counts.get(src_ip, 0) + 1

            if enable_pattern_detection:
                proto = packet.proto if hasattr(packet, 'proto') else 'unknown'
                attack_patterns[proto] = attack_patterns.get(proto, 0) + 1

def monitor_packets():
    sniff(prn=packet_callback, store=0, iface=network_interface, filter=filter_arguments)

def detect_attacks():
    while True:
        time.sleep(1)
        total_packets = sum(ip_packet_counts.values())

        if enable_fallback_blocking and total_packets > detection_threshold * 10:
            console.print("[red]⚠️ Fallback: blocking all suspicious traffic[/red]")
            for ip in ip_packet_counts.keys():
                block_ip(ip)

        for ip, count in list(ip_packet_counts.items()):
            if count > pps_threshold:
                block_ip(ip)

                if block_other_attack_contributors:
                    for other_ip, other_count in ip_packet_counts.items():
                        if other_count > contributor_threshold:
                            block_ip(other_ip)

        if block_autodetected_patterns:
            for pattern, count in attack_patterns.items():
                if count > contributor_threshold:
                    console.print(f"[red]🚨 Blocking pattern: {pattern}[/red]")
                    send_webhook(f"Blocked pattern: {pattern}")

        ip_packet_counts.clear()
        attack_patterns.clear()

        now = time.time()
        for ip in list(blocked_ips.keys()):
            if now - blocked_ips[ip] > mitigation_pause:
                unblock_ip(ip)

def send_blocked_ips_batch():
    while True:
        if sending_mode == "batch" and batch_queue:
            batch = []
            while batch_queue and len(batch) < max_ips_per_batch:
                batch.append(batch_queue.pop(0))
            try:
                requests.post("https://external-firewall.example.com/block", json={"ips": batch})
                console.print(f"[blue]✅ Sent batch to external firewall: {batch}[/blue]")
            except Exception as e:
                console.print(f"[yellow]⚠️ Failed to send batch: {e}[/yellow]")
        time.sleep(5)

def display_monitor():
    while True:
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent

        table = Table(title="🚨 VPS DDoS Monitor 🚨")
        table.add_column("Metric", style="cyan", justify="right")
        table.add_column("Value", style="magenta")

        table.add_row("VPS IP", VPS_IP)
        table.add_row("CPU Usage (%)", f"{cpu}%")
        table.add_row("RAM Usage (%)", f"{ram}%")
        table.add_row("Blocked IPs", f"{len(blocked_ips)}")

        if blocked_ips:
            blocked_list = ", ".join(blocked_ips.keys())
            table.add_row("Blocked List", blocked_list)

        console.clear()
        console.print(table)

        time.sleep(1)

if __name__ == "__main__":
    console.print("[bold blue]Starting Auto-DDoS Defense System with Advanced Mitigation and External Firewall Integration...[/bold blue]")
    threading.Thread(target=monitor_packets, daemon=True).start()
    threading.Thread(target=detect_attacks, daemon=True).start()
    threading.Thread(target=send_blocked_ips_batch, daemon=True).start()
    display_monitor()
