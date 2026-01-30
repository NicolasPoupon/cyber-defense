from scapy.all import *
from collections import defaultdict
import time
import threading
import os
import subprocess

# ===== CONFIG =====
LOG_FILE = "connections.log"
WHITE_FILE = "list/white.list"
BLACK_FILE = "list/black.list"

BLOCK_THRESHOLD = 50
TIME_WINDOW = 60
DDOS_WINDOW = 5
DDOS_ALERT = 100
DDOS_BLOCK = 300
DECAY_FACTOR = 0.7

BASTION_IP = "10.10.10.111"
INTERNAL_NET_PREFIX = "192.168.11."

BPF_FILTER = "(tcp port 22 or tcp port 80) or net 192.168.11.0/24"

# ===== LOAD LISTS =====
def load_list(file_path):
    if not os.path.exists(file_path):
        return set()
    with open(file_path, "r") as f:
        return set(line.strip() for line in f if line.strip())

WHITELIST = load_list(WHITE_FILE)
BLACKLIST = load_list(BLACK_FILE)

# ===== DATA =====
stats = defaultdict(lambda: {
    "syn_times": [],
    "ssh_times": [],
    "ddos_times": [],
    "vscan_ports": defaultdict(set),
    "hscan_targets": defaultdict(set),
    "vscan": 0,
    "hscan": 0,
    "score": 0,
    "blocked": False
})

lock = threading.Lock()

# ===== UTIL =====
def is_incoming(ip_dst):
    return ip_dst == BASTION_IP or ip_dst.startswith(INTERNAL_NET_PREFIX)

def cleanup(ip):
    now = time.time()
    stats[ip]["syn_times"] = [t for t in stats[ip]["syn_times"] if now - t < TIME_WINDOW]
    stats[ip]["ssh_times"] = [t for t in stats[ip]["ssh_times"] if now - t < TIME_WINDOW]
    stats[ip]["ddos_times"] = [t for t in stats[ip]["ddos_times"] if now - t < DDOS_WINDOW]

def decay_scores():
    while True:
        time.sleep(60)
        with lock:
            for ip in stats:
                stats[ip]["score"] *= DECAY_FACTOR

# ===== LOG =====
def log_event(ip, action):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {ip} -> {action}\n")

# ===== IPTABLES =====
def apply_iptables_block(ip):
    subprocess.call(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
    result = subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    return result == 0

def add_to_blacklist(ip):
    if ip in BLACKLIST:
        return
    with open(BLACK_FILE, "a") as f:
        f.write(ip + "\n")
    BLACKLIST.add(ip)

def block_ip(ip):

    if ip in WHITELIST:
        log_event(ip, "WHITELIST - NOT BLOCKED")
        return

    if apply_iptables_block(ip):
        add_to_blacklist(ip)
        stats[ip]["blocked"] = True
        log_event(ip, "BLOCKED & added to blacklist")

# ===== SCORE =====
def update_score(ip, points):
    stats[ip]["score"] += points
    if stats[ip]["score"] >= BLOCK_THRESHOLD and not stats[ip]["blocked"]:
        block_ip(ip)

# ===== PACKET HANDLER =====
def packet_callback(pkt):

    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    tcp = pkt[TCP]

    if not is_incoming(ip_dst):
        return

    with lock:

        # Si IP déjà blacklist → applique iptables
        if ip_src in BLACKLIST and not stats[ip_src]["blocked"]:
            apply_iptables_block(ip_src)
            stats[ip_src]["blocked"] = True

        now = time.time()

        # SYN
        if tcp.flags == "S":
            stats[ip_src]["syn_times"].append(now)

        # SSH
        if tcp.dport == 22:
            stats[ip_src]["ssh_times"].append(now)

        # DDoS tracking
        stats[ip_src]["ddos_times"].append(now)

        # VERTICAL SCAN
        stats[ip_src]["vscan_ports"][ip_dst].add(tcp.dport)
        if len(stats[ip_src]["vscan_ports"][ip_dst]) > 10:
            stats[ip_src]["vscan"] += 1
            update_score(ip_src, 6)
            log_event(ip_src, "Vertical scan detected")

        # HORIZONTAL SCAN
        stats[ip_src]["hscan_targets"][tcp.dport].add(ip_dst)
        if len(stats[ip_src]["hscan_targets"][tcp.dport]) > 10:
            stats[ip_src]["hscan"] += 1
            update_score(ip_src, 6)
            log_event(ip_src, "Horizontal scan detected")

        cleanup(ip_src)

        # SYN flood
        if len(stats[ip_src]["syn_times"]) > 40:
            update_score(ip_src, 5)
            log_event(ip_src, "SYN flood suspected")

        # SSH brute force
        if len(stats[ip_src]["ssh_times"]) > 20:
            update_score(ip_src, 8)
            log_event(ip_src, "SSH brute force suspected")

        # DDoS
        ddos_count = len(stats[ip_src]["ddos_times"])

        if ddos_count > DDOS_ALERT:
            update_score(ip_src, 10)
            log_event(ip_src, "DDoS suspected")

        if ddos_count > DDOS_BLOCK:
            update_score(ip_src, 50)
            block_ip(ip_src)

# ===== DASHBOARD =====
def dashboard():
    while True:
        os.system("clear")
        print("==== BASTION IDS DASHBOARD ====\n")
        print(f"{'IP':<18}{'Score':<8}{'SYN':<8}{'SSH':<8}{'VSCAN':<8}{'HSCAN':<8}{'DDoS(5s)':<10}{'BLK':<6}")
        print("-"*95)

        with lock:
            for ip, data in sorted(stats.items(), key=lambda x: x[1]["score"], reverse=True):
                print(f"{ip:<18}"
                      f"{round(data['score'],1):<8}"
                      f"{len(data['syn_times']):<8}"
                      f"{len(data['ssh_times']):<8}"
                      f"{data['vscan']:<8}"
                      f"{data['hscan']:<8}"
                      f"{len(data['ddos_times']):<10}"
                      f"{str(data['blocked']):<6}")

        time.sleep(2)

# ===== INIT BLACKLIST =====
def init_blacklist():
    for ip in BLACKLIST:
        if ip not in WHITELIST:
            apply_iptables_block(ip)

# ===== MAIN =====
if __name__ == "__main__":

    os.makedirs("list", exist_ok=True)

    print("Starting Bastion IDS...")
    print("Whitelist:", WHITELIST if WHITELIST else "None")
    print("Blacklist:", BLACKLIST if BLACKLIST else "None")

    init_blacklist()

    threading.Thread(target=dashboard, daemon=True).start()
    threading.Thread(target=decay_scores, daemon=True).start()

    sniff(filter=BPF_FILTER, prn=packet_callback, store=False, promisc=True)
