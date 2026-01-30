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
BLOCK_THRESHOLD = 30
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
    "syn": 0,
    "ssh": 0,
    "vscan": 0,
    "hscan": 0,
    "ports": defaultdict(set),
    "targets": defaultdict(set),
    "score": 0,
    "blocked": False
})

lock = threading.Lock()
packets_since_last = 0

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

# ===== PERSIST BLACKLIST =====
def add_to_blacklist(ip):
    if ip in BLACKLIST:
        return
    with open(BLACK_FILE, "a") as f:
        f.write(ip + "\n")
    BLACKLIST.add(ip)

# ===== BLOCK LOGIC =====
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
    global packets_since_last

    if not pkt.haslayer(IP):
        return

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    packets_since_last += 1

    with lock:

        if ip_src in BLACKLIST and not stats[ip_src]["blocked"]:
            apply_iptables_block(ip_src)
            stats[ip_src]["blocked"] = True

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]

            if tcp.flags == "S":
                stats[ip_src]["syn"] += 1
                update_score(ip_src, 1)
                log_event(ip_src, "SYN packet")

            if tcp.dport == 22:
                stats[ip_src]["ssh"] += 1
                log_event(ip_src, "SSH attempt")

                if stats[ip_src]["ssh"] > 10:
                    update_score(ip_src, 6)
                    log_event(ip_src, "SSH BRUTE FORCE suspected")

            stats[ip_src]["ports"][ip_dst].add(tcp.dport)
            if len(stats[ip_src]["ports"][ip_dst]) > 10:
                stats[ip_src]["vscan"] += 1
                update_score(ip_src, 4)
                log_event(ip_src, "Vertical scan detected")

            stats[ip_src]["targets"][tcp.dport].add(ip_dst)
            if len(stats[ip_src]["targets"][tcp.dport]) > 10:
                stats[ip_src]["hscan"] += 1
                update_score(ip_src, 4)
                log_event(ip_src, "Horizontal scan detected")

# ===== DASHBOARD =====
def dashboard():
    global packets_since_last

    while True:
        os.system("clear")
        print("==== BASTION IDS DASHBOARD ====\n")
        print(f"{'IP':<18}{'Score':<8}{'SYN':<6}{'SSH':<6}{'VSCAN':<8}{'HSCAN':<8}{'PKTS':<8}{'BLK':<6}")
        print("-"*80)

        with lock:
            for ip, data in sorted(stats.items(), key=lambda x: x[1]["score"], reverse=True):
                print(f"{ip:<18}{data['score']:<8}{data['syn']:<6}{data['ssh']:<6}{data['vscan']:<8}{data['hscan']:<8}{packets_since_last:<8}{str(data['blocked']):<6}")

        packets_since_last = 0
        time.sleep(2)

# ===== INIT BLACKLIST IPTABLES =====
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
    sniff(filter=BPF_FILTER, prn=packet_callback, store=False, promisc=True)
