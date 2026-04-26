import threading
from datetime import datetime

# ─── Try to import Scapy ───
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ifaces
    SCAPY_AVAILABLE = True
    print('[NET] Scapy loaded successfully!')
except Exception as e:
    SCAPY_AVAILABLE = False
    print('[NET] Scapy not available: ' + str(e))

# ─── Auto-detect best interface ───
def get_best_interface():
    """Auto-detect the active network interface."""
    try:
        skip_keywords = [
            'loopback', 'miniport', 'vmware', 'virtualbox',
            'virtual', 'warp', 'direct', 'wan'
        ]
        for iface_name, iface in ifaces.items():
            name_lower = iface.name.lower() if iface.name else ''
            skip = False
            for kw in skip_keywords:
                if kw in name_lower:
                    skip = True
                    break
            if skip:
                continue
            if hasattr(iface, 'ip') and iface.ip and not iface.ip.startswith('169.254'):
                print('[NET] Auto-selected interface: ' + iface.name + ' (' + str(iface.ip) + ')')
                return iface_name
    except Exception as e:
        print('[NET] Auto-detect error: ' + str(e))

    fallback = '\\Device\\NPF_{2BA48F54-FAE4-458C-974D-E24B8A1F69E3}'
    print('[NET] Using fallback interface: ' + fallback)
    return fallback

# ─── Global State ───
capture_running  = False
captured_packets = []
capture_thread   = None
stats = {
    'total':      0,
    'normal':     0,
    'suspicious': 0,
    'blocked':    0
}

# ─── Suspicious Ports ───
SUSPICIOUS_PORTS = {
    4444:  'Metasploit Default',
    1337:  'Common Backdoor',
    31337: 'Elite Backdoor',
    6666:  'IRC Botnet',
    6667:  'IRC Botnet',
    9001:  'Tor Relay',
    9050:  'Tor Proxy',
    12345: 'NetBus RAT',
    27374: 'Sub7 RAT',
    5900:  'VNC Exposed',
    23:    'Telnet Plaintext',
    1433:  'MSSQL Exposed',
    3306:  'MySQL Exposed',
    27017: 'MongoDB Exposed',
    3389:  'RDP Exposed',
}

# ─── Known Malicious IP Ranges ───
MALICIOUS_IP_RANGES = [
    '185.220.101.',
    '45.33.32.',
    '198.199.',
    '104.244.',
    '176.10.',
    '195.206.',
]

def is_suspicious_ip(ip):
    for bad in MALICIOUS_IP_RANGES:
        if ip.startswith(bad):
            return True
    return False

def analyze_packet(pkt):
    """Analyze a real captured packet and store it."""
    global stats, captured_packets

    try:
        # Handle both IP and raw loopback packets
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto  = 'OTHER'
        port   = 0
        sport  = 0
        size   = len(pkt)

        # Protocol and ports (both src and dst)
        if pkt.haslayer(TCP):
            proto = 'TCP'
            port  = pkt[TCP].dport
            sport = pkt[TCP].sport
        elif pkt.haslayer(UDP):
            proto = 'UDP'
            port  = pkt[UDP].dport
            sport = pkt[UDP].sport
        elif pkt.haslayer(ICMP):
            proto = 'ICMP'

        # ─── Threat Detection ───
        threats = []

        # Check IPs
        if is_suspicious_ip(src_ip):
            threats.append('MALICIOUS IP: ' + src_ip)
        if is_suspicious_ip(dst_ip):
            threats.append('CONNECTING TO MALICIOUS IP: ' + dst_ip)

        # Check BOTH src and dst ports
        if port in SUSPICIOUS_PORTS:
            threats.append(SUSPICIOUS_PORTS[port].upper())
        if sport in SUSPICIOUS_PORTS:
            threats.append(SUSPICIOUS_PORTS[sport].upper() + ' (SRC)')

        # Extra rules — check both directions
        for p in [port, sport]:
            if proto == 'TCP' and p == 4444:
                threats.append('METASPLOIT C2 DETECTED')
            if proto == 'TCP' and p == 23:
                threats.append('TELNET - PLAINTEXT CREDENTIALS')
            if proto == 'TCP' and p == 3389:
                threats.append('RDP EXPOSED')
            if proto == 'TCP' and p == 6667:
                threats.append('IRC BOTNET CHANNEL')
            if proto == 'TCP' and p == 1337:
                threats.append('BACKDOOR DETECTED')
            if proto == 'TCP' and p == 31337:
                threats.append('ELITE BACKDOOR DETECTED')
            if proto == 'TCP' and p == 5900:
                threats.append('VNC REMOTE ACCESS')
            if proto == 'TCP' and p == 9050:
                threats.append('TOR PROXY DETECTED')

        # Remove duplicates
        threats = list(dict.fromkeys(threats))

        status = 'suspicious' if threats else 'normal'

        packet_data = {
            'timestamp':    datetime.now().strftime('%H:%M:%S'),
            'src_ip':       src_ip,
            'dst_ip':       dst_ip,
            'port':         int(port),
            'sport':        int(sport),
            'proto':        proto,
            'size':         int(size),
            'status':       status,
            'threats':      threats,
            'threat_label': ' | '.join(threats) if threats else '',
        }

        # Update stats
        stats['total'] += 1
        if status == 'suspicious':
            stats['suspicious'] += 1
            stats['blocked']    += 1
        else:
            stats['normal'] += 1

        # Keep last 200 packets
        captured_packets.insert(0, packet_data)
        if len(captured_packets) > 200:
            captured_packets = captured_packets[:200]

    except Exception as e:
        print('[NET] Packet error: ' + str(e))

def loopback_capture():
    """Capture on loopback interface to catch local connections."""
    loopback_iface = '\\Device\\NPF_Loopback'
    print('[NET] Capturing on Loopback: ' + loopback_iface)
    try:
        sniff(
            iface=loopback_iface,
            prn=analyze_packet,
            store=False,
            stop_filter=lambda p: not capture_running,
        )
    except Exception as e:
        print('[NET] Loopback capture error: ' + str(e))

def capture_loop():
    """Real packet capture on WiFi + Loopback interfaces."""
    global capture_running

    wifi_iface = get_best_interface()
    print('[NET] Capturing on WiFi: ' + str(wifi_iface))

    # Start loopback capture in separate thread
    lb_thread = threading.Thread(target=loopback_capture, daemon=True)
    lb_thread.start()

    # WiFi capture in main thread
    try:
        sniff(
            iface=wifi_iface,
            prn=analyze_packet,
            store=False,
            stop_filter=lambda p: not capture_running,
        )
    except Exception as e:
        print('[NET] WiFi capture error: ' + str(e))
        capture_running = False

def start_capture():
    global capture_running, capture_thread, captured_packets, stats

    if capture_running:
        return {'status': 'already_running', 'message': 'Capture already running'}

    if not SCAPY_AVAILABLE:
        return {'status': 'error', 'message': 'Scapy not available. Run: pip install scapy'}

    # Reset state
    captured_packets = []
    stats = {'total': 0, 'normal': 0, 'suspicious': 0, 'blocked': 0}
    capture_running  = True

    capture_thread = threading.Thread(target=capture_loop, daemon=True)
    capture_thread.start()

    return {
        'status':  'started',
        'message': 'Real packet capture started on WiFi + Loopback!'
    }

def stop_capture():
    global capture_running

    if not capture_running:
        return {'status': 'not_running', 'message': 'Capture is not running'}

    capture_running = False
    return {
        'status':  'stopped',
        'message': 'Capture stopped. Total packets: ' + str(stats['total'])
    }

def get_packets():
    return {
        'packets':    captured_packets[:50],
        'stats':      stats,
        'is_running': capture_running,
    }