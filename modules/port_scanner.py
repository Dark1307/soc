import socket
import concurrent.futures
import subprocess
import platform
from datetime import datetime

# Common ports with service names
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MSRPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 8888: 'HTTP-Dev', 27017: 'MongoDB'
}

def grab_banner(ip, port, timeout=2):
    """Try to grab service banner for version detection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in [80, 8080]:
            s.send(b'HEAD / HTTP/1.0\r\nHost: target\r\n\r\n')
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner.split('\n')[0][:80] if banner else ''
    except:
        return ''

def scan_port(ip, port, timeout=1):
    """Scan a single port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            service = COMMON_PORTS.get(port, 'Unknown')
            banner = grab_banner(ip, port)
            return {
                'port': port,
                'state': 'open',
                'service': service,
                'version': banner if banner else service
            }
        return None
    except:
        return None

def resolve_host(target):
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def ping_host(ip):
    """Check if host is alive."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        result = subprocess.run(
            ['ping', param, '1', ip],
            capture_output=True, timeout=3
        )
        return result.returncode == 0
    except:
        return True

def scan(target, scan_type='common'):
    """Main scan function."""
    start_time = datetime.now()
    logs = []
    open_ports = []
    closed_count = 0

    # Resolve target
    ip = resolve_host(target)
    if not ip:
        return {'error': f'Cannot resolve host: {target}', 'logs': []}

    logs.append(f'[INFO] Starting {scan_type} scan on {target} ({ip})')
    logs.append(f'[INFO] Scan started at {start_time.strftime("%H:%M:%S")}')

    # Check if host is up
    alive = ping_host(ip)
    if alive:
        logs.append(f'[OK] Host {ip} is up')
    else:
        logs.append(f'[WARN] Host may be blocking ICMP — scanning anyway')

    # Determine ports to scan
    if scan_type == 'common':
        ports = list(COMMON_PORTS.keys())
    elif scan_type == 'full':
        ports = list(range(1, 1025))
    elif scan_type == 'service':
        ports = list(COMMON_PORTS.keys())
    elif scan_type == 'stealth':
        ports = list(COMMON_PORTS.keys())
    else:
        ports = list(COMMON_PORTS.keys())

    timeout = 0.5 if scan_type == 'stealth' else 1.0
    logs.append(f'[INFO] Scanning {len(ports)} ports...')

    # Threaded scanning for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                logs.append(
                    f'[OPEN] Port {result["port"]}/tcp '
                    f'— {result["service"]} — {result["version"]}'
                )
            else:
                closed_count += 1

    # Sort open ports
    open_ports.sort(key=lambda x: x['port'])

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    logs.append(f'[DONE] Scan complete in {duration:.1f}s')
    logs.append(
        f'[SUMMARY] Open: {len(open_ports)} | '
        f'Closed/Filtered: {closed_count}'
    )

    # Risk check
    risky = {
        21: 'FTP (plaintext credentials)',
        23: 'Telnet (plaintext credentials)',
        3389: 'RDP (brute-force risk)',
        445: 'SMB (ransomware vector)',
        1433: 'MSSQL (exposed database)',
        3306: 'MySQL (exposed database)',
    }
    for p in open_ports:
        if p['port'] in risky:
            logs.append(
                f'[RISK] Port {p["port"]} — {risky[p["port"]]} is OPEN!'
            )

    return {
        'target': target,
        'ip': ip,
        'open_ports': open_ports,
        'closed_count': closed_count,
        'scan_type': scan_type,
        'duration': round(duration, 1),
        'logs': logs,
        'timestamp': start_time.strftime('%Y-%m-%d %H:%M:%S')
    }