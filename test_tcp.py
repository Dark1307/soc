from scapy.all import sniff, IP, TCP

def show(p):
    if p.haslayer(IP) and p.haslayer(TCP):
        print('TCP:', p[IP].src, '->', p[IP].dst, 
              'dport:', p[TCP].dport, 'sport:', p[TCP].sport)

print('Sniffing TCP for 15 seconds...')
print('Now run the connect command in another terminal!')
sniff(filter='tcp', timeout=15, prn=show)
print('Done!')