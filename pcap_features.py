#pcap_features.py
#Alberto Gaspar
#CECS 451 Phase 2: turns a raw PCAP into the same kind of rows as pcap.parquet (one row = 10 packets in a row).
#The dataset does not publish its feature definitions, so these are decoded from the rows in pcap.parquet.
#Checked against the rows:  Header_Length, TTL, flag_number/count, protocol fractions, packet size stats, Variance (n-1).
#GUESSED (not confirmed):   Rate (= 1 / IAT), IAT (mean gap between packets inside the window), LLC (= IPv), ICMPv6 counted as ICMP.

import dpkt
import numpy as np
import pandas as pd
from collections import Counter

WINDOW = 10

def _open(f):
    try:
        return dpkt.pcap.Reader(f)
    except ValueError:        #Wireshark pcapng file
        f.seek(0)
        return dpkt.pcapng.Reader(f)

def _parse(buf, dlt):
    #one packet -> small dict. Anything that is not IP or ARP counts as proto 0 and no header, like ARP in the dataset
    p = {'len': len(buf), 'ttl': 0, 'proto': 0, 'hdr': 0, 'ip': 0, 'arp': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'igmp': 0,
         'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0, 'ack': 0, 'ece': 0, 'cwr': 0,
         'http': 0, 'https': 0, 'dns': 0, 'telnet': 0, 'smtp': 0, 'ssh': 0, 'irc': 0, 'dhcp': 0}
    try:
        if dlt == 1:
            l3 = dpkt.ethernet.Ethernet(buf).data
        elif dlt in (12, 101):
            l3 = dpkt.ip.IP(buf) if buf[0] >> 4 == 4 else dpkt.ip6.IP6(buf)
        else:
            raise ValueError("unsupported link type %d (use an Ethernet capture)" % dlt)
    except (dpkt.dpkt.UnpackError, IndexError):
        return p
    if isinstance(l3, dpkt.arp.ARP):
        p['arp'] = 1
        return p
    if isinstance(l3, dpkt.ip.IP):
        p['ttl'], p['proto'] = l3.ttl, l3.p
    elif isinstance(l3, dpkt.ip6.IP6):
        p['ttl'], p['proto'] = l3.hlim, getattr(l3, 'p', None) or l3.nxt
    else:
        return p
    p['ip'] = 1
    l4, proto = l3.data, p['proto']
    p['tcp'], p['udp'] = int(proto == 6), int(proto == 17)
    p['icmp'], p['igmp'] = int(proto in (1, 58)), int(proto == 2)
    ports = ()
    if isinstance(l4, dpkt.tcp.TCP):
        p['hdr'] = l4.off * 4
        f = l4.flags
        p['fin'], p['syn'], p['rst'], p['psh'] = f & 1, (f >> 1) & 1, (f >> 2) & 1, (f >> 3) & 1
        p['ack'], p['ece'], p['cwr'] = (f >> 4) & 1, (f >> 6) & 1, (f >> 7) & 1
        ports = (l4.sport, l4.dport)
    elif isinstance(l4, dpkt.udp.UDP):
        p['hdr'] = 8
        ports = (l4.sport, l4.dport)
    for name, port in [('http', 80), ('https', 443), ('dns', 53), ('telnet', 23), ('smtp', 25), ('ssh', 22), ('irc', 6667)]:
        p[name] = int(port in ports)
    p['dhcp'] = int(p['udp'] == 1 and (67 in ports or 68 in ports))
    return p

def _row(pk, ts):
    n = len(pk)
    ln = np.array([p['len'] for p in pk], dtype=float)
    mean_f = lambda key: sum(p[key] for p in pk) / n
    sum_f  = lambda key: sum(p[key] for p in pk)
    counts = Counter(p['proto'] for p in pk)
    top    = max(counts.values())
    iat    = float(np.diff(ts).mean())
    return {
        'Header_Length': mean_f('hdr'), 'Protocol Type': min(c for c in counts if counts[c] == top),
        'Time_To_Live': mean_f('ttl'), 'Rate': 1 / iat if iat > 0 else np.nan,
        'fin_flag_number': mean_f('fin'), 'syn_flag_number': mean_f('syn'), 'rst_flag_number': mean_f('rst'),
        'psh_flag_number': mean_f('psh'), 'ack_flag_number': mean_f('ack'), 'ece_flag_number': mean_f('ece'),
        'cwr_flag_number': mean_f('cwr'),
        'ack_count': sum_f('ack'), 'syn_count': sum_f('syn'), 'fin_count': sum_f('fin'), 'rst_count': sum_f('rst'),
        'HTTP': mean_f('http'), 'HTTPS': mean_f('https'), 'DNS': mean_f('dns'), 'Telnet': mean_f('telnet'),
        'SMTP': mean_f('smtp'), 'SSH': mean_f('ssh'), 'IRC': mean_f('irc'), 'TCP': mean_f('tcp'), 'UDP': mean_f('udp'),
        'DHCP': mean_f('dhcp'), 'ARP': mean_f('arp'), 'ICMP': mean_f('icmp'), 'IGMP': mean_f('igmp'),
        'IPv': mean_f('ip'), 'LLC': mean_f('ip'),
        'Tot sum': ln.sum(), 'Min': ln.min(), 'Max': ln.max(), 'AVG': ln.mean(), 'Std': ln.std(ddof=1),
        'Tot size': ln.mean(), 'IAT': iat, 'Number': n, 'Variance': ln.var(ddof=1),
    }

def pcap_to_rows(path):
    """Returns (DataFrame with one row per full 10-packet window, number of leftover packets dropped)."""
    rows, pk, ts = [], [], []
    with open(path, 'rb') as f:
        reader = _open(f)
        dlt = reader.datalink()
        for t, buf in reader:
            pk.append(_parse(buf, dlt))
            ts.append(t)
            if len(pk) == WINDOW:
                rrow = _row(pk, ts)
                row['window_start'] = float(ts[0])
                rows.append(row)
                pk, ts = [], []
    return pd.DataFrame(rows), len(pk)

def scale_rows(df, pre):
    """Window rows -> the exact model input: same one-hot Protocol Type, column order, imputer and scaler as training.
    pre = joblib.load('preprocess.joblib')."""
    dummies = pd.get_dummies(df['Protocol Type'].astype(int), prefix='Protocol Type', dtype=float)
    X = pd.concat([df, dummies], axis=1).reindex(columns=pre['columns'], fill_value=0.0)
    X = pd.DataFrame(pre['imputer'].transform(X), columns=pre['columns'])
    return pd.DataFrame(pre['scaler'].transform(X), columns=pre['columns'])
