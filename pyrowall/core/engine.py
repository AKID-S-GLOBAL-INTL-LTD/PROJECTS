"""
Packet inspection engine.
Uses Scapy to sniff packets, evaluates them against rules, and logs results.
"""

import threading
import logging
import time
import platform
from collections import deque

from db.models import RuleModel, BlacklistModel, LogModel, SettingsModel
from core.filter import evaluate

log = logging.getLogger('akid_firewall.engine')

# Shared live feed (last 100 packets for dashboard)
live_feed = deque(maxlen=100)
live_feed_lock = threading.Lock()

# Counters
_stats = {
    'total': 0,
    'blocked': 0,
    'allowed': 0,
    'start_time': time.time(),
}
_stats_lock = threading.Lock()


def get_live_stats():
    with _stats_lock:
        return dict(_stats)


def get_live_feed():
    with live_feed_lock:
        return list(live_feed)


class PacketEngine:
    def __init__(self):
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        log.info("Starting packet sniffer...")
        try:
            from scapy.all import sniff, conf
            conf.verb = 0  # suppress Scapy output

            iface = SettingsModel.get('interface', 'auto')
            kwargs = {'prn': self._process_packet, 'store': False}
            if iface and iface != 'auto':
                kwargs['iface'] = iface

            sniff(**kwargs)
        except ImportError:
            log.warning("Scapy not available — running in simulation mode.")
            self._simulation_mode()
        except PermissionError:
            log.error("Permission denied — cannot sniff packets without root/admin.")
            self._simulation_mode()
        except Exception as e:
            log.error(f"Packet engine error: {e}")
            self._simulation_mode()

    def stop(self):
        self._running = False
        log.info("Packet engine stopped.")

    def _process_packet(self, pkt):
        if not self._running:
            return
        if SettingsModel.get('engine_enabled', '1') != '1':
            return

        parsed = _parse_packet(pkt)
        if not parsed:
            return

        rules = RuleModel.enabled()
        blacklist_ips = {e['ip_address'] for e in BlacklistModel.all()}

        result = evaluate(parsed, rules, blacklist_ips)
        action = result['action']

        # Update live counters
        with _stats_lock:
            _stats['total'] += 1
            _stats[action + 'ed'] = _stats.get(action + 'ed', 0) + 1
            if action == 'block':
                _stats['blocked'] += 1
            else:
                _stats['allowed'] += 1

        log_entry = {
            'action':    action,
            'src_ip':    parsed.get('src_ip', ''),
            'dst_ip':    parsed.get('dst_ip', ''),
            'src_port':  parsed.get('src_port'),
            'dst_port':  parsed.get('dst_port'),
            'protocol':  parsed.get('protocol', ''),
            'rule_id':   result.get('rule_id'),
            'rule_name': result.get('rule_name', ''),
            'size':      parsed.get('size', 0),
            'flags':     parsed.get('flags', ''),
        }

        # Log to DB (if setting enabled)
        should_log = (
            (action == 'block' and SettingsModel.get('log_blocked', '1') == '1') or
            (action == 'allow' and SettingsModel.get('log_allowed', '1') == '1')
        )
        if should_log:
            LogModel.add(log_entry)

        # Push to live feed
        import time as t
        log_entry['timestamp'] = t.strftime('%H:%M:%S')
        with live_feed_lock:
            live_feed.appendleft(log_entry)

        # Periodic purge
        if _stats['total'] % 1000 == 0:
            max_entries = int(SettingsModel.get('max_log_entries', '50000'))
            LogModel.purge_old(max_entries)

    def _simulation_mode(self):
        """Generate synthetic traffic for demo/testing without real sniffing."""
        import random
        import time

        SAMPLE_IPS = [
            '192.168.1.10', '10.0.0.5', '172.16.0.1',
            '8.8.8.8', '1.1.1.1', '203.0.113.50',
            '198.51.100.1', '192.0.2.1',
        ]
        PROTOCOLS = ['tcp', 'udp', 'icmp', 'tcp', 'tcp']  # weighted toward TCP
        PORTS = [80, 443, 53, 22, 8080, 3306, 25, 110, 143, 3389]

        log.warning("Running in SIMULATION MODE — no real traffic is being captured.")
        log.warning("Install Scapy and run as root/admin for real packet inspection.")

        while self._running:
            proto = random.choice(PROTOCOLS)
            parsed = {
                'src_ip':    random.choice(SAMPLE_IPS),
                'dst_ip':    random.choice(SAMPLE_IPS),
                'src_port':  random.randint(1024, 65535),
                'dst_port':  random.choice(PORTS),
                'protocol':  proto,
                'direction': random.choice(['inbound', 'outbound']),
                'size':      random.randint(40, 1500),
                'flags':     random.choice(['', 'SYN', 'ACK', 'FIN', 'RST']),
            }

            rules = RuleModel.enabled()
            blacklist_ips = {e['ip_address'] for e in BlacklistModel.all()}
            result = evaluate(parsed, rules, blacklist_ips)
            action = result['action']

            with _stats_lock:
                _stats['total'] += 1
                if action == 'block':
                    _stats['blocked'] += 1
                else:
                    _stats['allowed'] += 1

            log_entry = {
                'action':    action,
                'src_ip':    parsed['src_ip'],
                'dst_ip':    parsed['dst_ip'],
                'src_port':  parsed['src_port'],
                'dst_port':  parsed['dst_port'],
                'protocol':  parsed['protocol'].upper(),
                'rule_id':   result.get('rule_id'),
                'rule_name': result.get('rule_name', ''),
                'size':      parsed['size'],
                'flags':     parsed['flags'],
            }

            LogModel.add(log_entry)

            import time as t
            log_entry['timestamp'] = t.strftime('%H:%M:%S')
            with live_feed_lock:
                live_feed.appendleft(log_entry)

            time.sleep(random.uniform(0.1, 0.6))


def _parse_packet(pkt):
    """Parse a Scapy packet into a dict."""
    try:
        from scapy.all import IP, TCP, UDP, ICMP, IPv6

        result = {'size': len(pkt), 'flags': '', 'direction': 'inbound'}

        if IP in pkt:
            result['src_ip']   = pkt[IP].src
            result['dst_ip']   = pkt[IP].dst
            result['protocol'] = 'unknown'

            if TCP in pkt:
                result['protocol'] = 'tcp'
                result['src_port'] = pkt[TCP].sport
                result['dst_port'] = pkt[TCP].dport
                flags = pkt[TCP].flags
                result['flags'] = str(flags)
            elif UDP in pkt:
                result['protocol'] = 'udp'
                result['src_port'] = pkt[UDP].sport
                result['dst_port'] = pkt[UDP].dport
            elif ICMP in pkt:
                result['protocol'] = 'icmp'
                result['src_port'] = None
                result['dst_port'] = None
            else:
                result['src_port'] = None
                result['dst_port'] = None
                result['protocol'] = str(pkt[IP].proto)

            return result

        return None  # skip non-IP packets
    except Exception:
        return None
