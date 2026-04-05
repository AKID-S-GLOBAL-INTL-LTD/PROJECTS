"""Linux iptables adapter — applies firewall rules at OS level."""

import subprocess
import logging

log = logging.getLogger('pyrowall.linux')


def run(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True
        )
        if result.returncode != 0:
            log.warning(f"iptables: {result.stderr.strip()}")
        return result.returncode == 0
    except Exception as e:
        log.error(f"iptables error: {e}")
        return False


def apply_rule(rule):
    """Translate a PyroWall rule dict to iptables commands."""
    action = 'DROP' if rule['action'] == 'block' else 'ACCEPT'
    chain_map = {
        'inbound': ['INPUT'],
        'outbound': ['OUTPUT'],
        'both': ['INPUT', 'OUTPUT'],
    }
    chains = chain_map.get(rule.get('direction', 'both'), ['INPUT', 'OUTPUT'])

    for chain in chains:
        parts = ['iptables', '-A', chain]

        proto = rule.get('protocol', 'any')
        if proto and proto != 'any':
            parts += ['-p', proto]

        src_ip = rule.get('src_ip', 'any')
        if src_ip and src_ip != 'any':
            parts += ['-s', src_ip]

        dst_ip = rule.get('dst_ip', 'any')
        if dst_ip and dst_ip != 'any':
            parts += ['-d', dst_ip]

        dst_port = rule.get('dst_port', 'any')
        if dst_port and dst_port != 'any' and proto in ('tcp', 'udp'):
            parts += ['--dport', str(dst_port)]

        parts += ['-j', action]
        run(' '.join(parts))


def block_ip(ip):
    run(f'iptables -I INPUT -s {ip} -j DROP')
    run(f'iptables -I OUTPUT -d {ip} -j DROP')


def unblock_ip(ip):
    run(f'iptables -D INPUT -s {ip} -j DROP')
    run(f'iptables -D OUTPUT -d {ip} -j DROP')


def flush_pyrowall_rules():
    """Flush all rules (use on shutdown)."""
    run('iptables -F INPUT')
    run('iptables -F OUTPUT')
    run('iptables -F FORWARD')
