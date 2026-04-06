"""
Rule-matching filter.
Given a parsed packet dict, walks the rule list and returns (action, rule).
"""

import ipaddress
import logging

log = logging.getLogger('akid_firewall.filter')


def _ip_matches(pattern, ip):
    """Match IP against a pattern which may be 'any', a CIDR, or an exact IP."""
    if not ip:
        return False
    if pattern == 'any' or not pattern:
        return True
    try:
        if '/' in pattern:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(ip) == ipaddress.ip_address(pattern)
    except ValueError:
        return False


def _port_matches(pattern, port):
    """Match port against pattern: 'any', exact number, or range like '1024-2048'."""
    if pattern == 'any' or not pattern:
        return True
    if port is None:
        return False
    try:
        if '-' in str(pattern):
            lo, hi = pattern.split('-', 1)
            return int(lo) <= int(port) <= int(hi)
        return int(pattern) == int(port)
    except (ValueError, TypeError):
        return False


def _proto_matches(rule_proto, pkt_proto):
    """Match protocol."""
    if rule_proto == 'any' or not rule_proto:
        return True
    return rule_proto.lower() == pkt_proto.lower()


def _direction_matches(rule_dir, pkt_dir):
    """Match direction."""
    if rule_dir == 'both':
        return True
    return rule_dir == pkt_dir


def evaluate(packet, rules, blacklist_ips):
    """
    Evaluate packet against blacklist then rules.
    Returns dict: { 'action': 'allow'|'block', 'rule_id': int|None, 'rule_name': str }
    """
    src_ip = packet.get('src_ip', '')
    dst_ip = packet.get('dst_ip', '')

    # 1. Blacklist check (highest priority)
    if src_ip in blacklist_ips:
        return {'action': 'block', 'rule_id': None, 'rule_name': 'Blacklist'}

    # 2. Walk rules in priority order
    for rule in rules:
        if not rule.get('enabled'):
            continue
        if not _proto_matches(rule.get('protocol', 'any'), packet.get('protocol', '')):
            continue
        if not _direction_matches(rule.get('direction', 'both'), packet.get('direction', 'inbound')):
            continue
        if not _ip_matches(rule.get('src_ip', 'any'), src_ip):
            continue
        if not _ip_matches(rule.get('dst_ip', 'any'), dst_ip):
            continue
        if not _port_matches(rule.get('src_port', 'any'), packet.get('src_port')):
            continue
        if not _port_matches(rule.get('dst_port', 'any'), packet.get('dst_port')):
            continue

        return {
            'action':    rule['action'],
            'rule_id':   rule['id'],
            'rule_name': rule['name'],
        }

    # 3. Default: allow (non-matching traffic passes through)
    return {'action': 'allow', 'rule_id': None, 'rule_name': 'Default Allow'}
