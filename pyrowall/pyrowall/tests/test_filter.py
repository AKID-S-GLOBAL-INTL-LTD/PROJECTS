"""Tests for the core packet filter logic."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.filter import evaluate

# Rules are pre-sorted by priority ASC (as returned by RuleModel.enabled())
RULES = sorted([
    {'id':1,'name':'Block HTTP','action':'block','protocol':'tcp','direction':'both',
     'src_ip':'any','dst_ip':'any','src_port':'any','dst_port':'80','enabled':1,'priority':10},
    {'id':2,'name':'Block ICMP','action':'block','protocol':'icmp','direction':'both',
     'src_ip':'any','dst_ip':'any','src_port':'any','dst_port':'any','enabled':1,'priority':11},
    {'id':3,'name':'Allow HTTPS','action':'allow','protocol':'tcp','direction':'both',
     'src_ip':'any','dst_ip':'any','src_port':'any','dst_port':'443','enabled':1,'priority':20},
    {'id':4,'name':'Allow Loopback','action':'allow','protocol':'any','direction':'both',
     'src_ip':'127.0.0.0/8','dst_ip':'any','src_port':'any','dst_port':'any','enabled':1,'priority':1},
], key=lambda r: r['priority'])


def test_block_http():
    pkt = {'src_ip':'10.0.0.1','dst_ip':'1.2.3.4','protocol':'tcp',
           'src_port':54321,'dst_port':80,'direction':'outbound'}
    r = evaluate(pkt, RULES, set())
    assert r['action'] == 'block', f"Expected block, got {r}"
    print("PASS: test_block_http")


def test_block_icmp():
    pkt = {'src_ip':'10.0.0.1','dst_ip':'8.8.8.8','protocol':'icmp',
           'src_port':None,'dst_port':None,'direction':'outbound'}
    r = evaluate(pkt, RULES, set())
    assert r['action'] == 'block', f"Expected block, got {r}"
    print("PASS: test_block_icmp")


def test_allow_https():
    pkt = {'src_ip':'10.0.0.1','dst_ip':'1.2.3.4','protocol':'tcp',
           'src_port':54321,'dst_port':443,'direction':'outbound'}
    r = evaluate(pkt, RULES, set())
    assert r['action'] == 'allow', f"Expected allow, got {r}"
    print("PASS: test_allow_https")


def test_blacklist_takes_priority():
    pkt = {'src_ip':'1.2.3.4','dst_ip':'10.0.0.1','protocol':'tcp',
           'src_port':12345,'dst_port':443,'direction':'inbound'}
    r = evaluate(pkt, RULES, {'1.2.3.4'})
    assert r['action'] == 'block', f"Expected block (blacklist), got {r}"
    assert r['rule_name'] == 'Blacklist'
    print("PASS: test_blacklist_takes_priority")


def test_loopback_allowed():
    pkt = {'src_ip':'127.0.0.1','dst_ip':'127.0.0.1','protocol':'tcp',
           'src_port':12345,'dst_port':80,'direction':'both'}
    r = evaluate(pkt, RULES, set())
    assert r['action'] == 'allow', f"Expected loopback allow, got {r}"
    print("PASS: test_loopback_allowed")


def test_default_allow_unknown():
    pkt = {'src_ip':'10.0.0.1','dst_ip':'10.0.0.2','protocol':'tcp',
           'src_port':54321,'dst_port':9999,'direction':'outbound'}
    r = evaluate(pkt, RULES, set())
    assert r['action'] == 'allow', f"Expected default allow, got {r}"
    print("PASS: test_default_allow_unknown")


def test_disabled_rule_skipped():
    rules_with_disabled = [
        {'id':99,'name':'Disabled Block','action':'block','protocol':'tcp','direction':'both',
         'src_ip':'any','dst_ip':'any','src_port':'any','dst_port':'9999','enabled':0,'priority':5},
    ] + RULES
    pkt = {'src_ip':'10.0.0.1','dst_ip':'10.0.0.2','protocol':'tcp',
           'src_port':54321,'dst_port':9999,'direction':'outbound'}
    r = evaluate(pkt, rules_with_disabled, set())
    assert r['action'] == 'allow', f"Disabled rule should be skipped, got {r}"
    print("PASS: test_disabled_rule_skipped")


def test_cidr_match():
    pkt = {'src_ip':'192.168.1.50','dst_ip':'10.0.0.1','protocol':'tcp',
           'src_port':12345,'dst_port':8080,'direction':'inbound'}
    rules = [
        {'id':10,'name':'Block Subnet','action':'block','protocol':'any','direction':'both',
         'src_ip':'192.168.1.0/24','dst_ip':'any','src_port':'any','dst_port':'any',
         'enabled':1,'priority':5},
    ]
    r = evaluate(pkt, rules, set())
    assert r['action'] == 'block', f"CIDR match failed, got {r}"
    print("PASS: test_cidr_match")


def test_port_range():
    pkt = {'src_ip':'10.0.0.1','dst_ip':'10.0.0.2','protocol':'tcp',
           'src_port':12345,'dst_port':1500,'direction':'outbound'}
    rules = [
        {'id':11,'name':'Block Range','action':'block','protocol':'tcp','direction':'both',
         'src_ip':'any','dst_ip':'any','src_port':'any','dst_port':'1024-2048',
         'enabled':1,'priority':5},
    ]
    r = evaluate(pkt, rules, set())
    assert r['action'] == 'block', f"Port range match failed, got {r}"
    print("PASS: test_port_range")


if __name__ == '__main__':
    tests = [
        test_block_http, test_block_icmp, test_allow_https,
        test_blacklist_takes_priority, test_loopback_allowed,
        test_default_allow_unknown, test_disabled_rule_skipped,
        test_cidr_match, test_port_range,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__} — {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {t.__name__} — {e}")
            failed += 1
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
