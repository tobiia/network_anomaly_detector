from collections import defaultdict
from pathlib import Path
from config import Config
import json
import ipaddress

EPS = 1e-9

def iter_json(path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def shannon_entropy(s):
    if not s:
        return 0.0
    from math import log2
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * log2(c/n) for c in counts.values())

def tld_from_domain(domain):
    if not domain or "." not in domain:
        return ""
    return domain.rsplit(".", 1)[-1].lower()

def split_labels(domain):
    if not domain:
        return []
    d = domain.strip(".").lower()
    if not d:
        return []
    return [p for p in d.split(".") if p]

def is_ip(s):
    if not s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
    
def weak_cipher(cipher):
    if not cipher:
        return 0
    c = cipher.upper()
    return 1 if ("RC4" in c or "3DES" in c or "MD5" in c) else 0


def new_flow(uid):
    return {
        "uid": uid,

        # base conn/flow
        "ts": None,
        "duration": 0.0,
        "proto": "",
        "id.orig_h": "",
        "id.resp_h": "",
        "id.orig_p": None,
        "id.resp_p": None,
        "orig_pkts": 0,
        "resp_pkts": 0,
        "orig_bytes": 0,
        "resp_bytes": 0,

        # derived flow
        "approx_fwd_pkt_len_mean": None,
        "approx_bwd_pkt_len_mean": None,
        "flow_bytes_per_sec": 0.0,
        "pkts_per_sec": 0.0,
        "pkt_ratio": 0.0,

        # DNS aggregates
        "dns_count": 0,
        "dns_qtype_counts": {},
        "dns_rcode_counts": {},
        "dns_unique_domains": set(),
        "dns_unique_tlds": set(),
        "dns_unique_ips": set(),

        # DNS derived -> done in window.py
        "dns_entropy_mean": None,
        "dns_entropy_max": None,
        "dns_len_mean": None,
        "dns_len_max": None,
        "dns_num_pct_mean": None,
        "dns_num_pct_max": None,
        "dns_subdomain_rate": None,

        # TLS features
        "tls_version": None,
        "tls_cipher": None,
        "tls_resumed": None,
        "tls_weak_cipher_flag": None,

        "tls_server_name": None,
        "tls_sni_present": None,
        "tls_sni_len": None,
        "tls_sni_tld": None,

        "tls_client_ext_count": None,
        "tls_server_ext_count": None,
        "tls_client_ext_enterprise_flag": None,

        # fingerprints
        "tls_ja3": None,
        "tls_ja3s": None,
        "tls_ja4": None,
        "tls_ja4s": None,
    }


def update_from_conn(flow, rec):
    flow["proto"] = rec.get("proto") or ""
    flow["ts"] = rec.get("ts")
    flow["id.orig_h"] = rec.get("id.orig_h") or "" # handles None or ""
    flow["id.resp_h"] = rec.get("id.resp_h") or ""
    flow["id.orig_p"] = rec.get("id.orig_p") or ""
    flow["id.resp_p"] = rec.get("id.resp_p") or ""

    duration = float(rec.get("duration") or 0.0)
    orig_pkts = int(rec.get("orig_pkts") or 0)
    resp_pkts = int(rec.get("resp_pkts") or 0)
    orig_bytes = int(rec.get("orig_bytes") or 0)
    resp_bytes = int(rec.get("resp_bytes") or 0)
    total_bytes = orig_bytes + resp_bytes
    total_pkts = orig_pkts + resp_pkts

    flow["duration"] = duration
    flow["orig_pkts"] = int(rec.get("orig_pkts") or 0)
    flow["resp_pkts"] = int(rec.get("resp_pkts") or 0)
    flow["orig_bytes"] = int(rec.get("orig_bytes") or 0)
    flow["resp_bytes"] = int(rec.get("resp_bytes") or 0)

    flow["approx_fwd_pkt_len_mean"] = (orig_bytes / orig_pkts) if orig_pkts > 0 else None
    flow["approx_bwd_pkt_len_mean"] = (resp_bytes / resp_pkts) if resp_pkts > 0 else None
    flow["flow_bytes_per_sec"] = total_bytes / duration if duration > 0 else None
    flow["pkts_per_sec"] = total_pkts / duration if duration > 0 else None
    flow["pkt_ratio"] = orig_pkts / (resp_pkts + 1)

def update_dns(flow, rec, dns_events_by_host):
    # f = flow uid, rec = specific record in log
    flow["dns_count"] = int(flow.get("dns_count") or 0) + 1

    ts = rec.get("ts")
    host = rec.get("id.orig_h") or flow.get("id.orig_h") or ""
    query = (rec.get("query") or "").strip().lower()
    qtype = (rec.get("qtype_name") or "").upper()
    rcode = (rec.get("rcode_name") or "").upper()
    # ttl or rtt?

    # counts
    qt = flow.setdefault("dns_qtype_counts", {})
    if qtype:
        qt[qtype] = qt.get(qtype, 0) + 1

    rc = flow.setdefault("dns_rcode_counts", {})
    if rcode:
        rc[rcode] = rc.get(rcode, 0) + 1

    # uniques + lexical stats across queries (per UID)
    if query:
        flow.setdefault("dns_unique_domains", set()).add(query)
        tld = tld_from_domain(query)
        if tld:
            flow.setdefault("dns_unique_tlds", set()).add(tld)

        labels = split_labels(query)
        has_sub = 1 if len(labels) > 2 else 0
        flow["dns_has_subdomain_count"] = int(flow.get("dns_has_subdomain_count") or 0) + has_sub

        qlen = len(query)
        digits = sum(ch.isdigit() for ch in query)
        num_pct = digits / max(qlen, 1)
        ent = shannon_entropy(query)

        flow["dns_len_sum"] = int(flow.get("dns_len_sum") or 0) + qlen
        flow["dns_len_max"] = max(int(flow.get("dns_len_max") or 0), qlen)

        flow["dns_num_pct_sum"] = float(flow.get("dns_num_pct_sum") or 0.0) + num_pct
        flow["dns_num_pct_max"] = max(float(flow.get("dns_num_pct_max") or 0.0), num_pct)

        flow["dns_entropy_sum"] = float(flow.get("dns_entropy_sum") or 0.0) + ent
        flow["dns_entropy_max"] = max(float(flow.get("dns_entropy_max") or 0.0), ent)

    # unique ips
    answers = rec.get("answers") or []
    ipset = flow.setdefault("dns_unique_ips", set())
    for a in answers:
        s = a.strip()
        if is_ip(s):
            ipset.add(s)

    # host-based events --> might not be necessary for windows
    if host and ts is not None:
        dns_events_by_host[host].append({
            "ts": float(ts),
            "rcode": rcode,
            "qtype": qtype,
            "query": query,
            "tld": tld_from_domain(query) if query else "",
        })


def update_tls(flow, rec:dict):
    flow["tls_version"] = rec.get("version")
    sni = rec.get("server_name")
    sni = sni.strip().lower() if sni else None
    flow["tls_server_name"] = sni
    flow["tls_resumed"] = 1 if rec.get("resumed") else 0

    flow["tls_sni_present"] = 1 if sni else 0
    flow["tls_sni_len"] = len(sni) if sni else 0
    flow["tls_sni_tld"] = tld_from_domain(sni) if sni else ""

    cipher = rec.get("cipher") or ""
    flow["tls_cipher"] = cipher
    flow["tls_weak_cipher_flag"] = weak_cipher(cipher)

    # fingerprints --> currently both available but check if both necessary
    # client hello
    flow["tls_ja3"] = rec.get("ja3") or flow.get("tls_ja3", "")
    flow["tls_ja4"] = rec.get("ja4") or flow.get("tls_ja4", "")
    # server hello
    flow["tls_ja3s"] = rec.get("ja3s") or flow.get("tls_ja3s", "")
    flow["tls_ja4s"] = rec.get("ja4s") or flow.get("tls_ja4s", "")

    # non-malware tend to have diff exts whereas malicious only 1
    # tls extension diversity
    client_exts = rec.get("ssl_client_exts") or []
    server_exts = rec.get("ssl_server_exts") or []

    flow["tls_client_ext_count"] = len(client_exts)
    flow["tls_server_ext_count"] = len(server_exts)

    # status_request=5, supported_groups=16, NPN=13172, EMS=23
    # most normal traffic uses above
    normal_exts = {5, 16, 13172, 23}
    cset = set(int(x) for x in client_exts if x is not None)
    flow["tls_client_ext_normal_flag"] = 1 if (cset & normal_exts) else 0


def parse_run(run_id):
    flows = {}
    dns_events_by_host = defaultdict(list)

    # conn
    conn_path = Config.RUNS_DIR / run_id / "conn.log"
    for rec in iter_json(conn_path):
        uid = rec.get("uid")
        if not uid:
            continue
        f = flows.get(uid)
        if f is None:
            f = new_flow(uid)
            flows[uid] = f
        update_from_conn(f, rec)

    # dns
    dns_path = Config.RUNS_DIR / run_id / "dns.log"
    if dns_path.exists():
        for rec in iter_json(dns_path):
            uid = rec.get("uid")
            if not uid:
                continue
            f = flows.get(uid)
            if f is None:
                continue
            update_dns(f, rec, dns_events_by_host)

    # tls
    ssl_path = Config.RUNS_DIR / run_id / "ssl.log"
    if ssl_path.exists():
        for rec in iter_json(ssl_path):
            uid = rec.get("uid")
            if not uid:
                continue
            f = flows.get(uid)
            if f is None:
                continue
            update_tls(f, rec)

    return flows, dns_events_by_host