from collections import defaultdict
from pathlib import Path
from typing import Dict, Generator, Iterator, Tuple

from config import Config
import re
from datetime import datetime
import json
import csv

def iter_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                yield json.loads(line)
    except FileNotFoundError:
        return
        
# dhunter -> ParseZeekLogs
def iter_csv(path: Path):
    try:
        options = {}
        with path.open("r", encoding="utf-8") as f:
            row = f.readline().strip()
            while row.startswith("#"):
                # parse the option # rows out
                if row.startswith("#separator"):
                    key = str(row[1:].split(" ")[0])
                    value = str.encode(row[1:].split(" ")[1].strip()).decode('unicode_escape')
                    options[key] = value
                elif row.startswith("#"):
                    key = str(row[1:].split(options.get("separator"))[0])
                    value = row[1:].split(options.get("separator"))[1:]
                    options[key] = value
                row = f.readline().strip()
            
            # dict should not include rows w/o info
            empty_val = options.get("empty_field", "(empty)")
            unset_val = options.get("unset_field", "-")
        
            dict_reader = csv.DictReader(
                f, 
                fieldnames=options.get("fields"), 
                delimiter=options.get("separator", "\t")
            )
            for row in dict_reader:
                filtered_row = {}
                for key, value in row.items():
                    if value not in [empty_val, unset_val]:
                        filtered_row[key] = value
                yield filtered_row
    except FileNotFoundError:
        return

def shannon_entropy(s):
    if not s:
        return 0.0
    from math import log2
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * log2(c/n) for c in counts.values())

def tld(domain):
    if not domain or "." not in domain:
        return ""
    return domain.rsplit(".", 1)[-1].lower()

def subdomain_labels(domain):
    # not including tld
    if not domain:
        return []
    d = domain.strip(".").lower()
    if not d:
        return []
    parts = [p for p in d.split(".") if p]
    return parts[:-1]

def consecutive_digits_ratio(domain):
    s = re.sub(r'[^a-z0-9]', '', domain.lower())
    if not s:
        return 0.0

    consecutive_digit_chars = 0
    for match in re.finditer(r'\d{2,}', s):
        consecutive_digit_chars += len(match.group())

    return consecutive_digit_chars / len(s)

def letter_digit_alternation_ratio(domain):
    s = re.sub(r'[^a-z0-9]', '', domain.lower())
    if len(s) < 2:
        return 0.0

    transitions = 0
    for i in range(len(s) - 1):
        if (s[i].isalpha() and s[i+1].isdigit()) or \
           (s[i].isdigit() and s[i+1].isalpha()):
            transitions += 1

    return transitions / (len(s) - 1)

def consecutive_consonant_ratio(domain):
    s = re.sub(r'[^a-z]', '', domain.lower())
    if not s:
        return 0.0

    consonants = "bcdfghjklmnpqrstvwxyz"
    consecutive_cons_chars = 0
    run_len = 0

    for ch in s:
        if ch in consonants:
            run_len += 1
        else:
            if run_len >= 2:
                consecutive_cons_chars += run_len
            run_len = 0

    if run_len >= 2:
        consecutive_cons_chars += run_len

    return consecutive_cons_chars / len(s)

def weak_cipher(cipher):
    if not cipher:
        return 0
    c = cipher.upper()
    return 1 if ("RC4" in c or "3DES" in c or "MD5" in c) else 0