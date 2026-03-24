#!/usr/bin/env python3
# AI GENERATED BS SANITIZER FOR TESTING PURPOSES ONLY
import re
from typing import List, Tuple, Optional

DANGEROUS_PATTERNS = [
    r'[;&|]',
    r'`',
    r'\$\(',
    r'\${'
    r'[<>]',
    r'\\x[0-9a-fA-F]',
    r'\n',
    r'\r',
]

# IPV4, CIDR, IPV6 and hostname sanitize regex that doesn't work
TARGET_PATTERN = re.compile(
    r'^('
    r'(\d{1,3}\.){3}\d{1,3}(/[0-3]?\d)?|'
    r'([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|'
    r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]){1,63}|'
    r'[a-zA-Z0-9]+'
    r')$'
)

# Allowed bool flags
BOOL_FLAGS = {
    '-v', '-vv', '-vvv',
    '-sS', '-sT', '-sU', '-sV', '-sC',
    '-O', '-A', '-Pn',
    '-n', '-r',
    '-T0', '-T1', '-T2', '-T3', '-T4', '-T5',
}


ARG_FLAGS = {
    '-p': lambda x: re.match(r'^[TU:0-9,\-]+$', x) and len(x) < 100,
    '-e': lambda x: re.match(r'^[a-z0-9]+$', x),
    '-S': lambda x: re.match(r'^(\d{1,3}\.){3}\d{1,3}$', x),
    '-g': lambda x: x.isdigit() and 0 < int(x) <= 65535,
    '--script': lambda x: all(
        s.strip() in ALLOWED_SCRIPTS or s.strip() in ALLOWED_CATEGORIES
        for s in x.split(',')
    ),
    '--script-args': lambda x: len(x) < 500 and not any(c in x for c in ';|&`$(){}<>'),
    '--host-timeout': lambda x: re.match(r'^\d+[smhd]?$', x),
    '--max-retries': lambda x: x.isdigit() and int(x) >= 0,
    '-oN': lambda x: re.match(r'^[\w\-\.]+$', x),
    '-oX': lambda x: re.match(r'^[\w\-\.]+$', x),
    '-oG': lambda x: re.match(r'^[\w\-\.]+$', x),
}

ALLOWED_SCRIPTS = {
    'vuln', 'vulners', 'banner', 'http-title', 'http-headers',
    'http-methods', 'http-enum', 'ssl-cert', 'ssl-enum-ciphers',
    'ssh-hostkey', 'dns-brute', 'ftp-anon', 'smb-os-discovery',
    'mysql-info', 'snmp-info', 'telnet-brute',
}

ALLOWED_CATEGORIES = {'safe', 'intrusive', 'discovery', 'vuln', 'auth'}


def contains_dangerous(content: str) -> bool:
    """Check for command injection attempts."""
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, content):
            return True
    return False


def is_valid_target(target: str) -> bool:
    """Validate scan target."""
    if not target or len(target) > 253:
        return False
    if contains_dangerous(target):
        return False
    return bool(TARGET_PATTERN.match(target))


def sanitize(cmd_array: List[str]) -> Tuple[List[str], List[str], Optional[str]]:

    if not isinstance(cmd_array, list):
        return [], [], "Input must be a list"
    
    if len(cmd_array) > 30:
        return [], [], "Too many arguments (max 30)"
    
    for item in cmd_array:
        if not isinstance(item, str):
            return [], [], "All arguments must be strings"
        if contains_dangerous(item):
            return [], [], f"Dangerous characters detected in: {item[:50]}"
    
    sanitized = []
    targets = []
    i = 0
    
    while i < len(cmd_array):
        item = cmd_array[i].strip()
        
        if not item:
            i += 1
            continue
        
        if not item.startswith('-'): #very dumb
            if is_valid_target(item):
                targets.append(item)
            else:
                return [], [], f"Invalid target: {item[:50]}"
            i += 1
            continue
        
        flag = item
        
        if flag in BOOL_FLAGS:
            sanitized.append(flag)
            i += 1
            continue
        
        if flag in ARG_FLAGS:
            validator = ARG_FLAGS[flag]
            
            if i + 1 >= len(cmd_array):
                return [], [], f"Flag {flag} requires an argument"
            
            arg = cmd_array[i + 1]
            
            if validator and not validator(arg):
                return [], [], f"Invalid argument for {flag}: {arg[:50]}"
            
            sanitized.append(flag)
            sanitized.append(arg)
            i += 2
            continue
        
        return [], [], f"Disallowed flag: {flag}"
    
    if not targets:
        return [], [], "No valid target specified"
    
    return sanitized, targets, None