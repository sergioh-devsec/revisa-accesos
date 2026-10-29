"""Offline authentication-log triage. Python 3.10+, standard library only."""
import argparse
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path

PATTERN = re.compile(r'([01]\d|2[0-3]):[0-5]\d:[0-5]\d\s+(ACCEPT|DENY)\s+((?:\d{1,3}\.){3}\d{1,3})')
MAX_BYTES = 2_000_000

def analyze(text, threshold=3):
    if not isinstance(threshold, int) or isinstance(threshold, bool) or not 1 <= threshold <= 100000:
        raise ValueError('threshold must be an integer from 1 to 100000')
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('maximum input size: 2 MB')
    denied = Counter(); valid = accepted = total = 0; invalid = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        total += 1
        match = PATTERN.fullmatch(line)
        if not match:
            invalid.append(number); continue
        try:
            address = str(ipaddress.IPv4Address(match[3]))
        except ipaddress.AddressValueError:
            invalid.append(number); continue
        valid += 1
        if match[2] == 'DENY': denied[address] += 1
        else: accepted += 1
    return {'total':total,'valid':valid,'accepted':accepted,'denied':sum(denied.values()),
            'invalid_lines':invalid,'threshold':threshold,
            'findings':[{'ip':ip,'denials':count} for ip,count in sorted(denied.items(),key=lambda x:(-x[1],x[0])) if count >= threshold],
            'limitations':'Counts the whole input, without a time window. Findings are triage signals, not proof of attack.'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('--threshold',type=int,default=3)
    parser.add_argument('--output',type=Path,help='Optional new JSON report; existing files are never overwritten.')
    args=parser.parse_args()
    try:
        if args.input.stat().st_size > MAX_BYTES: raise ValueError('maximum input size: 2 MB')
        report=analyze(args.input.read_text(encoding='utf-8-sig'),args.threshold)
        content=json.dumps(report,indent=2,ensure_ascii=False)+'\n'
        if args.output:
            with args.output.open('x',encoding='utf8') as stream: stream.write(content)
        else: print(content,end='')
    except (ValueError,OSError) as error: parser.exit(2,f'Error: {error}\n')

if __name__=='__main__': main()
