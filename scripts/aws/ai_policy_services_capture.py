#!/usr/bin/env python3
"""Generate AI opt-out service names from the AWS Organizations syntax reference."""
import argparse
from pathlib import Path
import re
import subprocess
import urllib.request

URL = 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out_syntax.md'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--markdown', type=Path)
    args = parser.parse_args()
    source = args.markdown.read_text() if args.markdown else urllib.request.urlopen(URL, timeout=30).read().decode()
    section = source.split('The following key names are valid values for this field:', 1)[1].split('Each policy statement', 1)[0]
    services = sorted(set(re.findall(r'`([a-z][a-z:]*)`', section)))
    if 'default' not in services:
        raise RuntimeError('AWS AI opt-out service names not found')
    lines = ['// Code generated from the AWS Organizations AI opt-out policy syntax; DO NOT EDIT.',
             '// Source: ' + URL, 'package organizations', '', 'var aiOptOutServices = map[string]bool{']
    lines += ['\t"' + service + '": true,' for service in services]
    lines += ['}', '']
    path = Path('internal/services/organizations/ai_services_generated.go')
    path.write_text('\n'.join(lines))
    subprocess.run(['gofmt', '-w', str(path)], check=True)


if __name__ == '__main__': main()
