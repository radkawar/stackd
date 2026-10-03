#!/usr/bin/env python3
"""Generate backup-policy resource selectors from the AWS syntax reference."""
import argparse
from pathlib import Path
import re
import subprocess
import urllib.request

URL='https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_backup_syntax.md'

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--markdown',type=Path)
    args=parser.parse_args()
    source=args.markdown.read_text() if args.markdown else urllib.request.urlopen(URL,timeout=30).read().decode()
    section=source.split('**Supported resource types**',1)[1].split('For more information',1)[0]
    resources=sorted(set(re.findall(r'"(arn:[^"]+)"',section)))
    if not resources: raise RuntimeError('AWS resource selector table not found')
    lines=['// Code generated from the AWS Organizations backup-policy syntax; DO NOT EDIT.','// Source: '+URL,'package organizations','','var backupResourceTypes = map[string]bool{']
    lines += ['\t"'+resource+'": true,' for resource in resources]
    lines += ['}','']
    path=Path('internal/services/organizations/backup_resources_generated.go')
    path.write_text('\n'.join(lines))
    subprocess.run(['gofmt','-w',str(path)],check=True)

if __name__=='__main__': main()
