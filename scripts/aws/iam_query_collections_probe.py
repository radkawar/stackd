#!/usr/bin/env python3
"""Read-only capture of AWS Query list indexing through IAM policy inspection."""
import datetime
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from iam_conditions_probe import require
from iam_last_access_probe import raw_query


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    document = '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}'
    capture = {'source': 'Signed AWS IAM GetContextKeysForCustomPolicy Query requests',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Read-only policy inspection; no resources created.', 'observations': []}
    cases = [(index, {f'PolicyInputList.member.{index}': document})
             for index in ['1', '01', '+1', 'one', '0', '-1', '11', '12', '16', '17', '20', '21', '22', '31', '32', '33']]
    for indices in [['1', '12'], ['12', '1'], ['1', '8', '15'], ['1', '22'], ['22', '1'], ['1', '22', '43'],
                    [str(i) for i in range(1, 11)] + ['21'], [str(i) for i in range(1, 11)] + ['22']]:
        cases.append(('_'.join(indices), {f'PolicyInputList.member.{index}': document for index in indices}))
    for case, fields in cases:
        result = raw_query('get-context-keys-for-custom-policy', fields)
        row = {'case': case, 'query': fields, 'code': result['code'], 'http_status': result['http_status']}
        if result['code'] != 'Success':
            row['message'] = result['message']
        else:
            row['context_keys'] = result['output'].get('ContextKeyNames') or []
        capture['observations'].append(row)
        print(json.dumps(row), flush=True)
    Path('.stackd/probes/iam/query_collections.json').parent.mkdir(parents=True, exist_ok=True)
    Path('.stackd/probes/iam/query_collections.json').write_text(json.dumps(capture, indent=2) + '\n')


if __name__ == '__main__':
    main()
