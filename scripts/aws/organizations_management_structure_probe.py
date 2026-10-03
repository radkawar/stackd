#!/usr/bin/env python3
"""Capture tag/backup document structure using owned unattached policies."""
import copy
import json
from pathlib import Path

from organizations_policy_admission_probe import capture, probe_parser


def cases(kind):
    root = 'tags' if kind == 'TAG_POLICY' else 'plans'
    for level in ['root', 'container']:
        for operator in ['@@assign', '@@append', '@@remove']:
            for value in ['value', None, ['value'], [], {}, 1]:
                doc = {root: {}}
                node = doc if level == 'root' else doc[root]
                node[operator] = value
                yield level + '-' + operator + '-' + json.dumps(value), doc
    if kind == 'TAG_POLICY':
        document = {'tags': {'Key': {'tag_key': {'@@assign': 'Key'}, 'tag_value': {'@@assign': ['red']}}}}
        field = 'tag_value'
    else:
        document = {'plans': {'Key': {'regions': {'@@assign': ['us-east-1']}}}}
        field = 'regions'
    for level in ['root', 'field', 'operator', 'control']:
        doc = copy.deepcopy(document)
        if level == 'root': doc[root.upper()] = doc.pop(root)
        elif level == 'field': doc[root]['Key'][field.upper()] = doc[root]['Key'].pop(field)
        elif level == 'operator': doc[root]['Key'][field]['@@Assign'] = doc[root]['Key'][field].pop('@@assign')
        else: doc[root]['Key'][field]['@@Operators_Allowed_For_Child_Policies'] = ['@@None']
        yield level + '-case', doc
    for values in [['@@assign', '@@Assign'], ['@@none', '@@Assign']]:
        doc = copy.deepcopy(document)
        doc[root]['Key'][field]['@@operators_allowed_for_child_policies'] = values
        yield 'control-values-' + json.dumps(values), doc


if __name__ == '__main__':
    parser = probe_parser(output_help='Directory for the tag and backup structure captures (default: .stackd/probes/iam)')
    parser.set_defaults(output=Path('.stackd/probes/iam'))
    args = parser.parse_args()
    for kind, name in [('TAG_POLICY', 'tag'), ('BACKUP_POLICY', 'backup')]:
        capture(cases(kind), args.output / ('organizations_' + name + '_structure.json'), kind, args.account)
