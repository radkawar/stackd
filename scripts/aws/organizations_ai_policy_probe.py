#!/usr/bin/env python3
"""Capture AI opt-out policy admission without changing account preferences."""
import json
from pathlib import Path
import re

from organizations_policy_admission_probe import capture, probe_parser


def policy(setting, service='default'):
    return {'services': {service: {'opt_out_policy': setting}}}


def cases():
    yield 'empty-document', {}
    yield 'empty-services', {'services': {}}
    yield 'empty-service', {'services': {'default': {}}}
    yield 'empty-setting', policy({})
    yield 'unknown-root', {'other': {}}
    yield 'unknown-service-field', {'services': {'default': {'other': {'@@assign': 'optOut'}}}}
    yield 'unknown-setting-field', policy({'other': {}})
    source = Path('internal/services/organizations/ai_services_generated.go').read_text()
    services = re.findall(r'"([a-z:]+)":', source)
    for service in services + ['unknown', 's3', '*', 'Default', 'LEX', '', 'lex ', 'connecthealth']:
        yield 'service-' + service, policy({'@@assign': 'optOut'}, service)
    for value in ['optIn', 'optOut', 'optin', 'optout', 'OptOut', 'optOut ', '', True, False, 1, None, [], ['optOut'], {}]:
        yield 'value-' + json.dumps(value), policy({'@@assign': value})
    for operator in ['@@append', '@@remove', '@@enforced_for']:
        yield operator, policy({operator: ['optOut']})
        yield operator + '-with-assign', policy({'@@assign': 'optOut', operator: ['optIn']})
    for level in ['root', 'services', 'service', 'setting']:
        for values in [['@@assign'], ['@@none'], ['@@all'], ['@@append'], ['@@remove'], ['@@assign', '@@none'], [], ['@@assign', '@@assign']]:
            doc = policy({'@@assign': 'optOut'})
            node = {'root': doc, 'services': doc['services'], 'service': doc['services']['default'], 'setting': doc['services']['default']['opt_out_policy']}[level]
            node['@@operators_allowed_for_child_policies'] = values
            yield level + '-controls-' + json.dumps(values), doc
        doc = policy({'@@assign': 'optOut'})
        node = {'root': doc, 'services': doc['services'], 'service': doc['services']['default'], 'setting': doc['services']['default']['opt_out_policy']}[level]
        node['@@append'] = []
        yield level + '-empty-append', doc
    for level in ['root', 'services', 'service']:
        doc = policy({'@@assign': 'optOut'})
        node = {'root': doc, 'services': doc['services'], 'service': doc['services']['default']}[level]
        node['@@assign'] = 'optOut'
        yield level + '-assign-with-children', doc
    yield 'controls-only-setting', policy({'@@operators_allowed_for_child_policies': ['@@none']})
    yield 'controls-only-services', {'services': {'@@operators_allowed_for_child_policies': ['@@none']}}


def details():
    yield 'service-q', policy({'@@assign': 'optOut'}, 'q')
    for values in [['@@assign', '@@append'], ['@@append', '@@remove'], ['@@assign', '@@append', '@@remove'], ['@@all', '@@assign'], ['@@none', '@@remove'], ['@@none', '@@none']]:
        yield 'combined-controls-' + json.dumps(values), policy({'@@assign': 'optOut', '@@operators_allowed_for_child_policies': values})
    for service in ['unknown', '', 'Default']:
        yield 'empty-unknown-service-' + service, {'services': {service: {}}}
    for operator in ['@@assign', '@@append', '@@remove']:
        for value in [None, 'optOut', {}, [], ['one'], 1, [None], [{}], [['one']]]:
            doc = policy({'@@assign': 'optOut'})
            doc[operator] = value
            yield 'root-' + operator + '-' + json.dumps(value), doc
    for content in [
        '{"services":{},"services":{}}',
        '{"services":{"default":{},"default":{}}}',
        '{"services":{"default":{"opt_out_policy":{},"opt_out_policy":{}}}}',
        '{"services":{"default":{"opt_out_policy":{"@@assign":"optIn","@@assign":"optOut"}}}}',
        '{"services":{"default":{"opt_out_policy":{"@@operators_allowed_for_child_policies":["@@none"],"@@operators_allowed_for_child_policies":["@@assign"]}}}}',
    ]:
        yield 'duplicate-' + str(len(content)), content
    for level in ['services', 'service', 'setting']:
        doc = policy({'@@assign': 'optOut'})
        if level == 'services': doc['services'] = None
        elif level == 'service': doc['services']['default'] = None
        else: doc['services']['default']['opt_out_policy'] = None
        yield 'null-' + level, doc


if __name__ == '__main__':
    parser = probe_parser()
    parser.add_argument('--details', action='store_true')
    args = parser.parse_args()
    filename = 'organizations_ai_policy_details.json' if args.details else 'organizations_ai_policy.json'
    capture(details() if args.details else cases(), args.output or Path('.stackd/probes/iam') / filename, 'AISERVICES_OPT_OUT_POLICY', args.account)
