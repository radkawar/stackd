#!/usr/bin/env python3
"""Capture chat policy admission using owned, unattached Organizations policies."""
import json
from pathlib import Path

from organizations_policy_admission_probe import capture, probe_parser


def assign(value): return {'@@assign': value}
def platform(name='slack', **settings): return {'chatbot': {'platforms': {name: settings}}}


def cases():
    yield 'empty-document', {}
    yield 'empty-chatbot', {'chatbot': {}}
    yield 'empty-platforms', {'chatbot': {'platforms': {}}}
    yield 'unknown-root', {'other': {}}
    yield 'unknown-chatbot-field', {'chatbot': {'other': {}}}
    for name in ['slack', 'microsoft_teams', 'chime', 'default', 'unknown', 'Slack']:
        yield 'empty-platform-' + name, platform(name)
        yield 'platform-client-' + name, platform(name, client=assign('enabled'))
    for name in ['slack', 'microsoft_teams', 'chime']:
        yield 'unknown-platform-field-' + name, platform(name, other=assign('enabled'))
    yield 'chatbot-default', {'chatbot': {'default': {'client': assign('disabled')}}}
    yield 'unknown-chatbot-default', {'chatbot': {'default': {'other': assign('disabled')}}}
    yield 'empty-client', platform(client={})
    for value in ['enabled', 'disabled', 'ENABLED', 'true', True, 1, None, [], ['enabled'], {}]:
        yield 'client-' + json.dumps(value), platform(client=assign(value))
    for value in ['*', 'T0123', 'one', '', 'a' * 255, 'a' * 256, 'with space', 'T*', 1, True, None, {}, []]:
        yield 'workspace-' + json.dumps(value), platform(workspaces=assign([value]))
    for value in [[], '*', ['*', 'T0123'], ['T0123', 'T0123']]:
        yield 'workspaces-' + json.dumps(value), platform(workspaces=assign(value))
    for count in [255, 256]:
        yield 'workspace-count-' + str(count), platform(workspaces=assign(['T' + str(i) for i in range(count)]))
    for field, values in [('supported_channel_types', ['public', 'private', 'PUBLIC', '*', 'wrong']), ('supported_role_settings', ['user_role', 'channel_role', 'USER_ROLE', '*', 'wrong'])]:
        for value in values + [True, 1, None]:
            yield field + '-' + json.dumps(value), platform(default={field: assign([value])})
        yield field + '-empty', platform(default={field: assign([])})
        yield field + '-scalar', platform(default={field: assign(values[0])})
        yield field + '-duplicates', platform(default={field: assign([values[0], values[0]])})
    for operator in ['@@append', '@@remove']:
        yield 'workspace-' + operator, platform(workspaces={operator: ['T0123']})
        yield 'client-' + operator, platform(client={operator: ['enabled']})
        yield 'channel-' + operator, platform(default={'supported_channel_types': {operator: ['public']}})
    yield 'chime-default', platform('chime', default={'supported_role_settings': assign(['user_role'])})
    yield 'teams-channel-types', platform('microsoft_teams', default={'supported_channel_types': assign(['public'])})
    yield 'teams-roles', platform('microsoft_teams', default={'supported_role_settings': assign(['user_role'])})
    for value in ['*', 'one', '', 'a' * 36, 'a' * 37, '12345678-1234-1234-1234-123456789abc', 'with space']:
        yield 'tenant-' + value, platform('microsoft_teams', tenants={value: assign(['*'])})
        yield 'team-' + value, platform('microsoft_teams', tenants={'12345678-1234-1234-1234-123456789abc': assign([value])})
    for count in [36, 37]:
        yield 'tenant-count-' + str(count), platform('microsoft_teams', tenants={str(i): assign(['*']) for i in range(count)})
        yield 'team-count-' + str(count), platform('microsoft_teams', tenants={'one': assign([str(i) for i in range(count)])})
    for name in ['*', 'T0123', '', 'with space', 'T*']:
        yield 'slack-override-' + name, platform(overrides={name: {'supported_channel_types': assign(['private'])}})
    yield 'unknown-slack-default', platform(default={'other': assign(['private'])})
    yield 'unknown-slack-override', platform(overrides={'T0123': {'other': assign(['private'])}})
    yield 'teams-override', platform('microsoft_teams', overrides={'tenant': {'team': {'supported_role_settings': assign(['user_role'])}}})
    yield 'teams-override-wildcards', platform('microsoft_teams', overrides={'*': {'*': {'supported_role_settings': assign(['user_role'])}}})
    yield 'teams-override-channel', platform('microsoft_teams', overrides={'tenant': {'team': {'supported_channel_types': assign(['private'])}}})
    for level in ['root', 'chatbot', 'platforms', 'slack', 'client']:
        doc = platform(client=assign('enabled'))
        node = {'root': doc, 'chatbot': doc['chatbot'], 'platforms': doc['chatbot']['platforms'], 'slack': doc['chatbot']['platforms']['slack'], 'client': doc['chatbot']['platforms']['slack']['client']}[level]
        node['@@operators_allowed_for_child_policies'] = ['@@none']
        yield level + '-controls', doc
        node.pop('@@operators_allowed_for_child_policies')
        node['@@append'] = ['enabled']
        yield level + '-append', doc


def details():
    for level, key in [('root', 'CHATBOT'), ('chatbot', 'Platforms'), ('platforms', 'SLACK'), ('slack', 'Client')]:
        doc = platform(client=assign('enabled'))
        node, original = {'root': (doc, 'chatbot'), 'chatbot': (doc['chatbot'], 'platforms'), 'platforms': (doc['chatbot']['platforms'], 'slack'), 'slack': (doc['chatbot']['platforms']['slack'], 'client')}[level]
        node[key] = node.pop(original)
        yield level + '-case', doc
    yield 'default-field-case', platform(default={'Supported_Channel_Types': assign(['private'])})
    yield 'duplicate-platform-case', {'chatbot': {'platforms': {'slack': {}, 'Slack': {}}}}
    yield 'duplicate-root-case', {'chatbot': {}, 'Chatbot': {}}
    yield 'duplicate-client-case', platform(client=assign('enabled'), Client=assign('disabled'))
    yield 'assignment-operator-case', platform(client={'@@Assign': 'enabled'})
    for value in ['T' * 255, 'T' * 256, '123', 'aBC', 'T_A', 'T-A']:
        yield 'workspace-detail-' + str(len(value)) + '-' + value[:8], platform(workspaces=assign([value]))
        yield 'override-detail-' + str(len(value)) + '-' + value[:8], platform(overrides={value: {}})
    for count in [36, 37]:
        ids = ['00000000-0000-0000-0000-' + f'{i:012x}' for i in range(count)]
        yield 'valid-tenants-' + str(count), platform('microsoft_teams', tenants={key: assign(['*']) for key in ids})
        yield 'valid-teams-' + str(count), platform('microsoft_teams', tenants={ids[0]: assign(ids)})
    tenant = '12345678-1234-1234-1234-123456789abc'
    team = '12345678-ABCD-1234-1234-123456789ABC'
    for tenant_key, team_key in [(tenant, team), ('*', team), (tenant, '*')]:
        yield 'override-' + tenant_key + '-' + team_key, platform('microsoft_teams', overrides={tenant_key: {team_key: {'supported_role_settings': assign(['user_role'])}}})
    yield 'empty-teams-tenant', platform('microsoft_teams', tenants={tenant: {}})
    yield 'empty-teams-list', platform('microsoft_teams', tenants={tenant: assign([])})
    yield 'mixed-teams-wildcard', platform('microsoft_teams', tenants={tenant: assign(['*', team])})
    for operator in ['@@append', '@@remove']:
        yield 'teams-' + operator, platform('microsoft_teams', tenants={tenant: {operator: [team]}})
        yield 'roles-' + operator, platform('microsoft_teams', default={'supported_role_settings': {operator: ['user_role']}})
    for value in [None, [], ['one'], {}, 'one', 1, [None], [{}]]:
        doc = platform(client=assign('enabled'))
        doc['@@assign'] = value
        yield 'root-assign-' + json.dumps(value), doc
    for value in [['private', 'public'], ['private', 'public', 'private']]:
        yield 'channel-types-' + json.dumps(value), platform(default={'supported_channel_types': assign(value)})


def overrides():
    tenant = '12345678-1234-1234-1234-123456789abc'
    team = '12345678-abcd-1234-1234-123456789abc'
    for key in [team, team.upper()]:
        yield 'team-case-' + key, platform('microsoft_teams', tenants={tenant: assign([key])})
        yield 'tenant-case-' + key, platform('microsoft_teams', tenants={key: assign(['*'])})
        for settings in [{}, {'supported_role_settings': assign(['user_role'])}, {'supported_role_settings': assign([])}]:
            yield 'override-case-' + key + '-' + json.dumps(settings), platform('microsoft_teams', overrides={tenant: {key: settings}})
    for name, body in [
        ('empty-overrides', {}), ('empty-tenant', {tenant: {}}), ('wildcard-empty', {'*': {}}),
        ('flat', {team: {'supported_role_settings': assign(['user_role'])}}),
        ('tenant-with-teams', {tenant: {'teams': {team: {'supported_role_settings': assign(['user_role'])}}}}),
        ('short-key', {tenant: {'team': {}}}), ('wildcard-team', {tenant: {'*': {}}}),
    ]:
        yield name, platform('microsoft_teams', overrides=body)
    for name, setting in [('slack', {'client': assign('disabled')}), ('slack-empty', {}), ('slack-client-and-role', {'client': assign('disabled'), 'supported_role_settings': assign(['user_role'])})]:
        yield name + '-override-fields', platform(overrides={'T0123': setting})
    yield 'workspace-only-wildcard-append', platform(workspaces={'@@append': ['*']})
    for value in ['@@assign', '@@Assign', '@@ASSIGN', '@@All', '@@NONE']:
        yield 'child-control-case-' + value, platform(client={'@@Operators_Allowed_For_Child_Policies': [value], '@@Assign': 'enabled'})


if __name__ == '__main__':
    parser = probe_parser()
    parser.add_argument('--details', action='store_true')
    parser.add_argument('--overrides', action='store_true')
    args = parser.parse_args()
    observations = overrides() if args.overrides else details() if args.details else cases()
    suffix = '_overrides' if args.overrides else '_details' if args.details else ''
    output = args.output or Path('.stackd/probes/iam/organizations_chat_policy' + suffix + '.json')
    capture(observations, output, 'CHATBOT_POLICY', args.account)
