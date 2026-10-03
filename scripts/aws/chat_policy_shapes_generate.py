#!/usr/bin/env python3
"""Generate Organizations chat-policy identifiers from the Chatbot Smithy model."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', type=Path, default=Path('clones/aws-sdk-go-v2/codegen/sdk-codegen/aws-models/chatbot.json'))
    args = parser.parse_args()
    shapes = json.loads(args.model.read_text())['shapes']
    lines = ['// Code generated from AWS SDK for Go v2 chatbot.json; DO NOT EDIT.',
             'package organizations', '', 'import "regexp"', '']
    for variable, shape in [('chatWorkspaceID', 'SlackTeamId'), ('chatTeamsID', 'UUID')]:
        pattern = shapes['com.amazonaws.chatbot#' + shape]['traits']['smithy.api#pattern']
        lines.append('var ' + variable + ' = regexp.MustCompile(' + json.dumps(pattern) + ')')
    path = Path('internal/services/organizations/chat_shapes_generated.go')
    path.write_text('\n'.join(lines) + '\n')
    subprocess.run(['gofmt', '-w', str(path)], check=True)


if __name__ == '__main__': main()
