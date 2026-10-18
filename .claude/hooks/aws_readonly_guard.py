#!/usr/bin/env python3
"""Claude Code PreToolUse hook: only let read-only AWS CLI commands through.

Policy in one sentence: every `aws ...` invocation found in a Bash command must
be positively identified as read-only, otherwise the whole command is denied.

Design rules (keep them when editing):
  * Deny by default. Only an explicit allowlist lets a command through.
  * Fail closed. Anything we cannot parse or recognise is denied.
  * The hook never *grants* permission; on success it stays silent so the
    normal Claude Code permission flow still applies.
  * No dependencies outside the Python standard library.
"""

import json
import re
import shlex
import sys

# --------------------------------------------------------------------------- #
# Policy                                                                       #
# --------------------------------------------------------------------------- #

# AWS names read operations with these prefixes (same convention the AWS-managed
# ReadOnlyAccess policy relies on: Describe*, List*, Get*, ...).
READ_ONLY_VERB_PREFIXES = (
    "describe-",
    "list-",
    "get-",
    "head-",
    "lookup-",
    "search-",
    "batch-get-",
    "batch-describe-",
)

# Read-only verbs that do not follow the prefix convention, grouped by service.
# "*" applies to every service (e.g. `aws ec2 wait ...`, `aws s3 help`).
READ_ONLY_VERBS = {
    "*": {"help", "wait"},
    "s3": {"ls", "presign"},
    "s3api": {"select-object-content"},
    "logs": {"tail", "filter-log-events"},
    "dynamodb": {"query", "scan"},
    "cloudformation": {"validate-template", "estimate-template-cost"},
    "cloudtrail": {"lookup-events"},
    "iam": {"simulate-principal-policy", "simulate-custom-policy"},
    "sts": {"assume-role", "decode-authorization-message"},
    "route53": {"test-dns-answer"},
    "config": {"select-resource-config", "select-aggregate-resource-config"},
    "access-analyzer": {"validate-policy"},
    # Local-only commands (touch ~/.aws, never the AWS account).
    "configure": {"list", "list-profiles", "get", "export-credentials"},
    "sso": {"login", "logout"},
}

# Global CLI options that may appear before the service name.
GLOBAL_OPTIONS_WITH_VALUE = {
    "--profile", "--region", "--output", "--endpoint-url", "--ca-bundle",
    "--cli-read-timeout", "--cli-connect-timeout", "--query", "--color",
    "--cli-binary-format",
}
GLOBAL_FLAGS = {
    "--debug", "--no-verify-ssl", "--no-paginate", "--no-sign-request",
    "--no-cli-pager", "--cli-auto-prompt", "--no-cli-auto-prompt", "--version",
}


class Denied(Exception):
    """Raised with a human-readable reason whenever a command must be blocked."""


# --------------------------------------------------------------------------- #
# Classification of one `aws ...` invocation                                   #
# --------------------------------------------------------------------------- #

def check_aws_invocation(args):
    """Raise Denied unless `aws <args>` is a read-only command."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        name = args[i].split("=", 1)[0]
        if "=" in args[i] or name in GLOBAL_FLAGS:
            i += 1
        elif name in GLOBAL_OPTIONS_WITH_VALUE:
            i += 2
        else:
            raise Denied(f"unknown global option {args[i]!r} before the service name")

    if "--version" in args[:i]:
        return
    if i >= len(args):
        raise Denied("bare `aws` without a service (interactive prompt) is not allowed")

    service = args[i]
    if service == "help":
        return
    if i + 1 >= len(args):
        raise Denied(f"`aws {service}` without a sub-command is not allowed")

    verb = args[i + 1]
    if verb.startswith(READ_ONLY_VERB_PREFIXES):
        return
    if verb in READ_ONLY_VERBS["*"] or verb in READ_ONLY_VERBS.get(service, ()):
        return
    raise Denied(f"`aws {service} {verb}` is not in the read-only allowlist")


# --------------------------------------------------------------------------- #
# Finding every `aws ...` invocation inside a shell command                    #
# --------------------------------------------------------------------------- #

# A quoted token that itself looks like a shell command running aws, e.g.
# sh -c "aws ec2 ..."  /  python -c "os.system('aws ec2 ...')"  /  "$(aws ...)".
# `aws` must be at a command position (start, or after ; & | ( `) and be
# followed by at least one argument, so the bare token `aws` does not match.
EMBEDDED_AWS_COMMAND = re.compile(r"""(^|[;&|(`])\s*['"]?aws\s+\S""")

MAX_NESTING = 5


def aws_invocations(command, depth=0):
    """Yield the argument list of every `aws ...` invocation in `command`."""
    if depth > MAX_NESTING:
        raise Denied("command nesting too deep to analyse")

    # Backticks are command substitution; treat them as command separators.
    lexer = shlex.shlex(command.replace("`", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise Denied(f"cannot tokenize shell command: {exc}") from exc

    # 1. Quoted tokens may hide a whole command: analyse them recursively.
    #    This also covers tokens that are *arguments* of an aws call, e.g.
    #    aws ec2 describe-instances --instance-ids "$(aws ec2 run-instances ...)".
    for token in tokens:
        if EMBEDDED_AWS_COMMAND.search(token):
            yield from aws_invocations(token, depth + 1)

    # 2. Every token `aws` (or /path/to/aws) starts an invocation that runs
    #    until the next shell operator: ( ) ; < > | &
    separators = set(lexer.punctuation_chars)
    i = 0
    while i < len(tokens):
        if tokens[i] == "aws" or tokens[i].endswith("/aws"):
            args = []
            i += 1
            while i < len(tokens) and not set(tokens[i]) <= separators:
                args.append(tokens[i])
                i += 1
            yield args
        else:
            i += 1


# --------------------------------------------------------------------------- #
# Hook entry point                                                             #
# --------------------------------------------------------------------------- #

def check_command(command):
    """Raise Denied if `command` contains any non-read-only aws invocation."""
    for args in aws_invocations(command):
        check_aws_invocation(args)


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"aws-readonly-guard: {reason}",
        }
    }))
    sys.exit(0)


def main():
    try:
        payload = json.load(sys.stdin)
        if payload.get("tool_name") != "Bash":
            return
        check_command(payload.get("tool_input", {}).get("command", ""))
    except Denied as exc:
        deny(str(exc))
    except Exception as exc:  # fail closed on anything unexpected
        deny(f"internal error, blocking to be safe ({type(exc).__name__}: {exc})")


if __name__ == "__main__":
    main()
