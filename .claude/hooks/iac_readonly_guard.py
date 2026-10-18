#!/usr/bin/env python3
"""Claude Code PreToolUse hook: only let read-only infrastructure-as-code
commands through. Covers Terraform / OpenTofu / Terragrunt, AWS CDK, CDKTF,
Pulumi, AWS SAM, eksctl and the Serverless Framework.

Same design as aws_readonly_guard.py:
  * Deny by default. Only an explicit allowlist lets a command through.
  * Fail closed. Anything we cannot parse or recognise is denied.
  * The hook never *grants* permission; on success it stays silent so the
    normal Claude Code permission flow still applies.
  * No dependencies outside the Python standard library.

"Read-only" here means: nothing is created, changed or destroyed in a cloud
account or in a remote state backend. Commands that only write files inside the
project (fmt, synth, build, init scaffolding) are allowed.
"""

import json
import re
import shlex
import sys

# --------------------------------------------------------------------------- #
# Policy                                                                       #
# --------------------------------------------------------------------------- #

# Allowed sub-commands per tool. An entry may be one word ("plan") or two
# ("state list"). A one-word entry allows every sub-sub-command under it, so
# only use one word when nothing under it can write to the cloud
# (e.g. "state" is NOT listed because of "state rm"; "state list" is).
TERRAFORM = {
    "init", "validate", "fmt", "plan", "show", "output", "graph", "console",
    "get", "providers", "version",
    "state list", "state show", "state pull",
    "workspace list", "workspace show", "workspace select",
}
CDK = {
    "synth", "synthesize", "diff", "ls", "list", "doctor", "context", "metadata",
    "notices", "acknowledge", "ack", "init", "version",
}
SERVERLESS = {"print", "info", "logs", "package", "metrics", "version"}

READ_ONLY_COMMANDS = {
    "terraform": TERRAFORM,
    "tofu": TERRAFORM,
    "terragrunt": TERRAFORM | {
        "run-all init", "run-all validate", "run-all plan", "run-all output",
        "hclfmt", "validate-inputs", "graph-dependencies", "render-json",
    },
    "cdk": CDK,
    "aws-cdk": CDK,  # `npx aws-cdk ...`
    "cdktf": {"synth", "diff", "list", "get", "convert", "debug", "init"},
    "pulumi": {
        "preview", "pre", "config", "whoami", "about", "version", "logs", "login", "logout",
        "stack ls", "stack output", "stack export", "stack history", "stack select",
        "plugin ls",
    },
    "sam": {"build", "validate", "init", "local", "list", "logs", "traces"},
    "eksctl": {"get", "info", "version", "completion", "utils describe-stacks", "utils schema"},
    "serverless": SERVERLESS,
    "sls": SERVERLESS,
}

# Flags that turn an otherwise read-only sub-command into a write.
DENIED_FLAGS = {
    "init": ("-migrate-state", "-force-copy"),  # terraform init: moves remote state
}

# Allowed when the tool is called with options only (no sub-command).
HELP_FLAGS = {"-h", "-help", "--help", "-v", "-version", "--version"}
HELP_WORDS = {"help", "version"}


class Denied(Exception):
    """Raised with a human-readable reason whenever a command must be blocked."""


# --------------------------------------------------------------------------- #
# Classification of one `<tool> ...` invocation                                #
# --------------------------------------------------------------------------- #

def check_invocation(tool, args):
    """Raise Denied unless `<tool> <args>` is a read-only command."""
    positional = [a for a in args if not a.startswith("-")]
    if not positional:
        if all(a in HELP_FLAGS for a in args):
            return  # bare `terraform`, `cdk --version`, ...
        raise Denied(f"`{tool} {' '.join(args)}`: options without a recognised sub-command")

    one, two = positional[0], " ".join(positional[:2])
    if one in HELP_WORDS:
        return
    allowed = READ_ONLY_COMMANDS[tool]
    if one not in allowed and two not in allowed:
        raise Denied(
            f"`{tool} {two}` is not in the read-only allowlist "
            "(if this is a read command, put options after the sub-command)"
        )
    for flag in DENIED_FLAGS.get(one, ()):
        if any(a == flag or a.startswith(flag + "=") for a in args):
            raise Denied(f"`{tool} {one} {flag}` changes remote state")


# --------------------------------------------------------------------------- #
# Finding every tool invocation inside a shell command                         #
# --------------------------------------------------------------------------- #

def tool_name(token):
    """`/usr/local/bin/terraform` -> terraform, `aws-cdk@2.1.0` -> aws-cdk, else None."""
    name = token.rsplit("/", 1)[-1].split("@", 1)[0]
    return name if name in READ_ONLY_COMMANDS else None


# A quoted token that itself looks like a shell command running one of the
# tools, e.g. sh -c "terraform apply" or "$(pulumi up)". The tool must be at a
# command position (start, or after ; & | ( `) and be followed by an argument.
EMBEDDED_COMMAND = re.compile(
    r"""(^|[;&|(`])\s*['"]?(\S*/)?(%s)(@\S*)?\s+\S""" % "|".join(map(re.escape, READ_ONLY_COMMANDS))
)

MAX_NESTING = 5


def tool_invocations(command, depth=0):
    """Yield (tool, args) for every IaC tool invocation found in `command`."""
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
    for token in tokens:
        if EMBEDDED_COMMAND.search(token):
            yield from tool_invocations(token, depth + 1)

    # 2. Every token naming a tool starts an invocation that runs until the
    #    next shell operator: ( ) ; < > | &
    separators = set(lexer.punctuation_chars)
    i = 0
    while i < len(tokens):
        tool = tool_name(tokens[i])
        i += 1
        if tool is None:
            continue
        args = []
        while i < len(tokens) and not set(tokens[i]) <= separators:
            args.append(tokens[i])
            i += 1
        yield tool, args


# --------------------------------------------------------------------------- #
# Hook entry point                                                             #
# --------------------------------------------------------------------------- #

def check_command(command):
    """Raise Denied if `command` contains any non-read-only IaC invocation."""
    for tool, args in tool_invocations(command):
        check_invocation(tool, args)


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"iac-readonly-guard: {reason}",
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
