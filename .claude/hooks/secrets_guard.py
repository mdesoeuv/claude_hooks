#!/usr/bin/env python3
"""Claude Code PreToolUse hook: keep credentials out of Bash commands, out of
the transcript, and off the network.

Five independent rules, each a short list at the top of this file:
  1. Secret files are never named in a Bash command (credential stores, keys,
     .env files). Claude's own Read deny rules cover the file tools; this
     covers `cat`, `cp`, `python -c "open(...)"` and friends.
  2. Commands whose purpose is to print a credential are denied
     (aws sts assume-role, gh auth token, security find-generic-password, ...).
  3. Expanding a secret-looking variable ($AWS_SECRET_ACCESS_KEY, $GITHUB_TOKEN)
     or dumping the whole environment (`env`, `printenv`) is denied.
  4. Uploading a local file over the network is denied (curl -T / -d @file,
     wget --post-file, scp, rsync to a remote, nc, socat).
  5. Piping into a shell or decoding base64 into a shell is denied.

Deny by default, fail closed, standard library only. The hook never grants
permission; on a clean command it stays silent.
"""

import json
import re
import shlex
import sys

# --------------------------------------------------------------------------- #
# Policy                                                                       #
# --------------------------------------------------------------------------- #

# Boundaries so that `.aws/` does not match `foo.aws/bar` and `id_rsa` does not
# match `id_rsa.pub`.
_B = r"(?<![A-Za-z0-9_.\-])"  # not preceded by a filename character
_E = r"(?![A-Za-z0-9_.\-])"   # not followed by a filename character

SECRET_FILES = [
    (rf"{_B}\.aws(/|{_E})", "AWS CLI credentials and config"),
    (rf"{_B}\.ssh(/|{_E})", "SSH keys"),
    (rf"{_B}\.kube(/|{_E})", "kubeconfig"),
    (rf"{_B}kubeconfig{_E}", "kubeconfig"),
    (rf"{_B}\.gnupg(/|{_E})", "GPG keyring"),
    (rf"{_B}\.azure(/|{_E})", "Azure CLI tokens"),
    (rf"{_B}\.config/gcloud/", "gcloud credentials"),
    (rf"{_B}\.docker/config\.json{_E}", "Docker registry credentials"),
    (rf"{_B}\.terraform\.d/credentials", "Terraform Cloud token"),
    (rf"{_B}\.(netrc|npmrc|pypirc|git-credentials|credentials\.json|claude\.json){_E}", "credential file"),
    (rf"{_B}id_(rsa|dsa|ecdsa|ed25519){_E}", "SSH private key"),
    (rf"{_B}[A-Za-z0-9_\-]+\.(pem|p12|pfx|jks|key){_E}", "private key or keystore"),
    (rf"{_B}[A-Za-z0-9_\-]*\.env(\.[A-Za-z0-9_\-]+)*{_E}", ".env file"),
    (rf"{_B}\.envrc{_E}", "direnv file"),
]
# Tokens that look like a secret file but are not.
SECRET_FILE_EXCEPTIONS = re.compile(r"(process|import\.meta)\.env|\.env\.(example|sample|template|dist)\b")
# Options that hand a secret file to a program without printing it.
SAFE_CONSUMERS = {"--env-file"}

# Commands whose output is a credential: the tool name, then the sub-command
# words that must follow it (in order, contiguous, anywhere before the next
# shell operator), so `sudo aws --profile x sts assume-role` is caught too.
# The optional second element is a flag that must also be present.
SECRET_PRINTING = [
    (("aws", "configure", "export-credentials"),),
    (("aws", "sts", "assume-role"),),
    (("aws", "sts", "get-session-token"),),
    (("aws", "sts", "get-federation-token"),),
    (("aws", "secretsmanager", "get-secret-value"),),
    (("aws", "kms", "decrypt"),),
    (("aws", "ssm", "get-parameter"), "--with-decryption"),
    (("aws", "ssm", "get-parameters"), "--with-decryption"),
    (("aws", "ssm", "get-parameters-by-path"), "--with-decryption"),
    (("gh", "auth", "token"),),
    (("gcloud", "auth", "print-access-token"),),
    (("gcloud", "auth", "print-identity-token"),),
    (("az", "account", "get-access-token"),),
    (("kubectl", "get", "secret"),),
    (("kubectl", "get", "secrets"),),
    (("vault", "read"),),
    (("vault", "kv", "get"),),
    (("op", "read"),),
    (("op", "item", "get"),),
    (("security", "find-generic-password"),),
    (("security", "find-internet-password"),),
    (("security", "dump-keychain"),),
]

SECRET_VARIABLE = re.compile(
    r"\$\{?[A-Za-z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)[A-Za-z0-9_]*",
    re.IGNORECASE,
)
ENV_DUMPERS = {"env", "printenv"}

# Network tools. Pure transfer tools are denied outright; curl/wget/rsync only
# when they send a local file.
TRANSFER_TOOLS = {"scp", "sftp", "ftp", "nc", "ncat", "netcat", "socat", "telnet"}
CURL_UPLOAD_FLAGS = {"-T", "--upload-file"}
WGET_UPLOAD_FLAGS = {"--post-file", "--body-file"}

# Matched on the raw command so quoted forms such as eval "$(... | base64 -d)" are seen.
PIPE_TO_SHELL = re.compile(r"\|\s*(\S*/)?(sh|bash|zsh|dash|ksh|fish)(\s|$)")
BASE64_DECODE = re.compile(r"base64\s+(-[A-Za-z]*[dD][A-Za-z]*|--decode)\b")
SHELL_WORD = re.compile(r"""(^|[\s;&|(`'"])(\S*/)?(sh|bash|zsh|dash|ksh|fish|eval|exec)(\s|$)""")


class Denied(Exception):
    """Raised with a human-readable reason whenever a command must be blocked."""


# --------------------------------------------------------------------------- #
# Rules                                                                        #
# --------------------------------------------------------------------------- #

def check_secret_files(tokens):
    previous = ""
    for token in tokens:
        skip = previous in SAFE_CONSUMERS or token.split("=", 1)[0] in SAFE_CONSUMERS
        previous = token
        if skip or SECRET_FILE_EXCEPTIONS.search(token):
            continue
        for pattern, what in SECRET_FILES:
            if re.search(pattern, token):
                raise Denied(f"{token!r} refers to a {what}; secret files must not appear in commands")


def check_secret_printing(tokens, separators):
    for words, *required in SECRET_PRINTING:
        tool, sub = words[0], list(words[1:])
        for i, token in enumerate(tokens):
            if token.rsplit("/", 1)[-1] != tool:
                continue
            tail = []
            for t in tokens[i + 1:]:
                if set(t) <= separators:
                    break
                tail.append(t)
            follows = any(tail[j:j + len(sub)] == sub for j in range(len(tail)))
            if follows and (not required or required[0] in tail):
                raise Denied(f"`{' '.join(words)}` prints a credential into the transcript")


def check_variables(command, tokens, separators):
    match = SECRET_VARIABLE.search(command)
    if match:
        raise Denied(f"expanding {match.group(0)!r} would expose a secret")
    for i, token in enumerate(tokens):
        if token in ENV_DUMPERS and (i + 1 == len(tokens) or set(tokens[i + 1]) <= separators):
            raise Denied(f"`{token}` dumps the whole environment, including credentials")


def check_network(tokens):
    for i, token in enumerate(tokens):
        name = token.rsplit("/", 1)[-1]
        rest = tokens[i + 1:]
        if name in TRANSFER_TOOLS:
            raise Denied(f"`{name}` transfers files to another host")
        if name == "curl" and any(
            t in CURL_UPLOAD_FLAGS or t.startswith("--upload-file=") or t.startswith("@") or "=@" in t
            for t in rest
        ):
            raise Denied("`curl` uploading a local file is not allowed")
        if name == "wget" and any(t.split("=", 1)[0] in WGET_UPLOAD_FLAGS for t in rest):
            raise Denied("`wget` uploading a local file is not allowed")
        if name == "rsync" and any(":" in t and not t.startswith("-") for t in rest):
            raise Denied("`rsync` to a remote host is not allowed")


def check_obfuscation(command):
    if PIPE_TO_SHELL.search(command):
        raise Denied("piping into a shell runs code that cannot be reviewed")
    if BASE64_DECODE.search(command) and SHELL_WORD.search(command):
        raise Denied("decoding base64 into a shell hides the real command")


# --------------------------------------------------------------------------- #
# Hook entry point                                                             #
# --------------------------------------------------------------------------- #

def tokenize(command):
    lexer = shlex.shlex(command.replace("`", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer), set(lexer.punctuation_chars)
    except ValueError as exc:
        raise Denied(f"cannot tokenize shell command: {exc}") from exc


def check_command(command):
    """Raise Denied if `command` could expose or exfiltrate a credential."""
    tokens, separators = tokenize(command)
    check_secret_files(tokens)
    check_secret_printing(tokens, separators)
    check_variables(command, tokens, separators)
    check_network(tokens)
    check_obfuscation(command)


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"secrets-guard: {reason}",
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
