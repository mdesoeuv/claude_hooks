#!/usr/bin/env python3
"""install.py - make the guard hooks apply to every project on this machine.

Registers the four hooks and the Read/Edit deny rules in ~/.claude/settings.json
(user scope), pointing at this checkout by absolute path. Works on macOS and
WSL/Linux. Safe to re-run: previous entries from this repo are replaced.

Usage:
  ./install.py                      install or update
  ./install.py --aws-profile NAME   also set env.AWS_PROFILE for every session
  ./install.py --dry-run            print the resulting settings, change nothing
  ./install.py --uninstall          remove what this script added

Requirements: python3 >= 3.8, git. Nothing is downloaded.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
HOOKS_DIR = REPO_DIR / ".claude" / "hooks"
SETTINGS = Path.home() / ".claude" / "settings.json"

GUARDS = ["aws_readonly_guard", "iac_readonly_guard", "git_safety_guard", "secrets_guard"]
# One command per guard that the hook must deny; proves the entry point works here.
SMOKE_TESTS = {
    "aws_readonly_guard": "aws s3 rm s3://bucket/key",
    "iac_readonly_guard": "terraform apply",
    "git_safety_guard": "git push --force",
    "secrets_guard": "cat .env",
}
READ_RULES = ["Read(./.env)", "Read(./.env.*)", "Read(~/.aws/**)", "Read(~/.ssh/**)"]
# Edit rules protecting a checkout of this repo, whatever path it had before.
OUR_EDIT_RULE = re.compile(r"^Edit\(//.*/\.claude/(hooks/\*\*|settings\.json)\)$")


def die(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- prerequisites

def check_prerequisites():
    if sys.version_info < (3, 8):
        die(f"python3 >= 3.8 is required, this is {sys.version.split()[0]}")
    if shutil.which("python3") is None:
        die("'python3' is not on PATH; the hooks are registered as 'python3 -I ...'. "
            "macOS: 'xcode-select --install' or 'brew install python'. WSL: 'sudo apt install python3'.")
    if shutil.which("git") is None:
        die("git not found (git_safety_guard.py needs it). WSL: 'sudo apt install git'.")
    for guard in GUARDS:
        for name in (f"{guard}.py", f"test_{guard}.py"):
            if not (HOOKS_DIR / name).is_file():
                die(f"missing {HOOKS_DIR / name}")


# ------------------------------------------------------------- tests + smoke test
# A hook that is broken on this machine would, with onFailure=block, deny every
# Bash command in every project. So prove each one works before registering it.

def run_tests():
    print(f"Testing the hooks with python {sys.version.split()[0]} ...")
    for guard in GUARDS:
        test = HOOKS_DIR / f"test_{guard}.py"
        result = subprocess.run(["python3", "-I", str(test)], capture_output=True, text=True)
        if result.returncode != 0:
            die(f"{guard} tests fail. Run: python3 -I {test}")
        print(f"  {guard}: tests pass")


def smoke_test():
    for guard, command in SMOKE_TESTS.items():
        payload = json.dumps({"tool_name": "Bash", "cwd": "/", "tool_input": {"command": command}})
        result = subprocess.run(
            ["python3", "-I", str(HOOKS_DIR / f"{guard}.py")], input=payload, capture_output=True, text=True,
        )
        if '"deny"' not in result.stdout:
            die(f"{guard} did not deny '{command}' when run through the hook entry point")
        print(f"  {guard}: denies '{command}'")


# ------------------------------------------------------------ merge the settings

def hook_is_ours(hook):
    return any(f"/{guard}.py" in hook.get("command", "") for guard in GUARDS)


def merge(settings, mode, aws_profile):
    """Return `settings` with this repo's entries removed, then re-added if installing."""
    groups = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
    for group in groups:
        group["hooks"] = [h for h in group.get("hooks", []) if not hook_is_ours(h)]
    groups[:] = [g for g in groups if g.get("hooks")]

    deny = settings.setdefault("permissions", {}).setdefault("deny", [])
    deny[:] = [r for r in deny if not OUR_EDIT_RULE.match(r)]
    if mode == "uninstall":
        deny[:] = [r for r in deny if r not in READ_RULES]

    if mode == "install":
        groups.append({"matcher": "Bash", "hooks": [
            {"type": "command", "command": f'python3 -I "{HOOKS_DIR / guard}.py"', "timeout": 10, "onFailure": "block"}
            for guard in GUARDS
        ]})
        deny += [r for r in READ_RULES if r not in deny]
        root = REPO_DIR.as_posix().lstrip("/")
        deny += [f"Edit(//{root}/.claude/hooks/**)", f"Edit(//{root}/.claude/settings.json)"]
        if aws_profile:
            settings.setdefault("env", {})["AWS_PROFILE"] = aws_profile

    # Drop containers we emptied, so an uninstall leaves no trace.
    for parent, key in (("hooks", "PreToolUse"), ("permissions", "deny")):
        if not settings.get(parent, {}).get(key):
            settings.get(parent, {}).pop(key, None)
        if parent in settings and not settings[parent]:
            del settings[parent]
    return settings


def load_settings():
    if not SETTINGS.exists():
        return {}
    try:
        return json.loads(SETTINGS.read_text())
    except json.JSONDecodeError as exc:
        die(f"{SETTINGS} is not valid JSON ({exc}); fix it before running this script")


def write_settings(settings, dry_run, mode):
    text = json.dumps(settings, indent=2) + "\n"
    if dry_run:
        print(f"--- {SETTINGS} would become:")
        print(text, end="")
        return
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    if SETTINGS.exists():
        backup = SETTINGS.with_name(f"settings.json.bak.{datetime.now():%Y%m%d%H%M%S}")
        shutil.copy2(SETTINGS, backup)
    SETTINGS.write_text(text)
    print(f"{'Updated' if mode == 'install' else 'Cleaned'} {SETTINGS}")


# ------------------------------------------------------------------- what's next

def next_steps(mode, aws_profile):
    if mode == "install":
        print()
        print(f"Installed for every project of {os.environ.get('USER', 'this user')}. Hooks run from: {HOOKS_DIR}")
        print("  - start a new Claude Code session (or run /hooks in an open one) to load them")
        print("  - verify from any project: ask Claude to run 'aws s3 rm s3://x/y'; it must be denied")
        print("  - do not move or delete this checkout: the hooks fail closed and would block every Bash command")
        if not aws_profile:
            print("  - to pin a read-only AWS profile, re-run with --aws-profile NAME (see README, 'Pinning the agent')")
        print("  - inside this repository the hooks also run from .claude/settings.json; that is harmless")
    else:
        print("Removed the hooks and deny rules added by this script. env.AWS_PROFILE, if set, was left in place.")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[1], formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--aws-profile", metavar="NAME", help="also set env.AWS_PROFILE for every session")
    parser.add_argument("--dry-run", action="store_true", help="print the resulting settings, change nothing")
    parser.add_argument("--uninstall", action="store_true", help="remove what this script added")
    args = parser.parse_args()
    mode = "uninstall" if args.uninstall else "install"

    check_prerequisites()
    settings = load_settings()  # fail on a broken settings file before running the tests
    if mode == "install":
        run_tests()
        smoke_test()
    settings = merge(settings, mode, args.aws_profile)
    write_settings(settings, args.dry_run, mode)
    if not args.dry_run:
        next_steps(mode, args.aws_profile)


if __name__ == "__main__":
    main()
