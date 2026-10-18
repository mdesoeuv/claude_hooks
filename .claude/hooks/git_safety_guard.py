#!/usr/bin/env python3
"""Claude Code PreToolUse hook: block destructive git operations, pushes to
protected branches, and bypasses of commit hooks.

Unlike aws_readonly_guard.py and iac_readonly_guard.py this is a *deny list*:
git is used constantly and almost everything it does is recoverable through the
reflog, so allowlisting every sub-command would only create friction. The deny
list targets what cannot be recovered (uncommitted changes, remote history,
stashes, the reflog itself) and what bypasses team controls (protected
branches, commit hooks). Parsing still fails closed: unknown global options,
git aliases and an unresolvable current branch are denied.
"""

import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys

# --------------------------------------------------------------------------- #
# Policy                                                                       #
# --------------------------------------------------------------------------- #

# Branches that must only change through pull requests (fnmatch patterns).
PROTECTED_BRANCHES = ("main", "master", "production", "release/*")

# git global options that may appear before the sub-command.
GLOBAL_OPTIONS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
GLOBAL_FLAGS = {
    "--no-pager", "-p", "--paginate", "-P", "--bare", "--no-replace-objects",
    "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
    "--icase-pathspecs", "--no-optional-locks", "--version", "--help", "-h",
}
PUSH_OPTIONS_WITH_VALUE = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}

WHOLE_TREE = {".", ":/", ":/.", "*"}


class Denied(Exception):
    """Raised with a human-readable reason whenever a command must be blocked."""


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def split_args(args, options_with_value=()):
    """Return (long_flags, short_letters, positionals) for one sub-command."""
    longs, shorts, positionals = set(), set(), []
    it = iter(args)
    for arg in it:
        if arg == "--":
            positionals.extend(it)
        elif arg.startswith("--"):
            longs.add(arg.split("=", 1)[0])
            if arg in options_with_value:
                next(it, None)
        elif arg.startswith("-") and len(arg) > 1:
            shorts.update(arg[1:])
            if arg in options_with_value:
                next(it, None)
        else:
            positionals.append(arg)
    return longs, shorts, positionals


def run_git(directory, *args):
    """Return git's stdout, or None if git failed (not a repo, detached HEAD, ...)."""
    try:
        proc = subprocess.run(["git", "-C", directory, *args], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def is_protected(branch):
    branch = re.sub(r"^refs/heads/", "", branch)
    return any(fnmatch.fnmatchcase(branch, pattern) for pattern in PROTECTED_BRANCHES)


# --------------------------------------------------------------------------- #
# Per sub-command checks. Each receives the args after the sub-command.        #
# --------------------------------------------------------------------------- #

def check_push(args, ctx):
    longs, shorts, positionals = split_args(args, PUSH_OPTIONS_WITH_VALUE)
    if "f" in shorts or longs & {"--force", "--force-with-lease", "--force-if-includes"}:
        raise Denied("force push rewrites remote history")
    if "d" in shorts or longs & {"--delete", "--mirror", "--all", "--prune"}:
        raise Denied("`git push --delete/--mirror/--all/--prune` can remove or overwrite remote branches")
    if "--no-verify" in longs:
        raise Denied("`git push --no-verify` skips the pre-push hooks")

    targets = []
    for spec in positionals[1:]:  # positionals[0] is the remote
        if spec.startswith("+"):
            raise Denied(f"refspec {spec!r} is a force push")
        src, has_colon, dst = spec.partition(":")
        if has_colon and not src:
            raise Denied(f"refspec {spec!r} deletes a remote branch")
        targets.append(dst if has_colon else src)
    if "--tags" in longs and not positionals[1:]:
        return  # `git push --tags` pushes tags only, not the current branch
    if not positionals[1:] or "HEAD" in targets:
        targets += current_branch_targets(ctx)

    for target in targets:
        if is_protected(target):
            raise Denied(f"push to protected branch {target!r}; open a pull request instead")


def current_branch_targets(ctx):
    """Branches a bare `git push` would update: the current branch and its upstream."""
    if ctx["changes_directory"]:
        raise Denied("`git push` after `cd`: name the remote and branch explicitly")
    branch = run_git(ctx["git_dir"], "symbolic-ref", "--short", "-q", "HEAD")
    if not branch:
        raise Denied("cannot determine the current branch; name the remote and branch explicitly")
    upstream = run_git(ctx["git_dir"], "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    targets = [branch]
    if upstream and "/" in upstream:
        targets.append(upstream.split("/", 1)[1])  # drop the remote name
    return targets


def check_reset(args, ctx):
    longs, _, _ = split_args(args)
    if "--hard" in longs:
        raise Denied("`git reset --hard` discards uncommitted changes")


def check_clean(args, ctx):
    longs, shorts, _ = split_args(args)
    if "n" not in shorts and "--dry-run" not in longs:
        raise Denied("`git clean` deletes untracked files; only --dry-run is allowed")


def check_checkout(args, ctx):
    longs, shorts, positionals = split_args(args)
    if "f" in shorts or "--force" in longs:
        raise Denied("`git checkout --force` discards uncommitted changes")
    if WHOLE_TREE & set(positionals):
        raise Denied("`git checkout .` discards every uncommitted change")


def check_restore(args, ctx):
    _, _, positionals = split_args(args)
    if WHOLE_TREE & set(positionals):
        raise Denied("`git restore .` discards every uncommitted change")


def check_switch(args, ctx):
    longs, shorts, _ = split_args(args)
    if "f" in shorts or longs & {"--force", "--discard-changes"}:
        raise Denied("`git switch --discard-changes` discards uncommitted changes")


def check_branch(args, ctx):
    longs, shorts, _ = split_args(args)
    if "D" in shorts or "f" in shorts or "--force" in longs:
        raise Denied("`git branch -D/--force` deletes or moves a branch without safety checks")


def check_commit(args, ctx):
    longs, shorts, _ = split_args(args)
    if "n" in shorts or "--no-verify" in longs:
        raise Denied("`git commit --no-verify` skips the pre-commit hooks")


def check_stash(args, ctx):
    if args and args[0] in {"drop", "clear"}:
        raise Denied(f"`git stash {args[0]}` deletes stashed work")


def check_reflog(args, ctx):
    if args and args[0] in {"expire", "delete"}:
        raise Denied(f"`git reflog {args[0]}` destroys the safety net for every other recovery")


def check_gc(args, ctx):
    if any(a.startswith("--prune=") for a in args):
        raise Denied("`git gc --prune=<date>` permanently deletes unreachable commits")


def check_update_ref(args, ctx):
    if "-d" in args:
        raise Denied("`git update-ref -d` deletes a ref")


def always_denied(reason):
    def check(args, ctx):
        raise Denied(reason)
    return check


CHECKS = {
    "push": check_push,
    "reset": check_reset,
    "clean": check_clean,
    "checkout": check_checkout,
    "restore": check_restore,
    "switch": check_switch,
    "branch": check_branch,
    "commit": check_commit,
    "stash": check_stash,
    "reflog": check_reflog,
    "gc": check_gc,
    "update-ref": check_update_ref,
    "prune": always_denied("`git prune` permanently deletes unreachable objects"),
    "filter-branch": always_denied("`git filter-branch` rewrites history"),
    "filter-repo": always_denied("`git filter-repo` rewrites history"),
}


# --------------------------------------------------------------------------- #
# One `git ...` invocation                                                     #
# --------------------------------------------------------------------------- #

def check_git_invocation(args, ctx):
    ctx = dict(ctx)
    i = 0
    while i < len(args) and args[i].startswith("-"):
        name, _, inline_value = args[i].partition("=")
        if name in GLOBAL_FLAGS:
            value, i = None, i + 1
        elif name in GLOBAL_OPTIONS_WITH_VALUE:
            value = inline_value if inline_value else (args[i + 1] if i + 1 < len(args) else "")
            i += 1 if inline_value else 2
        else:
            raise Denied(f"unknown git global option {args[i]!r}")
        if name == "-C" and value:
            ctx["git_dir"] = os.path.join(ctx["git_dir"], value)
        if name in {"-c", "--config-env"} and value.lower().startswith("core.hookspath"):
            raise Denied("overriding core.hooksPath disables the repository hooks")

    if i >= len(args):
        return  # bare `git` prints help
    sub, rest = args[i], args[i + 1:]

    if run_git(ctx["git_dir"], "config", "--get", f"alias.{sub}"):
        raise Denied(f"`git {sub}` is an alias; aliases are not inspected, run the underlying command")

    check = CHECKS.get(sub)
    if check:
        check(rest, ctx)


# --------------------------------------------------------------------------- #
# Finding every git invocation inside a shell command                          #
# --------------------------------------------------------------------------- #

# Quoted token that is itself a shell command running git, e.g. sh -c "git push -f".
EMBEDDED_GIT = re.compile(r"""(^|[;&|(`])\s*['"]?(\S*/)?git(-[a-z-]+)?\s+\S""")
MAX_NESTING = 5


def tokenize(command):
    lexer = shlex.shlex(command.replace("`", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer), set(lexer.punctuation_chars)
    except ValueError as exc:
        raise Denied(f"cannot tokenize shell command: {exc}") from exc


def git_invocations(command, depth=0):
    """Yield the argument list of every `git ...` (or `git-<sub> ...`) invocation."""
    if depth > MAX_NESTING:
        raise Denied("command nesting too deep to analyse")
    tokens, separators = tokenize(command)

    for token in tokens:
        if EMBEDDED_GIT.search(token):
            yield from git_invocations(token, depth + 1)

    i = 0
    while i < len(tokens):
        name = tokens[i].rsplit("/", 1)[-1]
        i += 1
        if name != "git" and not name.startswith("git-"):
            continue
        args = [name[4:]] if name.startswith("git-") else []
        while i < len(tokens) and not set(tokens[i]) <= separators:
            args.append(tokens[i])
            i += 1
        yield args


# --------------------------------------------------------------------------- #
# Hook entry point                                                             #
# --------------------------------------------------------------------------- #

def check_command(command, cwd):
    """Raise Denied if `command` contains a forbidden git operation."""
    tokens, _ = tokenize(command)
    ctx = {"git_dir": cwd, "changes_directory": bool({"cd", "pushd"} & set(tokens))}
    for args in git_invocations(command):
        check_git_invocation(args, ctx)


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"git-safety-guard: {reason}",
        }
    }))
    sys.exit(0)


def main():
    try:
        payload = json.load(sys.stdin)
        if payload.get("tool_name") != "Bash":
            return
        check_command(payload.get("tool_input", {}).get("command", ""), payload.get("cwd") or os.getcwd())
    except Denied as exc:
        deny(str(exc))
    except Exception as exc:  # fail closed on anything unexpected
        deny(f"internal error, blocking to be safe ({type(exc).__name__}: {exc})")


if __name__ == "__main__":
    main()
