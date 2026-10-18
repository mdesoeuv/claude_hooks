#!/usr/bin/env python3
"""Tests for git_safety_guard.py. Run: python3 -I .claude/hooks/test_git_safety_guard.py"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from git_safety_guard import Denied, check_command  # noqa: E402

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "git_safety_guard.py")

# Commands whose verdict does not depend on the repository state.
ALLOWED = [
    "git status",
    "git log --oneline -20",
    "git diff main...HEAD",
    "git add -A && git commit -m 'feat: add hook'",
    "git commit -am 'fix: do not reset --hard in docs'",
    "git fetch --all --prune",
    "git pull --rebase",
    "git checkout -b feature/x",
    "git checkout main",
    "git checkout -- src/app.py",
    "git restore --staged src/app.py",
    "git switch feature/x",
    "git branch -d merged-branch",
    "git branch -m old new",
    "git stash && git stash pop",
    "git stash list",
    "git reset HEAD~1",
    "git reset --soft HEAD~1",
    "git clean -n",
    "git clean --dry-run -d",
    "git rebase -i main",
    "git cherry-pick abc123",
    "git push origin feature/x",
    "git push -u origin feature/x",
    "git push --set-upstream origin feature/x",
    "git push origin HEAD:feature/x",
    "git push origin feature/x:refs/heads/feature/x",
    "git push --dry-run origin feature/x",
    "git push -n origin feature/x",
    "git push origin --tags",
    "git -C sub/repo push origin feature/x",
    "git --no-pager log -1",
    "git -c user.name=bot commit -m msg",
    "git gc",
    "git reflog",
    "git update-ref refs/heads/x abc123",
    "git",
    "git --version",
    # commands that merely mention git
    "cat .gitignore",
    "ls .git/hooks",
    "echo 'use git push -f carefully'",
    "pip install gitpython",
    "",
]

DENIED = [
    # remote history
    "git push -f",
    "git push --force",
    "git push -f origin feature/x",
    "git push --force-with-lease origin feature/x",
    "git push --force-with-lease=feature/x:abc origin feature/x",
    "git push --force-if-includes origin feature/x",
    "git push origin +feature/x",
    "git push -fu origin feature/x",
    "git push --delete origin feature/x",
    "git push -d origin feature/x",
    "git push origin :feature/x",
    "git push --mirror backup",
    "git push --all origin",
    "git push --prune origin",
    "git push --no-verify origin feature/x",
    # protected branches
    "git push origin main",
    "git push origin master",
    "git push origin production",
    "git push origin release/2.0",
    "git push origin feature/x:main",
    "git push origin HEAD:main",
    "git push origin HEAD:refs/heads/main",
    "git push upstream main",
    "git push -o ci.skip origin main",
    # uncommitted work
    "git reset --hard",
    "git reset --hard HEAD~3",
    "git clean -f",
    "git clean -fd",
    "git clean -fdx",
    "git clean -xdf",
    "git checkout .",
    "git checkout -- .",
    "git checkout -f main",
    "git checkout --force main",
    "git restore .",
    "git restore --staged --worktree :/",
    "git switch -f main",
    "git switch --discard-changes main",
    "git branch -D feature/x",
    "git branch -f main abc123",
    "git branch --force main abc123",
    "git stash drop",
    "git stash clear",
    # recovery safety net
    "git reflog expire --expire=now --all",
    "git reflog delete HEAD@{1}",
    "git gc --prune=now",
    "git prune",
    "git update-ref -d refs/heads/main",
    "git filter-branch --tree-filter 'rm -f secrets' HEAD",
    "git filter-repo --path secrets --invert-paths",
    "git-filter-repo --path secrets --invert-paths",
    # bypassing team controls
    "git commit --no-verify -m msg",
    "git commit -n -m msg",
    "git -c core.hooksPath=/dev/null commit -m msg",
    "git -c core.hookspath=/tmp commit -m msg",
    # hidden behind shell constructs
    "git fetch && git push origin main",
    "git status; git reset --hard",
    "sh -c 'git push --force'",
    "bash -c \"cd repo && git push origin main\"",
    "echo \"$(git push -f)\"",
    "/usr/bin/git push --force",
    "sudo git clean -fd",
    "yes | git clean -fd",
    # fail closed
    "git --unknown-global push origin feature/x",
    "git push origin 'unterminated",
]


def git(repo, *args):
    subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, text=True)


class GitSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.repo = os.path.join(cls.tmp.name, "repo")
        cls.remote = os.path.join(cls.tmp.name, "remote.git")
        subprocess.run(["git", "init", "-q", "--bare", cls.remote], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", cls.repo], check=True)
        git(cls.repo, "config", "user.email", "t@example.com")
        git(cls.repo, "config", "user.name", "test")
        git(cls.repo, "commit", "-q", "--allow-empty", "-m", "init")
        git(cls.repo, "remote", "add", "origin", cls.remote)
        git(cls.repo, "push", "-q", "-u", "origin", "main")
        git(cls.repo, "branch", "feature")
        git(cls.repo, "branch", "tracks-main", "--track", "origin/main")
        git(cls.repo, "config", "alias.pf", "push --force")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_allowed(self):
        for command in ALLOWED:
            with self.subTest(command=command):
                check_command(command, self.repo)  # must not raise

    def test_denied(self):
        for command in DENIED:
            with self.subTest(command=command):
                with self.assertRaises(Denied):
                    check_command(command, self.repo)

    def test_bare_push_depends_on_current_branch(self):
        git(self.repo, "checkout", "-q", "main")
        with self.assertRaises(Denied):
            check_command("git push", self.repo)
        git(self.repo, "checkout", "-q", "feature")
        check_command("git push", self.repo)
        check_command("git push origin HEAD", self.repo)
        git(self.repo, "checkout", "-q", "tracks-main")  # upstream is origin/main
        with self.assertRaises(Denied):
            check_command("git push", self.repo)
        git(self.repo, "checkout", "-q", "--detach")
        with self.assertRaises(Denied):
            check_command("git push", self.repo)
        git(self.repo, "checkout", "-q", "feature")

    def test_bare_push_after_cd_is_denied(self):
        git(self.repo, "checkout", "-q", "feature")
        with self.assertRaises(Denied):
            check_command("cd other && git push", self.repo)

    def test_bare_push_outside_a_repo_is_denied(self):
        with self.assertRaises(Denied):
            check_command("git push", self.tmp.name)

    def test_alias_is_denied(self):
        with self.assertRaises(Denied):
            check_command("git pf origin feature", self.repo)

    def run_hook(self, payload):
        proc = subprocess.run(
            [sys.executable, "-I", HOOK], input=json.dumps(payload),
            capture_output=True, text=True, check=False,
        )
        return proc.returncode, proc.stdout

    def test_hook_denies_with_json(self):
        code, out = self.run_hook({"tool_name": "Bash", "cwd": self.repo, "tool_input": {"command": "git push -f"}})
        self.assertEqual(code, 0)
        decision = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn("force push", decision["permissionDecisionReason"])

    def test_hook_stays_silent_on_safe_command(self):
        code, out = self.run_hook({"tool_name": "Bash", "cwd": self.repo, "tool_input": {"command": "git status"}})
        self.assertEqual((code, out), (0, ""))

    def test_hook_ignores_other_tools(self):
        code, out = self.run_hook({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}})
        self.assertEqual((code, out), (0, ""))

    def test_hook_fails_closed_on_garbage_input(self):
        code, out = self.run_hook({"tool_name": "Bash", "tool_input": None})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")


if __name__ == "__main__":
    unittest.main()
