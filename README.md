# Guard hooks for Claude Code in a cloud team

Four `PreToolUse` hooks for Claude Code that inspect every Bash command before
it runs:

| Hook | Denies | Style |
| --- | --- | --- |
| `aws_readonly_guard.py` | any `aws` CLI call not positively identified as read-only | allowlist |
| `iac_readonly_guard.py` | any Terraform / OpenTofu / Terragrunt, CDK, CDKTF, Pulumi, SAM, eksctl or Serverless command that would change cloud resources or remote state | allowlist |
| `git_safety_guard.py` | force pushes, pushes to protected branches, discarding uncommitted work, destroying the reflog, bypassing commit hooks | deny list |
| `secrets_guard.py` | naming credential files or `.env` files, commands that print credentials, secret variable expansion, file uploads, pipe-to-shell | deny list |

Each hook is one self-contained Python file, standard library only, so it can be
audited in a few minutes. They share the same design and the same shell parser,
and each ships with a test file whose allowed / denied lists double as the
policy specification.

```
.claude/
├── settings.json                      # registers the hooks + Read/Edit deny rules
└── hooks/
    ├── aws_readonly_guard.py          test_aws_readonly_guard.py
    ├── iac_readonly_guard.py          test_iac_readonly_guard.py
    ├── git_safety_guard.py            test_git_safety_guard.py
    └── secrets_guard.py               test_secrets_guard.py
```

## What "read-only" means here

An `aws <service> <verb>` call is allowed when **either**:

1. the verb starts with one of the prefixes AWS reserves for read operations
   (the same convention the AWS-managed `ReadOnlyAccess` policy is built on):
   `describe-`, `list-`, `get-`, `head-`, `lookup-`, `search-`, `batch-get-`, `batch-describe-`;
2. or the `service verb` pair is in a short explicit allowlist of read verbs that
   do not follow the convention, for example `s3 ls`, `s3 presign`, `logs tail`,
   `dynamodb query|scan`, `cloudformation validate-template`,
   `iam simulate-*-policy`, `sts assume-role`, `<any> wait`, `<any> help`, and
   the local-only `configure list|get|list-profiles|export-credentials`, `sso login|logout`.

Everything else is denied. That includes `aws s3 cp/sync/rm`, `lambda invoke`,
`ssm start-session`, `ecs execute-command`, `sqs receive-message`, `*-dry-run`
variants, `configure set`, user-defined CLI aliases, and any verb the hook
does not recognise.

Both lists live at the top of `aws_readonly_guard.py` and are the only thing you
should need to edit to tune the policy.

## What "read-only" means for the IaC hook

Nothing is created, changed or destroyed in a cloud account or a remote state
backend. Commands that only write files inside the project (`fmt`, `synth`,
`build`, `init` scaffolding) are allowed. The allowlist per tool is at the top of
`iac_readonly_guard.py`:

| Tool | Allowed | Denied (everything else, for example) |
| --- | --- | --- |
| `terraform`, `tofu` | `init`¹, `validate`, `fmt`, `plan`, `show`, `output`, `graph`, `console`, `get`, `providers`, `version`, `state list|show|pull`, `workspace list|show|select` | `apply`, `destroy`, `import`, `refresh`, `taint`, `test`, `force-unlock`, `state rm|mv|push`, `workspace new|delete` |
| `terragrunt` | the terraform list plus `run-all init|validate|plan|output`, `hclfmt`, `validate-inputs`, `graph-dependencies`, `render-json` | `apply`, `run-all apply|destroy` |
| `cdk`, `npx aws-cdk`, `cdktf` | `synth`, `diff`, `ls`, `doctor`, `context`, `metadata`, `notices`, `init` | `deploy`, `destroy`, `bootstrap`, `import`, `watch` |
| `pulumi` | `preview`, `config`, `whoami`, `about`, `logs`, `login`, `stack ls|output|export|history|select`, `plugin ls` | `up`, `destroy`, `refresh`, `import`, `cancel`, `state *`, `stack rm|init` |
| `sam` | `build`, `validate`, `init`, `local *`, `list *`, `logs`, `traces` | `deploy`, `delete`, `sync`, `package`, `remote invoke`, `pipeline *` |
| `eksctl` | `get *`, `info`, `version`, `utils describe-stacks|schema` | `create`, `delete`, `scale`, `upgrade`, `utils update-*` |
| `serverless`, `sls` | `print`, `info`, `logs`, `package`, `metrics` | `deploy`, `remove`, `invoke`, `rollback` |

¹ `init` is denied when combined with `-migrate-state` or `-force-copy`, which
move remote state.

An allowlist entry can be one word or two. A one-word entry allows every
sub-sub-command under it, so one-word entries are only used where nothing
underneath can write to the cloud (`sam local`, `eksctl get`). `terraform state`
and `pulumi stack` are deliberately listed two words at a time.

The IaC hook recognises a tool by the basename of the command word, with any
`@version` suffix removed, so `npx cdk deploy`, `yarn cdk deploy`,
`node_modules/.bin/cdk deploy` and `npx aws-cdk@2 deploy` are all caught.
Options placed before the sub-command must use the `-opt=value` form
(`terraform -chdir=envs/prod plan`); `pulumi -s dev stack output` is denied with
a hint to put options after the sub-command.

## How the hooks find a command in a shell string

The hook tokenises the command with Python's `shlex` (shell operators `; | & ( ) < >`
become separators, backticks are treated as separators too) and then:

* every token equal to `aws`, or ending in `/aws` (`/opt/homebrew/bin/aws`), starts
  an invocation that runs until the next shell operator. Position does not
  matter, so `sudo aws …`, `AWS_PROFILE=x aws …`, `xargs aws …`, `$(aws …)` and
  `` `aws …` `` are all seen;
* every quoted token that looks like a command string starting with `aws`
  (`sh -c "aws …"`, `python -c "os.system('aws …')"`, `"$(aws …)"` passed as an
  argument) is analysed recursively.

Every invocation found must pass the read-only check; one failure denies the
whole command. The hook denies on anything it cannot parse (unterminated quote,
unknown global option before the service, bare `aws`, nesting deeper than 5).

## Git safety policy

Git is used constantly and almost everything it does is recoverable through the
reflog, so this hook is a **deny list** rather than an allowlist: it names the
operations that destroy work for good or bypass team controls, and lets the rest
through. Parsing still fails closed: unknown global options, an unterminated
quote, a git alias (aliases can hide anything) and a bare `git push` whose
target cannot be resolved are all denied.

| Area | Denied |
| --- | --- |
| Remote history | `push --force`, `-f`, `--force-with-lease`, `--force-if-includes`, `+refspec`, `push --delete`, `:branch`, `--mirror`, `--all`, `--prune` |
| Protected branches | any push whose destination is `main`, `master`, `production` or `release/*` (edit `PROTECTED_BRANCHES`), including `HEAD:main` and a bare `git push` while on such a branch or tracking one |
| Uncommitted work | `reset --hard`, `clean` without `--dry-run`, `checkout .` / `checkout -f`, `restore .`, `switch --discard-changes`, `branch -D` / `-f`, `stash drop` / `clear` |
| Recovery safety net | `reflog expire` / `delete`, `gc --prune=<date>`, `prune`, `update-ref -d`, `filter-branch`, `filter-repo` |
| Team controls | `commit --no-verify` / `-n`, `push --no-verify`, `-c core.hooksPath=…` |

A bare `git push` is resolved against the repository in the hook's working
directory: the current branch and its upstream are both checked. If the command
also contains `cd`, or HEAD is detached, the hook asks for an explicit
`git push origin <branch>` instead of guessing.

## Secrets policy

Five independent rules, each a short list at the top of `secrets_guard.py`:

1. **Secret files are never named in a Bash command.** `~/.aws`, `~/.ssh`,
   `~/.kube`, `~/.gnupg`, `~/.azure`, `~/.config/gcloud`, `~/.docker/config.json`,
   `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.claude.json`,
   `id_rsa`-style keys, `*.pem` / `*.p12` / `*.pfx` / `*.jks` / `*.key`, every
   `.env` variant and `.envrc`. The `Read(...)` deny rules in `settings.json`
   cover Claude's file tools; this rule covers `cat`, `cp`, `tar`,
   `python -c "open(...)"` and anything else run through the shell. Exceptions:
   `.env.example` / `.sample` / `.template` / `.dist`, `process.env`,
   `import.meta.env`, and a file passed through `--env-file`, which hands it to
   a program without printing it.
2. **Commands that print a credential are denied**: `aws sts assume-role`,
   `get-session-token`, `get-federation-token`, `aws configure
   export-credentials`, `secretsmanager get-secret-value`, `kms decrypt`,
   `ssm get-parameter* --with-decryption`, `gh auth token`, `gcloud auth
   print-*-token`, `az account get-access-token`, `kubectl get secret(s)`,
   `vault read` / `kv get`, `op read` / `item get`, and the macOS keychain
   (`security find-*-password`, `dump-keychain`). `aws ecr get-login-password`
   is deliberately not listed because it is almost always piped into
   `docker login`.
3. **Secret variables stay unexpanded.** Any `$VAR` whose name contains
   `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `API_KEY`, `PRIVATE_KEY` or
   `ACCESS_KEY` is denied, as are bare `env` and `printenv`, which dump
   everything.
4. **No file leaves over the network.** `scp`, `sftp`, `ftp`, `nc`, `socat`
   and `telnet` are denied outright; `curl` only when it uploads (`-T`,
   `--upload-file`, `-d @file`, `-F x=@file`), `wget` with `--post-file` /
   `--body-file`, `rsync` when a remote `host:` appears.
5. **No pipe-to-shell.** `curl … | sh`, `wget … | bash` and
   `base64 -d` combined with a shell or `eval` are denied.

## Install

Project scope (already done in this repo): `.claude/settings.json` registers the
hook for the `Bash` tool with a 10 s timeout and `"onFailure": "block"`, so a
crash or timeout of the hook also blocks the command. It also carries
`permissions.deny` rules that need no hook at all:

| Rule | Effect |
| --- | --- |
| `Read(./.env)`, `Read(./.env.*)` | Claude's file tools cannot read, `@`-reference, edit or write `.env` files in the project |
| `Read(~/.aws/**)`, `Read(~/.ssh/**)` | same for AWS credentials/config and SSH keys in your home directory |
| `Edit(/.claude/settings.json)`, `Edit(/.claude/hooks/**)` | Claude cannot rewrite this policy or the hook mid-session |

A `Read` deny rule also blocks `Edit` and `Write` on the same path (Claude Code
v2.1.228+). Only `Read(...)` and `Edit(...)` path rules are consulted; a
`Write(...)` path rule is accepted but ignored. These rules apply to Claude's
file tools, not to `cat` or `cp` run through Bash, which is why the Bash hook,
the sandbox and IAM still matter.

User scope, to protect every project on this machine, on macOS or WSL:

```sh
git clone <this repo> ~/claude_hook && cd ~/claude_hook
./install.py                           # or: ./install.py --aws-profile claude-readonly
```

`install.py` (standard library only, python3 >= 3.8) runs the four test suites
and a smoke test, backs up `~/.claude/settings.json`, then merges in the hooks
(pointing at this checkout by absolute path) and the `Read` / `Edit` deny
rules, leaving your other settings untouched. It is idempotent, `--dry-run`
shows the result without writing, and `--uninstall` removes exactly what it
added. Start a new Claude Code session afterwards. Keep the checkout where it
is: the hooks fail closed, so deleting it would block every Bash command until
you re-run the script or `--uninstall`.

WSL notes: clone inside the Linux filesystem (`~/claude_hook`, not `/mnt/c/...`)
so file modes and performance are normal; `.gitattributes` keeps the scripts in
LF even if `core.autocrlf` is on; `sudo apt install python3 git` covers the
prerequisites. If `./install.py` is not executable, `python3 install.py` works
the same.

Organisation scope: put the hook in [managed settings](https://code.claude.com/docs/en/settings-reference)
so users and the agent cannot remove it.

Run the tests after any change:

```sh
for t in aws_readonly iac_readonly git_safety secrets; do
  python3 -I ".claude/hooks/test_${t}_guard.py"
done
```

Simulate a hook call by hand:

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"aws s3 ls"}}' | python3 -I .claude/hooks/aws_readonly_guard.py
echo '{"tool_name":"Bash","tool_input":{"command":"terraform apply"}}' | python3 -I .claude/hooks/iac_readonly_guard.py
```

Silence means "no objection"; a denial prints a JSON `permissionDecision: "deny"`
with the reason, which Claude sees in the transcript.

## Best practices this hook follows

* **Deny by default, allowlist where the command space is small.** The cloud
  hooks have no blocklist of dangerous verbs to keep up to date. The git and
  secrets hooks are deny lists because allowlisting all of git or all of the
  shell would be unusable; they compensate by failing closed on anything they
  cannot parse.
* **Fail closed.** Parse errors, unknown options, internal exceptions, hook timeouts
  (`onFailure: block`) all result in a denial.
* **The hook only vetoes, it never grants.** On a read-only command it prints
  nothing, so your normal permission prompts and allow/deny rules still apply.
* **No dependencies, isolated interpreter.** Standard library only, run with
  `python3 -I` so a `shlex.py` or `json.py` dropped into the project cannot be
  imported in place of the real module.
* **Protected from the agent.** `Edit(/.claude/hooks/**)` and
  `Edit(/.claude/settings.json)` deny rules stop Claude's Edit/Write tools from
  rewriting the policy mid-session.
* **Tested with a readable truth table.** `ALLOWED` and `DENIED` lists in the test
  file double as the policy specification; add a line there whenever you change
  the policy.

## What this hook does NOT protect against (read this)

A hook is a guardrail against mistakes, not a security boundary. The agent runs
with your credentials and can reach AWS without the `aws` binary:

* SDK calls from scripts (`boto3`, AWS SDK for JavaScript, …), `curl` with SigV4;
* `kubectl`, `helm` and other tools not in the IaC list, and `terraform plan` or
  `cdk synth` whose own code performs writes (an `external` data source, a
  CDK app calling an SDK);
* commands hidden behind a script or task runner the agent invokes later
  (`bash deploy.sh`, `make deploy`, `npm run deploy`), base64 or other
  obfuscation, aliases or wrapper scripts not named like the tool;
* MCP servers or other tools that talk to AWS directly;
* `ssh` to another host, `gh` operations (`gh pr merge`, `gh repo delete`) and
  secrets read through an SDK (`boto3.client("secretsmanager")`), none of which
  the git or secrets hooks inspect.

**The real control is IAM.** Give the session credentials that cannot write.
The next section shows how to pin the agent to such a profile. With IAM doing
the enforcement, the hooks' job is to give fast, readable feedback before a
mistaken write ever leaves the machine, and to keep the agent from burning time
on calls that would be rejected anyway.

Note that `ReadOnlyAccess` still allows reading data: `s3api get-object`,
`ssm get-parameter --with-decryption`, `secretsmanager get-secret-value`. If
secrets exposure matters to you, remove `get-` from `READ_ONLY_VERB_PREFIXES`
and allowlist the specific `get-*` verbs you need, or scope the IAM policy.

## Pinning the agent to a read-only IAM profile

Configuration alone cannot *force* a profile: whatever default you set, a
command can override it inline with `--profile prod` or `AWS_PROFILE=prod aws …`.
Forcing is the combination of two layers. Layer 1 makes the read-only profile
the default. Layer 2 makes it the only credential the agent can reach, so there
is nothing to override to.

### Layer 1: make the read-only profile the default

Create the profile first. Prefer IAM Identity Center (SSO) with a read-only
permission set; it gives short-lived credentials and no key to leak. Put it in a
**dedicated config file** that contains nothing else, for example
`~/.aws/claude-config`:

```ini
[sso-session corp]
sso_start_url = https://my-org.awsapps.com/start
sso_region = eu-west-1
sso_registration_scopes = sso:account:access

[profile claude-readonly]
sso_session = corp
sso_account_id = 123456789012
sso_role_name = ReadOnlyAccess
region = eu-west-1
output = json
```

Without Identity Center, use a role-chaining profile so the agent never holds
the human's permissions directly. `role_session_name` makes the agent's calls
recognisable in CloudTrail:

```ini
[profile claude-readonly]
role_arn = arn:aws:iam::123456789012:role/ClaudeReadOnly
source_profile = me
role_session_name = claude
duration_seconds = 3600
region = eu-west-1
```

The `ClaudeReadOnly` role carries the AWS-managed `ReadOnlyAccess` policy (or
the stricter `ViewOnlyAccess`) and a permission boundary so it cannot be
widened later.

Then tell Claude Code to use it. The `env` block in settings is applied to every
Bash command of the session. Use absolute paths, not `~`:

```json
{
  "env": {
    "AWS_PROFILE": "claude-readonly",
    "AWS_CONFIG_FILE": "/Users/me/.aws/claude-config",
    "AWS_SHARED_CREDENTIALS_FILE": "/dev/null"
  }
}
```

* `AWS_PROFILE` selects the profile for the `aws` CLI **and** for every SDK
  (boto3, JavaScript, Go), Terraform's AWS provider, CDK, Pulumi and SAM, so one
  setting covers all the tools the hooks watch and the ones they cannot see.
* `AWS_CONFIG_FILE` points at the dedicated file, so profiles from your normal
  `~/.aws/config` are not visible to the session.
* `AWS_SHARED_CREDENTIALS_FILE=/dev/null` hides any static keys stored in
  `~/.aws/credentials`.

Put this in `~/.claude/settings.json` for every project on the machine, or in
managed settings for the whole team. Combined with the `Read(~/.aws/**)` deny
rule already in this repo, Claude's file tools cannot discover other profiles
either.

Log in once before starting Claude (`aws sso login --profile claude-readonly`),
and check what the session sees:

```sh
aws sts get-caller-identity
# "Arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_ReadOnlyAccess_…/me"
```

Layer 1 is enough against mistakes: the agent will use the read-only profile
unless it deliberately asks for another one. It is not enough against a
determined override, because `--profile prod` still resolves if `prod` exists
on the machine. That is what layer 2 removes.

### Layer 2: make it the only credential the agent can reach

Run the agent where **no other AWS credential exists**. Three ways, from
lightest to strongest:

1. **Credentials injected by a wrapper, profile files hidden.** Start Claude
   from a process that already holds the read-only session and exposes it only
   through environment variables:

   ```sh
   # with aws-vault
   AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
     aws-vault exec claude-readonly -- claude

   # with the CLI alone (Identity Center or role-chaining profile)
   eval "$(aws configure export-credentials --profile claude-readonly --format env)"
   AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null claude
   ```

   Inside the session `aws --profile prod …` fails with "profile not found",
   because no config file is readable. The credentials expire with the session
   token, so a leaked transcript is worth little.

2. **A dedicated OS user.** Create a `claude` user on the workstation whose
   home directory holds only `~/.aws/config` with the read-only profile, and run
   Claude Code as that user. File permissions, not configuration, keep the
   human's credentials out of reach, and the user's home is a natural place for
   the managed `settings.json` and the hooks in this repo.

3. **A container.** Run Claude Code in a devcontainer or Docker image that
   mounts only the read-only config file and the SSO token cache:

   ```yaml
   # devcontainer.json (excerpt)
   "mounts": [
     "source=${localEnv:HOME}/.aws/claude-config,target=/home/node/.aws/config,type=bind,readonly",
     "source=${localEnv:HOME}/.aws/sso,target=/home/node/.aws/sso,type=bind"
   ],
   "containerEnv": { "AWS_PROFILE": "claude-readonly" }
   ```

   Anthropic publishes a reference devcontainer in the
   [claude-code repository](https://github.com/anthropics/claude-code/tree/main/.devcontainer)
   with a network firewall; this is the setup to use for unattended or
   `--dangerously-skip-permissions` runs. Nothing on the host is reachable, so
   even a script with hard-coded `boto3.Session(profile_name="prod")` has no
   `prod` to find.

Whichever variant you pick, keep layer 1 in place as well: the `env` block is
what makes the read-only profile the *default* inside the isolated environment,
so tools work without the agent having to name a profile at all.

### Checking it holds

* `aws sts get-caller-identity` from inside a Claude session must return the
  read-only role ARN. A `SessionStart` hook can run this and abort the session
  otherwise.
* `aws configure list-profiles` must list `claude-readonly` and nothing else.
* `aws --profile prod sts get-caller-identity` must fail with a profile error,
  not succeed.

## Known false positives

Fail-closed means a few harmless commands get denied. Rephrase them or run them
yourself:

* `grep aws file`: any bare token `aws` is treated as the CLI, quoting does not
  change that. Use a pattern that is not the bare word, e.g. `grep 'aw[s]' file`.
* `echo "aws ec2 …"`, a heredoc, or a `--description` text that starts with
  `aws <something>` or contains `; aws <something>`: the quoted text looks like
  an embedded command and is analysed as one.
* `ls infra/aws`: a token ending in `/aws` is treated as a path to the binary.
  Add a trailing slash: `ls infra/aws/`. The IaC hook is more lenient: a bare
  `terraform` or `infra/terraform` with no arguments is allowed, since the tools
  only print help in that case.
* `grep sam file` or `cat sam`: `sam`, `cdk`, `sls` as a bare word followed by
  arguments are treated as the tool. The same goes for `nc` in the secrets hook.
* `cat ~/.ssh/known_hosts`, `cat ~/.ssh/id_rsa.pub`, `ls ~/.aws`: the whole
  directory is off limits, public keys and config included. Use `ssh-add -L`
  or `aws configure list-profiles` instead.
* `grep -r TOKEN src/` is fine, but `echo "token=$MY_TOKEN"` is denied because
  the variable name looks like a secret; so is `env | grep PATH`, use `echo $PATH`.
* `git push` right after `cd`, or in a detached HEAD: name the remote and branch.
* `git commit -n`: `-n` means `--no-verify` for commit, so it is denied.
