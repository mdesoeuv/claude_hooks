#!/usr/bin/env python3
"""Tests for iac_readonly_guard.py. Run: python3 -I .claude/hooks/test_iac_readonly_guard.py"""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iac_readonly_guard import Denied, check_command  # noqa: E402

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iac_readonly_guard.py")

ALLOWED = [
    # terraform / tofu / terragrunt
    "terraform init",
    "terraform init -backend-config=prod.hcl -reconfigure",
    "terraform -chdir=envs/prod plan -var-file=prod.tfvars -out=plan.tfplan",
    "terraform plan -destroy",
    "terraform validate && terraform fmt -check -recursive",
    "terraform show -json plan.tfplan | jq '.resource_changes[].change.actions'",
    "terraform output -json",
    "terraform state list",
    "terraform state show aws_instance.web",
    "terraform workspace list",
    "terraform providers schema -json",
    "terraform -version",
    "terraform",
    "tofu plan",
    "terragrunt run-all plan --terragrunt-non-interactive",
    "terragrunt hclfmt",
    # cdk / cdktf
    "cdk synth",
    "npx cdk diff --profile prod",
    "npx aws-cdk@2.150.0 ls",
    "yarn cdk synth",
    "node_modules/.bin/cdk doctor",
    "cdk --version",
    "cdktf synth && cdktf diff",
    # pulumi
    "pulumi preview --stack dev --diff",
    "pulumi stack output --stack dev --json",
    "pulumi stack ls",
    "pulumi config",
    "pulumi whoami",
    # sam / eksctl / serverless
    "sam build --use-container",
    "sam validate --lint",
    "sam local invoke MyFunction -e event.json",
    "sam local start-api",
    "sam list stack-outputs --stack-name app",
    "sam logs -n MyFunction --stack-name app --tail",
    "eksctl get cluster --region eu-west-1",
    "eksctl get nodegroup --cluster prod",
    "eksctl utils describe-stacks --cluster prod",
    "serverless print",
    "sls info --stage prod",
    "sls package",
    # commands that merely mention a tool
    "ls infra/terraform",
    "cat terraform.tfstate | jq .",
    "git log --oneline -- cdk/",
    "grep -r pulumi.yaml .",
    "cd infra/terraform/ && ls",
    "echo 'run terraform plan first'",
    "",
]

DENIED = [
    # terraform / tofu / terragrunt
    "terraform apply",
    "terraform apply -auto-approve",
    "terraform apply plan.tfplan",
    "terraform destroy -auto-approve",
    "terraform import aws_s3_bucket.b my-bucket",
    "terraform taint aws_instance.web",
    "terraform untaint aws_instance.web",
    "terraform refresh",
    "terraform force-unlock 1234",
    "terraform test",
    "terraform state rm aws_instance.web",
    "terraform state mv a b",
    "terraform state push local.tfstate",
    "terraform state",
    "terraform workspace new staging",
    "terraform workspace delete staging",
    "terraform init -migrate-state",
    "terraform init -force-copy -backend-config=new.hcl",
    "tofu apply",
    "terragrunt apply",
    "terragrunt run-all apply",
    "terragrunt run-all destroy --terragrunt-non-interactive",
    # cdk / cdktf
    "cdk deploy",
    "cdk deploy --all --require-approval never",
    "cdk destroy MyStack",
    "cdk bootstrap aws://123/eu-west-1",
    "cdk import MyStack",
    "cdk watch",
    "npx cdk deploy",
    "npx aws-cdk deploy",
    "yarn cdk deploy",
    "node_modules/.bin/cdk deploy",
    "cdktf deploy",
    "cdktf destroy",
    # pulumi
    "pulumi up",
    "pulumi up --yes --skip-preview",
    "pulumi update",
    "pulumi destroy --yes",
    "pulumi refresh --yes",
    "pulumi import aws:s3/bucket:Bucket b my-bucket",
    "pulumi stack rm dev --yes",
    "pulumi stack init prod",
    "pulumi stack",
    "pulumi state delete urn:...",
    "pulumi cancel",
    # sam / eksctl / serverless
    "sam deploy --guided",
    "sam deploy --no-confirm-changeset",
    "sam delete --stack-name app",
    "sam sync --watch",
    "sam package --s3-bucket b",
    "sam remote invoke MyFunction",
    "sam pipeline bootstrap",
    "eksctl create cluster -f cluster.yaml",
    "eksctl delete cluster --name prod",
    "eksctl scale nodegroup --cluster prod --nodes 5 ng-1",
    "eksctl upgrade cluster --name prod --approve",
    "eksctl utils update-cluster-logging --cluster prod --enable-types all",
    "serverless deploy",
    "sls deploy --stage prod",
    "sls remove",
    "sls invoke -f hello",
    # hidden behind read-only commands or shell constructs
    "terraform plan && terraform apply -auto-approve",
    "terraform plan; terraform apply",
    "cdk synth | tee out.txt && cdk deploy",
    "sh -c 'terraform apply -auto-approve'",
    "bash -c \"cd infra && pulumi up --yes\"",
    "echo \"$(terraform destroy -auto-approve)\"",
    "echo `cdk deploy`",
    "/usr/local/bin/terraform apply",
    "sudo terraform apply",
    "echo yes | terraform apply",
    "cat <<EOF > deploy.sh\nterraform apply -auto-approve\nEOF",
    # fail-closed cases: ambiguous ordering or unparsable
    "pulumi -s dev stack output",
    "terraform -chdir=x",
    "terraform plan 'unterminated",
]


class IacGuardTests(unittest.TestCase):
    def test_allowed(self):
        for command in ALLOWED:
            with self.subTest(command=command):
                check_command(command)  # must not raise

    def test_denied(self):
        for command in DENIED:
            with self.subTest(command=command):
                with self.assertRaises(Denied):
                    check_command(command)

    def run_hook(self, payload):
        proc = subprocess.run(
            [sys.executable, "-I", HOOK], input=json.dumps(payload),
            capture_output=True, text=True, check=False,
        )
        return proc.returncode, proc.stdout

    def test_hook_denies_with_json(self):
        code, out = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "terraform apply"}})
        self.assertEqual(code, 0)
        decision = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn("terraform apply", decision["permissionDecisionReason"])

    def test_hook_stays_silent_on_read_only(self):
        code, out = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "terraform plan"}})
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
