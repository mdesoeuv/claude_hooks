#!/usr/bin/env python3
"""Tests for aws_readonly_guard.py. Run: python3 -I .claude/hooks/test_aws_readonly_guard.py"""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aws_readonly_guard import Denied, check_command  # noqa: E402

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aws_readonly_guard.py")

ALLOWED = [
    # plain read-only calls
    "aws sts get-caller-identity",
    "aws ec2 describe-instances --filters Name=tag:Name,Values=web",
    "aws s3 ls s3://my-bucket/prefix/",
    "aws s3api list-objects-v2 --bucket my-bucket",
    "aws s3api head-object --bucket b --key k",
    "aws iam list-attached-role-policies --role-name admin",
    "aws cloudtrail lookup-events --max-results 5",
    "aws logs tail /aws/lambda/fn --since 1h",
    "aws dynamodb scan --table-name t --limit 10",
    "aws ec2 wait instance-running --instance-ids i-123",
    "aws ssm get-parameters-by-path --path /app/ --recursive",
    # global options before the service
    "aws --profile prod --region eu-west-1 rds describe-db-instances",
    "aws --output=json --no-cli-pager lambda list-functions",
    "aws --version",
    "aws help",
    "aws ec2 help",
    # shell plumbing around a read-only call
    "aws ec2 describe-vpcs | jq '.Vpcs[].VpcId'",
    "AWS_PROFILE=prod aws ec2 describe-subnets > subnets.json 2>&1",
    "for r in us-east-1 eu-west-1; do aws --region $r ec2 describe-regions; done",
    "ID=$(aws sts get-caller-identity --query Account --output text) && echo $ID",
    "echo i-1 | xargs aws ec2 describe-instances --instance-ids",
    "sh -c 'aws s3 ls'",
    "/opt/homebrew/bin/aws s3 ls",
    # commands that merely mention aws without invoking it
    "cat ~/.aws/config",
    'aws ec2 describe-instances --filters "Name=tag:Name,Values=my aws box"',
    "cd infra/aws/ && ls",
    "ls -la",
    "git commit -m 'document aws setup'",
    "",
]

DENIED = [
    # classic mutations
    "aws ec2 terminate-instances --instance-ids i-123",
    "aws ec2 run-instances --image-id ami-1 --count 1",
    "aws s3 rm s3://my-bucket --recursive",
    "aws s3 cp file.txt s3://my-bucket/",
    "aws s3 sync . s3://my-bucket/",
    "aws s3api put-bucket-policy --bucket b --policy file://p.json",
    "aws iam attach-role-policy --role-name r --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    "aws iam create-access-key --user-name bob",
    "aws lambda invoke --function-name fn out.json",
    "aws lambda update-function-code --function-name fn --zip-file fileb://x.zip",
    "aws cloudformation deploy --template-file t.yaml --stack-name s",
    "aws cloudformation delete-stack --stack-name s",
    "aws rds delete-db-instance --db-instance-identifier db --skip-final-snapshot",
    "aws ssm start-session --target i-123",
    "aws ssm send-command --instance-ids i-123 --document-name AWS-RunShellScript",
    "aws ecs execute-command --cluster c --task t --command bash --interactive",
    "aws sqs receive-message --queue-url https://sqs.example/q",
    "aws ec2 terminate-instances --dry-run --instance-ids i-123",
    "aws configure set region us-east-1",
    # mutation hidden behind a read-only one, or behind shell constructs
    "aws ec2 describe-instances && aws ec2 terminate-instances --instance-ids i-123",
    "aws ec2 describe-instances; aws ec2 stop-instances --instance-ids i-123",
    "aws ec2 describe-instances --instance-ids $(aws ec2 run-instances --image-id ami-1 --query 'Instances[0].InstanceId' --output text)",
    "echo `aws s3 rb s3://my-bucket --force`",
    'aws ec2 describe-instances --instance-ids "$(aws ec2 run-instances --image-id ami-1)"',
    "sh -c 'aws s3 rm s3://my-bucket/key'",
    "bash -c \"cd /tmp && aws ec2 delete-volume --volume-id vol-1\"",
    "python3 -c \"import os; os.system('aws ec2 reboot-instances --instance-ids i-1')\"",
    "echo i-1 | xargs aws ec2 terminate-instances --instance-ids",
    "sudo aws ec2 terminate-instances --instance-ids i-123",
    "/opt/homebrew/bin/aws s3 rm s3://my-bucket/key",
    "cat <<EOF > run.sh\naws ec2 terminate-instances --instance-ids i-1\nEOF",
    # fail-closed cases: unknown or ambiguous
    "aws",
    "aws ec2",
    "aws myalias",
    "aws --unknown-option ec2 describe-instances",
    "aws ec2 describe-instances 'unterminated",
]


class ReadOnlyGuardTests(unittest.TestCase):
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
        code, out = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "aws s3 rm s3://b/k"}})
        self.assertEqual(code, 0)
        decision = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn("aws s3 rm", decision["permissionDecisionReason"])

    def test_hook_stays_silent_on_read_only(self):
        code, out = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "aws s3 ls"}})
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
