#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.request
from dataclasses import dataclass


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing env var: {name}")
    return value


def _optional_env(name: str) -> str | None:
    return os.environ.get(name) or None


def _run(cmd: list[str], *, cwd: str | None = None, redact: set[str] | None = None) -> None:
    redact = redact or set()
    display = []
    for token in cmd:
        if any(token.startswith(f"{k}=") for k in redact):
            key = token.split("=", 1)[0]
            display.append(f"{key}=***")
        else:
            display.append(token)

    print(f"+ {shlex.join(display)}", flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


@dataclass(frozen=True)
class DiscordAppInfo:
    application_id: str
    public_key: str


def _fetch_discord_app_info(bot_token: str) -> DiscordAppInfo:
    req = urllib.request.Request(
        "https://discord.com/api/v10/oauth2/applications/@me",
        headers={"Authorization": f"Bot {bot_token}"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode("utf-8")
        data = json.loads(body)

    application_id = data.get("id") or (data.get("application") or {}).get("id")
    public_key = data.get("verify_key") or (data.get("application") or {}).get("verify_key")
    if not application_id or not public_key:
        raise RuntimeError("Could not read application id / verify_key from /oauth2/applications/@me response")
    return DiscordAppInfo(application_id=str(application_id), public_key=str(public_key))


def _describe_stack_outputs(stack_name: str, region: str) -> None:
    try:
        proc = subprocess.run(
            [
                "aws",
                "cloudformation",
                "describe-stacks",
                "--stack-name",
                stack_name,
                "--region",
                region,
                "--query",
                "Stacks[0].Outputs",
                "--output",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        print(f"NOTE: Failed to read stack outputs: {exc}", file=sys.stderr)
        return

    try:
        outputs = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        print("NOTE: Failed to parse stack outputs JSON", file=sys.stderr)
        return

    if not outputs:
        print("NOTE: No stack outputs found.", file=sys.stderr)
        return

    print("\nStack outputs:")
    for o in outputs:
        k = o.get("OutputKey")
        v = o.get("OutputValue")
        if k and v:
            print(f"- {k}: {v}")

def _try_read_stack_output(stack_name: str, region: str, output_key: str) -> str | None:
    try:
        proc = subprocess.run(
            [
                "aws",
                "cloudformation",
                "describe-stacks",
                "--stack-name",
                stack_name,
                "--region",
                region,
                "--query",
                f"Stacks[0].Outputs[?OutputKey==`{output_key}`].OutputValue",
                "--output",
                "text",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return None
    value = (proc.stdout or "").strip()
    if not value or value == "None":
        return None
    return value


_SEMVER_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")


def _next_sequential_version(current_version: str | None) -> str:
    desired_major = 0
    desired_minor = 0
    max_patch = 1_000_000  # treat huge patch (old timestamp style) as "unknown"

    if not current_version:
        return f"{desired_major}.{desired_minor}.1"

    m = _SEMVER_RE.match(current_version.strip())
    if not m:
        return f"{desired_major}.{desired_minor}.1"

    major = int(m.group("major"))
    minor = int(m.group("minor"))
    patch = int(m.group("patch"))

    if major != desired_major or minor != desired_minor:
        return f"{desired_major}.{desired_minor}.1"
    if patch >= max_patch:
        return f"{desired_major}.{desired_minor}.1"
    return f"{desired_major}.{desired_minor}.{patch + 1}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy the SAM backend without --guided prompts (redacts secrets in logs)."
    )
    parser.add_argument("--stack-name", default="discord-trpg-app")
    parser.add_argument("--region", default=_optional_env("AWS_REGION") or _optional_env("AWS_DEFAULT_REGION") or "us-east-1")
    parser.add_argument("--table-name", default=_optional_env("TABLE_NAME") or "trpg-discord-bot")
    parser.add_argument("--create-table", action="store_true", help="Let CloudFormation create the DynamoDB table.")
    parser.add_argument("--skip-build", action="store_true", help="Skip `sam build`.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands only; do not execute.")
    args = parser.parse_args()

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    bot_token = _require_env("DISCORD_BOT_TOKEN")
    client_secret = _require_env("DISCORD_CLIENT_SECRET")
    backend_build_version = os.environ.get("BACKEND_BUILD_VERSION")
    if not backend_build_version:
        current = _try_read_stack_output(args.stack_name, args.region, "BackendBuildVersion")
        backend_build_version = _next_sequential_version(current)

    application_id = _optional_env("DISCORD_APPLICATION_ID")
    public_key = _optional_env("DISCORD_PUBLIC_KEY")
    if not application_id or not public_key:
        info = _fetch_discord_app_info(bot_token)
        application_id = application_id or info.application_id
        public_key = public_key or info.public_key

    if args.dry_run:
        print("DRY RUN: no commands will be executed.\n")

    if not args.skip_build:
        if not args.dry_run:
            _run(["sam", "build", "--template-file", "template.yaml"], cwd=repo_root)
        else:
            print("+ sam build --template-file template.yaml")

    deploy_cmd = [
        "sam",
        "deploy",
        "--template-file",
        "template.yaml",
        "--stack-name",
        args.stack_name,
        "--region",
        args.region,
        "--resolve-s3",
        "--capabilities",
        "CAPABILITY_IAM",
        "--no-confirm-changeset",
        "--no-fail-on-empty-changeset",
        "--parameter-overrides",
        f"DiscordApplicationId={application_id}",
        f"DiscordClientSecret={client_secret}",
        f"DiscordPublicKey={public_key}",
        f"DiscordBotToken={bot_token}",
        f"BackendBuildVersion={backend_build_version}",
        f"TableName={args.table_name}",
        f"CreateTable={'true' if args.create_table else 'false'}",
    ]

    if args.dry_run:
        _run(deploy_cmd, cwd=repo_root, redact={"DiscordClientSecret", "DiscordBotToken"})
        return 0

    _run(deploy_cmd, cwd=repo_root, redact={"DiscordClientSecret", "DiscordBotToken"})
    _describe_stack_outputs(args.stack_name, args.region)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
