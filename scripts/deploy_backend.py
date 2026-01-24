#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    except OSError as exc:
        print(f"NOTE: Failed to read dotenv file: {path} ({exc})", file=sys.stderr)
        return

    def unescape_double_quoted(value: str) -> str:
        result: list[str] = []
        i = 0
        while i < len(value):
            ch = value[i]
            if ch != "\\" or i + 1 >= len(value):
                result.append(ch)
                i += 1
                continue

            nxt = value[i + 1]
            if nxt == "n":
                result.append("\n")
            elif nxt == "r":
                result.append("\r")
            elif nxt == "t":
                result.append("\t")
            else:
                result.append(nxt)
            i += 2
        return "".join(result)

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue

        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue

        value = raw_value.strip()
        if value.startswith(("'", '"')):
            quote = value[0]
            end_quote_index: int | None = None
            escaped = False
            for i in range(1, len(value)):
                ch = value[i]
                if quote == '"' and ch == "\\" and not escaped:
                    escaped = True
                    continue
                if ch == quote and not escaped:
                    end_quote_index = i
                    break
                escaped = False

            if end_quote_index is None:
                value = value[1:]
            else:
                value = value[1:end_quote_index]
                if quote == '"':
                    value = unescape_double_quoted(value)
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()

        os.environ.setdefault(key, value)


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing env var: {name}")
    return value


def _optional_env(name: str) -> str | None:
    return os.environ.get(name) or None


def _format_cmd(cmd: list[str], *, redact: set[str] | None = None) -> list[str]:
    redact = redact or set()
    display = []
    for token in cmd:
        if any(token.startswith(f"{k}=") for k in redact):
            key = token.split("=", 1)[0]
            display.append(f"{key}=***")
        else:
            display.append(token)
    return display


def _print_cmd(cmd: list[str], *, redact: set[str] | None = None) -> None:
    display = _format_cmd(cmd, redact=redact)
    print(f"+ {shlex.join(display)}", flush=True)


def _run(
    cmd: list[str],
    *,
    cwd: str | None = None,
    redact: set[str] | None = None,
    redact_values: list[str] | None = None,
) -> None:
    _print_cmd(cmd, redact=redact)
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    for value in redact_values or []:
        if value:
            stdout = stdout.replace(value, "***")
            stderr = stderr.replace(value, "***")

    if stdout:
        print(stdout, end="")
    if stderr:
        print(stderr, end="", file=sys.stderr)

    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)

    


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
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            data = json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = ""
        raise RuntimeError(
            "Failed to fetch Discord application info from /oauth2/applications/@me "
            f"(HTTP {exc.code}). Set DISCORD_APPLICATION_ID and DISCORD_PUBLIC_KEY explicitly, "
            "or ensure DISCORD_BOT_TOKEN is a valid bot token.\n"
            f"Response: {detail or exc.reason}"
        ) from exc

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


def _try_read_stack_parameter(stack_name: str, region: str, parameter_key: str) -> str | None:
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
                f"Stacks[0].Parameters[?ParameterKey==`{parameter_key}`].ParameterValue",
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
_BUILD_NUMBER_RE = re.compile(r"^(?P<num>\d+)$")


def _format_build_number(num: int) -> str:
    if num < 0:
        num = 0
    if num < 1000:
        return f"{num:03d}"
    return str(num)


def _parse_build_number(value: str | None) -> int:
    if not value:
        return 0
    raw = value.strip()
    if not raw or raw == "None":
        return 0

    m = _BUILD_NUMBER_RE.match(raw)
    if m:
        try:
            return int(m.group("num"))
        except ValueError:
            return 0

    m = _SEMVER_RE.match(raw)
    if m:
        try:
            return int(m.group("patch"))
        except ValueError:
            return 0

    return 0


def _normalize_build_version(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip()
    if not raw or raw == "None":
        return None

    m = _BUILD_NUMBER_RE.match(raw)
    if m:
        try:
            return _format_build_number(int(m.group("num")))
        except ValueError:
            return None

    m = _SEMVER_RE.match(raw)
    if m:
        try:
            return _format_build_number(int(m.group("patch")))
        except ValueError:
            return None

    return raw


def _next_sequential_version(current_version: str | None) -> str:
    current = _parse_build_number(current_version)
    return _format_build_number(max(1, current + 1))

def _sync_achievement_catalog(repo_root: Path) -> None:
    source = repo_root / "scenario-weaver" / "archivement.csv"
    if not source.exists():
        fallback = repo_root / "scenario-weaver" / "achivement.csv"
        if fallback.exists():
            source = fallback
        else:
            return

    dest = repo_root / "src" / "trpg_bot" / "archivement.csv"
    try:
        src_bytes = source.read_bytes()
        if dest.exists() and dest.read_bytes() == src_bytes:
            return
        dest.write_bytes(src_bytes)
        print(f"Synced achievement catalog: {source} -> {dest}", file=sys.stderr)
    except Exception as exc:
        print(f"NOTE: Failed to sync achievement catalog CSV: {exc}", file=sys.stderr)


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

    script_dir = Path(__file__).resolve().parent
    repo_root_path = script_dir.parent
    repo_root = str(repo_root_path)

    # Convenience: allow running the script without manually exporting variables.
    # Does not override existing environment variables.
    _load_dotenv(Path(repo_root) / ".env")
    _load_dotenv(script_dir / ".env")

    _sync_achievement_catalog(repo_root_path)

    bot_token = _require_env("DISCORD_BOT_TOKEN")
    client_secret = _require_env("DISCORD_CLIENT_SECRET")
    backend_build_version = _normalize_build_version(os.environ.get("BACKEND_BUILD_VERSION"))
    if not backend_build_version:
        current = _try_read_stack_output(args.stack_name, args.region, "BackendBuildVersion")
        backend_build_version = _next_sequential_version(current)

    application_id = _optional_env("DISCORD_APPLICATION_ID")
    public_key = _optional_env("DISCORD_PUBLIC_KEY")
    if not application_id:
        application_id = _try_read_stack_parameter(args.stack_name, args.region, "DiscordApplicationId")
    if not public_key:
        public_key = _try_read_stack_parameter(args.stack_name, args.region, "DiscordPublicKey")
    if not application_id or not public_key:
        info = _fetch_discord_app_info(bot_token)
        application_id = application_id or info.application_id
        public_key = public_key or info.public_key

    ui_stack_name = (
        _optional_env("UI_STACK_NAME")
        or _optional_env("ACTIVITY_UI_STACK_NAME")
        or _optional_env("ACTIVITY_STACK_NAME")
        or "discord-trpg-ui"
    )

    upload_bucket_name = _optional_env("UPLOAD_BUCKET_NAME")
    upload_public_base_url = _optional_env("UPLOAD_PUBLIC_BASE_URL")
    if not upload_bucket_name or not upload_public_base_url:
        if not upload_bucket_name:
            upload_bucket_name = _try_read_stack_output(ui_stack_name, args.region, "ActivityUiBucketName")
        if not upload_public_base_url:
            domain = _try_read_stack_output(ui_stack_name, args.region, "ActivityUiDomainName")
            if domain:
                upload_public_base_url = f"https://{domain}"

    if args.dry_run:
        print("DRY RUN: no commands will be executed.\n")

    if not args.skip_build:
        if not args.dry_run:
            _run(["sam", "build", "--template-file", "template.yaml"], cwd=repo_root)
        else:
            print("+ sam build --template-file template.yaml")

    built_template = Path(repo_root) / ".aws-sam" / "build" / "template.yaml"
    template_file = ".aws-sam/build/template.yaml" if built_template.exists() else "template.yaml"

    deploy_cmd = [
        "sam",
        "deploy",
        "--template-file",
        template_file,
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

    if upload_bucket_name:
        deploy_cmd.append(f"UploadBucketName={upload_bucket_name}")
    if upload_public_base_url:
        deploy_cmd.append(f"UploadPublicBaseUrl={upload_public_base_url}")

    if args.dry_run:
        _print_cmd(deploy_cmd, redact={"DiscordClientSecret", "DiscordBotToken"})
        return 0

    _run(
        deploy_cmd,
        cwd=repo_root,
        redact={"DiscordClientSecret", "DiscordBotToken"},
        redact_values=[bot_token, client_secret],
    )
    _describe_stack_outputs(args.stack_name, args.region)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
