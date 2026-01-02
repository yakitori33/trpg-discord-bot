from __future__ import annotations

import base64
import json
import os
import sys
from typing import Any

import requests


API_BASE = "https://discord.com/api/v10"
DEFAULT_APPLICATION_ID: str | None = None  # Optional: set to your Application ID (Client ID)


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Missing env var: {name}")
    return value


def _derive_application_id_from_bot_token(bot_token: str) -> str | None:
    first_segment = bot_token.split(".", 1)[0]
    padded = first_segment + "=" * (-len(first_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
    except Exception:
        return None
    return decoded if decoded.isdigit() else None


def _resolve_application_id(bot_token: str) -> str:
    env_value = os.getenv("DISCORD_APPLICATION_ID")
    if env_value:
        return env_value
    if DEFAULT_APPLICATION_ID:
        return DEFAULT_APPLICATION_ID
    derived = _derive_application_id_from_bot_token(bot_token)
    if derived:
        return derived
    raise SystemExit("Missing DISCORD_APPLICATION_ID (and could not derive from DISCORD_BOT_TOKEN)")


def build_commands() -> list[dict[str, Any]]:
    # https://discord.com/developers/docs/interactions/application-commands#application-command-object-application-command-option-type
    STRING = 3
    INTEGER = 4
    USER = 6
    SUB_COMMAND = 1

    def str_opt(name: str, description: str, required: bool = False) -> dict[str, Any]:
        return {"type": STRING, "name": name, "description": description, "required": required}

    def int_opt(name: str, description: str, required: bool = False) -> dict[str, Any]:
        return {"type": INTEGER, "name": name, "description": description, "required": required}

    def user_opt(name: str, description: str, required: bool = False) -> dict[str, Any]:
        return {"type": USER, "name": name, "description": description, "required": required}

    def sub(name: str, description: str, options: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"type": SUB_COMMAND, "name": name, "description": description}
        if options:
            payload["options"] = options
        return payload

    return [
        {"name": "setup", "description": "管制塔パネルを投稿します"},
        {"name": "health", "description": "DynamoDBの状態チェック"},
        {
            "name": "scenario",
            "description": "シナリオ管理",
            "options": [
                sub(
                    "add",
                    "シナリオを追加",
                    [
                        str_opt("title", "タイトル", required=True),
                        str_opt("system", "システム"),
                        str_opt("estimated_time", "想定時間"),
                        str_opt("tags", "タグ (カンマ区切り)"),
                        str_opt("notes", "メモ(非ネタバレ推奨)"),
                    ],
                ),
                sub(
                    "edit",
                    "シナリオを編集",
                    [
                        str_opt("scenario_id", "シナリオID (例: scn_xxxxxxxx)", required=True),
                        str_opt("title", "タイトル", required=True),
                        str_opt("system", "システム"),
                        str_opt("estimated_time", "想定時間"),
                        str_opt("tags", "タグ (カンマ区切り)"),
                        str_opt("notes", "メモ(非ネタバレ推奨)"),
                    ],
                ),
                sub("info", "シナリオ詳細", [str_opt("scenario_id", "シナリオID", required=True)]),
                sub("search", "シナリオ検索", [str_opt("keyword", "検索キーワード", required=True)]),
                sub(
                    "canrun_add",
                    "回せるシナリオに登録",
                    [
                        str_opt("scenario_id", "シナリオID", required=True),
                        str_opt("confidence", "準備状況/自信 (例: ready)", required=False),
                    ],
                ),
                sub("canrun_remove", "回せる登録を削除", [str_opt("scenario_id", "シナリオID", required=True)]),
                sub("who_can_gm", "回せるGM一覧", [str_opt("scenario_id", "シナリオID", required=True)]),
                sub("who_played", "通過済み一覧", [str_opt("scenario_id", "シナリオID", required=True)]),
            ],
        },
        {
            "name": "session",
            "description": "セッション管理",
            "options": [
                sub(
                    "create",
                    "セッション(募集)を作成",
                    [
                        str_opt("title", "スレッド名/募集名", required=True),
                        str_opt("scenario_id", "シナリオID (任意)"),
                        user_opt("gm_user_id", "GM (任意)"),
                        int_opt("min_players", "最少PL数 (任意)"),
                        int_opt("max_players", "最大PL数 (任意)"),
                    ],
                ),
                sub("join", "参加する", [str_opt("session_id", "セッションID (例: ses_xxxxxxxx)", required=True)]),
                sub("leave", "参加をやめる", [str_opt("session_id", "セッションID", required=True)]),
            ],
        },
        {
            "name": "poll",
            "description": "日程調整",
            "options": [
                sub(
                    "create",
                    "日程調整を作成",
                    [
                        str_opt("session_id", "セッションID", required=True),
                        str_opt(
                            "slots",
                            "候補枠 (例: 2026-01-10 21:00/2026-01-10 24:00;...)",
                            required=True,
                        ),
                        str_opt("deadline", "締切 (例: 2026-01-05 23:59)"),
                        str_opt("timezone_basis", "タイムゾーン (例: Asia/Tokyo)"),
                    ],
                ),
                sub(
                    "avail_input",
                    "候補枠への回答",
                    [
                        str_opt("slot_id", "スロットID (例: slot_xxxxxxxx)", required=True),
                        {
                            "type": STRING,
                            "name": "status",
                            "description": "OK/MAYBE/NO",
                            "required": True,
                            "choices": [
                                {"name": "OK", "value": "OK"},
                                {"name": "MAYBE", "value": "MAYBE"},
                                {"name": "NO", "value": "NO"},
                            ],
                        },
                        str_opt("comment", "コメント (任意)"),
                    ],
                ),
                sub("status", "集計を見る", [str_opt("poll_id", "Poll ID (例: poll_xxxxxxxx)", required=True)]),
                sub(
                    "finalize",
                    "日程を確定する",
                    [
                        str_opt("slot_id", "確定するスロットID", required=True),
                        str_opt("poll_id", "Poll ID (任意)"),
                        str_opt("session_id", "Session ID (任意)"),
                    ],
                ),
            ],
        },
        {
            "name": "complete",
            "description": "セッション完了(履歴記録)",
            "options": [
                str_opt("session_id", "セッションID", required=True),
                str_opt("scenario_id", "シナリオID", required=True),
            ],
        },
        {
            "name": "nudge",
            "description": "未入力者へ催促",
            "options": [str_opt("poll_id", "Poll ID", required=True)],
        },
    ]


def main() -> int:
    bot_token = _require_env("DISCORD_BOT_TOKEN")
    application_id = _resolve_application_id(bot_token)
    guild_id = os.getenv("DISCORD_GUILD_ID")

    commands = build_commands()
    url = (
        f"{API_BASE}/applications/{application_id}/guilds/{guild_id}/commands"
        if guild_id
        else f"{API_BASE}/applications/{application_id}/commands"
    )
    scope = f"guild:{guild_id}" if guild_id else "global"

    resp = requests.put(
        url,
        headers={"Authorization": f"Bot {bot_token}", "Content-Type": "application/json"},
        data=json.dumps(commands),
        timeout=15,
    )
    if resp.status_code >= 300:
        print(resp.status_code, resp.text, file=sys.stderr)
        return 1

    result = resp.json()
    print(f"Registered {len(result)} commands ({scope})")
    for cmd in result:
        print(f"- {cmd['name']} (id={cmd['id']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
