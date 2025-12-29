from __future__ import annotations

from datetime import datetime
from typing import Any

from dateutil import parser as date_parser

from trpg_bot import embeds
from trpg_bot.db import get_conn, get_cursor
from trpg_bot import repositories
from trpg_bot.discord_api import create_thread, send_message, pin_message


EPHEMERAL = 1 << 6


def option_map(options: list[dict] | None) -> dict[str, Any]:
    if not options:
        return {}
    return {opt["name"]: opt.get("value") for opt in options}


def _respond(content: str, ephemeral: bool = True) -> dict:
    flags = EPHEMERAL if ephemeral else 0
    return {
        "type": 4,
        "data": {"content": content, "flags": flags},
    }


def handle_setup(interaction: dict) -> dict:
    channel_id = interaction["channel_id"]
    payload = {
        "embeds": [embeds.ops_panel_embed()],
        "components": [
            {
                "type": 1,
                "components": [
                    {"type": 2, "style": 1, "custom_id": "ops:create_session", "label": "募集作成"},
                    {"type": 2, "style": 2, "custom_id": "ops:search", "label": "検索"},
                    {"type": 2, "style": 2, "custom_id": "ops:nudge", "label": "未入力チェック"},
                ],
            }
        ],
    }
    message = send_message(channel_id, payload)
    pin_message(channel_id, message["id"])
    return _respond("管制塔パネルを投稿しました。", ephemeral=True)


def handle_scenario(interaction: dict) -> dict:
    data = interaction["data"]
    sub = data["options"][0]
    sub_name = sub["name"]
    opts = option_map(sub.get("options"))

    user_id = interaction["member"]["user"]["id"]
    display_name = interaction["member"]["user"]["username"]

    with get_conn() as conn:
        with get_cursor(conn) as cursor:
            repositories.upsert_user(cursor, user_id, display_name)
            if sub_name == "add":
                scenario_id = repositories.create_scenario(
                    cursor,
                    title=opts["title"],
                    system=opts.get("system", ""),
                    estimated_time=opts.get("estimated_time", ""),
                    tags=opts.get("tags", "").split(",") if opts.get("tags") else [],
                    notes=opts.get("notes", ""),
                    created_by=user_id,
                )
                return _respond(f"シナリオを登録しました (ID: {scenario_id})")
            if sub_name == "edit":
                repositories.update_scenario(
                    cursor,
                    scenario_id=int(opts["scenario_id"]),
                    title=opts["title"],
                    system=opts.get("system", ""),
                    estimated_time=opts.get("estimated_time", ""),
                    tags=opts.get("tags", "").split(",") if opts.get("tags") else [],
                    notes=opts.get("notes", ""),
                )
                return _respond("シナリオを更新しました")
            if sub_name == "info":
                scenario = repositories.get_scenario(cursor, int(opts["scenario_id"]))
                if not scenario:
                    return _respond("シナリオが見つかりませんでした")
                can_gm = repositories.list_capable_gms(cursor, scenario["scenario_id"])
                played = repositories.list_play_history(cursor, scenario["scenario_id"])
                return {
                    "type": 4,
                    "data": {
                        "embeds": [embeds.scenario_info_embed(scenario, can_gm, played)],
                        "flags": EPHEMERAL,
                    },
                }
            if sub_name == "search":
                results = repositories.search_scenarios(cursor, opts["keyword"])
                if not results:
                    return _respond("該当するシナリオがありません")
                summary = "\n".join(
                    [f"`{row['scenario_id']}` {row['title']} ({row['system']})" for row in results]
                )
                return _respond(summary)
            if sub_name == "canrun_add":
                repositories.add_capability(cursor, int(opts["scenario_id"]), user_id, opts.get("confidence", "ready"))
                return _respond("回せるシナリオに追加しました")
            if sub_name == "canrun_remove":
                repositories.remove_capability(cursor, int(opts["scenario_id"]), user_id)
                return _respond("回せるシナリオから削除しました")
            if sub_name == "who_can_gm":
                gms = repositories.list_capable_gms(cursor, int(opts["scenario_id"]))
                return _respond(", ".join(gms) or "登録なし")
            if sub_name == "who_played":
                played = repositories.list_play_history(cursor, int(opts["scenario_id"]))
                return _respond(", ".join(played) or "履歴なし")

    return _respond("未対応のサブコマンドです")


def handle_session(interaction: dict) -> dict:
    data = interaction["data"]
    sub = data["options"][0]
    sub_name = sub["name"]
    opts = option_map(sub.get("options"))

    user_id = interaction["member"]["user"]["id"]
    display_name = interaction["member"]["user"]["username"]

    with get_conn() as conn:
        with get_cursor(conn) as cursor:
            repositories.upsert_user(cursor, user_id, display_name)
            if sub_name == "create":
                scenario_id = int(opts["scenario_id"]) if opts.get("scenario_id") else None
                gm_user_id = opts.get("gm_user_id") or None
                thread = create_thread(interaction["channel_id"], opts.get("title", "TRPGセッション"))
                session_id = repositories.create_session(
                    cursor,
                    scenario_id=scenario_id,
                    gm_user_id=gm_user_id,
                    status="recruiting",
                    guild_id=interaction["guild_id"],
                    channel_id=interaction["channel_id"],
                    thread_id=thread["id"],
                    min_players=int(opts.get("min_players", 1)),
                    max_players=int(opts.get("max_players", 5)),
                    created_by=user_id,
                )
                session = {
                    "status": "recruiting",
                    "scenario_title": opts.get("title", "未設定"),
                    "gm_name": gm_user_id or "未設定",
                }
                card = embeds.session_card_embed(session, [], [], "参加者を募集中")
                message = send_message(thread["id"], {"embeds": [card]})
                pin_message(thread["id"], message["id"])
                return _respond(f"セッションを作成しました (ID: {session_id})")
            if sub_name == "join":
                repositories.add_participant(cursor, int(opts["session_id"]), user_id, "PL")
                return _respond("参加登録しました")
            if sub_name == "leave":
                repositories.remove_participant(cursor, int(opts["session_id"]), user_id)
                return _respond("参加を取り消しました")

    return _respond("未対応のサブコマンドです")


def handle_poll(interaction: dict) -> dict:
    data = interaction["data"]
    sub = data["options"][0]
    sub_name = sub["name"]
    opts = option_map(sub.get("options"))
    user_id = interaction["member"]["user"]["id"]
    display_name = interaction["member"]["user"]["username"]

    with get_conn() as conn:
        with get_cursor(conn) as cursor:
            repositories.upsert_user(cursor, user_id, display_name)
            if sub_name == "create":
                deadline = date_parser.parse(opts["deadline"]) if opts.get("deadline") else None
                poll_id = repositories.create_poll(cursor, int(opts["session_id"]), deadline, opts.get("timezone_basis", "Asia/Tokyo"))
                slots_raw = opts.get("slots", "")
                for slot in slots_raw.split(";"):
                    if not slot.strip():
                        continue
                    start_str, end_str = slot.split("/")
                    repositories.add_slot(cursor, poll_id, date_parser.parse(start_str), date_parser.parse(end_str))
                return _respond(f"日程調整を作成しました (Poll ID: {poll_id})")
            if sub_name == "avail_input":
                repositories.upsert_response(
                    cursor,
                    slot_id=int(opts["slot_id"]),
                    user_id=user_id,
                    status=opts["status"],
                    comment=opts.get("comment", ""),
                )
                return _respond("回答を登録しました")
            if sub_name == "status":
                poll_id = int(opts["poll_id"])
                slots = repositories.list_availability_summary(cursor, poll_id)
                deadline = repositories.get_poll_deadline(cursor, poll_id)
                missing = []
                embed = embeds.availability_summary_embed(
                    slots,
                    missing,
                    deadline.isoformat() if deadline else None,
                )
                return {"type": 4, "data": {"embeds": [embed], "flags": EPHEMERAL}}
            if sub_name == "finalize":
                repositories.mark_session_status(cursor, int(opts["session_id"]), "confirmed")
                return _respond("日程を確定しました")

    return _respond("未対応のサブコマンドです")


def handle_complete(interaction: dict) -> dict:
    data = interaction["data"]
    opts = option_map(data.get("options"))
    session_id = int(opts["session_id"])
    scenario_id = int(opts["scenario_id"])
    user_id = interaction["member"]["user"]["id"]
    display_name = interaction["member"]["user"]["username"]

    with get_conn() as conn:
        with get_cursor(conn) as cursor:
            repositories.upsert_user(cursor, user_id, display_name)
            repositories.add_play_history(cursor, scenario_id, user_id, "GM", session_id, "")
            repositories.mark_session_status(cursor, session_id, "completed")
            return _respond("完了しました。履歴を記録しました")


def handle_nudge(interaction: dict) -> dict:
    return _respond("未入力者への催促は準備中です")


def handle_command(interaction: dict) -> dict:
    name = interaction["data"]["name"]
    if name == "setup":
        return handle_setup(interaction)
    if name == "scenario":
        return handle_scenario(interaction)
    if name == "session":
        return handle_session(interaction)
    if name == "poll":
        return handle_poll(interaction)
    if name == "complete":
        return handle_complete(interaction)
    if name == "nudge":
        return handle_nudge(interaction)
    return _respond("未対応のコマンドです")
