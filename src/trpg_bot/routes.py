from __future__ import annotations

from typing import Any
import logging

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from dateutil import parser as date_parser

from trpg_bot import embeds
from trpg_bot import repositories
from trpg_bot.config import get_ddb_endpoint, get_region, get_table_name
from trpg_bot.db import get_key_attribute_names, get_table
from trpg_bot.discord_api import create_thread, send_message, pin_message, edit_message


EPHEMERAL = 1 << 6
logger = logging.getLogger(__name__)


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


def _format_deadline(deadline: Any | None) -> str | None:
    if not deadline:
        return None
    if isinstance(deadline, str):
        return deadline
    return deadline.strftime("%Y-%m-%d %H:%M")


def _next_action_text(session: dict, missing: list[str], poll_deadline: str | None) -> str:
    status = session.get("status", "")
    if status == "recruiting":
        return "参加者募集中。参加予定の人は /session join、日程調整を始めるなら /poll create。"
    if status == "scheduling":
        if missing:
            return f"{len(missing)} 名が未入力。締切後に /nudge または直接催促してください。"
        if poll_deadline:
            return f"締切 {poll_deadline}。候補が揃ったら /poll finalize で確定。"
        return "候補入力が揃ったら /poll finalize で確定。"
    if status == "confirmed":
        return "開催予定を参加者に共有。当日終了後 /complete で履歴を記録。"
    if status == "running":
        return "進行中。終わったら /complete。"
    if status == "completed":
        return "完了済み。履歴は PlayHistory に保存されています。"
    if status == "canceled":
        return "キャンセル済み。必要なら新しいセッションを作成してください。"
    return "運用を続行してください。"


def refresh_session_card(session_id: str) -> None:
    session = repositories.get_session_with_details(session_id)
    if not session:
        return

    participants = repositories.list_participants(session_id)
    poll = repositories.latest_poll_for_session(session_id)
    poll_deadline = _format_deadline(poll["deadline"]) if poll and poll.get("deadline") else None
    missing = []
    if poll:
        include_ids = [session["gm_user_id"]] if session.get("gm_user_id") else None
        missing_records = repositories.list_poll_missing_responses(poll["poll_id"], include_user_ids=include_ids)
        missing = [m["display_name"] for m in missing_records]

    next_action = _next_action_text(session, missing, poll_deadline)
    embed = embeds.session_card_embed(session, participants, missing, next_action, poll_deadline)

    if session.get("card_message_id"):
        edit_message(session["thread_id"], session["card_message_id"], {"embeds": [embed]})
    else:
        message = send_message(session["thread_id"], {"embeds": [embed]})
        pin_message(session["thread_id"], message["id"])
        repositories.update_session_card_message(session_id, message["id"])


def _ensure_manage_permission(session: dict, actor_id: str) -> bool:
    return actor_id == session.get("gm_user_id") or actor_id == session.get("created_by")


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


def handle_health(_: dict) -> dict:
    report: dict[str, Any] = {
        "region": None,
        "table_name": None,
        "table_status": None,
        "item_count": None,
        "checks": {},
        "warnings": [],
        "errors": [],
    }

    try:
        report["region"] = get_region()
        report["table_name"] = get_table_name()
        endpoint = get_ddb_endpoint()
        if endpoint:
            report["warnings"].append(f"DYNAMODB_ENDPOINT is set ({endpoint})")
    except Exception as exc:
        return _respond(f"設定エラー: {exc}")

    try:
        table = get_table()
    except Exception as exc:
        return _respond(f"DynamoDB初期化エラー: {exc}")

    client = table.meta.client
    try:
        desc = client.describe_table(TableName=report["table_name"])["Table"]
        report["table_status"] = desc.get("TableStatus")
        report["item_count"] = desc.get("ItemCount")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        report["errors"].append(f"DescribeTable failed: {code} {message}")
        embed = embeds.ddb_health_embed(report)
        return {"type": 4, "data": {"embeds": [embed], "flags": EPHEMERAL}}

    key_schema = desc.get("KeySchema") or []
    actual = {(ks.get("AttributeName"), ks.get("KeyType")) for ks in key_schema}
    pk_attr = next((ks.get("AttributeName") for ks in key_schema if ks.get("KeyType") == "HASH"), None)
    sk_attr = next((ks.get("AttributeName") for ks in key_schema if ks.get("KeyType") == "RANGE"), None)
    if not pk_attr or not sk_attr:
        report["errors"].append(f"Table must have partition+sort key: {sorted(actual)}")
    else:
        report["checks"]["KeySchema"] = f"{pk_attr}(HASH), {sk_attr}(RANGE)"

    gsi_list = desc.get("GlobalSecondaryIndexes") or []
    gsi_names = sorted([g.get("IndexName") for g in gsi_list if g.get("IndexName")])
    report["checks"]["GSIs"] = ", ".join(gsi_names) if gsi_names else "(none)"

    try:
        pk_name, sk_name = get_key_attribute_names()
        table.get_item(Key={pk_name: "HEALTH#0", sk_name: "0"})
        report["checks"]["GetItem"] = "OK"
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        report["checks"]["GetItem"] = f"FAIL ({code})"

    try:
        pk_name, sk_name = get_key_attribute_names()
        table.query(
            KeyConditionExpression=Key(pk_name).eq("HEALTH#Q") & Key(sk_name).begins_with("X#"),
            Limit=1,
        )
        report["checks"]["Query(pk/sk)"] = "OK"
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        report["checks"]["Query(pk/sk)"] = f"FAIL ({code})"

    embed = embeds.ddb_health_embed(report)
    return {"type": 4, "data": {"embeds": [embed], "flags": EPHEMERAL}}


def handle_scenario(interaction: dict) -> dict:
    data = interaction["data"]
    sub = data["options"][0]
    sub_name = sub["name"]
    opts = option_map(sub.get("options"))

    user_id = interaction["member"]["user"]["id"]
    display_name = interaction["member"]["user"]["username"]

    repositories.upsert_user(user_id, display_name)
    if sub_name == "add":
        scenario_id = repositories.create_scenario(
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
            scenario_id=str(opts["scenario_id"]),
            title=opts["title"],
            system=opts.get("system", ""),
            estimated_time=opts.get("estimated_time", ""),
            tags=opts.get("tags", "").split(",") if opts.get("tags") else [],
            notes=opts.get("notes", ""),
        )
        return _respond("シナリオを更新しました")
    if sub_name == "info":
        scenario = repositories.get_scenario(str(opts["scenario_id"]))
        if not scenario:
            return _respond("シナリオが見つかりませんでした")
        can_gm = repositories.list_capable_gms(scenario["scenario_id"])
        played = repositories.list_play_history(scenario["scenario_id"])
        return {
            "type": 4,
            "data": {
                "embeds": [embeds.scenario_info_embed(scenario, can_gm, played)],
                "flags": EPHEMERAL,
            },
        }
    if sub_name == "search":
        results = repositories.search_scenarios(opts["keyword"])
        if not results:
            return _respond("該当するシナリオがありません")
        summary = "\n".join(
            [f"`{row['scenario_id']}` {row['title']} ({row.get('system','')})" for row in results]
        )
        return _respond(summary)
    if sub_name == "canrun_add":
        repositories.add_capability(str(opts["scenario_id"]), user_id, display_name, opts.get("confidence", "ready"))
        return _respond("回せるシナリオに追加しました")
    if sub_name == "canrun_remove":
        repositories.remove_capability(str(opts["scenario_id"]), user_id)
        return _respond("回せるシナリオから削除しました")
    if sub_name == "who_can_gm":
        gms = repositories.list_capable_gms(str(opts["scenario_id"]))
        return _respond(", ".join(gms) or "登録なし")
    if sub_name == "who_played":
        played = repositories.list_play_history(str(opts["scenario_id"]))
        return _respond(", ".join(played) or "履歴なし")

    return _respond("未対応のサブコマンドです")


def handle_session(interaction: dict) -> dict:
    data = interaction["data"]
    sub = data["options"][0]
    sub_name = sub["name"]
    opts = option_map(sub.get("options"))

    user_id = interaction["member"]["user"]["id"]
    display_name = interaction["member"]["user"]["username"]

    repositories.upsert_user(user_id, display_name)
    if sub_name == "create":
        scenario_id = str(opts["scenario_id"]) if opts.get("scenario_id") else None
        gm_user_id = opts.get("gm_user_id") or None
        title = opts.get("title", "TRPGセッション")
        if gm_user_id and gm_user_id != user_id:
            repositories.upsert_user(gm_user_id, gm_user_id)
        thread = create_thread(interaction["channel_id"], title)
        session_id = repositories.create_session(
            scenario_id=scenario_id,
            gm_user_id=gm_user_id,
            title=title,
            status="recruiting",
            guild_id=interaction["guild_id"],
            channel_id=interaction["channel_id"],
            thread_id=thread["id"],
            min_players=int(opts.get("min_players", 1)),
            max_players=int(opts.get("max_players", 5)),
            created_by=user_id,
        )
        repositories.log_audit(session_id, "session_created", user_id, {"thread_id": thread["id"]})
        refresh_session_card(session_id)
        return _respond(f"セッションを作成しました (ID: {session_id})")
    if sub_name == "join":
        session_id = str(opts["session_id"])
        session = repositories.get_session_with_details(session_id)
        if not session:
            return _respond("セッションが見つかりませんでした")
        if session["status"] not in ("recruiting", "scheduling"):
            return _respond("このセッションは参加受付を終了しています")
        repositories.add_participant(session_id, user_id, display_name, "PL")
        refresh_session_card(session_id)
        return _respond("参加登録しました")
    if sub_name == "leave":
        session_id = str(opts["session_id"])
        session = repositories.get_session_with_details(session_id)
        if not session:
            return _respond("セッションが見つかりませんでした")
        repositories.remove_participant(session_id, user_id)
        refresh_session_card(session_id)
        return _respond("参加を取り消しました")

    return _respond("未対応のサブコマンドです")


def handle_poll(interaction: dict) -> dict:
    data = interaction["data"]
    sub = data["options"][0]
    sub_name = sub["name"]
    opts = option_map(sub.get("options"))
    user_id = interaction["member"]["user"]["id"]
    display_name = interaction["member"]["user"]["username"]

    repositories.upsert_user(user_id, display_name)
    if sub_name == "create":
        session_id = str(opts["session_id"])
        session = repositories.get_session_with_details(session_id)
        if not session:
            return _respond("セッションが見つかりませんでした")
        if session["status"] not in ("recruiting", "scheduling"):
            return _respond(f"このセッションは現在 {session['status']} のため日程調整を作成できません")
        deadline = date_parser.parse(opts["deadline"]) if opts.get("deadline") else None
        poll_id = repositories.create_poll(session_id, deadline, opts.get("timezone_basis", "Asia/Tokyo"))
        slots_raw = opts.get("slots", "")
        created_slots = 0
        for slot in slots_raw.split(";"):
            if not slot.strip():
                continue
            try:
                start_str, end_str = slot.split("/")
                repositories.add_slot(poll_id, date_parser.parse(start_str), date_parser.parse(end_str))
                created_slots += 1
            except ValueError:
                return _respond("スロットは `YYYY-MM-DD HH:MM/YYYY-MM-DD HH:MM;...` 形式で指定してください")
        repositories.mark_session_status(session_id, "scheduling")
        repositories.log_audit(session_id, "poll_created", user_id, {"poll_id": poll_id})
        refresh_session_card(session_id)
        return _respond(f"日程調整を作成しました (Poll ID: {poll_id}, Slots: {created_slots})")
    if sub_name == "avail_input":
        slot_id = str(opts["slot_id"])
        poll_id = repositories.poll_id_for_slot(slot_id)
        if not poll_id:
            return _respond("スロットが見つかりませんでした")
        poll = repositories.poll_by_id(poll_id)
        if not poll:
            return _respond("日程調整が見つかりませんでした")
        session = repositories.get_session_with_details(poll["session_id"])
        if session and session["status"] in ("completed", "canceled"):
            return _respond("このセッションは回答受付を終了しています")
        repositories.upsert_response(
            slot_id=slot_id,
            user_id=user_id,
            status=opts["status"],
            comment=opts.get("comment", ""),
        )
        refresh_session_card(poll["session_id"])
        return _respond("回答を登録しました")
    if sub_name == "status":
        poll_id = str(opts["poll_id"])
        poll = repositories.poll_by_id(poll_id)
        if not poll:
            return _respond("日程調整が見つかりませんでした")
        session = repositories.get_session_with_details(poll["session_id"]) or {}
        include_ids = [session.get("gm_user_id")] if session.get("gm_user_id") else None
        missing_records = repositories.list_poll_missing_responses(poll_id, include_user_ids=include_ids)
        missing = [m["display_name"] for m in missing_records]
        slots = repositories.list_availability_summary(poll_id)
        embed = embeds.availability_summary_embed(
            slots,
            missing,
            _format_deadline(poll.get("deadline")),
        )
        return {"type": 4, "data": {"embeds": [embed], "flags": EPHEMERAL}}
    if sub_name == "finalize":
        session_id = str(opts["session_id"]) if opts.get("session_id") else None
        slot_id = str(opts["slot_id"]) if opts.get("slot_id") else None
        poll_id = str(opts["poll_id"]) if opts.get("poll_id") else None

        if slot_id and not poll_id:
            poll_id = repositories.poll_id_for_slot(slot_id)
        if poll_id and not session_id:
            info = repositories.poll_session_info(poll_id)
            session_id = info["session_id"] if info else None
        if not session_id:
            return _respond("session_id または poll_id/slot_id を指定してください")

        session = repositories.get_session_with_details(session_id)
        if not session:
            return _respond("セッションが見つかりませんでした")
        if not _ensure_manage_permission(session, user_id):
            return _respond("GMまたは作成者のみ確定できます")
        if session["status"] not in ("scheduling", "recruiting"):
            return _respond("このセッションは既に確定済みです")

        if slot_id:
            repositories.set_session_schedule_from_slot(session_id, slot_id)
        repositories.mark_session_status(session_id, "confirmed")
        repositories.log_audit(session_id, "schedule_finalized", user_id, {"poll_id": poll_id, "slot_id": slot_id})
        refresh_session_card(session_id)

        if slot_id:
            slot = repositories.slot_detail(slot_id)
            start_text = slot["start"].strftime("%Y-%m-%d %H:%M") if slot and slot.get("start") else ""
            end_text = slot["end"].strftime("%H:%M") if slot and slot.get("end") else ""
            return _respond(f"日程を確定しました: {start_text} - {end_text}")
        return _respond("日程を確定しました")

    return _respond("未対応のサブコマンドです")


def handle_complete(interaction: dict) -> dict:
    data = interaction["data"]
    opts = option_map(data.get("options"))
    session_id = str(opts["session_id"])
    scenario_id = str(opts["scenario_id"])
    user_id = interaction["member"]["user"]["id"]
    display_name = interaction["member"]["user"]["username"]

    repositories.upsert_user(user_id, display_name)
    session = repositories.get_session_with_details(session_id)
    if not session:
        return _respond("セッションが見つかりませんでした")
    if not _ensure_manage_permission(session, user_id):
        return _respond("GMまたは作成者のみ完了できます")
    if session["status"] in ("completed", "canceled"):
        return _respond("このセッションは既にクローズしています")

    participants = repositories.list_participant_records(session_id)
    for participant in participants:
        repositories.add_play_history(
            scenario_id,
            participant["user_id"],
            participant["display_name"],
            "PL",
            session_id,
            "",
        )
    gm_to_record = session.get("gm_user_id") or user_id
    gm_name = session.get("gm_name") or display_name or gm_to_record
    repositories.upsert_user(gm_to_record, gm_name)
    repositories.add_play_history(scenario_id, gm_to_record, gm_name, "GM", session_id, "")
    repositories.mark_session_status(session_id, "completed")
    repositories.log_audit(session_id, "session_completed", user_id, {"scenario_id": scenario_id})
    refresh_session_card(session_id)
    return _respond("完了しました。履歴を記録しました")


def handle_nudge(interaction: dict) -> dict:
    data = interaction["data"]
    opts = option_map(data.get("options"))
    poll_id = str(opts["poll_id"]) if opts and opts.get("poll_id") else None
    user_id = interaction["member"]["user"]["id"]
    display_name = interaction["member"]["user"]["username"]

    if not poll_id:
        return _respond("poll_id を指定してください")

    repositories.upsert_user(user_id, display_name)
    info = repositories.poll_session_info(poll_id)
    if not info:
        return _respond("日程調整が見つかりませんでした")
    session = repositories.get_session_with_details(info["session_id"])
    if not session:
        return _respond("セッションが見つかりませんでした")
    if not _ensure_manage_permission(session, user_id):
        return _respond("GMまたは作成者のみ催促できます")
    if session["status"] not in ("scheduling", "recruiting"):
        return _respond("日程調整中のみ催促できます")

    include_ids = [session.get("gm_user_id")] if session.get("gm_user_id") else None
    missing_records = repositories.list_poll_missing_responses(poll_id, include_user_ids=include_ids)
    if not missing_records:
        return _respond("未入力者はいません")

    mentions = [f"<@{m['user_id']}> ({m['display_name']})" for m in missing_records]
    send_message(
        info["thread_id"],
        {
            "content": f"未入力の方: {', '.join(mentions)}\n締切前に入力をお願いします。",
        },
    )
    repositories.log_audit(
        info["session_id"],
        "nudge_missing",
        user_id,
        {"poll_id": poll_id, "missing": [m["user_id"] for m in missing_records]},
    )
    refresh_session_card(info["session_id"])
    return _respond("催促を送信しました", ephemeral=True)


def handle_component(interaction: dict) -> dict:
    custom_id = interaction["data"].get("custom_id")
    if custom_id == "ops:create_session":
        return _respond("`/session create` で新しい募集を作成します。")
    if custom_id == "ops:search":
        return _respond("`/scenario search keyword:<キーワード>` で検索できます。")
    if custom_id == "ops:nudge":
        return _respond("`/nudge poll_id:<ID>` で未入力者へ催促を送ります。")
    return _respond("未対応のボタンです")


def handle_command(interaction: dict) -> dict:
    name = interaction["data"]["name"]
    if name == "setup":
        return handle_setup(interaction)
    if name == "health":
        return handle_health(interaction)
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
