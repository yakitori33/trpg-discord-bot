from __future__ import annotations

from datetime import datetime

STATUS_COLORS = {
    "proposed": 0x9CA3AF,
    "recruiting": 0x10B981,
    "scheduling": 0xF59E0B,
    "confirmed": 0x2563EB,
    "running": 0x16A34A,
    "completed": 0x4B5563,
    "canceled": 0x6B7280,
}


def ops_panel_embed() -> dict:
    return {
        "title": "TRPG管制塔パネル",
        "description": "募集作成・検索・未入力チェックなどの起点です。",
        "color": 0x4F46E5,
        "fields": [
            {"name": "募集作成", "value": "セッション作成ボタンを使用"},
            {"name": "シナリオ検索", "value": "検索ボタンを使用"},
            {"name": "未入力チェック", "value": "締切前/後の催促に対応"},
        ],
    }


def _schedule_text(session: dict) -> str:
    start = session.get("scheduled_start")
    end = session.get("scheduled_end")
    if not start:
        return "未定"
    if isinstance(start, str):
        start_str = start
        end_str = end or ""
    else:
        start_str = start.strftime("%Y-%m-%d %H:%M")
        end_str = end.strftime("%H:%M") if end else ""
    if not end_str:
        return start_str
    return f"{start_str} - {end_str}"


def session_card_embed(session: dict, participants: list[str], missing: list[str], next_action: str, poll_deadline: str | None = None) -> dict:
    status = session.get("status", "recruiting")
    deadline_field = {"name": "回答締切", "value": poll_deadline or "未設定"} if poll_deadline else None
    title_text = session.get("title") or session.get("scenario_title") or "未設定"
    fields = [
        {"name": "GM", "value": session.get("gm_name", "未設定"), "inline": True},
        {"name": "参加者", "value": ", ".join(participants) or "なし", "inline": True},
        {"name": "未入力者", "value": ", ".join(missing) or "なし"},
        {"name": "予定", "value": _schedule_text(session), "inline": True},
        {"name": "次のアクション", "value": next_action},
    ]
    if deadline_field:
        fields.append(deadline_field)
    return {
        "title": f"セッションカード: {title_text}",
        "description": f"状態: **{session['status']}**",
        "footer": {"text": f"Session ID: {session.get('session_id', '-')}"},  # quick reference for commands
        "color": STATUS_COLORS.get(status, 0x10B981),
        "fields": fields,
        "timestamp": datetime.utcnow().isoformat(),
    }


def availability_summary_embed(slots: list[dict], missing: list[str], deadline: str | None) -> dict:
    fields = []
    for slot in slots:
        fields.append(
            {
                "name": f"#{slot['slot_id']} {slot['start']} - {slot['end']}",
                "value": f"OK: {slot['ok']} / MAYBE: {slot['maybe']} / NO: {slot['no']}",
            }
        )
    fields.append({"name": "未入力", "value": ", ".join(missing) or "なし"})
    if deadline:
        fields.append({"name": "締切", "value": deadline})
    return {
        "title": "日程調整 集計",
        "color": 0xF59E0B,
        "fields": fields,
    }


def scenario_info_embed(scenario: dict, can_gm: list[str], played: list[str]) -> dict:
    return {
        "title": scenario["title"],
        "description": scenario.get("notes", ""),
        "color": 0x3B82F6,
        "fields": [
            {"name": "システム", "value": scenario.get("system", "-"), "inline": True},
            {"name": "想定時間", "value": scenario.get("estimated_time", "-"), "inline": True},
            {"name": "回せるGM", "value": ", ".join(can_gm) or "なし"},
            {"name": "通過済み", "value": ", ".join(played) or "なし"},
        ],
    }


def ddb_health_embed(report: dict) -> dict:
    errors = report.get("errors") or []
    warnings = report.get("warnings") or []
    checks = report.get("checks") or {}

    if errors:
        color = 0xEF4444
        status = "ERROR"
    elif warnings:
        color = 0xF59E0B
        status = "WARN"
    else:
        color = 0x10B981
        status = "OK"

    checks_text = "\n".join([f"- {k}: {v}" for k, v in checks.items()]) or "-"
    warnings_text = "\n".join([f"- {w}" for w in warnings]) if warnings else "-"
    errors_text = "\n".join([f"- {e}" for e in errors]) if errors else "-"

    fields = [
        {"name": "Status", "value": status, "inline": True},
        {"name": "Region", "value": report.get("region") or "-", "inline": True},
        {"name": "Table", "value": report.get("table_name") or "-", "inline": False},
        {"name": "TableStatus", "value": report.get("table_status") or "-", "inline": True},
        {"name": "ItemCount", "value": str(report.get("item_count", "-")), "inline": True},
        {"name": "Checks", "value": checks_text, "inline": False},
    ]
    fields.append({"name": "Warnings", "value": warnings_text, "inline": False})
    fields.append({"name": "Errors", "value": errors_text, "inline": False})

    return {
        "title": "DynamoDB Health",
        "description": "Botが参照しているDynamoDBテーブル/インデックスの状態を確認します。",
        "color": color,
        "fields": fields,
        "timestamp": datetime.utcnow().isoformat(),
    }
