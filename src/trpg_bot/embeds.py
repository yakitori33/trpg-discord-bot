from __future__ import annotations

from datetime import datetime


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


def session_card_embed(session: dict, participants: list[str], missing: list[str], next_action: str) -> dict:
    return {
        "title": f"セッションカード: {session.get('scenario_title', '未設定')}",
        "description": f"状態: **{session['status']}**",
        "color": 0x10B981,
        "fields": [
            {"name": "GM", "value": session.get("gm_name", "未設定"), "inline": True},
            {"name": "参加者", "value": ", ".join(participants) or "なし", "inline": True},
            {"name": "未入力者", "value": ", ".join(missing) or "なし"},
            {"name": "次のアクション", "value": next_action},
        ],
        "timestamp": datetime.utcnow().isoformat(),
    }


def availability_summary_embed(slots: list[dict], missing: list[str], deadline: str | None) -> dict:
    fields = []
    for slot in slots:
        fields.append(
            {
                "name": f"{slot['start']} - {slot['end']}",
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
