from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Iterable

from boto3.dynamodb.conditions import Attr, Key

from trpg_bot.db import get_key_attribute_names, get_table


DEFAULT_ACTIVITY_SESSION_TTL_DAYS = 365


def _pk_name() -> str:
    return get_key_attribute_names()[0]


def _sk_name() -> str:
    return get_key_attribute_names()[1]


def _key(pk_value: str, sk_value: str) -> dict[str, str]:
    pk_attr, sk_attr = get_key_attribute_names()
    return {pk_attr: pk_value, sk_attr: sk_value}


def _with_keys(item: dict, pk_value: str, sk_value: str) -> dict:
    item.update(_key(pk_value, sk_value))
    return item


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _expires_ts(days: int) -> int:
    return int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())


def _new_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def upsert_user(
    discord_id: str,
    display_name: str,
    timezone_name: str | None = None,
    avatar_url: str | None = None,
) -> None:
    table = get_table()
    item = {
        "entity": "user",
        "discord_id": discord_id,
        "display_name_cache": display_name,
        "timezone": timezone_name,
        "avatar_url": avatar_url,
        "updated_at": _now_iso(),
    }
    _with_keys(item, f"USER#{discord_id}", "PROFILE")
    table.put_item(Item=item)


def ensure_user(
    discord_id: str,
    display_name: str,
    timezone_name: str | None = None,
    avatar_url: str | None = None,
) -> None:
    profile = get_user_profile(discord_id)
    if not profile:
        upsert_user(discord_id, display_name, timezone_name, avatar_url=avatar_url)
        return

    needs_name_update = str(profile.get("display_name_cache") or "") != str(display_name)
    needs_tz_update = timezone_name is not None and profile.get("timezone") != timezone_name
    needs_avatar_update = avatar_url is not None and str(profile.get("avatar_url") or "") != str(avatar_url)
    if not needs_name_update and not needs_tz_update and not needs_avatar_update:
        return

    update_parts = ["updated_at=:u"]
    values: dict[str, Any] = {":u": _now_iso()}
    if needs_name_update:
        update_parts.append("display_name_cache=:n")
        values[":n"] = display_name
    if needs_tz_update:
        update_parts.append("timezone=:tz")
        values[":tz"] = timezone_name
    if needs_avatar_update:
        update_parts.append("avatar_url=:a")
        values[":a"] = avatar_url

    get_table().update_item(
        Key=_key(f"USER#{discord_id}", "PROFILE"),
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=values,
    )


def _activity_session_pk(session_token: str) -> str:
    return f"ACTIVITY_SESSION#{session_token}"


def create_activity_session(
    discord_id: str,
    display_name: str,
    avatar_url: str | None = None,
    ttl_days: int = DEFAULT_ACTIVITY_SESSION_TTL_DAYS,
) -> str:
    table = get_table()
    session_token = f"trpg_act_{uuid.uuid4().hex}"
    item = {
        "entity": "activity_session",
        "session_token": session_token,
        "discord_id": discord_id,
        "display_name_cache": display_name,
        "avatar_url": avatar_url,
        "created_at": _now_iso(),
        "last_seen_at": _now_iso(),
        "expires_ts": _expires_ts(ttl_days),
    }
    _with_keys(item, _activity_session_pk(session_token), "META")
    table.put_item(Item=item)
    return session_token


def get_activity_session(session_token: str) -> dict | None:
    table = get_table()
    resp = table.get_item(Key=_key(_activity_session_pk(session_token), "META"))
    item = resp.get("Item")
    if not item:
        return None
    expires_ts = item.get("expires_ts")
    if isinstance(expires_ts, (int, float)) and int(expires_ts) < _now_ts():
        return None
    return item


def touch_activity_session(session_token: str, ttl_days: int = DEFAULT_ACTIVITY_SESSION_TTL_DAYS) -> None:
    get_table().update_item(
        Key=_key(_activity_session_pk(session_token), "META"),
        UpdateExpression="SET last_seen_at=:s, expires_ts=:e",
        ExpressionAttributeValues={":s": _now_iso(), ":e": _expires_ts(ttl_days)},
    )


def _scenario_pk(scenario_id: str) -> str:
    return f"SCENARIO#{scenario_id}"


def create_scenario(
    title: str,
    system: str,
    estimated_time: str,
    tags: list[str],
    notes: str,
    created_by: str,
    setting: str = "",
    recommended_skills: list[str] | None = None,
    not_recommended_skills: list[str] | None = None,
    loss_level: str = "不明",
    loss_note: str | None = None,
    cover_url: str | None = None,
    players_min: int | None = None,
    players_max: int | None = None,
) -> str:
    table = get_table()
    scenario_id = _new_id("scn_")
    item = {
        "entity": "scenario",
        "scenario_id": scenario_id,
        "title": title,
        "title_lower": title.lower(),
        "system": system,
        "estimated_time": estimated_time,
        "tags": tags,
        "notes": notes,
        "setting": setting,
        "recommended_skills": recommended_skills or [],
        "not_recommended_skills": not_recommended_skills or [],
        "loss_level": loss_level,
        "loss_note": loss_note,
        "cover_url": cover_url,
        "players_min": players_min,
        "players_max": players_max,
        "created_by": created_by,
        "created_at": _now_iso(),
    }
    _with_keys(item, _scenario_pk(scenario_id), "META")
    table.put_item(Item=item)
    return scenario_id


def update_scenario(
    scenario_id: str,
    title: str,
    system: str,
    estimated_time: str,
    tags: list[str],
    notes: str,
    setting: str = "",
    recommended_skills: list[str] | None = None,
    not_recommended_skills: list[str] | None = None,
    loss_level: str = "不明",
    loss_note: str | None = None,
    cover_url: str | None = None,
    players_min: int | None = None,
    players_max: int | None = None,
) -> None:
    table = get_table()
    table.update_item(
        Key=_key(_scenario_pk(scenario_id), "META"),
        UpdateExpression="SET title=:t, title_lower=:tl, system=:s, estimated_time=:e, tags=:tags, notes=:n, setting=:setting, recommended_skills=:rs, not_recommended_skills=:nrs, loss_level=:ll, loss_note=:ln, cover_url=:cu, players_min=:pmin, players_max=:pmax",
        ExpressionAttributeValues={
            ":t": title,
            ":tl": title.lower(),
            ":s": system,
            ":e": estimated_time,
            ":tags": tags,
            ":n": notes,
            ":setting": setting,
            ":rs": recommended_skills or [],
            ":nrs": not_recommended_skills or [],
            ":ll": loss_level,
            ":ln": loss_note,
            ":cu": cover_url,
            ":pmin": players_min,
            ":pmax": players_max,
        },
    )


def get_scenario(scenario_id: str) -> dict | None:
    table = get_table()
    resp = table.get_item(Key=_key(_scenario_pk(scenario_id), "META"))
    return resp.get("Item")


def _scan_filtered(filter_expression: Any, max_results: int, page_size: int = 200, max_pages: int = 10) -> list[dict]:
    table = get_table()
    results: list[dict] = []
    start_key = None
    pages = 0
    while len(results) < max_results and pages < max_pages:
        kwargs: dict[str, Any] = {"FilterExpression": filter_expression, "Limit": page_size}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.scan(**kwargs)
        results.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        pages += 1
        if not start_key:
            break
    return results


def list_scenarios(limit: int = 50) -> list[dict]:
    max_results = max(1, min(int(limit), 200))
    items = _scan_filtered(Attr("entity").eq("scenario"), max_results=max_results)
    items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return items[:max_results]


def search_scenarios(keyword: str, limit: int = 5) -> list[dict]:
    max_results = max(1, min(int(limit), 50))
    kw = keyword.lower()
    items = _scan_filtered(
        Attr("entity").eq("scenario") & Attr("title_lower").contains(kw),
        max_results=max_results,
        page_size=200,
    )
    items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return items[:max_results]


def add_capability(scenario_id: str, gm_user_id: str, gm_display_name: str, confidence: str) -> None:
    table = get_table()
    item = {
        "entity": "scenario_capability",
        "scenario_id": scenario_id,
        "gm_user_id": gm_user_id,
        "gm_display_name": gm_display_name,
        "confidence": confidence,
        "updated_at": _now_iso(),
    }
    _with_keys(item, _scenario_pk(scenario_id), f"GM#{gm_user_id}")
    table.put_item(Item=item)


def remove_capability(scenario_id: str, gm_user_id: str) -> None:
    get_table().delete_item(Key=_key(_scenario_pk(scenario_id), f"GM#{gm_user_id}"))


def list_capable_gms(scenario_id: str) -> list[str]:
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(_scenario_pk(scenario_id)) & Key(_sk_name()).begins_with("GM#"),
    )
    return [item.get("gm_display_name") or item.get("gm_user_id") for item in resp.get("Items", [])]


def list_play_history(scenario_id: str) -> list[str]:
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(_scenario_pk(scenario_id)) & Key(_sk_name()).begins_with("PLAY#"),
        ScanIndexForward=False,
        Limit=20,
    )
    return [item.get("user_display_name") or item.get("user_id") for item in resp.get("Items", [])]


def _session_pk(session_id: str) -> str:
    return f"SESSION#{session_id}"


def _session_status_pk(status: str) -> str:
    return f"SESSION_STATUS#{status}"


def _session_status_sk(created_at: str, session_id: str) -> str:
    return f"CREATED#{created_at}#{session_id}"


def _session_index_item(session: dict, status: str) -> dict:
    created_at = str(session.get("created_at") or _now_iso())
    session_id = str(session.get("session_id") or "")
    item = {
        "entity": "session_status_index",
        "status": status,
        "session_id": session_id,
        "scenario_id": session.get("scenario_id"),
        "gm_user_id": session.get("gm_user_id"),
        "title": session.get("title"),
        "guild_id": session.get("guild_id"),
        "channel_id": session.get("channel_id"),
        "thread_id": session.get("thread_id"),
        "min_players": session.get("min_players"),
        "max_players": session.get("max_players"),
        "session_type": session.get("session_type"),
        "duration": session.get("duration"),
        "teaser_slots": session.get("teaser_slots"),
        "created_at": created_at,
        "created_by": session.get("created_by"),
    }
    _with_keys(item, _session_status_pk(status), _session_status_sk(created_at, session_id))
    return item


def _upsert_session_status_index(session: dict, status: str) -> None:
    if not status:
        return
    session_id = str(session.get("session_id") or "")
    if not session_id:
        return
    get_table().put_item(Item=_session_index_item(session, status))


def _delete_session_status_index(session_id: str, status: str, created_at: str) -> None:
    if not session_id or not status or not created_at:
        return
    get_table().delete_item(Key=_key(_session_status_pk(status), _session_status_sk(created_at, session_id)))


def create_session(
    scenario_id: str | None,
    gm_user_id: str | None,
    title: str | None,
    status: str,
    guild_id: str,
    channel_id: str,
    thread_id: str | None,
    min_players: int,
    max_players: int,
    created_by: str,
    session_type: str | None = None,
    duration: str | None = None,
    teaser_slots: list[dict[str, Any]] | None = None,
) -> str:
    table = get_table()
    session_id = _new_id("ses_")
    created_at = _now_iso()
    item = {
        "entity": "session",
        "session_id": session_id,
        "scenario_id": scenario_id,
        "gm_user_id": gm_user_id,
        "title": title,
        "status": status,
        "guild_id": guild_id,
        "channel_id": channel_id,
        "thread_id": thread_id,
        "card_message_id": None,
        "min_players": min_players,
        "max_players": max_players,
        "session_type": session_type,
        "duration": duration,
        "teaser_slots": teaser_slots,
        "scheduled_start": None,
        "scheduled_end": None,
        "created_by": created_by,
        "created_at": created_at,
    }
    _with_keys(item, _session_pk(session_id), "META")
    table.put_item(Item=item)
    _upsert_session_status_index(item, status)
    return session_id


def get_session(session_id: str) -> dict | None:
    table = get_table()
    resp = table.get_item(Key=_key(_session_pk(session_id), "META"))
    return resp.get("Item")


def get_user_profile(discord_id: str) -> dict | None:
    table = get_table()
    resp = table.get_item(Key=_key(f"USER#{discord_id}", "PROFILE"))
    return resp.get("Item")


def get_session_with_details(session_id: str) -> dict | None:
    session = get_session(session_id)
    if not session:
        return None
    scenario_title = None
    gm_name = None
    if session.get("scenario_id"):
        scenario = get_scenario(session["scenario_id"])
        scenario_title = scenario.get("title") if scenario else None
    if session.get("gm_user_id"):
        gm = get_user_profile(session["gm_user_id"])
        gm_name = gm.get("display_name_cache") if gm else session.get("gm_user_id")
    session["scenario_title"] = scenario_title
    session["gm_name"] = gm_name
    return session


def update_session_card_message(session_id: str, message_id: str) -> None:
    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression="SET card_message_id=:m",
        ExpressionAttributeValues={":m": message_id},
    )


def update_session_thread(session_id: str, thread_id: str) -> None:
    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression="SET thread_id=:t",
        ExpressionAttributeValues={":t": thread_id},
    )


def list_sessions_by_status(status: str, limit: int = 30) -> list[dict]:
    table = get_table()

    try:
        resp = table.query(
            KeyConditionExpression=Key(_pk_name()).eq(_session_status_pk(status))
            & Key(_sk_name()).begins_with("CREATED#"),
            ScanIndexForward=False,
            Limit=limit,
        )
        items = resp.get("Items", [])
        if items:
            return items
    except Exception:
        # Fall back to scan below (for older sessions created before index existed).
        pass

    scanned: list[dict] = []
    start_key = None
    while True:
        kwargs: dict[str, Any] = {
            "FilterExpression": Attr("entity").eq("session") & Attr("status").eq(status),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.scan(**kwargs)
        scanned.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break

    scanned.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
    return scanned[:limit]


def list_participants(session_id: str) -> list[str]:
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(_session_pk(session_id)) & Key(_sk_name()).begins_with("PART#"),
    )
    return [item.get("display_name") or item.get("user_id") for item in resp.get("Items", [])]


def list_participant_records(session_id: str) -> list[dict]:
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(_session_pk(session_id)) & Key(_sk_name()).begins_with("PART#"),
    )
    return [{"user_id": item["user_id"], "display_name": item.get("display_name") or item["user_id"]} for item in resp.get("Items", [])]


def add_participant(session_id: str, user_id: str, display_name: str, role: str) -> None:
    item = {
        "entity": "session_participant",
        "session_id": session_id,
        "user_id": user_id,
        "display_name": display_name,
        "role": role,
        "joined_at": _now_iso(),
    }
    _with_keys(item, _session_pk(session_id), f"PART#{user_id}")
    get_table().put_item(Item=item)


def remove_participant(session_id: str, user_id: str) -> None:
    get_table().delete_item(Key=_key(_session_pk(session_id), f"PART#{user_id}"))


def create_poll(session_id: str, deadline: datetime | None, timezone_basis: str) -> str:
    table = get_table()
    poll_id = _new_id("poll_")
    created_at = _now_iso()
    poll_ref_item = {
        "entity": "poll_ref",
        "poll_id": poll_id,
        "session_id": session_id,
        "deadline": deadline.isoformat() if deadline else None,
        "timezone_basis": timezone_basis,
        "created_at": created_at,
    }
    _with_keys(poll_ref_item, _session_pk(session_id), f"POLL#{created_at}#{poll_id}")
    table.put_item(Item=poll_ref_item)

    poll_meta_item = {
        "entity": "poll",
        "poll_id": poll_id,
        "session_id": session_id,
        "deadline": deadline.isoformat() if deadline else None,
        "timezone_basis": timezone_basis,
        "created_at": created_at,
    }
    _with_keys(poll_meta_item, f"POLL#{poll_id}", "META")
    table.put_item(Item=poll_meta_item)
    return poll_id


def latest_poll_for_session(session_id: str) -> dict | None:
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(_session_pk(session_id)) & Key(_sk_name()).begins_with("POLL#"),
        ScanIndexForward=False,
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def poll_by_id(poll_id: str) -> dict | None:
    table = get_table()
    resp = table.get_item(Key=_key(f"POLL#{poll_id}", "META"))
    return resp.get("Item")


def poll_session_info(poll_id: str) -> dict | None:
    poll = poll_by_id(poll_id)
    if not poll:
        return None
    session = get_session(poll["session_id"])
    thread_id = session.get("thread_id") if session else None
    return {"poll_id": poll_id, "session_id": poll["session_id"], "thread_id": thread_id}


def add_slot(poll_id: str, start: datetime, end: datetime) -> str:
    table = get_table()
    slot_id = _new_id("slot_")
    slot_item = {
        "entity": "slot",
        "poll_id": poll_id,
        "slot_id": slot_id,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
    }
    _with_keys(slot_item, f"POLL#{poll_id}", f"SLOT#{slot_id}")
    table.put_item(Item=slot_item)

    slot_ref_item = {"entity": "slot_ref", "slot_id": slot_id, "poll_id": poll_id}
    _with_keys(slot_ref_item, f"SLOT#{slot_id}", "META")
    table.put_item(Item=slot_ref_item)
    return slot_id


def poll_id_for_slot(slot_id: str) -> str | None:
    table = get_table()
    resp = table.get_item(Key=_key(f"SLOT#{slot_id}", "META"))
    item = resp.get("Item")
    return item.get("poll_id") if item else None


def slot_detail(slot_id: str) -> dict | None:
    poll_id = poll_id_for_slot(slot_id)
    if not poll_id:
        return None
    table = get_table()
    resp = table.get_item(Key=_key(f"POLL#{poll_id}", f"SLOT#{slot_id}"))
    item = resp.get("Item")
    if not item:
        return None
    return {
        "slot_id": slot_id,
        "poll_id": poll_id,
        "start": datetime.fromisoformat(item["start_time"]),
        "end": datetime.fromisoformat(item["end_time"]),
    }


def upsert_response(slot_id: str, user_id: str, status: str, comment: str) -> None:
    poll_id = poll_id_for_slot(slot_id)
    if not poll_id:
        raise ValueError("poll not found for slot")
    item = {
        "entity": "response",
        "poll_id": poll_id,
        "slot_id": slot_id,
        "user_id": user_id,
        "status": status,
        "comment": comment,
        "updated_at": _now_iso(),
    }
    _with_keys(item, f"POLL#{poll_id}", f"RESP#{slot_id}#{user_id}")
    get_table().put_item(Item=item)


def list_availability_summary(poll_id: str) -> list[dict]:
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(f"POLL#{poll_id}"),
    )
    slots: dict[str, dict[str, Any]] = {}
    for item in resp.get("Items", []):
        sk: str = item[_sk_name()]
        if sk.startswith("SLOT#"):
            slots[item["slot_id"]] = {
                "slot_id": item["slot_id"],
                "start": item["start_time"],
                "end": item["end_time"],
                "ok": 0,
                "maybe": 0,
                "no": 0,
            }
    for item in resp.get("Items", []):
        sk: str = item[_sk_name()]
        if sk.startswith("RESP#"):
            slot_id = item["slot_id"]
            status = item["status"]
            if slot_id not in slots:
                continue
            if status == "OK":
                slots[slot_id]["ok"] += 1
            elif status == "MAYBE":
                slots[slot_id]["maybe"] += 1
            elif status == "NO":
                slots[slot_id]["no"] += 1
    return sorted(slots.values(), key=lambda x: x["start"])


def get_poll_deadline(poll_id: str) -> datetime | None:
    poll = poll_by_id(poll_id)
    if not poll:
        return None
    if not poll.get("deadline"):
        return None
    return datetime.fromisoformat(poll["deadline"])


def mark_session_status(session_id: str, status: str) -> None:
    session = get_session(session_id)
    prev_status = str(session.get("status") or "") if session else ""
    created_at = str(session.get("created_at") or "") if session else ""

    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression="SET #status=:s",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":s": status},
    )

    if session:
        session["status"] = status
        try:
            _upsert_session_status_index(session, status)
        except Exception:
            pass
        try:
            if prev_status and created_at and prev_status != status:
                _delete_session_status_index(session_id, prev_status, created_at)
        except Exception:
            pass


def add_play_history(scenario_id: str, user_id: str, user_display_name: str, role: str, session_id: str, notes: str) -> None:
    now = _now_iso()
    item = {
        "entity": "play_history",
        "scenario_id": scenario_id,
        "user_id": user_id,
        "user_display_name": user_display_name,
        "role": role,
        "session_id": session_id,
        "date": now,
        "notes": notes,
    }
    _with_keys(item, _scenario_pk(scenario_id), f"PLAY#{now}#{user_id}")
    get_table().put_item(Item=item)


def log_audit(session_id: str, action: str, actor_id: str, detail: dict | None = None) -> None:
    now = _now_iso()
    item = {
        "entity": "audit",
        "session_id": session_id,
        "action": action,
        "actor_id": actor_id,
        "detail": detail or {},
        "created_at": now,
    }
    _with_keys(item, _session_pk(session_id), f"AUDIT#{now}#{action}")
    get_table().put_item(Item=item)


def latest_poll_for_slot(slot_id: str) -> dict | None:
    poll_id = poll_id_for_slot(slot_id)
    if not poll_id:
        return None
    return poll_by_id(poll_id)


def list_poll_missing_responses(poll_id: str, include_user_ids: Iterable[str] | None = None) -> list[dict]:
    table = get_table()
    poll = poll_by_id(poll_id)
    if not poll:
        return []
    session_id = poll["session_id"]
    responded_resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(f"POLL#{poll_id}") & Key(_sk_name()).begins_with("RESP#"),
        ProjectionExpression="user_id",
    )
    responded = {item["user_id"] for item in responded_resp.get("Items", [])}
    participant_records = list_participant_records(session_id)
    participant_map = {p["user_id"]: p for p in participant_records}

    if include_user_ids:
        for uid in include_user_ids:
            if uid not in participant_map:
                prof = get_user_profile(uid)
                name = prof.get("display_name_cache") if prof else uid
                participant_map[uid] = {"user_id": uid, "display_name": name}

    missing = []
    for uid, record in participant_map.items():
        if uid not in responded:
            missing.append({"user_id": uid, "display_name": record["display_name"]})
    return missing


def set_session_schedule_from_slot(session_id: str, slot_id: str) -> None:
    detail = slot_detail(slot_id)
    if not detail:
        return
    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression="SET scheduled_start=:s, scheduled_end=:e",
        ExpressionAttributeValues={
            ":s": detail["start"].isoformat(),
            ":e": detail["end"].isoformat(),
        },
    )
