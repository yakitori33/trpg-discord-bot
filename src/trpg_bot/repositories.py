from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Iterable

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

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


def _normalize_handouts(raw_handouts: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_handouts, list):
        return []
    normalized: list[dict[str, Any]] = []
    for raw in raw_handouts[:20]:
        if not isinstance(raw, dict):
            continue
        handout_id = str(raw.get("id") or raw.get("handout_id") or raw.get("handoutId") or "").strip()
        name = str(raw.get("name") or "").strip()
        if not handout_id or not name:
            continue
        public_info = str(raw.get("public_info") or raw.get("publicInfo") or "").strip()
        private_val = raw.get("private_info") if "private_info" in raw else raw.get("privateInfo")
        private_info = str(private_val).strip() if private_val is not None else ""
        order_raw = raw.get("order")
        order: int | None = None
        if order_raw is not None:
            try:
                order = int(order_raw)
            except Exception:
                order = None

        item: dict[str, Any] = {"id": handout_id, "name": name, "public_info": public_info, "private_info": private_info}
        if order is not None:
            item["order"] = order
        normalized.append(item)
    return normalized


def upsert_user(
    discord_id: str,
    display_name: str,
    timezone_name: str | None = None,
    avatar_url: str | None = None,
    handle: str | None = None,
) -> None:
    table = get_table()
    item = {
        "entity": "user",
        "discord_id": discord_id,
        "display_name_cache": display_name,
        "timezone": timezone_name,
        "avatar_url": avatar_url,
        "handle": handle,
        "updated_at": _now_iso(),
    }
    _with_keys(item, f"USER#{discord_id}", "PROFILE")
    table.put_item(Item=item)


def ensure_user(
    discord_id: str,
    display_name: str,
    timezone_name: str | None = None,
    avatar_url: str | None = None,
    handle: str | None = None,
) -> None:
    profile = get_user_profile(discord_id)
    if not profile:
        upsert_user(discord_id, display_name, timezone_name, avatar_url=avatar_url, handle=handle)
        return

    needs_name_update = str(profile.get("display_name_cache") or "") != str(display_name)
    needs_tz_update = timezone_name is not None and profile.get("timezone") != timezone_name
    needs_avatar_update = avatar_url is not None and str(profile.get("avatar_url") or "") != str(avatar_url)
    needs_handle_update = handle is not None and str(profile.get("handle") or "") != str(handle)
    if not needs_name_update and not needs_tz_update and not needs_avatar_update and not needs_handle_update:
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
    if needs_handle_update:
        update_parts.append("handle=:h")
        values[":h"] = handle

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
    handle: str | None = None,
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
        "handle": handle,
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

def update_activity_session_profile(
    session_token: str,
    display_name: str | None = None,
    avatar_url: str | None = None,
    handle: str | None = None,
    ttl_days: int = DEFAULT_ACTIVITY_SESSION_TTL_DAYS,
) -> None:
    update_parts = ["last_seen_at=:s", "expires_ts=:e"]
    values: dict[str, Any] = {":s": _now_iso(), ":e": _expires_ts(ttl_days)}

    if display_name is not None:
        update_parts.append("display_name_cache=:n")
        values[":n"] = display_name
    if avatar_url is not None:
        update_parts.append("avatar_url=:a")
        values[":a"] = avatar_url
    if handle is not None:
        update_parts.append("handle=:h")
        values[":h"] = handle

    get_table().update_item(
        Key=_key(_activity_session_pk(session_token), "META"),
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=values,
    )


def _scenario_pk(scenario_id: str) -> str:
    return f"SCENARIO#{scenario_id}"


SCENARIO_GSI1_NAME = "GSI1"
SCENARIO_GSI2_NAME = "GSI2"
SCENARIO_GSI_PK = "SCENARIO"
SCENARIO_TOKEN_GSI_PREFIX = "SCENARIO_TOKEN#"

_SEARCH_WORD_RE = re.compile(r"[0-9a-z]+")
_SEARCH_CJK_RE = re.compile(r"[\u3040-\u30ff\u4e00-\u9fff]+")
_SEARCH_CONDENSE_RE = re.compile(r"[^0-9a-z\u3040-\u30ff\u4e00-\u9fff]+")


def _scenario_created_gsi_keys(created_at: str, scenario_id: str) -> dict[str, str]:
    return {
        "GSI1PK": SCENARIO_GSI_PK,
        "GSI1SK": f"CREATED#{created_at}#{scenario_id}",
    }


def _scenario_title_gsi_keys(title_lower: str, scenario_id: str) -> dict[str, str]:
    return {
        "GSI2PK": SCENARIO_GSI_PK,
        "GSI2SK": f"TITLE#{title_lower}#{scenario_id}",
    }


def _scenario_search_sk(token: str) -> str:
    return f"SEARCH#{token}"


def _scenario_token_gsi_pk(token: str) -> str:
    return f"{SCENARIO_TOKEN_GSI_PREFIX}{token}"


def _scenario_token_gsi_sk(created_at: str, scenario_id: str) -> str:
    return f"CREATED#{created_at}#{scenario_id}"


def _tokenize_search_text(text: str, max_tokens: int = 120) -> list[str]:
    raw = str(text or "").lower().strip()
    if not raw:
        return []
    tokens: set[str] = set()
    for word in _SEARCH_WORD_RE.findall(raw):
        if len(word) >= 2:
            tokens.add(word)
    for word in _SEARCH_CJK_RE.findall(raw):
        if len(word) >= 2:
            tokens.add(word)
    condensed = _SEARCH_CONDENSE_RE.sub("", raw)
    if len(condensed) >= 2:
        for i in range(len(condensed) - 1):
            tokens.add(condensed[i : i + 2])
    ordered = sorted(tokens, key=lambda t: (-len(t), t))
    if max_tokens > 0:
        return ordered[:max_tokens]
    return ordered


def _upsert_scenario_search_index(
    scenario_id: str,
    title: str,
    title_lower: str,
    created_at: str,
    tokens: list[str],
) -> None:
    if not tokens:
        return
    table = get_table()
    with table.batch_writer() as batch:
        for token in tokens:
            item = {
                "entity": "scenario_search",
                "scenario_id": scenario_id,
                "token": token,
                "title": title,
                "title_lower": title_lower,
                "created_at": created_at,
                "GSI2PK": _scenario_token_gsi_pk(token),
                "GSI2SK": _scenario_token_gsi_sk(created_at, scenario_id),
            }
            _with_keys(item, _scenario_pk(scenario_id), _scenario_search_sk(token))
            batch.put_item(Item=item)


def _delete_scenario_search_index(scenario_id: str, tokens: set[str]) -> None:
    if not tokens:
        return
    table = get_table()
    with table.batch_writer() as batch:
        for token in tokens:
            batch.delete_item(Key=_key(_scenario_pk(scenario_id), _scenario_search_sk(token)))


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
    cover_full_url: str | None = None,
    players_min: int | None = None,
    players_max: int | None = None,
    completion_achievements: list[dict[str, Any]] | None = None,
    is_handout_scenario: bool = False,
    handouts: list[dict[str, Any]] | None = None,
) -> str:
    table = get_table()
    scenario_id = _new_id("scn_")
    created_at = _now_iso()
    normalized_achievements: list[dict[str, Any]] = []
    for raw in completion_achievements or []:
        if not isinstance(raw, dict):
            continue
        title_raw = str(raw.get("title") or "").strip()
        if not title_raw:
            continue
        ach_id = str(raw.get("id") or raw.get("achievement_id") or "").strip()
        if not ach_id:
            ach_id = f"scn_{scenario_id}_end_{uuid.uuid4().hex[:8]}"
        item: dict[str, Any] = {
            "id": ach_id,
            "title": title_raw,
            "description": str(raw.get("description") or "").strip(),
            "is_spoiler": bool(raw.get("is_spoiler")),
        }
        normalized_achievements.append(item)

    normalized_handouts: list[dict[str, Any]] = []
    if is_handout_scenario and handouts:
        normalized_handouts = _normalize_handouts(handouts)

    title_lower = title.lower()
    search_tokens = _tokenize_search_text(title_lower)
    item = {
        "entity": "scenario",
        "scenario_id": scenario_id,
        "title": title,
        "title_lower": title_lower,
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
        "cover_full_url": cover_full_url,
        "players_min": players_min,
        "players_max": players_max,
        "completion_achievements": normalized_achievements,
        "is_handout_scenario": bool(is_handout_scenario),
        "handouts": normalized_handouts,
        "created_by": created_by,
        "created_at": created_at,
        "search_tokens": search_tokens,
    }
    item.update(_scenario_created_gsi_keys(created_at, scenario_id))
    item.update(_scenario_title_gsi_keys(title_lower, scenario_id))
    _with_keys(item, _scenario_pk(scenario_id), "META")
    table.put_item(Item=item)
    _upsert_scenario_search_index(scenario_id, title, title_lower, created_at, search_tokens)
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
    cover_full_url: str | None = None,
    players_min: int | None = None,
    players_max: int | None = None,
    completion_achievements: list[dict[str, Any]] | None = None,
    is_handout_scenario: bool | None = None,
    handouts: list[dict[str, Any]] | None = None,
) -> None:
    current = get_scenario(scenario_id) or {}
    created_at = str(current.get("created_at") or _now_iso())
    old_tokens: list[str] = []
    if isinstance(current.get("search_tokens"), list):
        old_tokens = [str(t) for t in current.get("search_tokens") if isinstance(t, str)]

    title_lower = title.lower()
    search_tokens = _tokenize_search_text(title_lower)

    update_parts = [
        "#title=:t",
        "#title_lower=:tl",
        "#GSI2PK=:g2pk",
        "#GSI2SK=:g2sk",
        "#search_tokens=:st",
        "#system=:s",
        "#estimated_time=:e",
        "#tags=:tags",
        "#notes=:n",
        "#setting=:setting",
        "#recommended_skills=:rs",
        "#not_recommended_skills=:nrs",
        "#loss_level=:ll",
        "#loss_note=:ln",
        "#cover_url=:cu",
        "#cover_full_url=:cfu",
        "#players_min=:pmin",
        "#players_max=:pmax",
    ]
    names: dict[str, str] = {
        "#title": "title",
        "#title_lower": "title_lower",
        "#GSI2PK": "GSI2PK",
        "#GSI2SK": "GSI2SK",
        "#search_tokens": "search_tokens",
        "#system": "system",
        "#estimated_time": "estimated_time",
        "#tags": "tags",
        "#notes": "notes",
        "#setting": "setting",
        "#recommended_skills": "recommended_skills",
        "#not_recommended_skills": "not_recommended_skills",
        "#loss_level": "loss_level",
        "#loss_note": "loss_note",
        "#cover_url": "cover_url",
        "#cover_full_url": "cover_full_url",
        "#players_min": "players_min",
        "#players_max": "players_max",
    }
    values: dict[str, Any] = {
        ":t": title,
        ":tl": title_lower,
        ":g2pk": SCENARIO_GSI_PK,
        ":g2sk": _scenario_title_gsi_keys(title_lower, scenario_id)["GSI2SK"],
        ":st": search_tokens,
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
        ":cfu": cover_full_url,
        ":pmin": players_min,
        ":pmax": players_max,
    }
    if completion_achievements is not None:
        update_parts.append("#completion_achievements=:ca")
        names["#completion_achievements"] = "completion_achievements"
        values[":ca"] = completion_achievements or []
    if is_handout_scenario is not None:
        update_parts.append("#is_handout_scenario=:ih")
        names["#is_handout_scenario"] = "is_handout_scenario"
        values[":ih"] = bool(is_handout_scenario)
    if handouts is not None:
        update_parts.append("#handouts=:hos")
        names["#handouts"] = "handouts"
        values[":hos"] = _normalize_handouts(handouts)

    get_table().update_item(
        Key=_key(_scenario_pk(scenario_id), "META"),
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )

    old_set = set(old_tokens)
    new_set = set(search_tokens)
    removed = old_set - new_set
    if removed:
        _delete_scenario_search_index(scenario_id, removed)
    if new_set:
        _upsert_scenario_search_index(scenario_id, title, title_lower, created_at, search_tokens)


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


def _batch_get_scenarios_by_ids(scenario_ids: list[str]) -> list[dict]:
    if not scenario_ids:
        return []
    table = get_table()
    client = table.meta.client
    pk_attr, sk_attr = get_key_attribute_names()
    items: list[dict] = []
    for i in range(0, len(scenario_ids), 100):
        chunk = scenario_ids[i : i + 100]
        keys = [{pk_attr: _scenario_pk(sid), sk_attr: "META"} for sid in chunk]
        req = {table.name: {"Keys": keys}}
        while True:
            resp = client.batch_get_item(RequestItems=req)
            items.extend(resp.get("Responses", {}).get(table.name, []))
            unprocessed = resp.get("UnprocessedKeys", {}).get(table.name, {}).get("Keys", [])
            if not unprocessed:
                break
            req = {table.name: {"Keys": unprocessed}}
    return items


def batch_get_scenarios(scenario_ids: list[str]) -> dict[str, dict]:
    items = _batch_get_scenarios_by_ids(scenario_ids)
    out: dict[str, dict] = {}
    for item in items:
        scenario_id = str(item.get("scenario_id") or "").strip()
        if scenario_id:
            out[scenario_id] = item
    return out


def list_scenarios(limit: int = 50) -> list[dict]:
    max_results = max(1, min(int(limit), 200))
    try:
        resp = get_table().query(
            IndexName=SCENARIO_GSI1_NAME,
            KeyConditionExpression=Key("GSI1PK").eq(SCENARIO_GSI_PK)
            & Key("GSI1SK").begins_with("CREATED#"),
            ScanIndexForward=False,
            Limit=max_results,
        )
        return resp.get("Items", [])[:max_results]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code == "ValidationException":
            raise RuntimeError("GSI1 is required for list_scenarios. Create GSI1 (GSI1PK/GSI1SK).") from exc
        raise


def list_scenarios_page(limit: int = 50, cursor: dict | None = None) -> tuple[list[dict], dict | None]:
    max_results = max(1, min(int(limit), 200))
    try:
        kwargs: dict[str, Any] = {
            "IndexName": SCENARIO_GSI1_NAME,
            "KeyConditionExpression": Key("GSI1PK").eq(SCENARIO_GSI_PK)
            & Key("GSI1SK").begins_with("CREATED#"),
            "ScanIndexForward": False,
            "Limit": max_results,
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor
        resp = get_table().query(**kwargs)
        return resp.get("Items", [])[:max_results], resp.get("LastEvaluatedKey")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code == "ValidationException":
            raise RuntimeError("GSI1 is required for list_scenarios. Create GSI1 (GSI1PK/GSI1SK).") from exc
        raise


def search_scenarios(keyword: str, limit: int = 5) -> list[dict]:
    max_results = max(1, min(int(limit), 50))
    kw = keyword.strip().lower()
    if not kw:
        return []
    try:
        tokens = _tokenize_search_text(kw)
        if not tokens:
            return []
        condensed = _SEARCH_CONDENSE_RE.sub("", kw)
        primary = condensed[:2] if len(condensed) >= 2 else max(tokens, key=len)
        table = get_table()
        matched: list[dict] = []
        start_key = None
        page_size = max(max_results * 4, 40)
        while len(matched) < max_results:
            kwargs: dict[str, Any] = {
                "IndexName": SCENARIO_GSI2_NAME,
                "KeyConditionExpression": Key("GSI2PK").eq(_scenario_token_gsi_pk(primary))
                & Key("GSI2SK").begins_with("CREATED#"),
                "ScanIndexForward": False,
                "Limit": page_size,
            }
            if start_key:
                kwargs["ExclusiveStartKey"] = start_key
            resp = table.query(**kwargs)
            items = resp.get("Items", [])
            for item in items:
                title_lower = str(item.get("title_lower") or "").lower()
                if kw in title_lower:
                    matched.append(item)
                    if len(matched) >= max_results:
                        break
            start_key = resp.get("LastEvaluatedKey")
            if not start_key:
                break

        scenario_ids = [item.get("scenario_id") for item in matched if item.get("scenario_id")]
        scenarios = _batch_get_scenarios_by_ids(scenario_ids)
        scenario_map = {item.get("scenario_id"): item for item in scenarios}
        return [scenario_map[sid] for sid in scenario_ids if sid in scenario_map][:max_results]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code == "ValidationException":
            raise RuntimeError("GSI2 is required for search_scenarios. Create GSI2 (GSI2PK/GSI2SK).") from exc
        raise


def _scenario_stats_sk() -> str:
    return "STATS"


def increment_scenario_stats(scenario_id: str, increments: dict[str, int] | None = None) -> None:
    scenario_id = str(scenario_id or "").strip()
    if not scenario_id:
        return
    inc = increments or {}
    update_parts: list[str] = []
    values: dict[str, Any] = {":u": _now_iso()}
    names: dict[str, str] = {}

    set_parts = ["updated_at=:u"]
    if set_parts:
        update_parts.append("SET " + ", ".join(set_parts))

    add_parts: list[str] = []
    for k, v in inc.items():
        try:
            delta = int(v)
        except Exception:
            continue
        if delta == 0:
            continue
        placeholder = f":inc_{k}"
        name = f"#{k}"
        values[placeholder] = delta
        names[name] = k
        add_parts.append(f"{name} {placeholder}")
    if add_parts:
        update_parts.append("ADD " + ", ".join(add_parts))

    get_table().update_item(
        Key=_key(_scenario_pk(scenario_id), _scenario_stats_sk()),
        UpdateExpression=" ".join(update_parts),
        ExpressionAttributeValues=values,
        ExpressionAttributeNames=names or None,
    )


def _user_scenario_pref_sk(scenario_id: str) -> str:
    return f"SCENARIO_PREF#{scenario_id}"


def _user_scenario_metric_sk(scenario_id: str) -> str:
    return f"SCENARIO_METRIC#{scenario_id}"


def get_user_scenario_preference(user_id: str, scenario_id: str) -> dict | None:
    user_id = str(user_id or "").strip()
    scenario_id = str(scenario_id or "").strip()
    if not user_id or not scenario_id:
        return None
    resp = get_table().get_item(Key=_key(f"USER#{user_id}", _user_scenario_pref_sk(scenario_id)))
    return resp.get("Item")


def batch_get_user_scenario_preferences(user_id: str, scenario_ids: list[str]) -> dict[str, dict]:
    user_id = str(user_id or "").strip()
    if not user_id or not scenario_ids:
        return {}
    table = get_table()
    client = table.meta.client
    pk_attr, sk_attr = get_key_attribute_names()

    out: dict[str, dict] = {}
    unique_ids: list[str] = []
    seen: set[str] = set()
    for sid in scenario_ids:
        sid_str = str(sid or "").strip()
        if not sid_str or sid_str in seen:
            continue
        seen.add(sid_str)
        unique_ids.append(sid_str)

    for i in range(0, len(unique_ids), 100):
        chunk = unique_ids[i : i + 100]
        keys = [{pk_attr: f"USER#{user_id}", sk_attr: _user_scenario_pref_sk(sid)} for sid in chunk]
        req = {table.name: {"Keys": keys}}
        while True:
            resp = client.batch_get_item(RequestItems=req)
            items = resp.get("Responses", {}).get(table.name, [])
            for item in items:
                scenario_id = str(item.get("scenario_id") or "").strip()
                if scenario_id:
                    out[scenario_id] = item
            unprocessed = resp.get("UnprocessedKeys", {}).get(table.name, {}).get("Keys", [])
            if not unprocessed:
                break
            req = {table.name: {"Keys": unprocessed}}
    return out


def set_user_scenario_preference(
    user_id: str,
    scenario_id: str,
    *,
    is_bookmarked: bool | None = None,
    is_favorited: bool | None = None,
) -> dict[str, bool]:
    user_id = str(user_id or "").strip()
    scenario_id = str(scenario_id or "").strip()
    if not user_id or not scenario_id:
        raise ValueError("Missing user_id/scenario_id")

    existing = get_user_scenario_preference(user_id, scenario_id) or {}
    old_bookmarked = bool(existing.get("is_bookmarked"))
    old_favorited = bool(existing.get("is_favorited"))

    new_bookmarked = old_bookmarked if is_bookmarked is None else bool(is_bookmarked)
    new_favorited = old_favorited if is_favorited is None else bool(is_favorited)

    delta_bookmark = (1 if new_bookmarked else 0) - (1 if old_bookmarked else 0)
    delta_favorite = (1 if new_favorited else 0) - (1 if old_favorited else 0)

    if not new_bookmarked and not new_favorited:
        if existing:
            get_table().delete_item(Key=_key(f"USER#{user_id}", _user_scenario_pref_sk(scenario_id)))
        if delta_bookmark or delta_favorite:
            inc: dict[str, int] = {}
            if delta_bookmark:
                inc["bookmark_count"] = delta_bookmark
            if delta_favorite:
                inc["favorite_count"] = delta_favorite
            increment_scenario_stats(scenario_id, inc)
        return {"isBookmarked": False, "isFavorited": False}

    now = _now_iso()
    created_at = str(existing.get("created_at") or now)
    item = {
        "entity": "scenario_preference",
        "user_id": user_id,
        "scenario_id": scenario_id,
        "is_bookmarked": bool(new_bookmarked),
        "is_favorited": bool(new_favorited),
        "created_at": created_at,
        "updated_at": now,
    }
    _with_keys(item, f"USER#{user_id}", _user_scenario_pref_sk(scenario_id))
    get_table().put_item(Item=item)

    if delta_bookmark or delta_favorite:
        inc = {}
        if delta_bookmark:
            inc["bookmark_count"] = delta_bookmark
        if delta_favorite:
            inc["favorite_count"] = delta_favorite
        increment_scenario_stats(scenario_id, inc)

    return {"isBookmarked": bool(new_bookmarked), "isFavorited": bool(new_favorited)}


def list_user_scenario_preferences(user_id: str, limit: int = 200) -> list[dict]:
    user_id = str(user_id or "").strip()
    if not user_id:
        return []
    max_results = max(1, min(int(limit), 500))
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(_user_pk(user_id))
        & Key(_sk_name()).begins_with("SCENARIO_PREF#"),
        Limit=max_results,
    )
    return resp.get("Items", [])[:max_results]


def record_scenario_impression(
    user_id: str,
    scenario_id: str,
    *,
    impression_ms: int | None = None,
    source: str | None = None,
) -> None:
    user_id = str(user_id or "").strip()
    scenario_id = str(scenario_id or "").strip()
    if not user_id or not scenario_id:
        return
    now = _now_iso()
    imp_ms = int(impression_ms) if isinstance(impression_ms, (int, float)) else None
    src = str(source or "").strip() or None

    # User-level metric
    update_parts = ["#ua=:u", "#li=:t"]
    values: dict[str, Any] = {":u": now, ":t": now, ":one": 1}
    names: dict[str, str] = {"#ic": "impression_count", "#ua": "updated_at", "#li": "last_impression_at"}
    if imp_ms is not None and imp_ms >= 0:
        update_parts.append("#lm=:ms")
        values[":ms"] = int(imp_ms)
        names["#lm"] = "last_impression_ms"
    if src:
        update_parts.append("#ls=:src")
        values[":src"] = src
        names["#ls"] = "last_impression_source"

    get_table().update_item(
        Key=_key(f"USER#{user_id}", _user_scenario_metric_sk(scenario_id)),
        UpdateExpression="SET " + ", ".join(update_parts) + " ADD #ic :one",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )

    # Scenario-level aggregate
    inc: dict[str, int] = {"impression_count": 1}
    if imp_ms is not None and imp_ms >= 0:
        inc["impression_ms_sum"] = int(imp_ms)
    increment_scenario_stats(scenario_id, inc)


def record_scenario_detail_view(
    user_id: str,
    scenario_id: str,
    *,
    dwell_ms: int,
    source: str | None = None,
) -> None:
    user_id = str(user_id or "").strip()
    scenario_id = str(scenario_id or "").strip()
    if not user_id or not scenario_id:
        return
    now = _now_iso()
    ms = max(0, int(dwell_ms))
    src = str(source or "").strip() or None

    # User-level metric
    update_parts = ["#ua=:u", "#ld=:t"]
    values: dict[str, Any] = {":u": now, ":t": now, ":one": 1, ":ms": ms}
    names: dict[str, str] = {
        "#dc": "detail_view_count",
        "#ds": "detail_dwell_ms_sum",
        "#ua": "updated_at",
        "#ld": "last_detail_view_at",
    }
    if src:
        update_parts.append("#ls=:src")
        values[":src"] = src
        names["#ls"] = "last_detail_view_source"

    get_table().update_item(
        Key=_key(f"USER#{user_id}", _user_scenario_metric_sk(scenario_id)),
        UpdateExpression="SET " + ", ".join(update_parts) + " ADD #dc :one, #ds :ms",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )

    bucket_key = "detail_dwell_b5_count"
    if ms < 2_000:
        bucket_key = "detail_dwell_b0_count"
    elif ms < 5_000:
        bucket_key = "detail_dwell_b1_count"
    elif ms < 15_000:
        bucket_key = "detail_dwell_b2_count"
    elif ms < 60_000:
        bucket_key = "detail_dwell_b3_count"
    elif ms < 300_000:
        bucket_key = "detail_dwell_b4_count"

    increment_scenario_stats(
        scenario_id,
        {
            "detail_view_count": 1,
            "detail_dwell_ms_sum": ms,
            bucket_key: 1,
        },
    )


def batch_get_scenario_stats(scenario_ids: list[str]) -> dict[str, dict]:
    if not scenario_ids:
        return {}
    table = get_table()
    client = table.meta.client
    pk_attr, sk_attr = get_key_attribute_names()

    out: dict[str, dict] = {}
    unique: list[str] = []
    seen: set[str] = set()
    for sid in scenario_ids:
        sid_str = str(sid or "").strip()
        if not sid_str or sid_str in seen:
            continue
        seen.add(sid_str)
        unique.append(sid_str)

    for i in range(0, len(unique), 100):
        chunk = unique[i : i + 100]
        keys = [{pk_attr: _scenario_pk(sid), sk_attr: _scenario_stats_sk()} for sid in chunk]
        req = {table.name: {"Keys": keys}}
        while True:
            resp = client.batch_get_item(RequestItems=req)
            items = resp.get("Responses", {}).get(table.name, [])
            for item in items:
                scenario_id = str(item.get("scenario_id") or "").strip()
                if not scenario_id:
                    pk = str(item.get(pk_attr) or "")
                    if pk.startswith("SCENARIO#"):
                        scenario_id = pk.split("SCENARIO#", 1)[1]
                if scenario_id:
                    out[scenario_id] = item
            unprocessed = resp.get("UnprocessedKeys", {}).get(table.name, {}).get("Keys", [])
            if not unprocessed:
                break
            req = {table.name: {"Keys": unprocessed}}
    return out


def batch_get_user_scenario_metrics(user_id: str, scenario_ids: list[str]) -> dict[str, dict]:
    user_id = str(user_id or "").strip()
    if not user_id or not scenario_ids:
        return {}
    table = get_table()
    client = table.meta.client
    pk_attr, sk_attr = get_key_attribute_names()

    out: dict[str, dict] = {}
    unique: list[str] = []
    seen: set[str] = set()
    for sid in scenario_ids:
        sid_str = str(sid or "").strip()
        if not sid_str or sid_str in seen:
            continue
        seen.add(sid_str)
        unique.append(sid_str)

    for i in range(0, len(unique), 100):
        chunk = unique[i : i + 100]
        keys = [{pk_attr: f"USER#{user_id}", sk_attr: _user_scenario_metric_sk(sid)} for sid in chunk]
        req = {table.name: {"Keys": keys}}
        while True:
            resp = client.batch_get_item(RequestItems=req)
            items = resp.get("Responses", {}).get(table.name, [])
            for item in items:
                scenario_id = str(item.get("scenario_id") or "").strip()
                if scenario_id:
                    out[scenario_id] = item
            unprocessed = resp.get("UnprocessedKeys", {}).get(table.name, {}).get("Keys", [])
            if not unprocessed:
                break
            req = {table.name: {"Keys": unprocessed}}
    return out


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

def is_scenario_gm_registered(scenario_id: str, user_id: str) -> bool:
    scenario_id = str(scenario_id or "").strip()
    user_id = str(user_id or "").strip()
    if not scenario_id or not user_id:
        return False
    resp = get_table().get_item(Key=_key(_scenario_pk(scenario_id), f"GM#{user_id}"))
    return bool(resp.get("Item"))


def list_scenario_gm_user_ids(scenario_id: str, limit: int = 200) -> list[str]:
    scenario_id = str(scenario_id or "").strip()
    if not scenario_id:
        return []
    max_results = max(1, min(int(limit), 500))
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(_scenario_pk(scenario_id)) & Key(_sk_name()).begins_with("GM#"),
        Limit=max_results,
    )
    user_ids: list[str] = []
    for item in resp.get("Items", []):
        uid = str(item.get("gm_user_id") or "").strip()
        if not uid:
            sk_val = str(item.get(_sk_name()) or "")
            if sk_val.startswith("GM#"):
                uid = sk_val.split("#", 1)[1].strip()
        if uid:
            user_ids.append(uid)
    return user_ids


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
        "updated_at": session.get("updated_at"),
        "last_activity_at": session.get("last_activity_at"),
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
    flow_mode: str | None = None,
    fixed_schedule: list[dict[str, Any]] | None = None,
) -> str:
    table = get_table()
    session_id = _new_id("ses_")
    created_at = _now_iso()

    copied_handouts: list[dict[str, Any]] = []
    is_handout_session = False
    if scenario_id:
        try:
            scenario = get_scenario(scenario_id) or {}
            is_handout_session = bool(scenario.get("is_handout_scenario"))
            if is_handout_session:
                copied_handouts = scenario.get("handouts") if isinstance(scenario.get("handouts"), list) else []
        except Exception:
            scenario = {}
            is_handout_session = False
            copied_handouts = []

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
        "flow_mode": flow_mode,
        "fixed_schedule": fixed_schedule,
        "scheduled_start": None,
        "scheduled_end": None,
        "is_handout_session": is_handout_session,
        "handouts": copied_handouts if copied_handouts else [],
        "created_by": created_by,
        "created_at": created_at,
        "updated_at": created_at,
        "last_activity_at": created_at,
    }
    _with_keys(item, _session_pk(session_id), "META")
    table.put_item(Item=item)
    _upsert_session_status_index(item, status)
    if gm_user_id:
        try:
            upsert_user_session_link(str(gm_user_id), session_id, is_gm=True)
        except Exception:
            pass
    return session_id


def get_session(session_id: str) -> dict | None:
    table = get_table()
    resp = table.get_item(Key=_key(_session_pk(session_id), "META"))
    return resp.get("Item")


def batch_get_sessions(session_ids: list[str]) -> dict[str, dict]:
    if not session_ids:
        return {}
    table = get_table()
    client = table.meta.client
    pk_attr, sk_attr = get_key_attribute_names()

    out: dict[str, dict] = {}
    unique_ids: list[str] = []
    seen: set[str] = set()
    for sid in session_ids:
        sid_str = str(sid or "").strip()
        if not sid_str or sid_str in seen:
            continue
        seen.add(sid_str)
        unique_ids.append(sid_str)

    for i in range(0, len(unique_ids), 100):
        chunk = unique_ids[i : i + 100]
        keys = [{pk_attr: _session_pk(sid), sk_attr: "META"} for sid in chunk]
        req = {table.name: {"Keys": keys}}
        while True:
            resp = client.batch_get_item(RequestItems=req)
            items = resp.get("Responses", {}).get(table.name, [])
            for item in items:
                session_id = str(item.get("session_id") or "").strip()
                if session_id:
                    out[session_id] = item
            unprocessed = resp.get("UnprocessedKeys", {}).get(table.name, {}).get("Keys", [])
            if not unprocessed:
                break
            req = {table.name: {"Keys": unprocessed}}
    return out


def touch_session_activity(session_id: str, at: str | None = None) -> None:
    session_id = str(session_id or "").strip()
    if not session_id:
        return
    now = str(at or _now_iso())
    pk_attr, sk_attr = get_key_attribute_names()
    try:
        get_table().update_item(
            Key=_key(_session_pk(session_id), "META"),
            UpdateExpression="SET updated_at=:u, last_activity_at=:a",
            ExpressionAttributeValues={":u": now, ":a": now},
            ConditionExpression=f"attribute_exists({pk_attr}) AND attribute_exists({sk_attr})",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return
        raise


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

def update_session_gm(session_id: str, gm_user_id: str) -> None:
    gm_user_id = str(gm_user_id or "").strip()
    if not gm_user_id:
        raise ValueError("gm_user_id is required")

    session = get_session(session_id)
    status = str(session.get("status") or "") if session else ""

    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression="SET gm_user_id=:g",
        ExpressionAttributeValues={":g": gm_user_id},
    )

    if session:
        session["gm_user_id"] = gm_user_id
        try:
            if status:
                _upsert_session_status_index(session, status)
        except Exception:
            pass

    try:
        upsert_user_session_link(gm_user_id, session_id, is_gm=True)
    except Exception:
        pass


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


def list_sessions_by_status_page(status: str, limit: int = 30, cursor: dict | None = None) -> tuple[list[dict], dict | None]:
    table = get_table()
    max_results = max(1, min(int(limit), 200))

    try:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key(_pk_name()).eq(_session_status_pk(status))
            & Key(_sk_name()).begins_with("CREATED#"),
            "ScanIndexForward": False,
            "Limit": max_results,
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor
        resp = table.query(**kwargs)
        return resp.get("Items", [])[:max_results], resp.get("LastEvaluatedKey")
    except Exception:
        # Fall back to the non-paginated helper (may scan on older tables).
        return list_sessions_by_status(status, limit=max_results), None


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


def list_waitlist_records(session_id: str) -> list[dict]:
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(_session_pk(session_id)) & Key(_sk_name()).begins_with("WAIT#"),
    )
    items = resp.get("Items", [])
    records: list[dict[str, Any]] = []
    for item in items:
        user_id = str(item.get("user_id") or "")
        if not user_id:
            continue
        records.append(
            {
                "user_id": user_id,
                "display_name": item.get("display_name") or user_id,
                "requested_at": item.get("requested_at") or "",
            }
        )
    records.sort(key=lambda x: str(x.get("requested_at") or ""))
    return records


def add_waitlist(session_id: str, user_id: str, display_name: str) -> None:
    item = {
        "entity": "session_waitlist",
        "session_id": session_id,
        "user_id": user_id,
        "display_name": display_name,
        "requested_at": _now_iso(),
    }
    _with_keys(item, _session_pk(session_id), f"WAIT#{user_id}")
    get_table().put_item(Item=item)
    try:
        touch_session_activity(session_id)
    except Exception:
        pass
    try:
        upsert_user_session_link(user_id, session_id, is_waitlisted=True)
    except Exception:
        pass


def remove_waitlist(session_id: str, user_id: str) -> None:
    get_table().delete_item(Key=_key(_session_pk(session_id), f"WAIT#{user_id}"))
    try:
        touch_session_activity(session_id)
    except Exception:
        pass
    try:
        upsert_user_session_link(user_id, session_id, is_waitlisted=False, create_if_missing=False)
    except Exception:
        pass


def is_waitlisted(session_id: str, user_id: str) -> bool:
    resp = get_table().get_item(Key=_key(_session_pk(session_id), f"WAIT#{user_id}"))
    return bool(resp.get("Item"))


def list_session_character_records(session_id: str) -> list[dict]:
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(_session_pk(session_id)) & Key(_sk_name()).begins_with("CHAR#"),
    )
    return resp.get("Items", [])


def get_session_character(session_id: str, user_id: str) -> dict | None:
    resp = get_table().get_item(Key=_key(_session_pk(session_id), f"CHAR#{user_id}"))
    return resp.get("Item")


def upsert_session_character(
    session_id: str,
    user_id: str,
    name: str,
    sheet_url: str,
    portrait_url: str | None = None,
    visibility: str = "public",
) -> None:
    if visibility not in ("public", "private"):
        visibility = "public"
    item = {
        "entity": "session_character",
        "session_id": session_id,
        "user_id": user_id,
        "name": name,
        "sheet_url": sheet_url,
        "portrait_url": portrait_url,
        "visibility": visibility,
        "updated_at": _now_iso(),
    }
    _with_keys(item, _session_pk(session_id), f"CHAR#{user_id}")
    get_table().put_item(Item=item)
    try:
        touch_session_activity(session_id)
    except Exception:
        pass


def delete_session_character(session_id: str, user_id: str) -> None:
    get_table().delete_item(Key=_key(_session_pk(session_id), f"CHAR#{user_id}"))
    try:
        touch_session_activity(session_id)
    except Exception:
        pass


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
    try:
        touch_session_activity(session_id)
    except Exception:
        pass
    try:
        upsert_user_session_link(user_id, session_id, is_participant=True, is_waitlisted=False)
    except Exception:
        pass


def remove_participant(session_id: str, user_id: str) -> None:
    get_table().delete_item(Key=_key(_session_pk(session_id), f"PART#{user_id}"))
    try:
        touch_session_activity(session_id)
    except Exception:
        pass
    try:
        upsert_user_session_link(user_id, session_id, is_participant=False, create_if_missing=False)
    except Exception:
        pass


def is_participant(session_id: str, user_id: str) -> bool:
    resp = get_table().get_item(Key=_key(_session_pk(session_id), f"PART#{user_id}"))
    return bool(resp.get("Item"))


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


def add_play_history(
    scenario_id: str,
    user_id: str,
    user_display_name: str,
    role: str,
    session_id: str,
    notes: str,
    handout_name: str | None = None,
) -> None:
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
    if handout_name:
        item["handout_name"] = handout_name
    _with_keys(item, _scenario_pk(scenario_id), f"PLAY#{now}#{user_id}")
    get_table().put_item(Item=item)


def _handout_assignment_sk(handout_id: str) -> str:
    return f"HOASSIGN#{handout_id}"


def list_handout_assignments(session_id: str) -> list[dict]:
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(_session_pk(session_id)) & Key(_sk_name()).begins_with("HOASSIGN#"),
    )
    return resp.get("Items", [])


def get_handout_assignment(session_id: str, handout_id: str) -> dict | None:
    resp = get_table().get_item(Key=_key(_session_pk(session_id), _handout_assignment_sk(handout_id)))
    return resp.get("Item")


def upsert_handout_assignment(
    session_id: str,
    handout_id: str,
    handout_name: str,
    participant_id: str,
    participant_name: str,
    assigned_at: str | None = None,
    notified_at: str | None = None,
    extra_private_info: str | None = None,
) -> None:
    extra_private_info = str(extra_private_info).strip() if extra_private_info else None
    item = {
        "entity": "handout_assignment",
        "session_id": session_id,
        "handout_id": handout_id,
        "handout_name": handout_name,
        "participant_id": participant_id,
        "participant_name": participant_name,
        "assigned_at": assigned_at or _now_iso(),
        "notified_at": notified_at,
    }
    if extra_private_info:
        item["extra_private_info"] = extra_private_info
    _with_keys(item, _session_pk(session_id), _handout_assignment_sk(handout_id))
    get_table().put_item(Item=item)


def delete_handout_assignment(session_id: str, handout_id: str) -> None:
    get_table().delete_item(Key=_key(_session_pk(session_id), _handout_assignment_sk(handout_id)))


def mark_handout_assignment_notified(session_id: str, handout_id: str, notified_at: str | None = None) -> None:
    get_table().update_item(
        Key=_key(_session_pk(session_id), _handout_assignment_sk(handout_id)),
        UpdateExpression="SET notified_at=:n",
        ExpressionAttributeValues={":n": notified_at or _now_iso()},
    )


def set_handout_assignment_extra_private_info(session_id: str, handout_id: str, extra_private_info: str | None) -> None:
    extra_private_info = str(extra_private_info).strip() if extra_private_info is not None else ""
    if not extra_private_info:
        get_table().update_item(
            Key=_key(_session_pk(session_id), _handout_assignment_sk(handout_id)),
            UpdateExpression="REMOVE extra_private_info",
        )
        return

    get_table().update_item(
        Key=_key(_session_pk(session_id), _handout_assignment_sk(handout_id)),
        UpdateExpression="SET extra_private_info=:v",
        ExpressionAttributeValues={":v": extra_private_info},
    )


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
    try:
        touch_session_activity(session_id)
    except Exception:
        pass


def set_session_schedule_manual(session_id: str, start: datetime, end: datetime | None) -> None:
    set_parts = ["scheduled_start=:s"]
    values: dict[str, Any] = {":s": start.isoformat()}
    remove_parts = ["decided_slot_id"]
    if end is not None:
        set_parts.append("scheduled_end=:e")
        values[":e"] = end.isoformat()
    else:
        remove_parts.append("scheduled_end")

    expr = "SET " + ", ".join(set_parts)
    if remove_parts:
        expr += " REMOVE " + ", ".join(remove_parts)
    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression=expr,
        ExpressionAttributeValues=values,
    )
    try:
        touch_session_activity(session_id)
    except Exception:
        pass


def set_session_fixed_schedule(session_id: str, fixed_schedule: list[dict[str, Any]] | None) -> None:
    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression="SET fixed_schedule=:f",
        ExpressionAttributeValues={":f": fixed_schedule or []},
    )
    try:
        touch_session_activity(session_id)
    except Exception:
        pass


def set_session_flow_mode(session_id: str, flow_mode: str) -> None:
    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression="SET flow_mode=:m",
        ExpressionAttributeValues={":m": flow_mode},
    )
    try:
        touch_session_activity(session_id)
    except Exception:
        pass


def set_session_decided_slot_id(session_id: str, slot_id: str) -> None:
    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression="SET decided_slot_id=:d",
        ExpressionAttributeValues={":d": slot_id},
    )
    try:
        touch_session_activity(session_id)
    except Exception:
        pass


def clear_session_schedule(session_id: str) -> None:
    get_table().update_item(
        Key=_key(_session_pk(session_id), "META"),
        UpdateExpression="REMOVE scheduled_start, scheduled_end, decided_slot_id",
    )
    try:
        touch_session_activity(session_id)
    except Exception:
        pass


def list_poll_slots(poll_id: str) -> list[dict]:
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(f"POLL#{poll_id}") & Key(_sk_name()).begins_with("SLOT#"),
    )
    items = resp.get("Items", [])
    slots: list[dict] = []
    for item in items:
        slots.append(
            {
                "slot_id": str(item.get("slot_id") or ""),
                "start_time": item.get("start_time"),
                "end_time": item.get("end_time"),
            }
        )
    slots.sort(key=lambda x: str(x.get("start_time") or ""))
    return slots


def list_poll_responses(poll_id: str) -> list[dict]:
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(f"POLL#{poll_id}") & Key(_sk_name()).begins_with("RESP#"),
    )
    items = resp.get("Items", [])
    responses: list[dict] = []
    for item in items:
        responses.append(
            {
                "slot_id": str(item.get("slot_id") or ""),
                "user_id": str(item.get("user_id") or ""),
                "status": str(item.get("status") or ""),
                "comment": str(item.get("comment") or ""),
                "updated_at": str(item.get("updated_at") or ""),
            }
        )
    return responses


def _poll_comment_sk(comment_id: str) -> str:
    return f"COMM#{comment_id}"


def create_poll_comment(poll_id: str, user_id: str, text: str) -> str:
    comment_id = f"comm_{uuid.uuid4().hex[:12]}"
    item = {
        "entity": "poll_comment",
        "poll_id": poll_id,
        "comment_id": comment_id,
        "user_id": user_id,
        "text": text,
        "created_at": _now_iso(),
        "edited_at": None,
    }
    _with_keys(item, f"POLL#{poll_id}", _poll_comment_sk(comment_id))
    get_table().put_item(Item=item)
    return comment_id


def get_poll_comment(poll_id: str, comment_id: str) -> dict | None:
    resp = get_table().get_item(Key=_key(f"POLL#{poll_id}", _poll_comment_sk(comment_id)))
    return resp.get("Item")


def update_poll_comment(poll_id: str, comment_id: str, text: str) -> None:
    get_table().update_item(
        Key=_key(f"POLL#{poll_id}", _poll_comment_sk(comment_id)),
        UpdateExpression="SET #t=:t, edited_at=:e",
        ExpressionAttributeNames={"#t": "text"},
        ExpressionAttributeValues={":t": text, ":e": _now_iso()},
    )


def delete_poll_comment(poll_id: str, comment_id: str) -> None:
    get_table().delete_item(Key=_key(f"POLL#{poll_id}", _poll_comment_sk(comment_id)))


def list_poll_comments(poll_id: str) -> list[dict]:
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(f"POLL#{poll_id}") & Key(_sk_name()).begins_with("COMM#"),
    )
    items = resp.get("Items", [])
    comments: list[dict] = []
    for item in items:
        comments.append(
            {
                "comment_id": str(item.get("comment_id") or ""),
                "user_id": str(item.get("user_id") or ""),
                "text": str(item.get("text") or ""),
                "created_at": str(item.get("created_at") or ""),
                "edited_at": str(item.get("edited_at") or "") or None,
            }
        )
    comments.sort(key=lambda x: str(x.get("created_at") or ""))
    return comments


def _user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _user_session_sk(session_id: str) -> str:
    return f"USESS#{session_id}"


def upsert_user_session_link(
    user_id: str,
    session_id: str,
    *,
    is_gm: bool | None = None,
    is_participant: bool | None = None,
    is_waitlisted: bool | None = None,
    create_if_missing: bool = True,
) -> None:
    if not user_id or not session_id:
        return

    update_parts = ["entity=:e", "user_id=:uid", "session_id=:sid", "updated_at=:u"]
    values: dict[str, Any] = {
        ":e": "user_session",
        ":uid": user_id,
        ":sid": session_id,
        ":u": _now_iso(),
    }

    if is_gm is not None:
        update_parts.append("is_gm=:g")
        values[":g"] = bool(is_gm)
    if is_participant is not None:
        update_parts.append("is_participant=:p")
        values[":p"] = bool(is_participant)
    if is_waitlisted is not None:
        update_parts.append("is_waitlisted=:w")
        values[":w"] = bool(is_waitlisted)

    kwargs: dict[str, Any] = {
        "Key": _key(_user_pk(user_id), _user_session_sk(session_id)),
        "UpdateExpression": "SET " + ", ".join(update_parts),
        "ExpressionAttributeValues": values,
    }

    if not create_if_missing:
        pk_attr, sk_attr = get_key_attribute_names()
        kwargs["ConditionExpression"] = f"attribute_exists({pk_attr}) AND attribute_exists({sk_attr})"

    try:
        get_table().update_item(**kwargs)
    except ClientError as exc:
        if (
            not create_if_missing
            and exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"
        ):
            return
        raise


def list_user_session_links(user_id: str, limit: int = 200) -> list[dict]:
    if not user_id:
        return []
    max_results = max(1, min(int(limit), 500))
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(_user_pk(user_id)) & Key(_sk_name()).begins_with("USESS#"),
        Limit=max_results,
    )
    return resp.get("Items", [])[:max_results]


def _notification_sk(created_at: str, notification_id: str) -> str:
    return f"NOTIF#{created_at}#{notification_id}"


def create_notification(
    user_id: str,
    notif_type: str,
    title: str,
    subtitle: str,
    action_label: str | None = None,
    action_target: str | None = None,
    icon_type: str | None = None,
    thumbnail_url: str | None = None,
    handout_assignment: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> str:
    table = get_table()
    notification_id = _new_id("noti_")
    created_at = created_at or _now_iso()
    item = {
        "entity": "notification",
        "notification_id": notification_id,
        "user_id": user_id,
        "type": notif_type,
        "title": title,
        "subtitle": subtitle,
        "action_label": action_label,
        "action_target": action_target,
        "icon_type": icon_type,
        "thumbnail_url": thumbnail_url,
        "handout_assignment": handout_assignment,
        "created_at": created_at,
        "read_at": None,
    }
    _with_keys(item, _user_pk(user_id), _notification_sk(created_at, notification_id))
    table.put_item(Item=item)
    return notification_id


def list_user_notifications(user_id: str, limit: int = 50) -> list[dict]:
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(_user_pk(user_id)) & Key(_sk_name()).begins_with("NOTIF#"),
        ScanIndexForward=False,
        Limit=max(1, min(int(limit), 200)),
    )
    return resp.get("Items", [])


def _find_notification_item(user_id: str, notification_id: str) -> dict | None:
    table = get_table()
    resp = table.query(
        KeyConditionExpression=Key(_pk_name()).eq(_user_pk(user_id)) & Key(_sk_name()).begins_with("NOTIF#"),
        FilterExpression=Attr("notification_id").eq(notification_id),
        Limit=10,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def mark_notification_read(user_id: str, notification_id: str) -> bool:
    item = _find_notification_item(user_id, notification_id)
    if not item:
        return False
    pk_attr, sk_attr = get_key_attribute_names()
    pk = item.get(pk_attr)
    sk = item.get(sk_attr)
    if not pk or not sk:
        return False
    get_table().update_item(
        Key={pk_attr: pk, sk_attr: sk},
        UpdateExpression="SET read_at=:r",
        ExpressionAttributeValues={":r": _now_iso()},
    )
    return True


def mark_all_notifications_read(user_id: str) -> int:
    items = list_user_notifications(user_id, limit=200)
    if not items:
        return 0
    pk_attr, sk_attr = get_key_attribute_names()
    updated = 0
    for item in items:
        if item.get("read_at"):
            continue
        pk = item.get(pk_attr)
        sk = item.get(sk_attr)
        if not pk or not sk:
            continue
        get_table().update_item(
            Key={pk_attr: pk, sk_attr: sk},
            UpdateExpression="SET read_at=:r",
            ExpressionAttributeValues={":r": _now_iso()},
        )
        updated += 1
    return updated


def _achievement_def_pk() -> str:
    return "ACHIEVEMENT#DEF"


def _achievement_def_sk(achievement_id: str) -> str:
    return f"ACHV#{achievement_id}"


def upsert_achievement_definition(
    achievement_id: str,
    title: str,
    description: str,
    category: str,
    condition: Any | None = None,
    icon_url: str | None = None,
    is_spoiler: bool = False,
    trigger: str | None = None,
    scenario_id: str | None = None,
    audience: str | None = None,
) -> None:
    item = {
        "entity": "achievement_definition",
        "achievement_id": achievement_id,
        "title": title,
        "description": description,
        "category": category,
        "condition": condition,
        "icon_url": icon_url,
        "is_spoiler": is_spoiler,
        "updated_at": _now_iso(),
    }
    if trigger:
        item["trigger"] = trigger
    if scenario_id:
        item["scenario_id"] = scenario_id
    if audience:
        item["audience"] = audience
    _with_keys(item, _achievement_def_pk(), _achievement_def_sk(achievement_id))
    get_table().put_item(Item=item)


def list_achievement_definitions() -> list[dict]:
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(_achievement_def_pk()) & Key(_sk_name()).begins_with("ACHV#"),
    )
    return resp.get("Items", [])


def list_user_achievement_unlocks(user_id: str) -> list[dict]:
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(_user_pk(user_id)) & Key(_sk_name()).begins_with("ACHV#"),
    )
    return resp.get("Items", [])


def upsert_user_achievement_unlock(
    user_id: str,
    achievement_id: str,
    unlocked_at: str | None = None,
    visibility: str = "private",
    spoiler_level: str = "none",
    pinned: bool = False,
) -> None:
    unlocked_at = unlocked_at or _now_iso()
    item = {
        "entity": "achievement_unlock",
        "user_id": user_id,
        "achievement_id": achievement_id,
        "unlocked_at": unlocked_at,
        "visibility": visibility,
        "spoiler_level": spoiler_level,
        "pinned": pinned,
    }
    _with_keys(item, _user_pk(user_id), f"ACHV#{achievement_id}")
    get_table().put_item(Item=item)


def create_user_achievement_unlock_if_absent(
    user_id: str,
    achievement_id: str,
    unlocked_at: str | None = None,
    visibility: str = "private",
    spoiler_level: str = "none",
    pinned: bool = False,
) -> bool:
    unlocked_at = unlocked_at or _now_iso()
    item = {
        "entity": "achievement_unlock",
        "user_id": user_id,
        "achievement_id": achievement_id,
        "unlocked_at": unlocked_at,
        "visibility": visibility,
        "spoiler_level": spoiler_level,
        "pinned": pinned,
    }
    pk_value = _user_pk(user_id)
    sk_value = f"ACHV#{achievement_id}"
    pk_attr, sk_attr = get_key_attribute_names()
    _with_keys(item, pk_value, sk_value)
    try:
        get_table().put_item(
            Item=item,
            ConditionExpression=f"attribute_not_exists({pk_attr}) AND attribute_not_exists({sk_attr})",
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def list_user_characters(user_id: str) -> list[dict]:
    resp = get_table().query(
        KeyConditionExpression=Key(_pk_name()).eq(_user_pk(user_id)) & Key(_sk_name()).begins_with("CHAR#"),
    )
    return resp.get("Items", [])


def upsert_user_character(
    user_id: str,
    character_id: str,
    name: str,
    url: str,
    system: str | None = None,
) -> None:
    item = {
        "entity": "character",
        "user_id": user_id,
        "character_id": character_id,
        "name": name,
        "url": url,
        "system": system,
        "updated_at": _now_iso(),
    }
    _with_keys(item, _user_pk(user_id), f"CHAR#{character_id}")
    get_table().put_item(Item=item)


def list_user_session_ids(user_id: str, limit: int = 200) -> list[str]:
    max_results = max(1, min(int(limit), 500))

    try:
        links = list_user_session_links(user_id, limit=max_results)
        if links:
            session_ids: list[str] = []
            for item in links:
                if not (
                    item.get("is_gm")
                    or item.get("is_participant")
                    or item.get("is_waitlisted")
                ):
                    continue
                sid = str(item.get("session_id") or "").strip()
                if not sid:
                    sk_val = str(item.get(_sk_name()) or "")
                    if sk_val.startswith("USESS#"):
                        sid = sk_val.split("#", 1)[1]
                if sid:
                    session_ids.append(sid)
            if session_ids:
                # Preserve insertion order (Query returns sorted by SK).
                deduped = list(dict.fromkeys(session_ids))
                return deduped[:max_results]
    except Exception:
        pass

    # Fallback: Scan+Filter (first run only). Also backfills user_session links.
    session_ids: list[str] = []
    try:
        items = _scan_filtered(
            Attr("entity").eq("session_participant") & Attr("user_id").eq(user_id),
            max_results=max_results,
            page_size=200,
            max_pages=200,
        )
        for item in items:
            sid = str(item.get("session_id") or "").strip()
            if not sid:
                continue
            session_ids.append(sid)
            try:
                upsert_user_session_link(user_id, sid, is_participant=True)
            except Exception:
                pass
    except Exception:
        pass

    try:
        items = _scan_filtered(
            Attr("entity").eq("session_waitlist") & Attr("user_id").eq(user_id),
            max_results=max_results,
            page_size=200,
            max_pages=200,
        )
        for item in items:
            sid = str(item.get("session_id") or "").strip()
            if not sid:
                continue
            session_ids.append(sid)
            try:
                upsert_user_session_link(user_id, sid, is_waitlisted=True)
            except Exception:
                pass
    except Exception:
        pass

    deduped = list(dict.fromkeys(session_ids))
    return deduped[:max_results]


def list_sessions_by_gm(user_id: str, limit: int = 200) -> list[dict]:
    max_results = max(1, min(int(limit), 500))

    try:
        links = list_user_session_links(user_id, limit=max_results)
        session_ids = [
            str(item.get("session_id") or "")
            for item in links
            if item.get("is_gm") and item.get("session_id")
        ]
        sessions: list[dict] = []
        for sid in session_ids[:max_results]:
            session = get_session(sid)
            if session:
                sessions.append(session)
        if sessions:
            return sessions[:max_results]
    except Exception:
        pass

    # Fallback: Scan+Filter and backfill links.
    sessions = _scan_filtered(
        Attr("entity").eq("session") & Attr("gm_user_id").eq(user_id),
        max_results=max_results,
        page_size=200,
        max_pages=200,
    )
    for s in sessions:
        sid = str(s.get("session_id") or "").strip()
        if not sid:
            continue
        try:
            upsert_user_session_link(user_id, sid, is_gm=True)
        except Exception:
            pass
    return sessions


def list_play_history_for_user(user_id: str, limit: int = 200) -> list[dict]:
    items = _scan_filtered(
        Attr("entity").eq("play_history") & Attr("user_id").eq(user_id),
        max_results=max(1, min(int(limit), 500)),
        page_size=200,
    )
    items.sort(key=lambda x: str(x.get("date") or ""), reverse=True)
    return items
