from __future__ import annotations

import csv
import base64
import json
import logging
import math
import re
import uuid
from pathlib import Path
from urllib.parse import urlparse
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import requests

from trpg_bot import repositories
from trpg_bot.config import (
    get_discord_application_id,
    get_discord_client_secret,
    get_discord_oauth_redirect_uri,
    get_backend_build_version,
    get_log_level,
    get_upload_bucket_name,
    get_upload_public_base_url,
)
from trpg_bot.discord_api import API_BASE as DISCORD_API_BASE
from trpg_bot.discord_api import DiscordApiError, create_thread, get_channel, get_guild_member, get_user
from trpg_bot.routes import refresh_session_card

logger = logging.getLogger(__name__)
logger.setLevel(get_log_level())

ACTIVITY_SESSION_TOKEN_PREFIX = "trpg_act_"
JST = timezone(timedelta(hours=9))
WEEKDAYS_JA = ["月", "火", "水", "木", "金", "土", "日"]
ALLOWED_UPLOAD_CONTENT_TYPES: dict[str, str] = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024

_s3_client = boto3.client("s3")
_catalog_seeded = False


def _cors_headers() -> dict[str, str]:
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,OPTIONS",
    }


def _response(payload: dict | None, status: int = 200) -> dict:
    body = "" if payload is None else json.dumps(payload)
    headers = {"Content-Type": "application/json", **_cors_headers()}
    return {"statusCode": status, "headers": headers, "body": body}

def _binary_response(body_bytes: bytes, content_type: str, status: int = 200, extra_headers: dict[str, str] | None = None) -> dict:
    headers = {"Content-Type": content_type, **_cors_headers()}
    if extra_headers:
        headers.update(extra_headers)
    return {
        "statusCode": status,
        "headers": headers,
        "isBase64Encoded": True,
        "body": base64.b64encode(body_bytes).decode("ascii"),
    }


def _get_method(event: dict) -> str:
    return event.get("httpMethod") or ((event.get("requestContext") or {}).get("http") or {}).get("method") or ""


def _get_path(event: dict) -> str:
    return event.get("rawPath") or event.get("path") or ""


def _get_query_params(event: dict) -> dict[str, Any]:
    return event.get("queryStringParameters") or {}


def _get_body(event: dict) -> str:
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        try:
            decoded = base64.b64decode(body)
        except Exception:
            logger.exception("Failed to decode base64 request body")
            return ""
        try:
            return decoded.decode("utf-8")
        except Exception:
            logger.exception("Failed to decode request body as UTF-8")
            return ""
    return body


def _parse_json_body(event: dict) -> dict:
    raw = _get_body(event).strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except Exception:
        logger.exception("Failed to parse JSON request body")
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _bearer_token(headers: dict[str, Any]) -> str | None:
    auth = headers.get("authorization") or headers.get("Authorization")
    if not auth:
        return None
    parts = auth.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _is_activity_session_token(token: str) -> bool:
    return token.startswith(ACTIVITY_SESSION_TOKEN_PREFIX)


def _discord_get_current_user(access_token: str) -> dict:
    resp = requests.get(
        f"{DISCORD_API_BASE}/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    if resp.status_code >= 300:
        raise RuntimeError(f"Discord /users/@me failed: {resp.status_code} {resp.text}")
    return resp.json()


def _discord_avatar_url(me: dict) -> str | None:
    user_id = str(me.get("id") or "").strip()
    avatar = str(me.get("avatar") or "").strip()
    discriminator = str(me.get("discriminator") or "").strip()
    if user_id and avatar:
        ext = "gif" if avatar.startswith("a_") else "png"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.{ext}?size=128"

    if not user_id:
        return None

    # Default avatar (when user has no custom avatar).
    # Old accounts: discriminator % 5 (0-4). New accounts (discriminator=0): (user_id >> 22) % 6 (0-5).
    default_index = 0
    try:
        if discriminator and discriminator != "0":
            default_index = int(discriminator) % 5
        else:
            default_index = (int(user_id) >> 22) % 6
    except Exception:
        default_index = 0
    return f"https://cdn.discordapp.com/embed/avatars/{default_index}.png?size=128"


def _normalize_public_base_url(value: str) -> str:
    trimmed = value.strip().rstrip("/")
    if not trimmed:
        return ""
    if trimmed.startswith("http://") or trimmed.startswith("https://"):
        return trimmed
    return f"https://{trimmed}"


def _normalize_cover_url(value: Any) -> str:
    """Normalize stored cover URLs for Discord Activity CSP (img-src 'self').

    Returns a same-origin path like `/uploads/...` when possible.
    """
    if value is None:
        return "/placeholder.svg"
    cover_url = str(value).strip()
    if not cover_url:
        return "/placeholder.svg"

    public_base_url = _normalize_public_base_url(get_upload_public_base_url() or "")
    if public_base_url and cover_url.startswith(public_base_url):
        cover_url = cover_url[len(public_base_url) :]

    if cover_url.startswith("uploads/"):
        cover_url = f"/{cover_url}"

    if cover_url.startswith("http://") or cover_url.startswith("https://"):
        match = re.search(r"/uploads/[^?#]+", cover_url)
        if match:
            cover_url = match.group(0)

    if cover_url and not cover_url.startswith(("/", "http://", "https://", "data:")):
        cover_url = f"/{cover_url}"

    return cover_url or "/placeholder.svg"

def _normalize_optional_cover_url(value: Any) -> str | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    normalized = _normalize_cover_url(raw)
    if not normalized or normalized == "/placeholder.svg":
        return None
    return normalized


def _resolve_actor_from_auth_token(auth_token: str) -> tuple[str, str]:
    if _is_activity_session_token(auth_token):
        session = repositories.get_activity_session(auth_token)
        if not session:
            raise RuntimeError("Invalid session")
        actor_id = str(session.get("discord_id") or "")
        if not actor_id:
            raise RuntimeError("Invalid session (missing discord_id)")
        actor_name = str(session.get("display_name_cache") or actor_id)
        actor_avatar_url = session.get("avatar_url")
        try:
            repositories.ensure_user(actor_id, actor_name, avatar_url=str(actor_avatar_url) if actor_avatar_url else None)
        except Exception:
            logger.exception("Failed to ensure user profile from activity session")
        repositories.touch_activity_session(auth_token)
        return actor_id, actor_name

    me = _discord_get_current_user(auth_token)
    actor_id = me["id"]
    actor_name = me.get("global_name") or me.get("username") or actor_id
    repositories.ensure_user(actor_id, str(actor_name), avatar_url=_discord_avatar_url(me))
    return actor_id, str(actor_name)


def _exchange_code_for_token(code: str, code_verifier: str | None = None) -> dict:
    data: dict[str, str] = {
        "client_id": get_discord_application_id(),
        "client_secret": get_discord_client_secret(),
        "grant_type": "authorization_code",
        "code": code,
    }
    redirect_uri = get_discord_oauth_redirect_uri()
    if redirect_uri:
        data["redirect_uri"] = redirect_uri
    if code_verifier:
        data["code_verifier"] = code_verifier

    resp = requests.post(
        f"{DISCORD_API_BASE}/oauth2/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if resp.status_code >= 300:
        raise RuntimeError(f"Discord token exchange failed: {resp.status_code} {resp.text}")
    return resp.json()


def _handle_oauth_token(event: dict) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    body = _parse_json_body(event)
    code = body.get("code")
    if not code or not isinstance(code, str):
        return _response({"error": "Missing 'code' in body"}, status=400)

    code_verifier = body.get("code_verifier") or body.get("codeVerifier")
    try:
        token = _exchange_code_for_token(code, str(code_verifier) if code_verifier else None)
        return _response(token, status=200)
    except Exception as exc:
        logger.exception("Token exchange failed")
        return _response({"error": str(exc)}, status=500)


def _handle_activity_login(event: dict) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    body = _parse_json_body(event)
    code = body.get("code")
    if not code or not isinstance(code, str):
        return _response({"error": "Missing 'code' in body"}, status=400)

    code_verifier = body.get("code_verifier") or body.get("codeVerifier")
    try:
        token = _exchange_code_for_token(code, str(code_verifier) if code_verifier else None)
        access_token = token.get("access_token")
        if not access_token or not isinstance(access_token, str):
            return _response({"error": "Discord token exchange response missing access_token"}, status=502)

        me = _discord_get_current_user(access_token)
        actor_id = me["id"]
        actor_name = me.get("global_name") or me.get("username") or actor_id
        avatar_url = _discord_avatar_url(me)
        username = str(me.get("username") or "").strip()
        handle = f"@{username}" if username else None

        repositories.upsert_user(actor_id, str(actor_name), avatar_url=avatar_url, handle=handle)
        session_token = repositories.create_activity_session(actor_id, str(actor_name), avatar_url=avatar_url, handle=handle)
        return _response(
            {
                "sessionToken": session_token,
                "userId": actor_id,
                "displayName": str(actor_name),
                "avatarUrl": _user_avatar_url(actor_id),
                "handle": handle,
            },
            status=200,
        )
    except Exception as exc:
        logger.exception("Activity login failed")
        return _response({"error": str(exc)}, status=500)


def _handle_activity_me(event: dict) -> dict:
    if _get_method(event) != "GET":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    token = _bearer_token(headers)
    if not token or not _is_activity_session_token(token):
        return _response({"error": "Missing Authorization: Bearer <session_token>"}, status=401)

    session = repositories.get_activity_session(token)
    if not session:
        return _response({"error": "Invalid session"}, status=401)

    user_id = session.get("discord_id") or ""
    display_name = session.get("display_name_cache") or user_id
    avatar_url = session.get("avatar_url") or None
    handle = session.get("handle") or None

    profile = {}
    if user_id:
        try:
            profile = repositories.get_user_profile(str(user_id)) or {}
        except Exception:
            logger.exception("Failed to load user profile on activity/me")
            profile = {}

    if not avatar_url and profile.get("avatar_url"):
        avatar_url = str(profile.get("avatar_url") or "").strip() or None
    if not handle and profile.get("handle"):
        handle = str(profile.get("handle") or "").strip() or None

    # Backfill missing avatar/handle for old sessions (created before storing these fields).
    if user_id and (not avatar_url or not handle):
        try:
            discord_user = get_user(str(user_id))
            fetched_display_name = discord_user.get("global_name") or discord_user.get("username") or display_name
            fetched_avatar_url = _discord_avatar_url(discord_user)
            username = str(discord_user.get("username") or "").strip()
            fetched_handle = f"@{username}" if username else None

            repositories.ensure_user(
                str(user_id),
                str(fetched_display_name),
                avatar_url=str(fetched_avatar_url) if fetched_avatar_url else None,
                handle=str(fetched_handle) if fetched_handle else None,
            )
            repositories.update_activity_session_profile(
                token,
                display_name=str(fetched_display_name),
                avatar_url=str(fetched_avatar_url) if fetched_avatar_url else None,
                handle=str(fetched_handle) if fetched_handle else None,
            )

            display_name = str(fetched_display_name)
            avatar_url = fetched_avatar_url or avatar_url
            handle = fetched_handle or handle
        except DiscordApiError:
            # Bot may not be configured in some environments; continue without backfill.
            logger.exception("Failed to backfill Discord user profile via bot API")
        except Exception:
            logger.exception("Failed to backfill Discord user profile via bot API")

    try:
        repositories.touch_activity_session(token)
    except Exception:
        logger.exception("Failed to touch activity session")
    if user_id:
        try:
            repositories.ensure_user(
                str(user_id),
                str(display_name),
                avatar_url=str(avatar_url) if avatar_url else None,
                handle=str(handle) if handle else None,
            )
        except Exception:
            logger.exception("Failed to ensure user profile on activity/me")
    return _response(
        {"userId": user_id, "displayName": display_name, "avatarUrl": _user_avatar_url(str(user_id)), "handle": handle},
        status=200,
    )


def _handle_upload_image(event: dict) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    token = _bearer_token(headers)
    if not token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(token)
    except Exception:
        logger.exception("Failed to resolve actor for upload")
        return _response({"error": "Invalid session"}, status=401)

    bucket = (get_upload_bucket_name() or "").strip()
    public_base_url = _normalize_public_base_url(get_upload_public_base_url() or "")
    if not bucket or not public_base_url:
        return _response(
            {"error": "Upload is not configured (set UPLOAD_BUCKET_NAME and UPLOAD_PUBLIC_BASE_URL)"},
            status=501,
        )

    body = _parse_json_body(event)
    raw_b64 = body.get("dataBase64") or body.get("data_base64") or body.get("data")
    content_type = body.get("contentType") or body.get("content_type")
    data_url = body.get("dataUrl") or body.get("data_url")

    if not raw_b64 and isinstance(data_url, str):
        m = re.match(r"^data:(?P<ct>[^;]+);base64,(?P<data>.+)$", data_url.strip())
        if m:
            content_type = content_type or m.group("ct")
            raw_b64 = m.group("data")

    if not isinstance(raw_b64, str) or not raw_b64.strip():
        return _response({"error": "Missing image data (dataBase64 or dataUrl)"}, status=400)

    if not isinstance(content_type, str) or not content_type.strip():
        return _response({"error": "Missing contentType (e.g. image/jpeg)"}, status=400)

    content_type = content_type.strip().lower()
    ext = ALLOWED_UPLOAD_CONTENT_TYPES.get(content_type)
    if not ext:
        return _response({"error": f"Unsupported contentType: {content_type}"}, status=400)

    purpose = body.get("purpose") or body.get("category") or "image"
    purpose = str(purpose).strip().lower()
    purpose = re.sub(r"[^a-z0-9_-]+", "-", purpose).strip("-")[:32] or "image"

    try:
        data = base64.b64decode(raw_b64, validate=True)
    except Exception:
        return _response({"error": "Invalid base64 payload"}, status=400)

    if len(data) > MAX_UPLOAD_BYTES:
        return _response({"error": f"Payload too large (max {MAX_UPLOAD_BYTES} bytes)"}, status=413)

    key = f"uploads/{purpose}/{actor_id}/{uuid.uuid4().hex}.{ext}"

    try:
        _s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
            CacheControl="public, max-age=31536000, immutable",
        )
    except Exception as exc:
        logger.exception("S3 put_object failed")
        return _response({"error": f"Upload failed: {exc}"}, status=502)

    # IMPORTANT:
    # Discord Activity runs under `*.discordsays.com` and proxies requests to the configured targets.
    # Using an absolute CloudFront/S3 URL can be blocked by the Activity CSP (img-src 'self').
    # So we return a same-origin path that Discord can proxy via the Root Mapping.
    relative_url = f"/{key}"
    absolute_url = f"{public_base_url}/{key}"
    return _response({"url": relative_url, "publicUrl": absolute_url, "key": key}, status=201)


def _scenario_to_ui(s: dict, *, viewer_id: str | None = None, include_private_handouts: bool = False) -> dict:
    scenario_id = s.get("scenario_id") or ""
    title = s.get("title") or ""
    system = s.get("system") or ""
    tags = s.get("tags") if isinstance(s.get("tags"), list) else []
    estimated_time = s.get("estimated_time") or ""
    notes = s.get("notes") or ""
    setting = s.get("setting") or ""
    cover_url = _normalize_cover_url(s.get("cover_url") or s.get("coverUrl"))
    cover_full_url = _normalize_optional_cover_url(s.get("cover_full_url") or s.get("coverFullUrl"))
    loss_level = s.get("loss_level") or s.get("lossLevel") or "不明"
    loss_note = s.get("loss_note") or s.get("lossNote") or None
    recommended_skills = s.get("recommended_skills") if isinstance(s.get("recommended_skills"), list) else []
    not_recommended_skills = (
        s.get("not_recommended_skills") if isinstance(s.get("not_recommended_skills"), list) else []
    )
    players_min = s.get("players_min")
    players_max = s.get("players_max")
    players_text = "—"
    players_min_int: int | None = None
    players_max_int: int | None = None
    if isinstance(players_min, (int, float, Decimal)):
        players_min_int = int(players_min)
    if isinstance(players_max, (int, float, Decimal)):
        players_max_int = int(players_max)
    if players_min_int is not None and players_max_int is not None:
        players_text = (
            f"{players_min_int}人" if players_min_int == players_max_int else f"{players_min_int}-{players_max_int}人"
        )
    elif players_min_int is not None:
        players_text = f"{players_min_int}人〜"
    elif players_max_int is not None:
        players_text = f"〜{players_max_int}人"

    ui = {
        "id": str(scenario_id),
        "title": str(title),
        "coverUrl": cover_url,
        "system": str(system),
        "durationText": str(estimated_time) if estimated_time else "—",
        "playersText": players_text,
        "tags": [str(t) for t in tags],
        "lossLevel": str(loss_level) if str(loss_level) in ("低", "中", "高", "不明") else "不明",
        "lossNote": str(loss_note) if loss_note else None,
        "description": str(notes) if notes else "（詳細は未登録）",
        "setting": str(setting),
        "recommendedSkills": [str(x) for x in recommended_skills],
        "notRecommendedSkills": [str(x) for x in not_recommended_skills],
        "estimatedTimeRaw": str(estimated_time) if estimated_time else "",
        "notesRaw": str(notes) if notes else "",
    }
    if cover_full_url:
        ui["coverFullUrl"] = cover_full_url
    if players_min_int is not None:
        ui["playersMin"] = players_min_int
    if players_max_int is not None:
        ui["playersMax"] = players_max_int

    is_handout = _coerce_bool(s.get("is_handout_scenario") or s.get("isHandoutScenario"))
    raw_handouts = s.get("handouts") if isinstance(s.get("handouts"), list) else []
    if is_handout and raw_handouts:
        handouts_ui: list[dict[str, Any]] = []
        for raw in raw_handouts[:20]:
            if not isinstance(raw, dict):
                continue
            hid = str(raw.get("id") or "").strip()
            name = str(raw.get("name") or "").strip()
            if not hid or not name:
                continue
            public_info = str(raw.get("public_info") or raw.get("publicInfo") or "").strip()
            private_info = ""
            if include_private_handouts:
                private_info = str(raw.get("private_info") or raw.get("privateInfo") or "").strip()
            order_val = raw.get("order")
            order: int | None = None
            if order_val is not None:
                try:
                    order = int(order_val)
                except Exception:
                    order = None
            payload: dict[str, Any] = {"id": hid, "name": name, "publicInfo": public_info}
            if include_private_handouts:
                payload["privateInfo"] = private_info
            if order is not None:
                payload["order"] = order
            handouts_ui.append(payload)
        if handouts_ui:
            ui["isHandoutScenario"] = True
            ui["handouts"] = handouts_ui
    if viewer_id:
        created_by = str(s.get("created_by") or "")
        is_gm_registered = False
        try:
            is_gm_registered = repositories.is_scenario_gm_registered(str(scenario_id), viewer_id)
        except Exception:
            is_gm_registered = False
        ui["isGmRegistered"] = bool(is_gm_registered)
        ui["canEdit"] = bool(created_by == viewer_id or is_gm_registered)
    return ui


def _attach_scenario_preference(ui: dict[str, Any], viewer_id: str, scenario_id: str) -> None:
    try:
        pref = repositories.get_user_scenario_preference(viewer_id, scenario_id)
    except Exception:
        pref = None
    ui["isBookmarked"] = bool(pref.get("is_bookmarked")) if pref else False
    ui["isFavorited"] = bool(pref.get("is_favorited")) if pref else False


def _session_status_to_recruiting_status(status: str) -> str:
    if status == "recruiting":
        return "recruiting"
    if status in ("confirmed", "running", "completed"):
        return "confirmed"
    return "locked"


def _session_to_recruiting_summary(session: dict) -> dict | None:
    session_id = str(session.get("session_id") or "")
    scenario_id = str(session.get("scenario_id") or "")
    if not session_id or not scenario_id:
        return None

    raw_status = str(session.get("status") or "recruiting")
    status = _session_status_to_recruiting_status(raw_status)

    try:
        participant_records = repositories.list_participant_records(session_id)
    except Exception:
        participant_records = []

    try:
        waitlist_records = repositories.list_waitlist_records(session_id)
    except Exception:
        waitlist_records = []

    applicants: list[dict[str, Any]] = []
    for p in participant_records:
        user_id = str(p.get("user_id") or "")
        if not user_id:
            continue
        name = str(p.get("display_name") or user_id)
        avatar_url = None
        try:
            prof = repositories.get_user_profile(user_id)
            avatar_url = (prof or {}).get("avatar_url") or None
        except Exception:
            avatar_url = None

        applicant: dict[str, Any] = {"id": user_id, "name": name}
        if avatar_url:
            applicant["avatarUrl"] = str(avatar_url)
        applicants.append(applicant)

    waitlist: list[dict[str, Any]] = []
    for w in waitlist_records:
        user_id = str(w.get("user_id") or "")
        if not user_id:
            continue
        name = str(w.get("display_name") or user_id)
        avatar_url = None
        try:
            prof = repositories.get_user_profile(user_id)
            avatar_url = (prof or {}).get("avatar_url") or None
        except Exception:
            avatar_url = None

        entry: dict[str, Any] = {"id": user_id, "name": name}
        if avatar_url:
            entry["avatarUrl"] = str(avatar_url)
        waitlist.append(entry)

    max_players = _parse_int(session.get("max_players"), default=0) or 0
    remaining_seats = max(0, int(max_players) - len(applicants)) if int(max_players) > 0 else 0

    deadline = None
    try:
        poll = repositories.latest_poll_for_session(session_id)
        if poll and poll.get("deadline"):
            deadline = str(poll.get("deadline"))
    except Exception:
        deadline = None

    teaser_slots = session.get("teaser_slots") if isinstance(session.get("teaser_slots"), list) else None

    flow_mode = str(session.get("flow_mode") or "people_first")
    if flow_mode not in ("people_first", "schedule_first"):
        flow_mode = "people_first"

    fixed_schedule_raw = session.get("fixed_schedule")
    fixed_schedule = None
    if isinstance(fixed_schedule_raw, list) and fixed_schedule_raw:
        normalized: list[dict[str, Any]] = []
        for raw in fixed_schedule_raw[:20]:
            if not isinstance(raw, dict):
                continue
            start_at = raw.get("startAt") or raw.get("start_at")
            if not start_at:
                continue
            item_id = str(raw.get("id") or "")
            if not item_id:
                continue
            item: dict[str, Any] = {
                "id": item_id,
                "label": str(raw.get("label") or "開催日"),
                "startAt": str(start_at),
            }
            end_at = raw.get("endAt") or raw.get("end_at")
            if end_at:
                item["endAt"] = str(end_at)
            normalized.append(item)
        if normalized:
            fixed_schedule = normalized

    gm_name = "未定"
    gm_user_id = session.get("gm_user_id")
    if gm_user_id:
        try:
            prof = repositories.get_user_profile(str(gm_user_id))
            gm_name = str((prof or {}).get("display_name_cache") or gm_user_id)
        except Exception:
            gm_name = str(gm_user_id)

    summary: dict[str, Any] = {
        "sessionId": session_id,
        "scenarioId": scenario_id,
        "status": status,
        "remainingSeats": remaining_seats,
        "applicants": applicants,
        "waitlist": waitlist,
        "maxPlayers": int(max_players),
        "gmName": gm_name,
        "flowMode": flow_mode,
    }
    if gm_user_id:
        summary["gmUserId"] = str(gm_user_id)
    if deadline:
        summary["deadline"] = deadline
    if teaser_slots:
        summary["teaserSlots"] = teaser_slots
    if fixed_schedule is not None:
        summary["fixedSchedule"] = fixed_schedule
    return summary


def _coerce_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return []


def _coerce_completion_achievements(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for raw in value[:20]:
        if not isinstance(raw, dict):
            continue
        title = str(raw.get("title") or "").strip()
        if not title:
            continue
        payload: dict[str, Any] = {
            "title": title,
            "description": str(raw.get("description") or "").strip(),
            "is_spoiler": bool(raw.get("isSpoiler") or raw.get("is_spoiler")),
        }
        ach_id = raw.get("id") or raw.get("achievementId") or raw.get("achievement_id")
        if isinstance(ach_id, str) and ach_id.strip():
            payload["id"] = ach_id.strip()
        items.append(payload)
    return items


def _coerce_handouts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for raw in value[:20]:
        if not isinstance(raw, dict):
            continue
        handout_id = str(raw.get("id") or raw.get("handoutId") or raw.get("handout_id") or "").strip()
        name = str(raw.get("name") or "").strip()
        if not handout_id or not name:
            continue
        public_info = str(raw.get("publicInfo") or raw.get("public_info") or "").strip()
        private_info = str(raw.get("privateInfo") or raw.get("private_info") or "").strip()
        order_raw = raw.get("order")
        order: int | None = None
        if order_raw is not None:
            try:
                order = int(order_raw)
            except Exception:
                order = None
        item: dict[str, Any] = {
            "id": handout_id,
            "name": name,
            "public_info": public_info,
            "private_info": private_info,
        }
        if order is not None:
            item["order"] = order
        items.append(item)
    return items


def _parse_int(value: Any, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float, Decimal)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return False


def _parse_iso_datetime(value: str) -> datetime:
    raw = str(value).strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_user_datetime(value: str, default_tz: timezone = JST) -> datetime:
    raw = str(value).strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt.astimezone(timezone.utc)


def _duration_hours_from_session(session: dict, default_hours: int = 4) -> int:
    raw = str(session.get("duration") or "").strip()
    if not raw:
        return default_hours
    numbers = [int(n) for n in re.findall(r"\d+", raw) if n.isdigit()]
    if not numbers:
        return default_hours
    hours = max(numbers)
    return max(1, min(hours, 24))


def _format_slot_label(start_iso: str) -> str:
    try:
        dt = _parse_iso_datetime(start_iso).astimezone(JST)
        weekday = WEEKDAYS_JA[dt.weekday()]
        return f"{dt.month}/{dt.day} ({weekday}) {dt.hour:02d}:{dt.minute:02d}〜"
    except Exception:
        return start_iso


def _session_gm_user_id(session: dict) -> str | None:
    gm_user_id = session.get("gm_user_id")
    if gm_user_id:
        return str(gm_user_id)
    return None


def _session_gm_name(session: dict, gm_user_id: str | None) -> str:
    if session.get("gm_name"):
        return str(session.get("gm_name"))
    if gm_user_id:
        prof = repositories.get_user_profile(gm_user_id)
        if prof and prof.get("display_name_cache"):
            return str(prof["display_name_cache"])
        return gm_user_id
    return "未定"


def _user_avatar_url(user_id: str) -> str | None:
    user_id = str(user_id or "").strip()
    if not user_id:
        return None
    return f"/proxy/api/users/{user_id}/avatar"

def _handle_user_avatar(event: dict, user_id: str) -> dict:
    if _get_method(event) != "GET":
        return {"statusCode": 405, "headers": _cors_headers(), "body": "method not allowed"}

    try:
        prof = repositories.get_user_profile(user_id) or {}
    except Exception:
        prof = {}

    avatar_url = str(prof.get("avatar_url") or "").strip()
    if not avatar_url:
        # Fallback: Discord default avatar.
        default_index = 0
        try:
            default_index = (int(str(user_id)) >> 22) % 6
        except Exception:
            default_index = 0
        avatar_url = f"https://cdn.discordapp.com/embed/avatars/{default_index}.png?size=128"

    # SSRF hardening: only allow Discord CDN hosts.
    try:
        parsed = urlparse(avatar_url)
        if parsed.scheme != "https":
            return {"statusCode": 404, "headers": _cors_headers(), "body": "not found"}
        if parsed.netloc not in ("cdn.discordapp.com", "media.discordapp.net"):
            return {"statusCode": 404, "headers": _cors_headers(), "body": "not found"}
    except Exception:
        return {"statusCode": 404, "headers": _cors_headers(), "body": "not found"}

    try:
        resp = requests.get(avatar_url, timeout=10)
        if resp.status_code >= 300:
            return {"statusCode": 404, "headers": _cors_headers(), "body": "not found"}
        content_type = str(resp.headers.get("content-type") or "image/png").split(";", 1)[0].strip()
        if not content_type.startswith("image/"):
            return {"statusCode": 502, "headers": _cors_headers(), "body": "invalid content type"}
        return _binary_response(
            resp.content,
            content_type,
            status=200,
            extra_headers={"Cache-Control": "public, max-age=3600"},
        )
    except Exception:
        logger.exception("Failed to proxy avatar")
        return {"statusCode": 502, "headers": _cors_headers(), "body": "proxy failed"}


def _list_scenarios_for_ui(keyword: str | None, limit: int) -> list[dict]:
    if keyword and isinstance(keyword, str) and keyword.strip():
        return repositories.search_scenarios(keyword.strip(), limit=limit)
    return repositories.list_scenarios(limit=limit)


def _handle_scenarios(event: dict) -> dict:
    method = _get_method(event)
    if method not in ("GET", "POST"):
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    if method == "POST":
        body = _parse_json_body(event)
        title = body.get("title")
        if not title or not isinstance(title, str) or not title.strip():
            return _response({"error": "Missing 'title'"}, status=400)

        system = str(body.get("system") or "")
        estimated_time = str(body.get("estimated_time") or body.get("estimatedTime") or "")
        tags = _coerce_str_list(body.get("tags"))
        notes = str(body.get("notes") or body.get("description") or "")

        setting = str(body.get("setting") or "")
        loss_level = str(body.get("lossLevel") or body.get("loss_level") or "不明")
        loss_note = body.get("lossNote") or body.get("loss_note") or None
        cover_url = str(body.get("coverUrl") or body.get("cover_url") or "") or None
        cover_full_url = str(body.get("coverFullUrl") or body.get("cover_full_url") or "").strip() or None

        recommended_skills = _coerce_str_list(body.get("recommendedSkills") or body.get("recommended_skills"))
        not_recommended_skills = _coerce_str_list(
            body.get("notRecommendedSkills") or body.get("not_recommended_skills")
        )
        completion_achievements = _coerce_completion_achievements(
            body.get("completionAchievements") or body.get("completion_achievements")
        )

        is_handout_scenario = _coerce_bool(body.get("isHandoutScenario") or body.get("is_handout_scenario"))
        handouts = _coerce_handouts(body.get("handouts") or body.get("handout_list") or body.get("handoutList"))
        if is_handout_scenario:
            if not handouts:
                return _response({"error": "handouts must be provided for HO scenarios"}, status=400)
            deduped: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            for ho in handouts:
                hid = str(ho.get("id") or "")
                if not hid or hid in seen_ids:
                    continue
                seen_ids.add(hid)
                deduped.append(ho)
            handouts = deduped

        players_min_raw = body.get("playersMin") if "playersMin" in body else body.get("players_min")
        players_max_raw = body.get("playersMax") if "playersMax" in body else body.get("players_max")
        players_min = _parse_int(players_min_raw)
        players_max = _parse_int(players_max_raw)
        if players_min is not None and players_min < 1:
            return _response({"error": "Invalid playersMin"}, status=400)
        if players_max is not None and players_max < 1:
            return _response({"error": "Invalid playersMax"}, status=400)
        if players_min is not None and players_max is not None and players_min > players_max:
            return _response({"error": "Invalid playersMin/playersMax"}, status=400)

        try:
            scenario_id = repositories.create_scenario(
                title=title.strip(),
                system=system,
                estimated_time=estimated_time,
                tags=tags,
                notes=notes,
                created_by=actor_id,
                setting=setting,
                recommended_skills=recommended_skills,
                not_recommended_skills=not_recommended_skills,
                loss_level=loss_level,
                loss_note=str(loss_note) if loss_note else None,
                cover_url=cover_url,
                cover_full_url=cover_full_url,
                players_min=players_min,
                players_max=players_max,
                completion_achievements=completion_achievements,
                is_handout_scenario=is_handout_scenario,
                handouts=handouts if is_handout_scenario else None,
            )
            created = repositories.get_scenario(scenario_id) or {"scenario_id": scenario_id, "title": title.strip()}
            try:
                for ach in created.get("completion_achievements") or []:
                    if not isinstance(ach, dict):
                        continue
                    ach_id = str(ach.get("id") or "").strip()
                    ach_title = str(ach.get("title") or "").strip()
                    if not ach_id or not ach_title:
                        continue
                    repositories.upsert_achievement_definition(
                        ach_id,
                        ach_title,
                        str(ach.get("description") or "").strip(),
                        category="scenario",
                        is_spoiler=bool(ach.get("is_spoiler")),
                        trigger="manual",
                        scenario_id=scenario_id,
                    )
            except Exception:
                logger.exception("Failed to upsert completion achievement definitions")
            try:
                repositories.create_notification(
                    actor_id,
                    "system",
                    "シナリオの登録が完了しました",
                    title.strip(),
                    action_label="確認",
                    action_target=f"/browse?scenario={scenario_id}&returnTo=/notifications",
                    icon_type="check",
                )
            except Exception:
                logger.exception("Failed to create notification for scenario create")
            return _response(
                {"scenario": _scenario_to_ui(created, viewer_id=actor_id, include_private_handouts=True)}, status=201
            )
        except Exception as exc:
            logger.exception("Scenario create failed")
            return _response({"error": str(exc)}, status=500)

    qp = _get_query_params(event)
    raw_limit = qp.get("limit") if isinstance(qp, dict) else None
    try:
        limit = int(raw_limit) if raw_limit is not None else 50
    except Exception:
        limit = 50

    keyword = qp.get("q") if isinstance(qp, dict) else None
    try:
        items = _list_scenarios_for_ui(str(keyword) if keyword is not None else None, limit=limit)
        scenarios = []
        for s in items:
            try:
                gm_count = len(repositories.list_capable_gms(str(s.get("scenario_id") or ""))) if s.get("scenario_id") else 0
            except Exception:
                gm_count = 0
            ui = _scenario_to_ui(s, viewer_id=actor_id)
            ui["availableGmCount"] = gm_count
            scenarios.append(ui)
        return _response({"scenarios": scenarios}, status=200)
    except Exception as exc:
        logger.exception("Scenario list failed")
        return _response({"error": str(exc)}, status=500)


def _handle_browse(event: dict) -> dict:
    if _get_method(event) != "GET":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    qp = _get_query_params(event)

    raw_limit = qp.get("limit") if isinstance(qp, dict) else None
    try:
        limit = int(raw_limit) if raw_limit is not None else 5
    except Exception:
        limit = 5
    limit = max(1, min(limit, 50))

    keyword = qp.get("q") if isinstance(qp, dict) else None
    row_id = str((qp.get("row") or qp.get("rowId") or qp.get("row_id") or "") if isinstance(qp, dict) else "").strip()
    cursor_token = (
        str((qp.get("cursor") or qp.get("nextCursor") or qp.get("pageToken") or "") if isinstance(qp, dict) else "")
        .strip()
        or None
    )

    def _encode_cursor(value: Any) -> str | None:
        if not value or not isinstance(value, dict):
            return None
        try:
            raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            return base64.urlsafe_b64encode(raw).decode("ascii")
        except Exception:
            return None

    def _decode_cursor(token: str | None) -> dict | None:
        if not token:
            return None
        try:
            raw = base64.urlsafe_b64decode(token.encode("ascii"))
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None

    cursor_data = _decode_cursor(cursor_token)

    try:
        recruiting_sessions: list[dict] = []
        try:
            recruiting_sessions = repositories.list_sessions_by_status("recruiting", limit=200)
        except Exception:
            recruiting_sessions = []

        recruiting_by_scenario: dict[str, dict] = {}
        for ses in recruiting_sessions:
            scenario_id = str(ses.get("scenario_id") or "")
            if not scenario_id:
                continue
            prev = recruiting_by_scenario.get(scenario_id)
            if not prev or str(ses.get("created_at") or "") > str(prev.get("created_at") or ""):
                recruiting_by_scenario[scenario_id] = ses

        def _scenario_ui(s: dict, *, include_recruiting: bool = True, pref: dict | None = None) -> dict:
            try:
                gm_count = len(repositories.list_capable_gms(str(s.get("scenario_id") or ""))) if s.get("scenario_id") else 0
            except Exception:
                gm_count = 0
            ui = _scenario_to_ui(s, viewer_id=actor_id)
            if pref:
                ui["isBookmarked"] = bool(pref.get("is_bookmarked"))
                ui["isFavorited"] = bool(pref.get("is_favorited"))
            else:
                ui["isBookmarked"] = False
                ui["isFavorited"] = False
            ui["availableGmCount"] = gm_count
            if include_recruiting:
                scenario_id = str(s.get("scenario_id") or "")
                if scenario_id and scenario_id in recruiting_by_scenario:
                    summary = _session_to_recruiting_summary(recruiting_by_scenario[scenario_id])
                    if summary:
                        ui["recruiting"] = summary
            return ui

        def _beta_mean(successes: int, trials: int, alpha: float, beta: float) -> float:
            s = max(0.0, float(successes))
            t = max(0.0, float(trials))
            return (s + alpha) / (t + alpha + beta) if (t + alpha + beta) > 0 else 0.0

        def _dwell_median_ms(stats: dict) -> float:
            bucket_keys = [
                "detail_dwell_b0_count",
                "detail_dwell_b1_count",
                "detail_dwell_b2_count",
                "detail_dwell_b3_count",
                "detail_dwell_b4_count",
                "detail_dwell_b5_count",
            ]
            counts: list[int] = []
            total = 0
            for k in bucket_keys:
                raw = stats.get(k) if isinstance(stats, dict) else 0
                try:
                    n = int(raw) if raw is not None else 0
                except Exception:
                    n = 0
                n = max(0, n)
                counts.append(n)
                total += n
            if total <= 0:
                try:
                    dv = int(stats.get("detail_view_count") or 0)
                    ds = float(stats.get("detail_dwell_ms_sum") or 0)
                    return ds / dv if dv > 0 else 0.0
                except Exception:
                    return 0.0

            # Representative median values (ms) for each bucket.
            # 0:<2s, 1:<5s, 2:<15s, 3:<60s, 4:<300s, 5:>=300s
            reps = [1_000, 3_500, 10_000, 30_000, 120_000, 420_000]
            target = (total + 1) // 2
            acc = 0
            for idx, n in enumerate(counts):
                acc += n
                if acc >= target:
                    return float(reps[idx])
            return float(reps[-1])

        def _dwell_score(stats: dict) -> float:
            ms = _dwell_median_ms(stats)
            seconds = max(0.0, ms / 1000.0)
            # Normalize to [0, 1] with log scale (2 min ~= 1.0).
            denom = math.log1p(120.0)
            if denom <= 0:
                return 0.0
            return max(0.0, min(1.0, math.log1p(seconds) / denom))

        def _compute_scores(
            scenarios: list[dict],
            *,
            actor_id: str,
            exclude_ids: set[str],
        ) -> tuple[list[dict], dict[str, dict], dict[str, dict], dict[str, dict]]:
            candidates: list[dict] = []
            ids: list[str] = []
            seen: set[str] = set()
            for s in scenarios:
                sid = str(s.get("scenario_id") or "").strip()
                if not sid or sid in exclude_ids or sid in seen:
                    continue
                seen.add(sid)
                candidates.append(s)
                ids.append(sid)

            if not ids:
                return [], {}, {}, {}

            stats_map = repositories.batch_get_scenario_stats(ids)
            metric_map = repositories.batch_get_user_scenario_metrics(actor_id, ids)
            pref_map = repositories.batch_get_user_scenario_preferences(actor_id, ids)

            # Priors (tune freely)
            alpha_start, beta_start = 1.0, 6.0
            alpha_fav, beta_fav = 1.0, 20.0
            alpha_comp, beta_comp = 1.0, 2.0

            now = datetime.now(timezone.utc)
            scored: list[dict] = []
            for s in candidates:
                sid = str(s.get("scenario_id") or "").strip()
                if not sid:
                    continue
                stats = stats_map.get(sid) or {}
                metrics = metric_map.get(sid) or {}

                def _int(v: Any) -> int:
                    try:
                        return max(0, int(v))
                    except Exception:
                        return 0

                detail_views = _int(stats.get("detail_view_count"))
                starts = _int(stats.get("session_created_count"))
                completes = _int(stats.get("session_completed_count"))
                favorites = _int(stats.get("favorite_count"))
                user_impressions = _int(metrics.get("impression_count"))

                start_rate = _beta_mean(starts, detail_views, alpha_start, beta_start)
                fav_rate = _beta_mean(favorites, detail_views, alpha_fav, beta_fav)
                comp_rate = _beta_mean(completes, starts, alpha_comp, beta_comp)
                dwell = _dwell_score(stats)

                quality = 0.45 * fav_rate + 0.25 * comp_rate + 0.20 * start_rate + 0.10 * dwell

                # Trend: weighted log(1+x) (normalized by log2 for x∈[0,1])
                log2 = math.log(2.0)
                trend = 0.0
                if log2 > 0:
                    trend = (
                        0.6 * (math.log1p(start_rate) / log2)
                        + 0.4 * (math.log1p(fav_rate) / log2)
                    )

                penalty = 0.12 * math.log1p(float(user_impressions))

                created_at = str(s.get("created_at") or "")
                try:
                    created_dt = _parse_iso_datetime(created_at)
                except Exception:
                    created_dt = now
                age_days = max(0.0, (now - created_dt).total_seconds() / 86400.0)

                decay_days = 21.0
                freshness = math.exp(-age_days / decay_days) if decay_days > 0 else 1.0
                new_score = freshness * (0.25 + quality) - 0.06 * math.log1p(float(user_impressions))
                rec_score = 0.55 * quality + 0.30 * trend - penalty

                scored.append(
                    {
                        "scenario": s,
                        "scenario_id": sid,
                        "created_by": str(s.get("created_by") or ""),
                        "system": str(s.get("system") or ""),
                        "tags": [str(t) for t in (s.get("tags") if isinstance(s.get("tags"), list) else [])],
                        "age_days": float(age_days),
                        "new_score": float(new_score),
                        "rec_score": float(rec_score),
                    }
                )

            scored.sort(key=lambda x: x["rec_score"], reverse=True)
            return scored, stats_map, metric_map, pref_map

        def _similarity(a: dict, b: dict) -> float:
            sim = 0.0
            if a.get("created_by") and a.get("created_by") == b.get("created_by"):
                sim += 1.0
            if a.get("system") and a.get("system") == b.get("system"):
                sim += 0.2
            tags_a = {t.lower() for t in (a.get("tags") or []) if isinstance(t, str) and t}
            tags_b = {t.lower() for t in (b.get("tags") or []) if isinstance(t, str) and t}
            if tags_a and tags_b:
                inter = len(tags_a & tags_b)
                union = len(tags_a | tags_b)
                if union:
                    sim += 0.4 * (inter / union)
            return min(1.0, sim)

        def _mmr_select(items: list[dict], score_key: str, k: int) -> list[dict]:
            mmr_lambda = 0.75
            sim_weight = 0.8
            author_repeat_penalty = 0.15

            selected: list[dict] = []
            remaining = items[:]

            while remaining and len(selected) < k:
                best = None
                best_score = -1e18
                for cand in remaining:
                    base = float(cand.get(score_key) or 0.0)
                    max_sim = 0.0
                    if selected:
                        max_sim = max(_similarity(cand, s) for s in selected)
                    author_repeats = 0
                    c_author = str(cand.get("created_by") or "")
                    if c_author:
                        author_repeats = sum(1 for s in selected if str(s.get("created_by") or "") == c_author)
                    score = mmr_lambda * base - (1.0 - mmr_lambda) * (max_sim * sim_weight) - author_repeats * author_repeat_penalty
                    if score > best_score:
                        best_score = score
                        best = cand
                if not best:
                    break
                selected.append(best)
                remaining.remove(best)
            return selected

        def _gather_recent_scenarios(max_candidates: int = 400) -> list[dict]:
            gathered: list[dict] = []
            cursor = None
            while len(gathered) < max_candidates:
                page, cursor = repositories.list_scenarios_page(limit=min(200, max_candidates - len(gathered)), cursor=cursor)
                gathered.extend(page)
                if not cursor:
                    break
            return gathered

        def _build_rank_rows() -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
            if keyword and isinstance(keyword, str) and keyword.strip():
                return None, None

            candidates = _gather_recent_scenarios(max_candidates=400)
            exclude_ids = set(recruiting_by_scenario.keys())
            scored, _stats_map, _metric_map, pref_map = _compute_scores(candidates, actor_id=actor_id, exclude_ids=exclude_ids)
            if not scored:
                return None, None

            rank_limit = max(10, limit)

            # Recommended: best by rec_score (diversified by MMR)
            rec_sorted = sorted(scored, key=lambda x: x["rec_score"], reverse=True)[:200]
            rec_selected = _mmr_select(rec_sorted, "rec_score", rank_limit)

            # New: best by new_score (diversified by MMR)
            selected_ids = {str(e.get("scenario_id") or "") for e in rec_selected}
            new_candidates = [e for e in scored if str(e.get("scenario_id") or "") not in selected_ids and float(e.get("age_days") or 0.0) <= 60.0]
            new_sorted = sorted(new_candidates, key=lambda x: x["new_score"], reverse=True)[:200]
            new_selected = _mmr_select(new_sorted, "new_score", rank_limit)

            def _to_ui(entry: dict) -> dict:
                s = entry["scenario"]
                sid = entry["scenario_id"]
                ui = _scenario_ui(s, include_recruiting=False, pref=pref_map.get(sid))
                return ui

            rec_ui = [_to_ui(e) for e in rec_selected]
            new_ui = [_to_ui(e) for e in new_selected]

            rec_row = {"id": "recommended", "title": "おすすめ", "scenarios": rec_ui} if rec_ui else None
            new_row = {"id": "new", "title": "新着", "scenarios": new_ui} if new_ui else None
            return rec_row, new_row

        def _build_registered_row() -> dict[str, Any]:
            next_key = None
            if keyword and isinstance(keyword, str) and keyword.strip():
                items = repositories.search_scenarios(keyword.strip(), limit=limit)
            else:
                items, next_key = repositories.list_scenarios_page(limit=limit, cursor=cursor_data)
            scenario_ids = [str(s.get("scenario_id") or "") for s in items if s.get("scenario_id")]
            pref_map = repositories.batch_get_user_scenario_preferences(actor_id, scenario_ids)
            scenarios_ui = [
                _scenario_ui(s, include_recruiting=True, pref=pref_map.get(str(s.get("scenario_id") or ""))) for s in items
            ]
            row: dict[str, Any] = {"id": "registered", "title": "登録済みのシナリオ", "scenarios": scenarios_ui}
            encoded = _encode_cursor(next_key)
            if encoded:
                row["nextCursor"] = encoded
            return row

        def _build_recruiting_row() -> dict[str, Any] | None:
            # Cursor is an offset for the recruiting row (because we dedupe by scenario).
            offset = 0
            if cursor_data and "offset" in cursor_data:
                try:
                    offset = int(cursor_data.get("offset") or 0)
                except Exception:
                    offset = 0
            offset = max(0, offset)

            sessions_sorted = list(recruiting_by_scenario.values())
            # Sort by a "formation likelihood" score that prioritizes:
            # - quality (scenario-level)
            # - recent activity (session-level)
            # - deadline proximity (session-level)
            now = datetime.now(timezone.utc)

            session_ids_all: list[str] = []
            scenario_ids_all: list[str] = []
            for ses in sessions_sorted:
                sid = str(ses.get("session_id") or "").strip()
                if sid:
                    session_ids_all.append(sid)
                scid = str(ses.get("scenario_id") or "").strip()
                if scid:
                    scenario_ids_all.append(scid)

            session_meta_map = repositories.batch_get_sessions(session_ids_all)

            # Some older index entries may miss scenario_id; prefer META when available.
            scenario_ids_all = []
            for sid in session_ids_all:
                meta = session_meta_map.get(sid) or {}
                scid = str(meta.get("scenario_id") or "").strip()
                if scid:
                    scenario_ids_all.append(scid)
            if not scenario_ids_all:
                # Fallback: use IDs from index entries.
                for ses in sessions_sorted:
                    scid = str(ses.get("scenario_id") or "").strip()
                    if scid:
                        scenario_ids_all.append(scid)

            scenario_stats_map = repositories.batch_get_scenario_stats(list(dict.fromkeys(scenario_ids_all)))

            alpha_start, beta_start = 1.0, 6.0
            alpha_fav, beta_fav = 1.0, 20.0
            alpha_comp, beta_comp = 1.0, 2.0

            def _int(v: Any) -> int:
                try:
                    return max(0, int(v))
                except Exception:
                    return 0

            def _scenario_quality(scenario_id: str) -> float:
                stats = scenario_stats_map.get(scenario_id) or {}
                detail_views = _int(stats.get("detail_view_count"))
                starts = _int(stats.get("session_created_count"))
                completes = _int(stats.get("session_completed_count"))
                favorites = _int(stats.get("favorite_count"))

                start_rate = _beta_mean(starts, detail_views, alpha_start, beta_start)
                fav_rate = _beta_mean(favorites, detail_views, alpha_fav, beta_fav)
                comp_rate = _beta_mean(completes, starts, alpha_comp, beta_comp)
                dwell = _dwell_score(stats)

                return float(0.45 * fav_rate + 0.25 * comp_rate + 0.20 * start_rate + 0.10 * dwell)

            def _safe_dt(value: Any) -> datetime | None:
                raw = str(value or "").strip()
                if not raw:
                    return None
                try:
                    return _parse_iso_datetime(raw)
                except Exception:
                    return None

            def _last_activity_dt(meta: dict, ses_index: dict) -> datetime:
                for key in ("last_activity_at", "updated_at", "created_at"):
                    dt = _safe_dt(meta.get(key) if isinstance(meta, dict) else None) or _safe_dt(ses_index.get(key))
                    if dt:
                        return dt
                return now

            def _deadline_dt(meta: dict, ses_index: dict) -> datetime | None:
                candidates: list[datetime] = []

                fixed_schedule = meta.get("fixed_schedule") if isinstance(meta, dict) else None
                if not isinstance(fixed_schedule, list):
                    fixed_schedule = ses_index.get("fixed_schedule") if isinstance(ses_index, dict) else None
                if isinstance(fixed_schedule, list):
                    for item in fixed_schedule[:50]:
                        if not isinstance(item, dict):
                            continue
                        start_at = item.get("startAt") or item.get("start_at")
                        dt = _safe_dt(start_at)
                        if dt:
                            candidates.append(dt)

                teaser_slots = meta.get("teaser_slots") if isinstance(meta, dict) else None
                if not isinstance(teaser_slots, list):
                    teaser_slots = ses_index.get("teaser_slots") if isinstance(ses_index, dict) else None
                if isinstance(teaser_slots, list):
                    for slot in teaser_slots[:50]:
                        if not isinstance(slot, dict):
                            continue
                        if str(slot.get("kind") or "").strip().lower() != "exact":
                            continue
                        start_at = slot.get("startAt") or slot.get("start_at")
                        dt = _safe_dt(start_at)
                        if dt:
                            candidates.append(dt)

                if not candidates:
                    return None
                return min(candidates)

            def _formation_score(ses_index: dict) -> tuple[float, float, float, str]:
                session_id = str(ses_index.get("session_id") or "").strip()
                meta = session_meta_map.get(session_id) or {}
                scenario_id = str((meta.get("scenario_id") if isinstance(meta, dict) else "") or ses_index.get("scenario_id") or "").strip()

                quality = _scenario_quality(scenario_id) if scenario_id else 0.0

                act_dt = _last_activity_dt(meta, ses_index)
                age_days = max(0.0, (now - act_dt).total_seconds() / 86400.0)
                activity_score = math.exp(-age_days / 7.0) if age_days > 0 else 1.0

                dl_dt = _deadline_dt(meta, ses_index)
                if dl_dt and dl_dt <= now:
                    deadline_score = 0.0
                elif dl_dt:
                    days_to = max(0.0, (dl_dt - now).total_seconds() / 86400.0)
                    deadline_score = math.exp(-days_to / 10.0) if days_to > 0 else 1.0
                else:
                    deadline_score = 0.25

                score = 0.55 * quality + 0.30 * activity_score + 0.15 * deadline_score
                if dl_dt and dl_dt <= now:
                    score *= 0.15

                # Tie-breakers: newer activity, then newer create.
                created_dt = _safe_dt(meta.get("created_at") if isinstance(meta, dict) else None) or _safe_dt(ses_index.get("created_at")) or now
                created_ts = created_dt.timestamp()
                return (float(score), float(act_dt.timestamp()), float(created_ts), session_id)

            sessions_sorted.sort(key=_formation_score, reverse=True)
            page = sessions_sorted[offset : offset + limit]
            if not page:
                return None

            scenario_ids_for_pref: list[str] = []
            for ses in page:
                session_id = str(ses.get("session_id") or "").strip()
                meta = session_meta_map.get(session_id) or {}
                scenario_id = str((meta.get("scenario_id") if isinstance(meta, dict) else "") or ses.get("scenario_id") or "").strip()
                if scenario_id:
                    scenario_ids_for_pref.append(scenario_id)
            pref_map = repositories.batch_get_user_scenario_preferences(actor_id, scenario_ids_for_pref)

            scenarios_ui: list[dict[str, Any]] = []
            for ses in page:
                session_id = str(ses.get("session_id") or "").strip()
                meta = session_meta_map.get(session_id) or {}
                scenario_id = str((meta.get("scenario_id") if isinstance(meta, dict) else "") or ses.get("scenario_id") or "").strip()
                if not scenario_id:
                    continue
                scenario = repositories.get_scenario(scenario_id) or {}
                if not scenario:
                    continue
                ui = _scenario_ui(scenario, include_recruiting=False, pref=pref_map.get(scenario_id))
                full_session = session_meta_map.get(session_id) or ses
                summary = _session_to_recruiting_summary(full_session)
                if summary:
                    ui["recruiting"] = summary
                scenarios_ui.append(ui)

            if not scenarios_ui:
                return None

            next_offset = offset + limit
            row: dict[str, Any] = {"id": "recruiting", "title": "募集中", "scenarios": scenarios_ui}
            if next_offset < len(sessions_sorted):
                encoded = _encode_cursor({"offset": next_offset})
                if encoded:
                    row["nextCursor"] = encoded
            return row

        if row_id == "registered":
            return _response({"rows": [_build_registered_row()]}, status=200)
        if row_id == "recruiting":
            recruiting_row = _build_recruiting_row()
            return _response({"rows": [recruiting_row] if recruiting_row else []}, status=200)
        if row_id == "recommended":
            rec_row, _new_row = _build_rank_rows()
            return _response({"rows": [rec_row] if rec_row else []}, status=200)
        if row_id == "new":
            _rec_row, new_row = _build_rank_rows()
            return _response({"rows": [new_row] if new_row else []}, status=200)

        rows: list[dict[str, Any]] = []
        recruiting_row = _build_recruiting_row()
        if recruiting_row:
            rows.append(recruiting_row)
        rec_row, new_row = _build_rank_rows()
        if rec_row:
            rows.append(rec_row)
        if new_row:
            rows.append(new_row)
        rows.append(_build_registered_row())
        return _response({"rows": rows}, status=200)
    except Exception as exc:
        logger.exception("Browse failed")
        return _response({"error": str(exc)}, status=500)


def _handle_scenario_detail(event: dict, scenario_id: str) -> dict:
    method = _get_method(event)
    if method not in ("GET", "PUT", "PATCH"):
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    if method in ("PUT", "PATCH"):
        scenario = repositories.get_scenario(scenario_id)
        if not scenario:
            return _response({"error": "not found"}, status=404)
        created_by = str(scenario.get("created_by") or "")
        is_gm_registered = False
        try:
            is_gm_registered = repositories.is_scenario_gm_registered(scenario_id, actor_id)
        except Exception:
            is_gm_registered = False
        if not (created_by and created_by == actor_id) and not is_gm_registered:
            return _response({"error": "forbidden"}, status=403)

        body = _parse_json_body(event)
        if not isinstance(body, dict):
            body = {}

        title = str(body.get("title") or scenario.get("title") or "").strip()
        if not title:
            return _response({"error": "Missing 'title'"}, status=400)

        system_raw = body.get("system") if "system" in body else scenario.get("system")
        system = str(system_raw or "")

        if "estimatedTime" in body:
            estimated_time_raw = body.get("estimatedTime")
        elif "estimated_time" in body:
            estimated_time_raw = body.get("estimated_time")
        elif "estimatedTime" in scenario:
            estimated_time_raw = scenario.get("estimatedTime")
        else:
            estimated_time_raw = scenario.get("estimated_time")
        estimated_time = str(estimated_time_raw or "")

        tags = _coerce_str_list(body.get("tags")) if "tags" in body else _coerce_str_list(scenario.get("tags"))
        if "notes" in body:
            notes_raw = body.get("notes")
        elif "description" in body:
            notes_raw = body.get("description")
        else:
            notes_raw = scenario.get("notes")
        notes = str(notes_raw or "")

        setting_raw = body.get("setting") if "setting" in body else scenario.get("setting")
        setting = str(setting_raw or "")
        loss_level = str(body.get("lossLevel") or body.get("loss_level") or scenario.get("loss_level") or "不明")
        loss_note_raw = body.get("lossNote") if "lossNote" in body else scenario.get("loss_note")
        if loss_note_raw is None:
            loss_note_raw = body.get("loss_note") if "loss_note" in body else scenario.get("loss_note")
        loss_note = str(loss_note_raw).strip() if loss_note_raw is not None and str(loss_note_raw).strip() else None

        cover_url_raw = body.get("coverUrl") if "coverUrl" in body else scenario.get("cover_url")
        if cover_url_raw is None:
            cover_url_raw = body.get("cover_url") if "cover_url" in body else scenario.get("cover_url")
        cover_url = str(cover_url_raw).strip() if cover_url_raw is not None and str(cover_url_raw).strip() else None

        cover_full_url_raw = body.get("coverFullUrl") if "coverFullUrl" in body else scenario.get("cover_full_url")
        if cover_full_url_raw is None:
            cover_full_url_raw = body.get("cover_full_url") if "cover_full_url" in body else scenario.get("cover_full_url")
        cover_full_url = (
            str(cover_full_url_raw).strip()
            if cover_full_url_raw is not None and str(cover_full_url_raw).strip()
            else None
        )

        recommended_skills = (
            _coerce_str_list(body.get("recommendedSkills") or body.get("recommended_skills"))
            if ("recommendedSkills" in body or "recommended_skills" in body)
            else _coerce_str_list(scenario.get("recommended_skills"))
        )
        not_recommended_skills = (
            _coerce_str_list(body.get("notRecommendedSkills") or body.get("not_recommended_skills"))
            if ("notRecommendedSkills" in body or "not_recommended_skills" in body)
            else _coerce_str_list(scenario.get("not_recommended_skills"))
        )

        players_min_raw = body.get("playersMin") if "playersMin" in body else body.get("players_min")
        players_max_raw = body.get("playersMax") if "playersMax" in body else body.get("players_max")
        has_players = ("playersMin" in body or "playersMax" in body or "players_min" in body or "players_max" in body)
        players_min = _parse_int(players_min_raw) if has_players else _parse_int(scenario.get("players_min"))
        players_max = _parse_int(players_max_raw) if has_players else _parse_int(scenario.get("players_max"))
        if has_players:
            if players_min is not None and players_min < 1:
                return _response({"error": "Invalid playersMin"}, status=400)
            if players_max is not None and players_max < 1:
                return _response({"error": "Invalid playersMax"}, status=400)
            if players_min is not None and players_max is not None and players_min > players_max:
                return _response({"error": "Invalid playersMin/playersMax"}, status=400)

        completion_achievements: list[dict[str, Any]] | None = None
        if "completionAchievements" in body or "completion_achievements" in body:
            raw_completion = body.get("completionAchievements") if "completionAchievements" in body else body.get("completion_achievements")
            coerced = _coerce_completion_achievements(raw_completion)
            normalized: list[dict[str, Any]] = []
            for raw in coerced:
                ach_title = str(raw.get("title") or "").strip()
                if not ach_title:
                    continue
                ach_id = str(raw.get("id") or "").strip()
                if not ach_id:
                    ach_id = f"scn_{scenario_id}_end_{uuid.uuid4().hex[:8]}"
                normalized.append(
                    {
                        "id": ach_id,
                        "title": ach_title,
                        "description": str(raw.get("description") or "").strip(),
                        "is_spoiler": bool(raw.get("is_spoiler")),
                    }
                )
            completion_achievements = normalized

        is_handout_scenario: bool | None = None
        if "isHandoutScenario" in body or "is_handout_scenario" in body:
            is_handout_scenario = _coerce_bool(body.get("isHandoutScenario") or body.get("is_handout_scenario"))

        handouts: list[dict[str, Any]] | None = None
        if "handouts" in body or "handout_list" in body or "handoutList" in body or "handout_list" in body:
            handouts = _coerce_handouts(body.get("handouts") or body.get("handout_list") or body.get("handoutList"))

        if is_handout_scenario is True:
            if not handouts:
                return _response({"error": "handouts must be provided for HO scenarios"}, status=400)

        try:
            repositories.update_scenario(
                scenario_id=scenario_id,
                title=title,
                system=system,
                estimated_time=estimated_time,
                tags=tags,
                notes=notes,
                setting=setting,
                recommended_skills=recommended_skills,
                not_recommended_skills=not_recommended_skills,
                loss_level=loss_level,
                loss_note=loss_note,
                cover_url=cover_url,
                cover_full_url=cover_full_url,
                players_min=players_min,
                players_max=players_max,
                completion_achievements=completion_achievements,
                is_handout_scenario=is_handout_scenario,
                handouts=handouts,
            )
            updated = repositories.get_scenario(scenario_id) or scenario
            try:
                for ach in updated.get("completion_achievements") or []:
                    if not isinstance(ach, dict):
                        continue
                    ach_id = str(ach.get("id") or "").strip()
                    ach_title = str(ach.get("title") or "").strip()
                    if not ach_id or not ach_title:
                        continue
                    repositories.upsert_achievement_definition(
                        ach_id,
                        ach_title,
                        str(ach.get("description") or "").strip(),
                        category="scenario",
                        is_spoiler=bool(ach.get("is_spoiler")),
                        trigger="manual",
                        scenario_id=scenario_id,
                    )
            except Exception:
                logger.exception("Failed to upsert completion achievement definitions (scenario update)")

            ui = _scenario_to_ui(updated, viewer_id=actor_id, include_private_handouts=True)
            if ui.get("canEdit"):
                completion_ui: list[dict[str, Any]] = []
                for raw in updated.get("completion_achievements") or []:
                    if not isinstance(raw, dict):
                        continue
                    aid = str(raw.get("id") or "").strip()
                    atitle = str(raw.get("title") or "").strip()
                    if not aid or not atitle:
                        continue
                    completion_ui.append(
                        {
                            "id": aid,
                            "title": atitle,
                            "description": str(raw.get("description") or "").strip(),
                            "isSpoiler": bool(raw.get("is_spoiler")),
                        }
                    )
                ui["completionAchievements"] = completion_ui
            _attach_scenario_preference(ui, actor_id, scenario_id)
            return _response({"scenario": ui}, status=200)
        except Exception as exc:
            logger.exception("Scenario update failed")
            return _response({"error": str(exc)}, status=500)

    try:
        scenario = repositories.get_scenario(scenario_id)
        if not scenario:
            return _response({"error": "not found"}, status=404)
        created_by = str(scenario.get("created_by") or "")
        is_gm_registered = False
        try:
            is_gm_registered = repositories.is_scenario_gm_registered(scenario_id, actor_id)
        except Exception:
            is_gm_registered = False
        can_edit = bool((created_by and created_by == actor_id) or is_gm_registered)
        ui = _scenario_to_ui(scenario, viewer_id=actor_id, include_private_handouts=can_edit)
        if can_edit:
            completion_ui: list[dict[str, Any]] = []
            for raw in scenario.get("completion_achievements") or []:
                if not isinstance(raw, dict):
                    continue
                aid = str(raw.get("id") or "").strip()
                atitle = str(raw.get("title") or "").strip()
                if not aid or not atitle:
                    continue
                completion_ui.append(
                    {
                        "id": aid,
                        "title": atitle,
                        "description": str(raw.get("description") or "").strip(),
                        "isSpoiler": bool(raw.get("is_spoiler")),
                    }
                )
            ui["completionAchievements"] = completion_ui
        try:
            ui["availableGmCount"] = len(repositories.list_capable_gms(scenario_id))
        except Exception:
            ui["availableGmCount"] = 0
        try:
            sessions = repositories.list_sessions_by_status("recruiting", limit=50)
            matching = [s for s in sessions if str(s.get("scenario_id") or "") == str(scenario_id)]
            if matching:
                matching.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
                summary = _session_to_recruiting_summary(matching[0])
                if summary:
                    ui["recruiting"] = summary
        except Exception:
            pass
        _attach_scenario_preference(ui, actor_id, scenario_id)
        return _response({"scenario": ui}, status=200)
    except Exception as exc:
        logger.exception("Scenario detail failed")
        return _response({"error": str(exc)}, status=500)


def _handle_scenario_preference(event: dict, scenario_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    try:
        if not repositories.get_scenario(scenario_id):
            return _response({"error": "not found"}, status=404)
    except Exception as exc:
        logger.exception("Scenario lookup failed")
        return _response({"error": str(exc)}, status=500)

    body = _parse_json_body(event)
    if not isinstance(body, dict):
        body = {}

    has_any = False
    is_bookmarked: bool | None = None
    is_favorited: bool | None = None

    if "isBookmarked" in body or "is_bookmarked" in body:
        is_bookmarked = _coerce_bool(body.get("isBookmarked") if "isBookmarked" in body else body.get("is_bookmarked"))
        has_any = True

    if "isFavorited" in body or "is_favorited" in body:
        is_favorited = _coerce_bool(body.get("isFavorited") if "isFavorited" in body else body.get("is_favorited"))
        has_any = True

    if not has_any:
        return _response({"error": "Missing preference fields (isBookmarked/isFavorited)"}, status=400)

    try:
        result = repositories.set_user_scenario_preference(
            actor_id,
            scenario_id,
            is_bookmarked=is_bookmarked,
            is_favorited=is_favorited,
        )
        return _response({"preference": result}, status=200)
    except ValueError as exc:
        return _response({"error": str(exc)}, status=400)
    except Exception as exc:
        logger.exception("Failed to update scenario preference")
        return _response({"error": str(exc)}, status=500)

def _handle_scenario_gm_register(event: dict, scenario_id: str) -> dict:
    method = _get_method(event)
    if method not in ("POST", "DELETE"):
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, actor_name = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    try:
        if not repositories.get_scenario(scenario_id):
            return _response({"error": "not found"}, status=404)
    except Exception as exc:
        logger.exception("Scenario lookup failed")
        return _response({"error": str(exc)}, status=500)

    try:
        repositories.upsert_user(actor_id, str(actor_name))
    except Exception:
        pass

    if method == "POST":
        try:
            repositories.add_capability(str(scenario_id), actor_id, str(actor_name), confidence="registered")
            return _response({"success": True, "registered": True}, status=200)
        except Exception as exc:
            logger.exception("GM registration failed")
            return _response({"error": str(exc)}, status=500)

    try:
        repositories.remove_capability(str(scenario_id), actor_id)
    except Exception:
        pass
    return _response({"success": True, "registered": False}, status=200)


def _handle_scenario_telemetry(event: dict, scenario_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    body = _parse_json_body(event)
    if not isinstance(body, dict):
        body = {}

    event_type = str(body.get("event") or body.get("type") or "").strip()
    source = str(body.get("source") or "").strip() or None

    def clamp_ms(value: Any, *, max_ms: int) -> int | None:
        if value is None:
            return None
        try:
            ms = int(value)
        except Exception:
            return None
        return max(0, min(max_ms, ms))

    if event_type in ("impression", "scenario_impression"):
        impression_ms = clamp_ms(body.get("impressionMs") if "impressionMs" in body else body.get("impression_ms"), max_ms=600_000)
        try:
            repositories.record_scenario_impression(actor_id, scenario_id, impression_ms=impression_ms, source=source)
        except Exception as exc:
            logger.exception("Failed to record scenario impression")
            return _response({"error": str(exc)}, status=500)
        return _response({"ok": True}, status=200)

    if event_type in ("detail_view", "detailView", "scenario_detail_view"):
        dwell_ms = clamp_ms(body.get("dwellMs") if "dwellMs" in body else body.get("dwell_ms"), max_ms=3_600_000)
        if dwell_ms is None:
            return _response({"error": "Missing dwellMs"}, status=400)
        try:
            repositories.record_scenario_detail_view(actor_id, scenario_id, dwell_ms=dwell_ms, source=source)
        except Exception as exc:
            logger.exception("Failed to record scenario detail view")
            return _response({"error": str(exc)}, status=500)
        return _response({"ok": True}, status=200)

    return _response({"error": "Unknown telemetry event"}, status=400)


def _handle_session_create(event: dict) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    body = _parse_json_body(event)

    guild_id = body.get("guildId") or body.get("guild_id")
    channel_id = body.get("channelId") or body.get("channel_id") or body.get("channel")
    title = body.get("title") or "TRPGセッション"

    if not guild_id or not channel_id:
        return _response({"error": "Missing guildId/channelId"}, status=400)

    players_min = int(body.get("playersMin") or body.get("players_min") or 1)
    players_max = int(body.get("playersMax") or body.get("players_max") or 5)
    if players_min < 1 or players_max < 1 or players_min > players_max:
        return _response({"error": "Invalid playersMin/playersMax"}, status=400)

    scenario_id = body.get("scenarioId") or body.get("scenario_id") or None
    gm_type = body.get("gmType") or body.get("gm_type") or "undecided"
    session_type = body.get("sessionType") or body.get("session_type") or None
    duration = body.get("duration") or None
    teaser_slots = body.get("teaserSlots") or body.get("teaser_slots") or None
    flow_mode = body.get("flowMode") or body.get("flow_mode") or "people_first"
    fixed_schedule = body.get("fixedSchedule") or body.get("fixed_schedule") or None
    create_thread_flag = _coerce_bool(body.get("createThread") or body.get("create_thread"))

    try:
        actor_id, actor_name = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Failed to resolve actor")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    if scenario_id:
        try:
            scenario = repositories.get_scenario(str(scenario_id))
            if not scenario:
                return _response({"error": "Scenario not found"}, status=400)
        except Exception as exc:
            logger.exception("Scenario lookup failed")
            return _response({"error": f"Scenario lookup failed: {exc}"}, status=500)
    else:
        scenario = None

    if create_thread_flag:
        # Basic validation that the channel belongs to the guild and the user is in that guild.
        try:
            ch = get_channel(str(channel_id))
            if str(ch.get("guild_id") or "") != str(guild_id):
                return _response({"error": "channelId does not belong to guildId"}, status=400)
        except DiscordApiError as exc:
            return _response({"error": f"Discord channel lookup failed: {exc}"}, status=403)

        try:
            get_guild_member(str(guild_id), actor_id)
        except DiscordApiError as exc:
            return _response({"error": f"User is not a guild member (or bot lacks permission): {exc}"}, status=403)

    gm_user_id = actor_id if str(gm_type) == "self" else None
    if gm_user_id and scenario_id:
        try:
            if not repositories.is_scenario_gm_registered(str(scenario_id), actor_id):
                return _response({"error": "GM registration required for this scenario"}, status=403)
        except Exception as exc:
            logger.exception("GM registration check failed")
            return _response({"error": f"GM registration check failed: {exc}"}, status=500)

    if str(flow_mode) not in ("people_first", "schedule_first"):
        return _response({"error": "Invalid flowMode (people_first|schedule_first)"}, status=400)

    normalized_fixed: list[dict[str, Any]] | None = None
    if str(flow_mode) == "schedule_first":
        if not isinstance(fixed_schedule, list) or not fixed_schedule:
            return _response({"error": "Missing fixedSchedule for schedule_first mode"}, status=400)
        normalized: list[dict[str, Any]] = []
        for raw in fixed_schedule[:20]:
            if not isinstance(raw, dict):
                continue
            label = str(raw.get("label") or "").strip() or "開催日"
            start_at = raw.get("startAt") or raw.get("start_at")
            end_at = raw.get("endAt") or raw.get("end_at")
            if not start_at:
                continue
            try:
                start_dt = _parse_iso_datetime(str(start_at))
            except Exception:
                continue
            item: dict[str, Any] = {
                "id": str(raw.get("id") or f"fixed_{uuid.uuid4().hex[:8]}"),
                "label": label,
                "startAt": start_dt.isoformat(),
            }
            if end_at:
                try:
                    end_dt = _parse_iso_datetime(str(end_at))
                    item["endAt"] = end_dt.isoformat()
                except Exception:
                    pass
            normalized.append(item)
        if not normalized:
            return _response({"error": "fixedSchedule must include at least one valid startAt"}, status=400)
        normalized_fixed = normalized

    try:
        repositories.upsert_user(actor_id, str(actor_name))
        if gm_user_id:
            repositories.upsert_user(gm_user_id, str(actor_name))

        session_id = repositories.create_session(
            scenario_id=str(scenario_id) if scenario_id else None,
            gm_user_id=gm_user_id,
            title=str(title),
            status="recruiting",
            guild_id=str(guild_id),
            channel_id=str(channel_id),
            thread_id=None,
            min_players=players_min,
            max_players=players_max,
            created_by=actor_id,
            session_type=str(session_type) if session_type else None,
            duration=str(duration) if duration else None,
            teaser_slots=teaser_slots if isinstance(teaser_slots, list) else None,
            flow_mode=str(flow_mode),
            fixed_schedule=normalized_fixed,
        )

        if not gm_user_id:
            try:
                repositories.add_participant(session_id, actor_id, str(actor_name), "PL")
            except Exception:
                logger.exception("Failed to add requester as participant")

        if not gm_user_id and scenario_id:
            scenario_title = str((scenario or {}).get("title") or title or "シナリオ")
            action_target = f"/browse?scenario={scenario_id}&returnTo=/notifications"
            try:
                gm_ids = repositories.list_scenario_gm_user_ids(str(scenario_id))
            except Exception:
                gm_ids = []
            for gm_id in gm_ids:
                gm_id = str(gm_id or "").strip()
                if not gm_id or gm_id == actor_id:
                    continue
                try:
                    repositories.create_notification(
                        gm_id,
                        "action",
                        "リクエストが届きました",
                        f"{scenario_title}: {actor_name}",
                        action_label="確認",
                        action_target=action_target,
                        icon_type="info",
                    )
                except Exception:
                    logger.exception("Failed to create request notification")

        if scenario_id:
            try:
                repositories.increment_scenario_stats(str(scenario_id), {"session_created_count": 1})
            except Exception:
                logger.exception("Failed to increment session_created_count")

        warnings: list[str] = []
        thread_id: str | None = None
        thread_url: str | None = None

        if create_thread_flag:
            try:
                thread = create_thread(str(channel_id), str(title))
                thread_id = str(thread.get("id") or "") or None
                if thread_id:
                    repositories.update_session_thread(session_id, thread_id)
                    thread_url = f"https://discord.com/channels/{guild_id}/{thread_id}"
                    repositories.log_audit(session_id, "session_thread_created_ui", actor_id, {"thread_id": thread_id})
                else:
                    warnings.append("Thread create returned no id")
            except DiscordApiError as exc:
                warnings.append(f"Thread create failed: {exc}")
            except Exception as exc:
                warnings.append(f"Thread create failed: {exc}")

            if thread_id:
                try:
                    refresh_session_card(session_id)
                except DiscordApiError as exc:
                    warnings.append(f"Session card refresh failed: {exc}")
                except Exception as exc:
                    warnings.append(f"Session card refresh failed: {exc}")

        repositories.log_audit(
            session_id,
            "session_created_ui",
            actor_id,
            {"thread_id": thread_id, "create_thread": create_thread_flag, "warnings": warnings[:5] if warnings else None},
        )

        payload: dict[str, Any] = {"success": True, "sessionId": session_id}
        if thread_id:
            payload["threadId"] = thread_id
        if thread_url:
            payload["threadUrl"] = thread_url
        if warnings:
            payload["warnings"] = warnings

        return _response(payload, status=200)
    except DiscordApiError as exc:
        logger.exception("Discord REST action failed")
        return _response({"error": str(exc)}, status=502)
    except Exception as exc:
        logger.exception("Session create failed")
        return _response({"error": str(exc)}, status=500)


def _handle_session_join(event: dict) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    body = _parse_json_body(event)
    session_id = body.get("sessionId") or body.get("session_id")
    if not session_id or not isinstance(session_id, str):
        return _response({"error": "Missing sessionId"}, status=400)

    try:
        actor_id, actor_name = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Failed to resolve actor")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(str(session_id))
    if not session:
        return _response({"error": "Session not found"}, status=404)

    status = str(session.get("status") or "")
    if status not in ("recruiting", "scheduling"):
        return _response({"error": f"Session is not joinable (status={status})"}, status=409)

    try:
        participant_records = repositories.list_participant_records(str(session_id))
        participant_ids = {p.get("user_id") for p in participant_records}
        queued = False
        max_players = _parse_int(session.get("max_players"), default=0) or 0

        if actor_id in participant_ids:
            queued = False
            try:
                repositories.remove_waitlist(str(session_id), actor_id)
            except Exception:
                pass
        else:
            is_full = int(max_players) > 0 and len(participant_ids) >= int(max_players)
            if is_full:
                queued = True
                repositories.add_waitlist(str(session_id), actor_id, str(actor_name))
            else:
                queued = False
                repositories.add_participant(str(session_id), actor_id, str(actor_name), "PL")
                try:
                    repositories.remove_waitlist(str(session_id), actor_id)
                except Exception:
                    pass

            try:
                gm_user_id = _session_gm_user_id(session) or ""
                if gm_user_id and gm_user_id != actor_id:
                    scenario_id = str(session.get("scenario_id") or "")
                    scenario = repositories.get_scenario(scenario_id) if scenario_id else None
                    scenario_title = str((scenario or {}).get("title") or session.get("title") or "シナリオ")
                    action_target = (
                        f"/browse?scenario={scenario_id}&returnTo=/notifications" if scenario_id else "/browse"
                    )
                    title = "参加希望が届きました" if not queued else "参加希望が届きました（待機）"
                    repositories.create_notification(
                        gm_user_id,
                        "action",
                        title,
                        f"{scenario_title}: {actor_name}",
                        action_label="確認",
                        action_target=action_target,
                        icon_type="info",
                    )
            except Exception:
                logger.exception("Failed to notify GM on join")

        repositories.log_audit(str(session_id), "session_join_ui", actor_id, {"queued": queued})
        return _response({"success": True, "sessionId": str(session_id), "queued": queued}, status=200)
    except Exception as exc:
        logger.exception("Session join failed")
        return _response({"error": str(exc)}, status=500)

def _handle_session_claim_gm(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, actor_name = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Failed to resolve actor")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(str(session_id))
    if not session:
        return _response({"error": "Session not found"}, status=404)

    if session.get("gm_user_id"):
        return _response({"error": "GM is already assigned"}, status=409)

    scenario_id = str(session.get("scenario_id") or "").strip()
    if not scenario_id:
        return _response({"error": "Scenario is required to claim GM"}, status=400)

    try:
        if not repositories.is_scenario_gm_registered(scenario_id, actor_id):
            return _response({"error": "forbidden"}, status=403)
    except Exception as exc:
        logger.exception("GM registration check failed")
        return _response({"error": str(exc)}, status=500)

    try:
        repositories.upsert_user(actor_id, str(actor_name))
    except Exception:
        pass

    try:
        repositories.update_session_gm(str(session_id), actor_id)
        repositories.log_audit(str(session_id), "session_gm_claimed_ui", actor_id, {"scenario_id": scenario_id})
    except Exception as exc:
        logger.exception("Failed to claim GM")
        return _response({"error": str(exc)}, status=500)

    requester_id = str(session.get("created_by") or "").strip()
    if requester_id and requester_id != actor_id:
        try:
            scenario = repositories.get_scenario(scenario_id) or {}
            scenario_title = str(scenario.get("title") or session.get("title") or "シナリオ")
            repositories.create_notification(
                requester_id,
                "action",
                "GMが決まりました",
                scenario_title,
                action_label="確認",
                action_target=f"/sessions?session={session_id}&returnTo=/notifications",
                icon_type="check",
            )
        except Exception:
            logger.exception("Failed to notify requester about GM claim")

    return _response({"success": True, "sessionId": str(session_id), "gmUserId": actor_id}, status=200)


def _handle_recruiting_select_members(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Failed to resolve actor")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(str(session_id))
    if not session:
        return _response({"error": "Session not found"}, status=404)

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    raw_status = str(session.get("status") or "")
    if raw_status != "recruiting":
        return _response({"error": f"Session is not recruiting (status={raw_status})"}, status=409)

    max_players = _parse_int(session.get("max_players"), default=0) or 0
    if int(max_players) <= 0:
        return _response({"error": "Selection is not applicable (maxPlayers is unlimited)"}, status=409)

    body = _parse_json_body(event)
    raw_ids = body.get("selectedUserIds") or body.get("selected_user_ids") or body.get("selectedUserIDs")
    if not isinstance(raw_ids, list):
        return _response({"error": "Missing selectedUserIds (array)"}, status=400)

    selected: list[str] = []
    seen: set[str] = set()
    for raw in raw_ids:
        uid = str(raw or "").strip()
        if not uid or uid in seen:
            continue
        seen.add(uid)
        selected.append(uid)

    if len(selected) > int(max_players):
        return _response({"error": f"Too many selected users (max {int(max_players)})"}, status=400)

    try:
        participant_records = repositories.list_participant_records(str(session_id))
        waitlist_records = repositories.list_waitlist_records(str(session_id))
    except Exception as exc:
        logger.exception("Failed to load participants/waitlist")
        return _response({"error": str(exc)}, status=500)

    participant_ids = {str(p.get("user_id") or "") for p in participant_records}
    participant_ids.discard("")
    waitlist_ids = {str(w.get("user_id") or "") for w in waitlist_records}
    waitlist_ids.discard("")
    allowed_ids = participant_ids | waitlist_ids

    unknown = [uid for uid in selected if uid not in allowed_ids]
    if unknown:
        return _response({"error": f"Unknown selected user(s): {', '.join(unknown[:5])}"}, status=400)

    display_name_map: dict[str, str] = {}
    for p in participant_records:
        uid = str(p.get("user_id") or "").strip()
        if not uid:
            continue
        display_name_map[uid] = str(p.get("display_name") or uid)
    for w in waitlist_records:
        uid = str(w.get("user_id") or "").strip()
        if not uid:
            continue
        display_name_map.setdefault(uid, str(w.get("display_name") or uid))

    to_demote = sorted(uid for uid in participant_ids if uid not in set(selected))
    to_promote = sorted(uid for uid in selected if uid not in participant_ids)

    try:
        for uid in to_demote:
            repositories.remove_participant(str(session_id), uid)
            repositories.add_waitlist(str(session_id), uid, display_name_map.get(uid) or uid)

        for uid in to_promote:
            repositories.add_participant(str(session_id), uid, display_name_map.get(uid) or uid, "PL")
            repositories.remove_waitlist(str(session_id), uid)

        for uid in selected:
            try:
                repositories.remove_waitlist(str(session_id), uid)
            except Exception:
                pass

        repositories.log_audit(
            str(session_id),
            "recruiting_select_members_ui",
            actor_id,
            {"selected_user_ids": selected, "max_players": int(max_players)},
        )
        return _response(
            {
                "success": True,
                "sessionId": str(session_id),
                "selectedCount": len(selected),
                "promotedCount": len(to_promote),
                "demotedCount": len(to_demote),
            },
            status=200,
        )
    except Exception as exc:
        logger.exception("Failed to apply member selection")
        return _response({"error": str(exc)}, status=500)


_UI_TO_DDB_SLOT_STATUS = {
    "available": "OK",
    "maybe": "MAYBE",
    "unavailable": "NO",
}
_DDB_TO_UI_SLOT_STATUS = {v: k for k, v in _UI_TO_DDB_SLOT_STATUS.items()}


def _extract_exact_teaser_starts(teaser_slots: Any) -> list[str]:
    if not isinstance(teaser_slots, list):
        return []
    starts: list[str] = []
    for raw in teaser_slots:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("kind") or "") != "exact":
            continue
        start_at = raw.get("startAt") or raw.get("start_at")
        if not start_at:
            continue
        starts.append(str(start_at))
    seen: set[str] = set()
    unique: list[str] = []
    for s in starts:
        if s in seen:
            continue
        seen.add(s)
        unique.append(s)
    return unique


def _ensure_poll_from_teasers(session_id: str, session: dict, actor_id: str) -> str | None:
    poll_ref = repositories.latest_poll_for_session(session_id)
    if poll_ref and poll_ref.get("poll_id"):
        return str(poll_ref["poll_id"])

    starts = _extract_exact_teaser_starts(session.get("teaser_slots"))
    if not starts:
        return None

    duration_hours = _duration_hours_from_session(session, default_hours=4)
    poll_id = repositories.create_poll(session_id=session_id, deadline=None, timezone_basis="Asia/Tokyo")
    created = 0
    for start_iso in starts:
        start_dt = _parse_iso_datetime(start_iso)
        end_dt = start_dt + timedelta(hours=duration_hours)
        repositories.add_slot(poll_id, start=start_dt, end=end_dt)
        created += 1

    try:
        current = str(session.get("status") or "")
        if current not in ("confirmed", "running", "completed", "canceled", "cancelled"):
            repositories.mark_session_status(session_id, "scheduling")
        if current == "recruiting":
            try:
                gm_user_id = _session_gm_user_id(session) or ""
                scenario_id = str(session.get("scenario_id") or "")
                scenario = repositories.get_scenario(scenario_id) if scenario_id else None
                scenario_title = str((scenario or {}).get("title") or session.get("title") or "セッション")
                for p in repositories.list_participant_records(session_id):
                    uid = str(p.get("user_id") or "")
                    if not uid or uid == gm_user_id:
                        continue
                    repositories.create_notification(
                        uid,
                        "action",
                        "日程調整が始まりました",
                        scenario_title,
                        action_label="可否入力",
                        action_target=f"/sessions/{session_id}/schedule",
                        icon_type="calendar",
                    )
            except Exception:
                logger.exception("Failed to notify participants for scheduling start (from teaser poll creation)")
    except Exception:
        logger.exception("Failed to mark session status to scheduling (from teaser poll creation)")

    try:
        repositories.log_audit(
            session_id,
            "poll_created_from_teasers_ui",
            actor_id,
            {"poll_id": poll_id, "slots_created": created},
        )
    except Exception:
        logger.exception("Failed to audit teaser poll creation")

    return poll_id


def _status_to_scheduling_status(session: dict) -> str:
    raw_status = str(session.get("status") or "")
    decided_slot_id = str(session.get("decided_slot_id") or "") or None
    scheduled_start = session.get("scheduled_start")
    if decided_slot_id or scheduled_start:
        return "decided"
    if raw_status in ("confirmed", "running", "completed"):
        return "decided"
    if raw_status in ("canceled", "cancelled"):
        return "cancelled"
    return "polling"


def _build_scheduling_session(session_id: str, actor_id: str) -> dict:
    session = repositories.get_session_with_details(session_id) or {}
    gm_user_id = _session_gm_user_id(session) or ""
    gm_name = _session_gm_name(session, gm_user_id)

    scenario_id = str(session.get("scenario_id") or "")
    scenario_title = str(session.get("scenario_title") or session.get("title") or "")
    created_at = str(session.get("created_at") or "")

    poll_id: str | None = None
    poll_ref = None
    try:
        poll_ref = repositories.latest_poll_for_session(session_id)
        if poll_ref and poll_ref.get("poll_id"):
            poll_id = str(poll_ref["poll_id"])
    except Exception:
        poll_id = None

    if not poll_id:
        try:
            poll_id = _ensure_poll_from_teasers(session_id, session, actor_id)
        except Exception:
            logger.exception("Failed to create poll from teasers")
            poll_id = None

    poll_meta = None
    if poll_id:
        try:
            poll_meta = repositories.poll_by_id(poll_id)
        except Exception:
            poll_meta = None

    slots: list[dict[str, Any]] = []
    if poll_id:
        for item in repositories.list_poll_slots(poll_id):
            slot_id = str(item.get("slot_id") or "")
            start_iso = str(item.get("start_time") or "")
            if not slot_id or not start_iso:
                continue
            slots.append({"id": slot_id, "startAt": start_iso, "label": _format_slot_label(start_iso)})

    votes: list[dict[str, Any]] = []
    if poll_id:
        responses = repositories.list_poll_responses(poll_id)
        votes_by_user: dict[str, dict[str, str]] = {}
        for resp in responses:
            user_id = str(resp.get("user_id") or "")
            slot_id = str(resp.get("slot_id") or "")
            raw = str(resp.get("status") or "")
            ui_status = _DDB_TO_UI_SLOT_STATUS.get(raw)
            if not user_id or not slot_id or not ui_status:
                continue
            votes_by_user.setdefault(user_id, {})[slot_id] = ui_status

        participant_records = repositories.list_participant_records(session_id)
        participant_name_map = {p["user_id"]: p.get("display_name") or p["user_id"] for p in participant_records}
        participant_avatar_map = {uid: _user_avatar_url(uid) for uid in participant_name_map}

        for user_id, vote_map in votes_by_user.items():
            if not vote_map:
                continue
            name = gm_name if user_id == gm_user_id else participant_name_map.get(user_id) or user_id
            vote: dict[str, Any] = {"participantId": user_id, "participantName": name, "votes": vote_map}
            avatar_url = _user_avatar_url(user_id) or participant_avatar_map.get(user_id)
            if avatar_url:
                vote["avatarUrl"] = avatar_url
            votes.append(vote)

    comments: list[dict[str, Any]] = []
    if poll_id:
        for c in repositories.list_poll_comments(poll_id):
            comment_id = str(c.get("comment_id") or "")
            user_id = str(c.get("user_id") or "")
            text = str(c.get("text") or "")
            created = str(c.get("created_at") or "")
            edited = c.get("edited_at") or None
            if not comment_id or not user_id or not created:
                continue
            ui_comment: dict[str, Any] = {"id": comment_id, "participantId": user_id, "text": text, "createdAt": created}
            if edited:
                ui_comment["editedAt"] = str(edited)
            comments.append(ui_comment)

    participants: list[dict[str, Any]] = []
    try:
        for p in repositories.list_participant_records(session_id):
            user_id = str(p.get("user_id") or "")
            if not user_id or user_id == gm_user_id:
                continue
            name = str(p.get("display_name") or user_id)
            summary: dict[str, Any] = {"id": user_id, "name": name}
            avatar_url = _user_avatar_url(user_id)
            if avatar_url:
                summary["avatarUrl"] = avatar_url
            participants.append(summary)
    except Exception:
        participants = []

    decided_slot_id = str(session.get("decided_slot_id") or "") or None
    if not decided_slot_id and session.get("scheduled_start") and slots:
        scheduled_start = str(session.get("scheduled_start") or "")
        for s in slots:
            if str(s.get("startAt") or "") == scheduled_start:
                decided_slot_id = str(s.get("id") or "") or None
                break

    deadline = None
    raw_deadline = None
    if poll_meta:
        raw_deadline = poll_meta.get("deadline")
    if not raw_deadline and poll_ref:
        raw_deadline = poll_ref.get("deadline")
    if raw_deadline:
        deadline = str(raw_deadline)

    scheduling_status = _status_to_scheduling_status(session)
    payload: dict[str, Any] = {
        "sessionId": session_id,
        "scenarioId": scenario_id,
        "scenarioTitle": scenario_title,
        "status": scheduling_status,
        "slots": slots,
        "votes": votes,
        "comments": comments,
        "gmUserId": gm_user_id,
        "gmName": gm_name,
        "participants": participants,
        "createdAt": created_at,
    }
    if decided_slot_id:
        payload["decidedSlotId"] = decided_slot_id
    if deadline:
        payload["deadline"] = deadline
    return payload


def _assert_scheduling_access(session_id: str, session: dict, actor_id: str) -> tuple[str, set[str]]:
    gm_user_id = _session_gm_user_id(session) or ""
    participant_records = repositories.list_participant_records(session_id)
    participant_ids = {str(p.get("user_id") or "") for p in participant_records}
    participant_ids.discard("")
    if actor_id != gm_user_id and actor_id not in participant_ids:
        requester_id = str(session.get("created_by") or "").strip()
        if requester_id and requester_id == actor_id:
            return gm_user_id, participant_ids
        scenario_id = str(session.get("scenario_id") or "").strip()
        if not gm_user_id and scenario_id:
            try:
                if repositories.is_scenario_gm_registered(scenario_id, actor_id):
                    return gm_user_id, participant_ids
            except Exception:
                pass
        raise PermissionError("forbidden")
    return gm_user_id, participant_ids


def _handle_scheduling_get(event: dict, session_id: str) -> dict:
    if _get_method(event) != "GET":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    try:
        _assert_scheduling_access(session_id, session, actor_id)
    except PermissionError:
        return _response({"error": "forbidden"}, status=403)
    except Exception as exc:
        logger.exception("Scheduling auth check failed")
        return _response({"error": str(exc)}, status=500)

    try:
        return _response({"session": _build_scheduling_session(session_id, actor_id)}, status=200)
    except Exception as exc:
        logger.exception("Scheduling fetch failed")
        return _response({"error": str(exc)}, status=500)


def _handle_scheduling_setup(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    prev_status = str(session.get("status") or "")

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    raw_slots = body.get("slots") if isinstance(body, dict) else None
    if not isinstance(raw_slots, list) or not raw_slots:
        return _response({"error": "Missing 'slots' (non-empty array)"}, status=400)

    start_ats: list[str] = []
    for raw in raw_slots[:50]:
        if not isinstance(raw, dict):
            continue
        start_at = raw.get("startAt") or raw.get("start_at")
        if not start_at:
            continue
        start_ats.append(str(start_at))
    if not start_ats:
        return _response({"error": "slots must include startAt"}, status=400)

    seen: set[str] = set()
    unique: list[str] = []
    for s in start_ats:
        if s in seen:
            continue
        seen.add(s)
        unique.append(s)

    duration_hours = _duration_hours_from_session(session, default_hours=4)

    try:
        try:
            repositories.clear_session_schedule(session_id)
        except Exception:
            logger.exception("Failed to clear existing session schedule before poll setup")

        poll_id = repositories.create_poll(session_id=session_id, deadline=None, timezone_basis="Asia/Tokyo")
        for start_iso in unique:
            start_dt = _parse_iso_datetime(start_iso)
            end_dt = start_dt + timedelta(hours=duration_hours)
            repositories.add_slot(poll_id, start=start_dt, end=end_dt)

        try:
            repositories.mark_session_status(session_id, "scheduling")
        except Exception:
            logger.exception("Failed to mark session status to scheduling")

        try:
            repositories.log_audit(
                session_id,
                "poll_setup_ui",
                actor_id,
                {"poll_id": poll_id, "slots": len(unique)},
            )
        except Exception:
            logger.exception("Failed to audit poll setup")

        if prev_status == "recruiting":
            try:
                scenario_id = str(session.get("scenario_id") or "")
                scenario = repositories.get_scenario(scenario_id) if scenario_id else None
                scenario_title = str((scenario or {}).get("title") or session.get("title") or "セッション")
                for p in repositories.list_participant_records(session_id):
                    uid = str(p.get("user_id") or "")
                    if not uid or uid == gm_user_id:
                        continue
                    repositories.create_notification(
                        uid,
                        "action",
                        "日程調整が始まりました",
                        scenario_title,
                        action_label="可否入力",
                        action_target=f"/sessions/{session_id}/schedule",
                        icon_type="calendar",
                    )
            except Exception:
                logger.exception("Failed to notify participants for scheduling start")

        return _response({"session": _build_scheduling_session(session_id, actor_id)}, status=200)
    except Exception as exc:
        logger.exception("Scheduling setup failed")
        return _response({"error": str(exc)}, status=500)


def _handle_scheduling_vote(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    try:
        _assert_scheduling_access(session_id, session, actor_id)
    except PermissionError:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    slot_id = body.get("slotId") or body.get("slot_id")
    status = body.get("status")
    if not slot_id or not isinstance(slot_id, str):
        return _response({"error": "Missing slotId"}, status=400)
    if not status or not isinstance(status, str):
        return _response({"error": "Missing status"}, status=400)
    ddb_status = _UI_TO_DDB_SLOT_STATUS.get(status)
    if not ddb_status:
        return _response({"error": "Invalid status"}, status=400)

    poll_ref = repositories.latest_poll_for_session(session_id)
    poll_id = str(poll_ref.get("poll_id") or "") if poll_ref else ""
    slot_poll_id = repositories.poll_id_for_slot(slot_id)
    if not poll_id or not slot_poll_id or str(slot_poll_id) != poll_id:
        return _response({"error": "Slot does not belong to current poll"}, status=409)

    try:
        repositories.upsert_response(slot_id, actor_id, ddb_status, comment="")
        try:
            repositories.log_audit(
                session_id,
                "poll_vote_ui",
                actor_id,
                {"slot_id": slot_id, "status": ddb_status},
            )
        except Exception:
            logger.exception("Failed to audit poll vote")
        return _response({"session": _build_scheduling_session(session_id, actor_id)}, status=200)
    except Exception as exc:
        logger.exception("Vote failed")
        return _response({"error": str(exc)}, status=500)


def _handle_scheduling_decide(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    prev_status = str(session.get("status") or "")
    prev_decided = str(session.get("decided_slot_id") or "") or None

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    slot_id = body.get("slotId") or body.get("slot_id")
    if not slot_id or not isinstance(slot_id, str):
        return _response({"error": "Missing slotId"}, status=400)

    poll_ref = repositories.latest_poll_for_session(session_id)
    poll_id = str(poll_ref.get("poll_id") or "") if poll_ref else ""
    slot_poll_id = repositories.poll_id_for_slot(slot_id)
    if not poll_id or not slot_poll_id or str(slot_poll_id) != poll_id:
        return _response({"error": "Slot does not belong to current poll"}, status=409)

    try:
        repositories.set_session_schedule_from_slot(session_id, slot_id)
        slot_label = None
        try:
            detail = repositories.slot_detail(slot_id)
            if detail and detail.get("start"):
                start_dt = detail["start"]
                slot_label = _format_slot_label(start_dt.isoformat())
        except Exception:
            slot_label = None
        try:
            fixed_schedule = session.get("fixed_schedule") if isinstance(session.get("fixed_schedule"), list) else []
            if not fixed_schedule:
                detail = repositories.slot_detail(slot_id)
                if detail:
                    item: dict[str, Any] = {
                        "id": f"fixed_{uuid.uuid4().hex[:8]}",
                        "label": "開催日",
                        "startAt": detail["start"].isoformat(),
                        "endAt": detail["end"].isoformat(),
                    }
                    repositories.set_session_fixed_schedule(session_id, [item])
        except Exception:
            logger.exception("Failed to set fixed schedule on decide")
        try:
            repositories.set_session_decided_slot_id(session_id, slot_id)
        except Exception:
            logger.exception("Failed to store decided_slot_id")

        try:
            repositories.mark_session_status(session_id, "confirmed")
        except Exception:
            logger.exception("Failed to mark session status to confirmed")

        if prev_status != "confirmed" or prev_decided != slot_id:
            try:
                scenario_id = str(session.get("scenario_id") or "")
                scenario = repositories.get_scenario(scenario_id) if scenario_id else None
                scenario_title = str((scenario or {}).get("title") or session.get("title") or "セッション")
                subtitle = f"{scenario_title}: {slot_label or slot_id}"
                for p in repositories.list_participant_records(session_id):
                    uid = str(p.get("user_id") or "")
                    if not uid or uid == gm_user_id:
                        continue
                    repositories.create_notification(
                        uid,
                        "action",
                        "日程が確定しました",
                        subtitle,
                        action_label="確認",
                        action_target=f"/sessions/{session_id}/schedule",
                        icon_type="calendar",
                    )
            except Exception:
                logger.exception("Failed to notify participants for scheduling decide")

        try:
            repositories.log_audit(session_id, "poll_decide_ui", actor_id, {"slot_id": slot_id})
        except Exception:
            logger.exception("Failed to audit decide")

        return _response({"session": _build_scheduling_session(session_id, actor_id)}, status=200)
    except Exception as exc:
        logger.exception("Decide failed")
        return _response({"error": str(exc)}, status=500)


def _handle_scheduling_comment(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    try:
        _assert_scheduling_access(session_id, session, actor_id)
    except PermissionError:
        return _response({"error": "forbidden"}, status=403)

    poll_ref = repositories.latest_poll_for_session(session_id)
    poll_id = str(poll_ref.get("poll_id") or "") if poll_ref else ""
    if not poll_id:
        return _response({"error": "poll not started"}, status=409)

    body = _parse_json_body(event)
    text = body.get("text") if isinstance(body, dict) else None
    if not text or not isinstance(text, str) or not text.strip():
        return _response({"error": "Missing text"}, status=400)

    try:
        repositories.create_poll_comment(poll_id, actor_id, text.strip())
        return _response({"session": _build_scheduling_session(session_id, actor_id)}, status=200)
    except Exception as exc:
        logger.exception("Comment failed")
        return _response({"error": str(exc)}, status=500)


def _handle_scheduling_comment_edit(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    try:
        _assert_scheduling_access(session_id, session, actor_id)
    except PermissionError:
        return _response({"error": "forbidden"}, status=403)

    poll_ref = repositories.latest_poll_for_session(session_id)
    poll_id = str(poll_ref.get("poll_id") or "") if poll_ref else ""
    if not poll_id:
        return _response({"error": "poll not started"}, status=409)

    body = _parse_json_body(event)
    comment_id = body.get("commentId") or body.get("comment_id")
    text = body.get("text")
    if not comment_id or not isinstance(comment_id, str):
        return _response({"error": "Missing commentId"}, status=400)
    if not text or not isinstance(text, str) or not text.strip():
        return _response({"error": "Missing text"}, status=400)

    try:
        existing = repositories.get_poll_comment(poll_id, comment_id)
        if not existing:
            return _response({"error": "not found"}, status=404)
        if str(existing.get("user_id") or "") != actor_id:
            return _response({"error": "forbidden"}, status=403)
        repositories.update_poll_comment(poll_id, comment_id, text.strip())
        return _response({"session": _build_scheduling_session(session_id, actor_id)}, status=200)
    except Exception as exc:
        logger.exception("Comment edit failed")
        return _response({"error": str(exc)}, status=500)


def _handle_scheduling_comment_delete(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    try:
        _assert_scheduling_access(session_id, session, actor_id)
    except PermissionError:
        return _response({"error": "forbidden"}, status=403)

    poll_ref = repositories.latest_poll_for_session(session_id)
    poll_id = str(poll_ref.get("poll_id") or "") if poll_ref else ""
    if not poll_id:
        return _response({"error": "poll not started"}, status=409)

    body = _parse_json_body(event)
    comment_id = body.get("commentId") or body.get("comment_id")
    if not comment_id or not isinstance(comment_id, str):
        return _response({"error": "Missing commentId"}, status=400)

    try:
        existing = repositories.get_poll_comment(poll_id, comment_id)
        if not existing:
            return _response({"error": "not found"}, status=404)
        if str(existing.get("user_id") or "") != actor_id:
            return _response({"error": "forbidden"}, status=403)
        repositories.delete_poll_comment(poll_id, comment_id)
        return _response({"session": _build_scheduling_session(session_id, actor_id)}, status=200)
    except Exception as exc:
        logger.exception("Comment delete failed")
        return _response({"error": str(exc)}, status=500)


def _session_cover_url(session: dict) -> str:
    scenario_id = str(session.get("scenario_id") or "")
    if not scenario_id:
        return "/placeholder.svg"
    scenario = repositories.get_scenario(scenario_id) or {}
    return _normalize_cover_url(scenario.get("cover_url") or scenario.get("coverUrl"))


def _session_thread_url(session: dict) -> str | None:
    guild_id = str(session.get("guild_id") or "")
    thread_id = str(session.get("thread_id") or "")
    if guild_id and thread_id:
        return f"https://discord.com/channels/{guild_id}/{thread_id}"
    return None


def _session_deadline_iso(session_id: str) -> str | None:
    poll_ref = repositories.latest_poll_for_session(session_id)
    if poll_ref and poll_ref.get("deadline"):
        return str(poll_ref["deadline"])
    return None


def _format_confirmed_label(start_iso: str) -> str:
    label = _format_slot_label(start_iso)
    return label[:-1] if label.endswith("〜") else label


def _teaser_slot_labels(teaser_slots: Any) -> list[str]:
    if not isinstance(teaser_slots, list):
        return []
    labels: list[str] = []
    for raw in teaser_slots:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind") or "")
        if kind == "coarse":
            label = str(raw.get("label") or "").strip()
            if label:
                labels.append(label)
            continue
        if kind == "exact":
            start_at = raw.get("startAt") or raw.get("start_at")
            if start_at:
                labels.append(_format_confirmed_label(str(start_at)))
    return labels


def _profile_status_from_session(status: str) -> str | None:
    if status == "recruiting":
        return "recruiting"
    if status == "scheduling":
        return "scheduling"
    if status == "confirmed":
        return "confirmed"
    if status == "running":
        return "in_progress"
    if status == "completed":
        return "completed"
    return None


def _user_has_voted(session_id: str, user_id: str) -> bool:
    poll_ref = repositories.latest_poll_for_session(session_id)
    poll_id = str(poll_ref.get("poll_id") or "") if poll_ref else ""
    if not poll_id:
        return False
    try:
        responses = repositories.list_poll_responses(poll_id)
    except Exception:
        return False
    for resp in responses:
        if str(resp.get("user_id") or "") == user_id:
            return True
    return False


def _notification_to_ui(item: dict) -> dict | None:
    notif_id = str(item.get("notification_id") or "")
    if not notif_id:
        return None
    notif_type = str(item.get("type") or "system")
    if notif_type not in ("action", "celebrate", "system"):
        notif_type = "system"
    payload: dict[str, Any] = {
        "id": notif_id,
        "type": notif_type,
        "title": str(item.get("title") or ""),
        "subtitle": str(item.get("subtitle") or ""),
        "createdAt": str(item.get("created_at") or ""),
        "isRead": bool(item.get("read_at")),
    }
    if item.get("action_label"):
        payload["actionLabel"] = str(item.get("action_label"))
    if item.get("action_target"):
        payload["actionTarget"] = str(item.get("action_target"))
    if item.get("icon_type"):
        payload["iconType"] = str(item.get("icon_type"))
    if item.get("thumbnail_url"):
        payload["thumbnailUrl"] = str(item.get("thumbnail_url"))
    handout_assignment = item.get("handout_assignment")
    if isinstance(handout_assignment, dict):
        hid = str(handout_assignment.get("handout_id") or handout_assignment.get("handoutId") or "").strip()
        hname = str(handout_assignment.get("handout_name") or handout_assignment.get("handoutName") or "").strip()
        sid = str(handout_assignment.get("scenario_id") or handout_assignment.get("scenarioId") or "").strip()
        ses = str(handout_assignment.get("session_id") or handout_assignment.get("sessionId") or "").strip()
        if hid and sid and ses:
            payload["handoutAssignment"] = {
                "handoutId": hid,
                "handoutName": hname or hid,
                "scenarioId": sid,
                "sessionId": ses,
            }
    return payload


def _handle_notifications_list(event: dict) -> dict:
    if _get_method(event) != "GET":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    qp = _get_query_params(event)
    raw_limit = qp.get("limit") if isinstance(qp, dict) else None
    try:
        limit = int(raw_limit) if raw_limit is not None else 100
    except Exception:
        limit = 100

    try:
        items = repositories.list_user_notifications(actor_id, limit=limit)
        notifications = []
        for item in items:
            ui = _notification_to_ui(item)
            if ui:
                notifications.append(ui)
        return _response({"notifications": notifications}, status=200)
    except Exception as exc:
        logger.exception("Notifications list failed")
        return _response({"error": str(exc)}, status=500)


def _handle_notifications_read(event: dict) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    body = _parse_json_body(event)
    notification_id = body.get("notificationId") or body.get("notification_id")
    if not notification_id or not isinstance(notification_id, str):
        return _response({"error": "Missing notificationId"}, status=400)

    try:
        updated = repositories.mark_notification_read(actor_id, notification_id)
        if not updated:
            return _response({"error": "Notification not found"}, status=404)
        return _response({"success": True, "notificationId": notification_id}, status=200)
    except Exception as exc:
        logger.exception("Notification read failed")
        return _response({"error": str(exc)}, status=500)


def _handle_notifications_read_all(event: dict) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    try:
        updated = repositories.mark_all_notifications_read(actor_id)
        return _response({"success": True, "updated": updated}, status=200)
    except Exception as exc:
        logger.exception("Notification read-all failed")
        return _response({"error": str(exc)}, status=500)


def _achievement_def_to_ui(item: dict) -> dict | None:
    achievement_id = str(item.get("achievement_id") or item.get("id") or "")
    if not achievement_id:
        return None
    category = str(item.get("category") or "milestone")
    if category not in ("milestone", "gm", "meme", "scenario"):
        category = "milestone"
    raw_condition = item.get("condition")
    if isinstance(raw_condition, (dict, list)):
        description = str(item.get("description") or "")
    else:
        description = str(raw_condition or item.get("description") or "")
    payload: dict[str, Any] = {
        "id": achievement_id,
        "title": str(item.get("title") or ""),
        "description": description,
        "category": category,
        "isSpoiler": bool(item.get("is_spoiler")),
    }
    if item.get("icon_url"):
        payload["iconUrl"] = str(item.get("icon_url"))
    if item.get("audience"):
        payload["audience"] = str(item.get("audience"))
    return payload


def _ensure_catalog_achievements_seeded() -> None:
    global _catalog_seeded
    if _catalog_seeded:
        return
    path = Path(__file__).with_name("archivement.csv")
    if not path.exists():
        _catalog_seeded = True
        return
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not isinstance(row, dict):
                    continue
                title = str(row.get("実績名") or "").strip()
                kind = str(row.get("種別") or "").strip()
                audience = str(row.get("対象") or "").strip()
                cond_text = str(row.get("条件") or "").strip()
                if not title:
                    continue

                if kind == "マイルストーン":
                    icon_url = None
                    m_icon = re.match(r"^閲覧許可([A-D])", title)
                    if m_icon:
                        icon_url = f"/achievements/milestone-access-{m_icon.group(1).lower()}.svg"
                    m = re.match(r"^(PL|GM)として(\d+)(?:つ)?の?シナリオを通過", cond_text)
                    if not m:
                        continue
                    role = m.group(1)
                    min_count = int(m.group(2))
                    condition: dict[str, Any] = {"kind": "session_count", "min": min_count, "role": role}
                    repositories.upsert_achievement_definition(
                        title,
                        title,
                        cond_text,
                        category="milestone",
                        condition=condition,
                        icon_url=icon_url,
                        is_spoiler=False,
                        trigger="session_completed",
                        audience=audience or "全員",
                    )
                elif kind == "記念":
                    category = "gm" if audience == "GM" else "meme"
                    repositories.upsert_achievement_definition(
                        title,
                        title,
                        cond_text,
                        category=category,
                        condition=cond_text,
                        is_spoiler=False,
                        trigger="manual",
                        audience=audience or "GM/PL",
                    )
    except Exception:
        logger.exception("Failed to seed achievement catalog")
        return
    _catalog_seeded = True


def _handle_achievements_list(event: dict) -> dict:
    if _get_method(event) != "GET":
        return _response({"error": "method not allowed"}, status=405)

    _ensure_catalog_achievements_seeded()

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    try:
        items = repositories.list_achievement_definitions()
        achievements = []
        for item in items:
            ui = _achievement_def_to_ui(item)
            if ui:
                achievements.append(ui)
        return _response({"achievements": achievements}, status=200)
    except Exception as exc:
        logger.exception("Achievements list failed")
        return _response({"error": str(exc)}, status=500)


def _handle_profile(event: dict) -> dict:
    if _get_method(event) != "GET":
        return _response({"error": "method not allowed"}, status=405)

    _ensure_catalog_achievements_seeded()

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, actor_name = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    query = _get_query_params(event)
    requested_user_id = str(query.get("userId") or query.get("user") or "").strip()
    target_id = actor_id
    is_self_view = True
    if requested_user_id and requested_user_id != actor_id:
        target_id = requested_user_id
        is_self_view = False

    profile = repositories.get_user_profile(target_id) or {}
    if not is_self_view and not profile:
        return _response({"error": "User not found"}, status=404)

    display_name = str(profile.get("display_name_cache") or (actor_name if is_self_view else target_id))
    avatar_url = _user_avatar_url(target_id)
    handle = str(profile.get("handle") or f"@{target_id}")

    # When viewing other users, only show sessions that the viewer can access (shared sessions).
    accessible_session_ids: set[str] | None = None
    if not is_self_view:
        accessible_session_ids = set()
        try:
            for session in repositories.list_sessions_by_gm(actor_id, limit=200):
                sid = str(session.get("session_id") or "")
                if sid:
                    accessible_session_ids.add(sid)
        except Exception:
            logger.exception("Failed to list viewer GM sessions for profile")
        try:
            for sid in repositories.list_user_session_ids(actor_id, limit=200):
                if sid:
                    accessible_session_ids.add(str(sid))
        except Exception:
            logger.exception("Failed to list viewer participant sessions for profile")

    session_map: dict[str, dict] = {}
    try:
        for session in repositories.list_sessions_by_gm(target_id, limit=200):
            sid = str(session.get("session_id") or "")
            if sid:
                session_map[sid] = session
    except Exception:
        logger.exception("Failed to list GM sessions")

    try:
        for sid in repositories.list_user_session_ids(target_id, limit=200):
            if sid in session_map:
                continue
            session = repositories.get_session(sid)
            if session:
                session_map[sid] = session
    except Exception:
        logger.exception("Failed to list participant sessions")

    sessions_ui: list[dict[str, Any]] = []
    for session in session_map.values():
        session_id = str(session.get("session_id") or "")
        if not session_id:
            continue
        if accessible_session_ids is not None and session_id not in accessible_session_ids:
            continue

        raw_status = str(session.get("status") or "")
        status = _profile_status_from_session(raw_status)
        if not status:
            continue

        gm_user_id = _session_gm_user_id(session) or ""
        gm_name = _session_gm_name(session, gm_user_id)
        gm_avatar = _user_avatar_url(gm_user_id) if gm_user_id else None

        scenario_id = str(session.get("scenario_id") or "")
        scenario = repositories.get_scenario(scenario_id) if scenario_id else None
        scenario_title = str((scenario or {}).get("title") or session.get("title") or "")
        scenario_cover = _normalize_cover_url((scenario or {}).get("cover_url") or (scenario or {}).get("coverUrl"))

        role = "gm" if gm_user_id and gm_user_id == target_id else ("applicant" if status == "recruiting" else "participant")

        try:
            participant_records = repositories.list_participant_records(session_id)
        except Exception:
            participant_records = []

        remaining_seats = None
        max_players = _parse_int(session.get("max_players"))
        if status == "recruiting" and max_players is not None:
            remaining_seats = max(0, max_players - len(participant_records))

        confirmed_date = None
        if session.get("scheduled_start"):
            confirmed_date = _format_confirmed_label(str(session.get("scheduled_start")))

        deadline = _session_deadline_iso(session_id)
        tentative_slots = _teaser_slot_labels(session.get("teaser_slots"))
        has_voted = _user_has_voted(session_id, target_id) if status == "scheduling" else None
        thread_url = _session_thread_url(session)

        payload: dict[str, Any] = {
            "sessionId": session_id,
            "scenarioId": scenario_id,
            "scenarioTitle": scenario_title,
            "scenarioCoverUrl": scenario_cover,
            "status": status,
            "role": role,
            "gmName": gm_name,
        }
        if gm_avatar:
            payload["gmAvatarUrl"] = gm_avatar
        if remaining_seats is not None:
            payload["remainingSeats"] = remaining_seats
        if tentative_slots:
            payload["tentativeSlots"] = tentative_slots
        if confirmed_date:
            payload["confirmedDate"] = confirmed_date
        if deadline:
            payload["deadline"] = deadline
        if has_voted is not None:
            payload["hasVoted"] = has_voted
        if thread_url:
            payload["threadUrl"] = thread_url
        sessions_ui.append(payload)

    sessions_ui.sort(key=lambda x: str(x.get("status") or ""))

    definitions = repositories.list_achievement_definitions()
    unlocks = repositories.list_user_achievement_unlocks(target_id)
    unlock_map = {str(u.get("achievement_id") or ""): u for u in unlocks if u.get("achievement_id")}

    achievements: list[dict[str, Any]] = []
    def_map: dict[str, dict] = {}
    for d in definitions:
        ui = _achievement_def_to_ui(d)
        if not ui:
            continue
        def_map[ui["id"]] = ui
        unlock = unlock_map.get(ui["id"])
        if not unlock and not is_self_view:
            continue
        payload = {
            **ui,
            "isUnlocked": bool(unlock),
        }
        if unlock:
            visibility = str(unlock.get("visibility") or "public")
            spoiler_level = str(unlock.get("spoiler_level") or "none")
            if not is_self_view:
                if spoiler_level in ("mild", "heavy"):
                    continue
                if ui.get("isSpoiler"):
                    continue
            if unlock.get("unlocked_at"):
                payload["unlockedAt"] = str(unlock.get("unlocked_at"))
            if visibility:
                payload["visibility"] = visibility
            if spoiler_level:
                payload["spoilerLevel"] = spoiler_level
        achievements.append(payload)

    pinned = None
    if is_self_view:
        for unlock in unlocks:
            if unlock.get("pinned"):
                ach_id = str(unlock.get("achievement_id") or "")
                base = def_map.get(ach_id)
                if base:
                    pinned = {
                        **base,
                        "isUnlocked": True,
                        "unlockedAt": str(unlock.get("unlocked_at") or ""),
                    }
                    break
        if not pinned:
            unlocked = [a for a in achievements if a.get("isUnlocked") and a.get("unlockedAt")]
            if unlocked:
                unlocked.sort(key=lambda x: str(x.get("unlockedAt") or ""), reverse=True)
                pinned = unlocked[0]
    else:
        unlocked = [a for a in achievements if a.get("isUnlocked") and a.get("unlockedAt")]
        if unlocked:
            unlocked.sort(key=lambda x: str(x.get("unlockedAt") or ""), reverse=True)
            pinned = unlocked[0]

    history = repositories.list_play_history_for_user(target_id)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)
    sessions_last_30 = 0
    gm_count = 0
    played_map: dict[str, dict[str, Any]] = {}
    scenario_cache: dict[str, dict] = {}
    for item in history:
        scenario_id = str(item.get("scenario_id") or "")
        if not scenario_id:
            continue
        date_str = str(item.get("date") or "")
        role = str(item.get("role") or "")
        handout_name = None
        if is_self_view:
            handout_name = str(item.get("handout_name") or "").strip() or None
        try:
            if date_str:
                dt = _parse_iso_datetime(date_str)
                if dt >= cutoff:
                    sessions_last_30 += 1
        except Exception:
            pass
        if role == "GM":
            gm_count += 1
        if scenario_id not in scenario_cache:
            scenario_cache[scenario_id] = repositories.get_scenario(scenario_id) or {}
        scenario = scenario_cache[scenario_id]
        entry = played_map.get(scenario_id)
        if not entry:
            entry = {
                "scenarioId": scenario_id,
                "scenarioTitle": str(scenario.get("title") or scenario_id),
                "coverUrl": _normalize_cover_url(scenario.get("cover_url") or scenario.get("coverUrl")),
                "system": str(scenario.get("system") or "—"),
                "role": role if role in ("PL", "GM") else "PL",
                "playCount": 0,
                "lastPlayedAt": date_str,
            }
            if handout_name:
                entry["handoutName"] = handout_name
            played_map[scenario_id] = entry
        entry["playCount"] = int(entry.get("playCount") or 0) + 1
        if date_str and str(date_str) > str(entry.get("lastPlayedAt") or ""):
            entry["lastPlayedAt"] = date_str
            if role in ("PL", "GM"):
                entry["role"] = role
            if handout_name:
                entry["handoutName"] = handout_name

    played_scenarios = list(played_map.values())
    played_scenarios.sort(key=lambda x: str(x.get("lastPlayedAt") or ""), reverse=True)

    total_scenarios = len(played_scenarios)

    favorited_scenarios: list[dict[str, Any]] = []
    bookmarked_scenarios: list[dict[str, Any]] = []
    try:
        prefs_raw = repositories.list_user_scenario_preferences(target_id, limit=500)
        prefs_raw.sort(key=lambda x: str(x.get("updated_at") or x.get("created_at") or ""), reverse=True)

        favorited_order: list[tuple[str, dict]] = []
        bookmarked_order: list[tuple[str, dict]] = []
        seen: set[str] = set()
        for pref in prefs_raw:
            scenario_id = str(pref.get("scenario_id") or "").strip()
            if not scenario_id or scenario_id in seen:
                continue
            seen.add(scenario_id)
            if pref.get("is_favorited"):
                favorited_order.append((scenario_id, pref))
            if is_self_view and pref.get("is_bookmarked"):
                bookmarked_order.append((scenario_id, pref))

        all_ids = [sid for sid, _ in favorited_order] + [sid for sid, _ in bookmarked_order]
        all_ids = list(dict.fromkeys(all_ids))

        scenario_map = repositories.batch_get_scenarios(all_ids)

        def _pref_scenario_ui(scenario_id: str, pref: dict) -> dict[str, Any] | None:
            scenario = scenario_map.get(scenario_id) or {}
            if not scenario:
                return None
            ui = {
                "scenarioId": scenario_id,
                "scenarioTitle": str(scenario.get("title") or scenario_id),
                "coverUrl": _normalize_cover_url(scenario.get("cover_url") or scenario.get("coverUrl")),
                "system": str(scenario.get("system") or "—"),
            }
            updated_at = str(pref.get("updated_at") or pref.get("created_at") or "").strip()
            if updated_at:
                ui["updatedAt"] = updated_at
            return ui

        for scenario_id, pref in favorited_order:
            ui = _pref_scenario_ui(scenario_id, pref)
            if ui:
                favorited_scenarios.append(ui)

        for scenario_id, pref in bookmarked_order:
            ui = _pref_scenario_ui(scenario_id, pref)
            if ui:
                bookmarked_scenarios.append(ui)
    except Exception:
        logger.exception("Failed to load scenario preferences for profile")

    characters_raw = repositories.list_user_characters(target_id) if is_self_view else []
    characters = []
    for item in characters_raw:
        character_id = str(item.get("character_id") or "")
        if not character_id:
            continue
        payload = {
            "id": character_id,
            "name": str(item.get("name") or ""),
            "url": str(item.get("url") or ""),
        }
        if item.get("system"):
            payload["system"] = str(item.get("system"))
        if item.get("updated_at"):
            payload["updatedAt"] = str(item.get("updated_at"))
        characters.append(payload)

    profile_payload: dict[str, Any] = {
        "user": {
            "userId": target_id,
            "displayName": display_name,
            "handle": handle,
            "stats": {
                "totalScenarios": total_scenarios,
                "gmCount": gm_count,
                "sessionsLast30Days": sessions_last_30,
            },
        },
        "sessions": sessions_ui,
        "achievements": achievements,
        "playedScenarios": played_scenarios,
        "favoritedScenarios": favorited_scenarios,
        "bookmarkedScenarios": bookmarked_scenarios,
        "characters": characters,
    }
    if avatar_url:
        profile_payload["user"]["avatarUrl"] = str(avatar_url)
    if pinned:
        profile_payload["user"]["pinnedAchievement"] = pinned

    return _response({"profile": profile_payload}, status=200)


def _session_to_card(session: dict, actor_id: str) -> dict:
    session_id = str(session.get("session_id") or "")
    scenario_id = str(session.get("scenario_id") or "")
    scenario_title = str(session.get("scenario_title") or session.get("title") or "")
    status = str(session.get("status") or "")
    gm_user_id = _session_gm_user_id(session) or ""
    gm_name = _session_gm_name(session, gm_user_id)

    participant_records = repositories.list_participant_records(session_id)
    participant_count = len(participant_records)
    max_players = _parse_int(session.get("max_players"))
    remaining_seats = None
    if max_players is not None:
        remaining_seats = max(0, int(max_players) - participant_count)

    role = "participant"
    requester_id = str(session.get("created_by") or "").strip()
    is_requester = bool(requester_id and requester_id == actor_id)
    try:
        is_participant = repositories.is_participant(session_id, actor_id) or repositories.is_waitlisted(session_id, actor_id)
    except Exception:
        is_participant = False

    if actor_id == gm_user_id:
        role = "gm"
    elif not gm_user_id:
        scenario_id = str(session.get("scenario_id") or "").strip()
        try:
            if scenario_id and repositories.is_scenario_gm_registered(scenario_id, actor_id):
                role = "gm"
        except Exception:
            role = "participant"
    elif is_requester or is_participant:
        role = "participant"

    scheduled_start = session.get("scheduled_start")
    deadline = None
    if status == "scheduling":
        deadline = _session_deadline_iso(session_id)

    flow_mode = str(session.get("flow_mode") or "people_first")
    if flow_mode not in ("people_first", "schedule_first"):
        flow_mode = "people_first"
    fixed_schedule = session.get("fixed_schedule") if isinstance(session.get("fixed_schedule"), list) else None

    card: dict[str, Any] = {
        "sessionId": session_id,
        "scenarioId": scenario_id,
        "scenarioTitle": scenario_title,
        "scenarioCoverUrl": _session_cover_url(session),
        "status": status,
        "gmUserId": gm_user_id,
        "gmName": gm_name,
        "participantCount": participant_count,
        "userRole": role,
        "flowMode": flow_mode,
    }
    if fixed_schedule:
        card["fixedSchedule"] = fixed_schedule
    if remaining_seats is not None:
        card["remainingSeats"] = remaining_seats
    if deadline:
        card["deadline"] = deadline
    if scheduled_start:
        card["confirmedStartAt"] = str(scheduled_start)
    thread_url = _session_thread_url(session)
    if thread_url:
        card["threadUrl"] = thread_url
    gm_avatar = _user_avatar_url(gm_user_id) if gm_user_id else None
    if gm_avatar:
        card["gmAvatarUrl"] = gm_avatar
    return card


def _handle_sessions_list(event: dict) -> dict:
    if _get_method(event) != "GET":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    qp = _get_query_params(event)
    raw_limit = qp.get("limit") if isinstance(qp, dict) else None
    try:
        limit = int(raw_limit) if raw_limit is not None else 50
    except Exception:
        limit = 50
    limit = max(1, min(limit, 200))

    include_recruiting = False
    if isinstance(qp, dict):
        include_recruiting = str(qp.get("includeRecruiting") or "").strip().lower() in ("1", "true", "yes", "y")
    guild_filter = str(qp.get("guildId") or "") if isinstance(qp, dict) else ""

    statuses = ["scheduling", "confirmed", "running", "completed", "canceled", "cancelled"]
    if include_recruiting:
        statuses = ["recruiting", *statuses]

    seen: set[str] = set()
    collected: list[dict] = []
    try:
        for status in statuses:
            for idx in repositories.list_sessions_by_status(status, limit=limit * 2):
                sid = str(idx.get("session_id") or "")
                if not sid or sid in seen:
                    continue
                seen.add(sid)
                session = repositories.get_session_with_details(sid) or repositories.get_session(sid)
                if not session:
                    continue
                if guild_filter and str(session.get("guild_id") or "") != guild_filter:
                    continue

                gm_user_id = _session_gm_user_id(session) or ""
                requester_id = str(session.get("created_by") or "").strip()
                is_involved = bool(gm_user_id and actor_id == gm_user_id)
                if not is_involved and requester_id and requester_id == actor_id:
                    is_involved = True
                if not is_involved:
                    try:
                        is_involved = repositories.is_participant(sid, actor_id) or repositories.is_waitlisted(sid, actor_id)
                    except Exception:
                        is_involved = False
                if not is_involved and not gm_user_id:
                    scenario_id = str(session.get("scenario_id") or "").strip()
                    if scenario_id:
                        try:
                            is_involved = repositories.is_scenario_gm_registered(scenario_id, actor_id)
                        except Exception:
                            is_involved = False
                if not is_involved:
                    continue

                collected.append(session)
    except Exception as exc:
        logger.exception("Session list failed")
        return _response({"error": str(exc)}, status=500)

    collected.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
    cards = []
    for s in collected[:limit]:
        try:
            cards.append(_session_to_card(s, actor_id))
        except Exception:
            logger.exception("Failed to build session card")
    return _response({"sessions": cards}, status=200)


def _handle_session_detail(event: dict, session_id: str) -> dict:
    if _get_method(event) != "GET":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session_with_details(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    try:
        _assert_scheduling_access(session_id, session, actor_id)
    except PermissionError:
        return _response({"error": "forbidden"}, status=403)
    except Exception as exc:
        logger.exception("Session auth check failed")
        return _response({"error": str(exc)}, status=500)

    gm_user_id = _session_gm_user_id(session) or ""
    gm_name = _session_gm_name(session, gm_user_id)
    is_gm_viewer = actor_id == gm_user_id

    participants: list[dict[str, Any]] = []
    try:
        for p in repositories.list_participant_records(session_id):
            user_id = str(p.get("user_id") or "")
            if not user_id:
                continue
            name = str(p.get("display_name") or user_id)
            summary: dict[str, Any] = {"id": user_id, "name": name}
            avatar_url = _user_avatar_url(user_id)
            if avatar_url:
                summary["avatarUrl"] = avatar_url
            participants.append(summary)
    except Exception:
        participants = []

    try:
        character_records = repositories.list_session_character_records(session_id)
    except Exception:
        character_records = []
    character_map: dict[str, dict] = {}
    for record in character_records:
        if not isinstance(record, dict):
            continue
        uid = str(record.get("user_id") or "")
        if uid:
            character_map[uid] = record
    for p in participants:
        uid = str(p.get("id") or "")
        record = character_map.get(uid)
        if not record:
            continue
        visibility = str(record.get("visibility") or "public")
        if visibility == "private" and not (is_gm_viewer or uid == actor_id):
            continue
        payload: dict[str, Any] = {
            "name": str(record.get("name") or ""),
            "sheetUrl": str(record.get("sheet_url") or ""),
            "visibility": visibility,
        }
        if record.get("portrait_url"):
            payload["portraitUrl"] = str(record.get("portrait_url"))
        p["character"] = payload

    detail: dict[str, Any] = {
        "sessionId": session_id,
        "scenarioId": str(session.get("scenario_id") or ""),
        "scenarioTitle": str(session.get("scenario_title") or session.get("title") or ""),
        "scenarioCoverUrl": _session_cover_url(session),
        "status": str(session.get("status") or ""),
        "flowMode": str(session.get("flow_mode") or "people_first"),
        "gmUserId": gm_user_id,
        "gmName": gm_name,
        "participants": participants,
        "createdAt": str(session.get("created_at") or ""),
        "teaserSlots": session.get("teaser_slots") if isinstance(session.get("teaser_slots"), list) else None,
        "fixedSchedule": session.get("fixed_schedule") if isinstance(session.get("fixed_schedule"), list) else None,
        "scheduledStart": session.get("scheduled_start"),
        "scheduledEnd": session.get("scheduled_end"),
        "minPlayers": _parse_int(session.get("min_players")),
        "maxPlayers": _parse_int(session.get("max_players")),
    }
    thread_url = _session_thread_url(session)
    if thread_url:
        detail["threadUrl"] = thread_url
    gm_avatar = _user_avatar_url(gm_user_id) if gm_user_id else None
    if gm_avatar:
        detail["gmAvatarUrl"] = gm_avatar
    deadline = _session_deadline_iso(session_id)
    if deadline:
        detail["deadline"] = deadline

    raw_handouts = session.get("handouts") if isinstance(session.get("handouts"), list) else []
    is_handout_session = _coerce_bool(session.get("is_handout_session")) or bool(raw_handouts)
    if is_handout_session:
        detail["isHandoutSession"] = True
        assignments_raw: list[dict] = []
        try:
            assignments_raw = repositories.list_handout_assignments(session_id)
        except Exception:
            assignments_raw = []
        assignments_ui: list[dict[str, Any]] = []
        for item in assignments_raw:
            if not isinstance(item, dict):
                continue
            handout_id = str(item.get("handout_id") or "")
            participant_id = str(item.get("participant_id") or "")
            if not handout_id or not participant_id:
                continue
            payload: dict[str, Any] = {
                "handoutId": handout_id,
                "handoutName": str(item.get("handout_name") or ""),
                "participantId": participant_id,
                "participantName": str(item.get("participant_name") or participant_id),
                "assignedAt": str(item.get("assigned_at") or ""),
            }
            if item.get("notified_at"):
                payload["notifiedAt"] = str(item.get("notified_at"))
            extra_private_info = str(item.get("extra_private_info") or "").strip()
            if extra_private_info:
                payload["extraPrivateInfo"] = extra_private_info
            assignments_ui.append(payload)

        visible_assignments = assignments_ui if is_gm_viewer else [a for a in assignments_ui if a.get("participantId") == actor_id]

        assigned_handout_ids = {a.get("handoutId") for a in visible_assignments if a.get("handoutId")}
        extra_private_map = {
            str(a.get("handoutId") or ""): str(a.get("extraPrivateInfo") or "").strip()
            for a in visible_assignments
            if a.get("handoutId")
        }

        handouts_ui: list[dict[str, Any]] = []
        for ho in raw_handouts[:30]:
            if not isinstance(ho, dict):
                continue
            hid = str(ho.get("id") or "").strip()
            name = str(ho.get("name") or "").strip()
            if not hid or not name:
                continue
            public_info = str(ho.get("public_info") or ho.get("publicInfo") or "").strip()
            private_info = str(ho.get("private_info") or ho.get("privateInfo") or "").strip()
            order_val = ho.get("order")
            order: int | None = None
            if order_val is not None:
                try:
                    order = int(order_val)
                except Exception:
                    order = None

            payload: dict[str, Any] = {"id": hid, "name": name, "publicInfo": public_info}
            if order is not None:
                payload["order"] = order
            if is_gm_viewer or hid in assigned_handout_ids:
                combined_private = private_info
                extra = extra_private_map.get(hid) or ""
                if extra:
                    if combined_private:
                        combined_private = combined_private.rstrip() + "\n\n" + extra
                    else:
                        combined_private = extra
                if combined_private:
                    payload["privateInfo"] = combined_private
            handouts_ui.append(payload)

        detail["handouts"] = handouts_ui
        detail["handoutAssignments"] = visible_assignments

    if is_gm_viewer:
        try:
            scenario_id = str(session.get("scenario_id") or "")
            scenario = repositories.get_scenario(scenario_id) if scenario_id else None
            completion_raw = (scenario or {}).get("completion_achievements") or []
            completion_ui: list[dict[str, Any]] = []
            if isinstance(completion_raw, list):
                for item in completion_raw:
                    if not isinstance(item, dict):
                        continue
                    ach_id = str(item.get("id") or "").strip()
                    title = str(item.get("title") or "").strip()
                    if not ach_id or not title:
                        continue
                    completion_ui.append(
                        {
                            "id": ach_id,
                            "title": title,
                            "description": str(item.get("description") or "").strip(),
                            "isSpoiler": bool(item.get("is_spoiler")),
                        }
                    )
            if completion_ui:
                detail["completionAchievements"] = completion_ui
        except Exception:
            logger.exception("Failed to attach completion achievements")

    return _response({"session": detail}, status=200)


def _handle_session_character_set(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    try:
        _assert_scheduling_access(session_id, session, actor_id)
    except PermissionError:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    name = str(body.get("name") or body.get("characterName") or "").strip()
    sheet_url = str(body.get("sheetUrl") or body.get("sheet_url") or body.get("url") or "").strip()
    portrait_url = body.get("portraitUrl") or body.get("portrait_url") or None
    portrait_url = str(portrait_url).strip() if portrait_url is not None else ""
    visibility = str(body.get("visibility") or "public").strip().lower()
    if visibility not in ("public", "private"):
        visibility = "public"

    if not name:
        return _response({"error": "Missing name"}, status=400)

    if not sheet_url and not portrait_url:
        return _response({"error": "Missing sheetUrl or portraitUrl"}, status=400)

    try:
        repositories.upsert_session_character(
            session_id=session_id,
            user_id=actor_id,
            name=name,
            sheet_url=sheet_url,
            portrait_url=portrait_url or None,
            visibility=visibility,
        )
        try:
            repositories.log_audit(
                session_id,
                "session_character_set_ui",
                actor_id,
                {"visibility": visibility, "has_sheet_url": bool(sheet_url), "has_portrait_url": bool(portrait_url)},
            )
        except Exception:
            logger.exception("Failed to audit character set")
    except Exception as exc:
        logger.exception("Character set failed")
        return _response({"error": str(exc)}, status=500)

    # Return the updated session detail for convenient UI refresh.
    return _handle_session_detail(
        {
            "headers": headers,
            "requestContext": event.get("requestContext"),
            "rawPath": f"/api/sessions/{session_id}",
            "path": f"/api/sessions/{session_id}",
            "httpMethod": "GET",
        },
        session_id,
    )


def _handle_session_handout_assign(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    handout_id = str(body.get("handoutId") or body.get("handout_id") or "").strip() if isinstance(body, dict) else ""
    participant_id = str(body.get("participantId") or body.get("participant_id") or "").strip() if isinstance(body, dict) else ""
    if not handout_id or not participant_id:
        return _response({"error": "Missing handoutId/participantId"}, status=400)

    raw_handouts = session.get("handouts") if isinstance(session.get("handouts"), list) else []
    handout = next((h for h in raw_handouts if isinstance(h, dict) and str(h.get("id") or "") == handout_id), None)
    if not handout:
        return _response({"error": "Handout not found"}, status=404)
    handout_name = str(handout.get("name") or handout_id)

    if not repositories.is_participant(session_id, participant_id):
        return _response({"error": "Participant not found in this session"}, status=404)

    participant_profile = repositories.get_user_profile(participant_id) or {}
    participant_name = str(participant_profile.get("display_name_cache") or participant_id)

    existing = repositories.get_handout_assignment(session_id, handout_id) or {}
    existing_participant_id = str(existing.get("participant_id") or "")
    same_participant = existing_participant_id == participant_id
    existing_notified_at = existing.get("notified_at") if same_participant else None
    existing_extra_private_info = (
        str(existing.get("extra_private_info") or "").strip() if same_participant else None
    )

    try:
        assignments = repositories.list_handout_assignments(session_id)
    except Exception:
        assignments = []
    for a in assignments:
        if not isinstance(a, dict):
            continue
        if str(a.get("handout_id") or "") == handout_id:
            continue
        if str(a.get("participant_id") or "") == participant_id:
            return _response({"error": "Participant already assigned to another handout"}, status=409)

    try:
        repositories.upsert_handout_assignment(
            session_id=session_id,
            handout_id=handout_id,
            handout_name=handout_name,
            participant_id=participant_id,
            participant_name=participant_name,
            notified_at=str(existing_notified_at) if existing_notified_at else None,
            extra_private_info=existing_extra_private_info,
        )
        repositories.log_audit(
            session_id,
            "handout_assigned_ui",
            actor_id,
            {"handout_id": handout_id, "participant_id": participant_id},
        )
    except Exception as exc:
        logger.exception("Handout assign failed")
        return _response({"error": str(exc)}, status=500)

    return _handle_session_detail(
        {
            "headers": headers,
            "requestContext": event.get("requestContext"),
            "rawPath": f"/api/sessions/{session_id}",
            "path": f"/api/sessions/{session_id}",
            "httpMethod": "GET",
        },
        session_id,
    )


def _handle_session_handout_unassign(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    handout_id = str(body.get("handoutId") or body.get("handout_id") or "").strip() if isinstance(body, dict) else ""
    if not handout_id:
        return _response({"error": "Missing handoutId"}, status=400)

    try:
        repositories.delete_handout_assignment(session_id, handout_id)
        repositories.log_audit(
            session_id,
            "handout_unassigned_ui",
            actor_id,
            {"handout_id": handout_id},
        )
    except Exception as exc:
        logger.exception("Handout unassign failed")
        return _response({"error": str(exc)}, status=500)

    return _handle_session_detail(
        {
            "headers": headers,
            "requestContext": event.get("requestContext"),
            "rawPath": f"/api/sessions/{session_id}",
            "path": f"/api/sessions/{session_id}",
            "httpMethod": "GET",
        },
        session_id,
    )


def _handle_session_handout_secret(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    handout_id = str(body.get("handoutId") or body.get("handout_id") or "").strip() if isinstance(body, dict) else ""
    extra_private_info = (
        body.get("extraPrivateInfo")
        if isinstance(body, dict) and "extraPrivateInfo" in body
        else (body.get("extra_private_info") if isinstance(body, dict) else None)
    )
    extra_private_info_str = str(extra_private_info or "").strip()

    if not handout_id:
        return _response({"error": "Missing handoutId"}, status=400)

    assignment = repositories.get_handout_assignment(session_id, handout_id)
    if not assignment:
        return _response({"error": "Handout assignment not found"}, status=404)

    if len(extra_private_info_str) > 4000:
        return _response({"error": "extraPrivateInfo too long (max 4000 chars)"}, status=400)

    try:
        repositories.set_handout_assignment_extra_private_info(session_id, handout_id, extra_private_info_str)
        repositories.log_audit(
            session_id,
            "handout_secret_updated_ui",
            actor_id,
            {"handout_id": handout_id, "length": len(extra_private_info_str)},
        )
    except Exception as exc:
        logger.exception("Handout secret update failed")
        return _response({"error": str(exc)}, status=500)

    return _handle_session_detail(
        {
            "headers": headers,
            "requestContext": event.get("requestContext"),
            "rawPath": f"/api/sessions/{session_id}",
            "path": f"/api/sessions/{session_id}",
            "httpMethod": "GET",
        },
        session_id,
    )


def _handle_session_handout_notify(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    handout_id = str(body.get("handoutId") or body.get("handout_id") or "").strip() if isinstance(body, dict) else ""
    if not handout_id:
        return _response({"error": "Missing handoutId"}, status=400)

    assignment = repositories.get_handout_assignment(session_id, handout_id)
    if not assignment:
        return _response({"error": "Handout assignment not found"}, status=404)
    if assignment.get("notified_at"):
        return _handle_session_detail(
            {
                "headers": headers,
                "requestContext": event.get("requestContext"),
                "rawPath": f"/api/sessions/{session_id}",
                "path": f"/api/sessions/{session_id}",
                "httpMethod": "GET",
            },
            session_id,
        )

    participant_id = str(assignment.get("participant_id") or "")
    handout_name = str(assignment.get("handout_name") or handout_id)
    scenario_id = str(session.get("scenario_id") or "")
    scenario = repositories.get_scenario(scenario_id) if scenario_id else None
    scenario_title = str((scenario or {}).get("title") or session.get("title") or "セッション")
    thumb = _normalize_cover_url((scenario or {}).get("cover_url") or (scenario or {}).get("coverUrl"))

    try:
        repositories.create_notification(
            participant_id,
            "action",
            "HOが付与されました",
            f"{scenario_title} / {handout_name}",
            action_label="確認",
            action_target=f"/sessions?session={session_id}&returnTo=/notifications&handout={handout_id}",
            icon_type="handout",
            thumbnail_url=thumb,
            handout_assignment={
                "handout_id": handout_id,
                "handout_name": handout_name,
                "scenario_id": scenario_id,
                "session_id": session_id,
            },
        )
        repositories.mark_handout_assignment_notified(session_id, handout_id)
        repositories.log_audit(
            session_id,
            "handout_notified_ui",
            actor_id,
            {"handout_id": handout_id, "participant_id": participant_id},
        )
    except Exception as exc:
        logger.exception("Handout notify failed")
        return _response({"error": str(exc)}, status=500)

    return _handle_session_detail(
        {
            "headers": headers,
            "requestContext": event.get("requestContext"),
            "rawPath": f"/api/sessions/{session_id}",
            "path": f"/api/sessions/{session_id}",
            "httpMethod": "GET",
        },
        session_id,
    )


def _handle_session_reopen_recruiting(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    status = str(session.get("status") or "")
    if status in ("completed", "canceled", "cancelled"):
        return _response({"error": f"Session cannot be reopened (status={status})"}, status=409)

    scheduled_start = session.get("scheduled_start")
    scheduled_end = session.get("scheduled_end")
    fixed_schedule = session.get("fixed_schedule") if isinstance(session.get("fixed_schedule"), list) else []

    if not fixed_schedule:
        if not scheduled_start:
            return _response({"error": "Session has no decided schedule to recruit after"}, status=409)
        fixed_item: dict[str, Any] = {
            "id": f"fixed_{uuid.uuid4().hex[:8]}",
            "label": "開催日",
            "startAt": str(scheduled_start),
        }
        if scheduled_end:
            fixed_item["endAt"] = str(scheduled_end)
        fixed_schedule = [fixed_item]

    try:
        repositories.set_session_flow_mode(session_id, "schedule_first")
        repositories.set_session_fixed_schedule(session_id, fixed_schedule)
        repositories.mark_session_status(session_id, "recruiting")
        repositories.log_audit(
            session_id,
            "session_reopen_recruiting_ui",
            actor_id,
            {"previous_status": status, "fixed_schedule_items": len(fixed_schedule)},
        )
    except Exception as exc:
        logger.exception("Reopen recruiting failed")
        return _response({"error": str(exc)}, status=500)

    return _handle_session_detail(
        {
            "headers": headers,
            "requestContext": event.get("requestContext"),
            "rawPath": f"/api/sessions/{session_id}",
            "path": f"/api/sessions/{session_id}",
            "httpMethod": "GET",
        },
        session_id,
    )


def _handle_session_reschedule(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    reason = body.get("reason")
    mode = body.get("mode") or "direct"
    if not isinstance(reason, str) or not reason.strip():
        return _response({"error": "Missing reason"}, status=400)
    if str(mode) not in ("direct", "poll"):
        return _response({"error": "Invalid mode (direct|poll)"}, status=400)

    flow_mode = str(session.get("flow_mode") or "people_first")

    try:
        if flow_mode == "schedule_first":
            if str(mode) != "direct":
                return _response({"error": "schedule_first reschedule supports direct mode only"}, status=409)

            new_start = body.get("newStartAt") or body.get("startAt") or body.get("start_at")
            new_end = body.get("newEndAt") or body.get("endAt") or body.get("end_at")
            if not new_start:
                return _response({"error": "Missing newStartAt"}, status=400)

            start_dt = _parse_user_datetime(str(new_start))
            end_dt = _parse_user_datetime(str(new_end)) if new_end else None

            fixed_schedule = session.get("fixed_schedule") if isinstance(session.get("fixed_schedule"), list) else []
            if not fixed_schedule:
                return _response({"error": "fixedSchedule missing"}, status=409)

            schedule_item_id = body.get("scheduleItemId") or body.get("schedule_item_id")
            target_idx = 0
            if schedule_item_id:
                found = False
                for idx, item in enumerate(fixed_schedule):
                    if str((item or {}).get("id") or "") == str(schedule_item_id):
                        target_idx = idx
                        found = True
                        break
                if not found:
                    return _response({"error": "scheduleItemId not found"}, status=404)

            item = fixed_schedule[target_idx] if target_idx < len(fixed_schedule) else {}
            if not isinstance(item, dict):
                item = {}
            item["startAt"] = start_dt.isoformat().replace("+00:00", "Z")
            if end_dt:
                item["endAt"] = end_dt.isoformat().replace("+00:00", "Z")
            else:
                item.pop("endAt", None)
                item.pop("end_at", None)
            fixed_schedule[target_idx] = item
            repositories.set_session_fixed_schedule(session_id, fixed_schedule)

            repositories.log_audit(
                session_id,
                "session_reschedule_fixed_direct_ui",
                actor_id,
                {
                    "reason": reason.strip(),
                    "schedule_item_id": schedule_item_id,
                    "new_start_at": item.get("startAt"),
                    "new_end_at": item.get("endAt"),
                },
            )

            return _handle_session_detail({"headers": headers, "requestContext": event.get("requestContext"), "rawPath": f"/api/sessions/{session_id}", "path": f"/api/sessions/{session_id}", "httpMethod": "GET"}, session_id)

        # people_first (default)
        if str(mode) == "direct":
            new_start = body.get("newStartAt") or body.get("startAt") or body.get("start_at")
            new_end = body.get("newEndAt") or body.get("endAt") or body.get("end_at")
            if not new_start:
                return _response({"error": "Missing newStartAt"}, status=400)

            start_dt = _parse_user_datetime(str(new_start))
            end_dt = _parse_user_datetime(str(new_end)) if new_end else (start_dt + timedelta(hours=_duration_hours_from_session(session)))

            schedule_item_id = body.get("scheduleItemId") or body.get("schedule_item_id")
            fixed_schedule = session.get("fixed_schedule") if isinstance(session.get("fixed_schedule"), list) else []
            target_idx = 0
            if schedule_item_id:
                found = False
                for idx, item in enumerate(fixed_schedule):
                    if str((item or {}).get("id") or "") == str(schedule_item_id):
                        target_idx = idx
                        found = True
                        break
                if fixed_schedule and not found:
                    return _response({"error": "scheduleItemId not found"}, status=404)

            if fixed_schedule:
                item = fixed_schedule[target_idx] if target_idx < len(fixed_schedule) else {}
                if not isinstance(item, dict):
                    item = {}
                item["startAt"] = start_dt.isoformat().replace("+00:00", "Z")
                item["endAt"] = end_dt.isoformat().replace("+00:00", "Z") if end_dt else None
                if not item.get("endAt"):
                    item.pop("endAt", None)
                    item.pop("end_at", None)
                fixed_schedule[target_idx] = item
            else:
                fixed_schedule = [
                    {
                        "id": f"fixed_{uuid.uuid4().hex[:8]}",
                        "label": "開催日",
                        "startAt": start_dt.isoformat().replace("+00:00", "Z"),
                        "endAt": end_dt.isoformat().replace("+00:00", "Z") if end_dt else None,
                    }
                ]
                if not fixed_schedule[0].get("endAt"):
                    fixed_schedule[0].pop("endAt", None)

            try:
                repositories.set_session_fixed_schedule(session_id, fixed_schedule)
            except Exception:
                logger.exception("Failed to update fixed schedule on reschedule direct")

            if target_idx == 0:
                repositories.set_session_schedule_manual(session_id, start_dt, end_dt)

            repositories.mark_session_status(session_id, "confirmed")

            try:
                for p in repositories.list_participant_records(session_id):
                    uid = str(p.get("user_id") or "")
                    if not uid or uid == gm_user_id:
                        continue
                    repositories.create_notification(
                        uid,
                        "action",
                        "日程が変更されました",
                        f"{session.get('title') or 'セッション'}: {reason.strip()}",
                        action_label="確認",
                        action_target=f"/sessions/{session_id}/schedule",
                        icon_type="calendar",
                    )
            except Exception:
                logger.exception("Failed to notify participants for reschedule")

            repositories.log_audit(
                session_id,
                "session_reschedule_direct_ui",
                actor_id,
                {
                    "reason": reason.strip(),
                    "schedule_item_id": schedule_item_id,
                    "new_start_at": start_dt.isoformat(),
                    "new_end_at": end_dt.isoformat() if end_dt else None,
                },
            )

            return _handle_session_detail({"headers": headers, "requestContext": event.get("requestContext"), "rawPath": f"/api/sessions/{session_id}", "path": f"/api/sessions/{session_id}", "httpMethod": "GET"}, session_id)

        candidate_slots = body.get("candidateSlots") or body.get("candidate_slots") or []
        if not isinstance(candidate_slots, list) or not candidate_slots:
            return _response({"error": "Missing candidateSlots"}, status=400)
        start_ats: list[str] = []
        for raw in candidate_slots[:50]:
            if not isinstance(raw, dict):
                continue
            start_at = raw.get("startAt") or raw.get("start_at")
            if start_at:
                start_ats.append(str(start_at))
        if not start_ats:
            return _response({"error": "candidateSlots must include startAt"}, status=400)

        seen: set[str] = set()
        unique: list[str] = []
        for s in start_ats:
            if s in seen:
                continue
            seen.add(s)
            unique.append(s)

        repositories.clear_session_schedule(session_id)
        try:
            repositories.set_session_fixed_schedule(session_id, [])
        except Exception:
            logger.exception("Failed to clear fixedSchedule on reschedule poll")
        poll_id = repositories.create_poll(session_id=session_id, deadline=None, timezone_basis="Asia/Tokyo")
        duration_hours = _duration_hours_from_session(session, default_hours=4)
        for start_iso in unique:
            start_dt = _parse_user_datetime(start_iso)
            end_dt = start_dt + timedelta(hours=duration_hours)
            repositories.add_slot(poll_id, start=start_dt, end=end_dt)

        repositories.mark_session_status(session_id, "scheduling")

        try:
            for p in repositories.list_participant_records(session_id):
                uid = str(p.get("user_id") or "")
                if not uid or uid == gm_user_id:
                    continue
                repositories.create_notification(
                    uid,
                    "action",
                    "日程の再調整が始まりました",
                    f"{session.get('title') or 'セッション'}: {reason.strip()}",
                    action_label="可否入力",
                    action_target=f"/sessions/{session_id}/schedule",
                    icon_type="calendar",
                )
        except Exception:
            logger.exception("Failed to notify participants for reschedule poll")

        repositories.log_audit(
            session_id,
            "session_reschedule_poll_ui",
            actor_id,
            {"reason": reason.strip(), "poll_id": poll_id, "slots": len(unique)},
        )

        return _handle_session_detail({"headers": headers, "requestContext": event.get("requestContext"), "rawPath": f"/api/sessions/{session_id}", "path": f"/api/sessions/{session_id}", "httpMethod": "GET"}, session_id)
    except Exception as exc:
        logger.exception("Reschedule failed")
        return _response({"error": str(exc)}, status=500)


def _handle_session_add_schedule(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    label = str(body.get("label") or "追加日程").strip() or "追加日程"
    start_at = body.get("startAt") or body.get("start_at")
    end_at = body.get("endAt") or body.get("end_at")
    if not start_at:
        return _response({"error": "Missing startAt"}, status=400)

    try:
        start_dt = _parse_user_datetime(str(start_at))
        end_dt = _parse_user_datetime(str(end_at)) if end_at else None
    except Exception:
        return _response({"error": "Invalid startAt/endAt"}, status=400)

    fixed_schedule = session.get("fixed_schedule") if isinstance(session.get("fixed_schedule"), list) else []
    item: dict[str, Any] = {
        "id": f"fixed_{uuid.uuid4().hex[:8]}",
        "label": label,
        "startAt": start_dt.isoformat().replace("+00:00", "Z"),
    }
    if end_dt:
        item["endAt"] = end_dt.isoformat().replace("+00:00", "Z")
    fixed_schedule.append(item)

    try:
        repositories.set_session_fixed_schedule(session_id, fixed_schedule)
        repositories.log_audit(
            session_id,
            "session_add_schedule_ui",
            actor_id,
            {"label": label, "startAt": item.get("startAt"), "endAt": item.get("endAt")},
        )
    except Exception as exc:
        logger.exception("Add schedule failed")
        return _response({"error": str(exc)}, status=500)

    return _handle_session_detail(
        {
            "headers": headers,
            "requestContext": event.get("requestContext"),
            "rawPath": f"/api/sessions/{session_id}",
            "path": f"/api/sessions/{session_id}",
            "httpMethod": "GET",
        },
        session_id,
    )


def _handle_session_cancel(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, _ = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    reason = body.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return _response({"error": "Missing reason"}, status=400)

    try:
        try:
            repositories.clear_session_schedule(session_id)
        except Exception:
            logger.exception("Failed to clear schedule on cancel")

        repositories.mark_session_status(session_id, "canceled")

        try:
            for p in repositories.list_participant_records(session_id):
                uid = str(p.get("user_id") or "")
                if not uid or uid == gm_user_id:
                    continue
                repositories.create_notification(
                    uid,
                    "system",
                    "セッションがキャンセルされました",
                    reason.strip(),
                    action_label="確認",
                    action_target="/notifications",
                    icon_type="alert",
                )
        except Exception:
            logger.exception("Failed to notify participants for cancel")

        repositories.log_audit(session_id, "session_cancel_ui", actor_id, {"reason": reason.strip()})
        return _response({"success": True, "sessionId": session_id}, status=200)
    except Exception as exc:
        logger.exception("Cancel failed")
        return _response({"error": str(exc)}, status=500)


def _coerce_bool_flag(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float, Decimal)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return default


def _grant_achievements_for_completion(
    session_id: str, scenario_id: str, participants: list[dict], gm_user_id: str
) -> int:
    defs = repositories.list_achievement_definitions()
    if not defs:
        return 0

    unlocked_total = 0
    now = datetime.now(timezone.utc).isoformat()

    user_ids = [str(p.get("user_id") or "") for p in participants if p.get("user_id")]
    if gm_user_id:
        user_ids.append(str(gm_user_id))
    seen_user_ids: set[str] = set()
    unique_user_ids: list[str] = []
    for uid in user_ids:
        if not uid or uid in seen_user_ids:
            continue
        seen_user_ids.add(uid)
        unique_user_ids.append(uid)

    participant_ids = {str(p.get("user_id") or "") for p in participants if p.get("user_id")}

    for user_id in unique_user_ids:
        # Count play history for evaluation.
        history = repositories.list_play_history_for_user(user_id, limit=500)
        all_scenarios = {str(h.get("scenario_id") or "") for h in history if h.get("scenario_id")}
        gm_scenarios = {str(h.get("scenario_id") or "") for h in history if str(h.get("role") or "") == "GM" and h.get("scenario_id")}
        pl_scenarios = {str(h.get("scenario_id") or "") for h in history if str(h.get("role") or "") == "PL" and h.get("scenario_id")}
        # Treat the just-completed session as passed even if play history recording is disabled.
        if scenario_id:
            all_scenarios.add(scenario_id)
            if user_id == gm_user_id:
                gm_scenarios.add(scenario_id)
            elif user_id in participant_ids:
                pl_scenarios.add(scenario_id)
        total_count = len([s for s in all_scenarios if s])
        gm_count = len([s for s in gm_scenarios if s])
        pl_count = len([s for s in pl_scenarios if s])

        existing_unlocks = repositories.list_user_achievement_unlocks(user_id)
        existing_ids = {str(u.get("achievement_id") or "") for u in existing_unlocks}

        for d in defs:
            trigger = str(d.get("trigger") or "")
            if trigger != "session_completed":
                continue
            achievement_id = str(d.get("achievement_id") or "")
            if not achievement_id or achievement_id in existing_ids:
                continue
            cond = d.get("condition")
            if isinstance(cond, str):
                # Free-form conditions are not machine-evaluable.
                continue
            if not isinstance(cond, dict):
                continue

            kind = str(cond.get("kind") or "")
            if kind == "session_count":
                min_count = _parse_int(cond.get("min"), default=1) or 1
                role = str(cond.get("role") or "any")
                if role == "GM":
                    count = gm_count
                elif role == "PL":
                    count = pl_count
                else:
                    count = total_count
                if count < min_count:
                    continue
            elif kind == "scenario_complete":
                target = str(cond.get("scenario_id") or "")
                if target and target != scenario_id:
                    continue
            else:
                continue

            spoiler_level = "mild" if bool(d.get("is_spoiler")) else "none"
            created = repositories.create_user_achievement_unlock_if_absent(
                user_id,
                achievement_id,
                unlocked_at=now,
                visibility="private",
                spoiler_level=spoiler_level,
            )
            if not created:
                continue
            existing_ids.add(achievement_id)
            unlocked_total += 1
            try:
                ach_title = str(d.get("title") or achievement_id)
                subtitle = "ネタバレ実績（プロフィールで確認）" if bool(d.get("is_spoiler")) else ach_title
                repositories.create_notification(
                    user_id,
                    "celebrate",
                    "実績を獲得しました",
                    subtitle,
                    action_label="プロフィール",
                    action_target="/profile",
                    icon_type="trophy",
                )
            except Exception:
                logger.exception("Failed to notify achievement unlock")

    return unlocked_total


def _handle_session_complete(event: dict, session_id: str) -> dict:
    if _get_method(event) != "POST":
        return _response({"error": "method not allowed"}, status=405)

    _ensure_catalog_achievements_seeded()

    headers = event.get("headers") or {}
    auth_token = _bearer_token(headers)
    if not auth_token:
        return _response({"error": "Missing Authorization: Bearer <token>"}, status=401)

    try:
        actor_id, actor_name = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    session = repositories.get_session(session_id)
    if not session:
        return _response({"error": "Session not found"}, status=404)

    was_completed = str(session.get("status") or "") in ("completed", "cancelled", "canceled")

    gm_user_id = _session_gm_user_id(session) or ""
    if not gm_user_id or actor_id != gm_user_id:
        return _response({"error": "forbidden"}, status=403)

    body = _parse_json_body(event)
    record_history = _coerce_bool_flag(body.get("recordPlayHistory") if isinstance(body, dict) else None, default=True)
    grant_achievements = _coerce_bool_flag(body.get("grantAchievements") if isinstance(body, dict) else None, default=True)
    grant_roles = _coerce_bool_flag(body.get("grantRoles") if isinstance(body, dict) else None, default=False)
    survival_statuses: dict[str, str] | None = None
    if isinstance(body, dict) and isinstance(body.get("participantSurvivalStatus"), dict):
        survival_statuses = {str(k): str(v) for k, v in body["participantSurvivalStatus"].items()}
    achievement_ids_raw = None
    if isinstance(body, dict):
        achievement_ids_raw = (
            body.get("achievementIds")
            or body.get("selectedScenarioAchievementIds")
            or body.get("achievement_ids")
            or body.get("completionAchievementIds")
            or body.get("completion_achievement_ids")
        )
    selected_achievement_ids: list[str] = []
    if isinstance(achievement_ids_raw, list):
        for raw in achievement_ids_raw[:30]:
            if isinstance(raw, str) and raw.strip():
                selected_achievement_ids.append(raw.strip())

    commem_pl_ids: list[str] = []
    commem_gm_ids: list[str] = []
    commem_all_ids: list[str] = []
    commem_map: dict[str, list[str]] = {}
    if isinstance(body, dict):
        raw_map = body.get("participantCommemorativeAchievements") or body.get("participant_commemorative_achievements")
        if isinstance(raw_map, dict):
            for raw_uid, raw_ids in raw_map.items():
                if not isinstance(raw_uid, str) or not raw_uid.strip():
                    continue
                ids = _coerce_str_list(raw_ids)
                if not ids:
                    continue
                commem_map[raw_uid.strip()] = ids[:50]

        commem_pl_ids = _coerce_str_list(
            body.get("commemorativeAchievementIdsForParticipants")
            or body.get("commemorativeAchievementsForParticipants")
            or body.get("commemorativeAchievementIdsParticipants")
        )
        commem_gm_ids = _coerce_str_list(
            body.get("commemorativeAchievementIdsForGm")
            or body.get("commemorativeAchievementsForGm")
            or body.get("commemorativeAchievementIdsGm")
        )
        commem_all_ids = _coerce_str_list(
            body.get("commemorativeAchievementIdsForAll")
            or body.get("commemorativeAchievementsForAll")
            or body.get("commemorativeAchievementIdsAll")
        )

    try:
        scenario_id = str(session.get("scenario_id") or "")
        if not scenario_id:
            return _response({"error": "Session missing scenario_id"}, status=409)

        participants = repositories.list_participant_records(session_id)
        if record_history:
            handout_by_participant: dict[str, str] = {}
            try:
                for a in repositories.list_handout_assignments(session_id):
                    if not isinstance(a, dict):
                        continue
                    pid = str(a.get("participant_id") or "")
                    hname = str(a.get("handout_name") or "")
                    if pid and hname:
                        handout_by_participant[pid] = hname
            except Exception:
                handout_by_participant = {}
            for p in participants:
                uid = str(p.get("user_id") or "")
                if not uid:
                    continue
                display_name = str(p.get("display_name") or uid)
                repositories.add_play_history(
                    scenario_id,
                    uid,
                    display_name,
                    "PL",
                    session_id,
                    "",
                    handout_name=handout_by_participant.get(uid),
                )
            repositories.add_play_history(scenario_id, gm_user_id, str(actor_name), "GM", session_id, "")

        unlocked = 0
        defs: list[dict] = []
        def_map: dict[str, dict] = {}
        if grant_achievements:
            try:
                defs = repositories.list_achievement_definitions()
                def_map = {str(d.get("achievement_id") or ""): d for d in defs if d.get("achievement_id")}
            except Exception:
                logger.exception("Failed to list achievement definitions")
                defs = []
                def_map = {}

        # Grant scenario-defined completion achievements (GM-selected).
        if grant_achievements and selected_achievement_ids:
            try:
                scenario = repositories.get_scenario(scenario_id) or {}
                allowed = set()
                raw_allowed = scenario.get("completion_achievements") if isinstance(scenario, dict) else None
                if isinstance(raw_allowed, list):
                    for item in raw_allowed:
                        if isinstance(item, dict) and item.get("id"):
                            allowed.add(str(item.get("id")))
                selected = [aid for aid in selected_achievement_ids if aid in allowed] if allowed else []
                seen_selected: set[str] = set()
                selected_unique: list[str] = []
                for aid in selected:
                    if aid in seen_selected:
                        continue
                    seen_selected.add(aid)
                    selected_unique.append(aid)
                if selected:
                    now = datetime.now(timezone.utc).isoformat()
                    for p in participants:
                        user_id = str(p.get("user_id") or "")
                        if not user_id:
                            continue
                        existing_unlocks = repositories.list_user_achievement_unlocks(user_id)
                        existing_ids = {str(u.get("achievement_id") or "") for u in existing_unlocks}
                        for achievement_id in selected_unique:
                            if achievement_id in existing_ids:
                                continue
                            d = def_map.get(achievement_id) or {}
                            spoiler_level = "mild" if bool(d.get("is_spoiler")) else "none"
                            created = repositories.create_user_achievement_unlock_if_absent(
                                user_id,
                                achievement_id,
                                unlocked_at=now,
                                visibility="private",
                                spoiler_level=spoiler_level,
                            )
                            if not created:
                                continue
                            existing_ids.add(achievement_id)
                            unlocked += 1
                            try:
                                ach_title = str(d.get("title") or achievement_id)
                                subtitle = "ネタバレ実績（プロフィールで確認）" if bool(d.get("is_spoiler")) else ach_title
                                repositories.create_notification(
                                    user_id,
                                    "celebrate",
                                    "実績を獲得しました",
                                    subtitle,
                                    action_label="プロフィール",
                                    action_target="/profile",
                                    icon_type="trophy",
                                )
                            except Exception:
                                logger.exception("Failed to notify achievement unlock (scenario-defined)")
            except Exception:
                logger.exception("Achievement grant failed")

        # Grant commemorative achievements (GM-selected, catalog).
        if grant_achievements and (commem_map or commem_pl_ids or commem_gm_ids or commem_all_ids):
            try:
                now = datetime.now(timezone.utc).isoformat()
                pl_user_ids = [str(p.get("user_id") or "") for p in participants if p.get("user_id")]
                gm_id = str(gm_user_id or "")

                def is_catalog_commemorative(defn: dict) -> bool:
                    if str(defn.get("trigger") or "") != "manual":
                        return False
                    if defn.get("scenario_id"):
                        return False
                    return str(defn.get("category") or "") in ("meme", "gm")

                def normalize_audience(value: str) -> str:
                    v = value.strip()
                    if v in ("GM/PL", "全員"):
                        return "GM/PL"
                    if v in ("GM", "PL"):
                        return v
                    return v or "GM/PL"

                grants: list[tuple[str, list[str], str]] = []
                if commem_map:
                    pl_set = {uid for uid in pl_user_ids if uid}
                    for uid, ids in commem_map.items():
                        if uid == gm_id:
                            grants.append((uid, ids, "GM"))
                        elif uid in pl_set:
                            grants.append((uid, ids, "PL"))
                else:
                    if commem_pl_ids:
                        for uid in pl_user_ids:
                            if uid:
                                grants.append((uid, commem_pl_ids, "PL"))
                    if gm_id and commem_gm_ids:
                        grants.append((gm_id, commem_gm_ids, "GM"))
                    if commem_all_ids:
                        for uid in [*pl_user_ids, gm_id]:
                            if uid:
                                grants.append((uid, commem_all_ids, "GM/PL"))

                existing_cache: dict[str, set[str]] = {}
                for uid, ach_ids, expected_audience in grants:
                    if uid not in existing_cache:
                        unlocks = repositories.list_user_achievement_unlocks(uid)
                        existing_cache[uid] = {str(u.get("achievement_id") or "") for u in unlocks if u.get("achievement_id")}
                    existing_ids = existing_cache[uid]
                    for achievement_id in ach_ids[:50]:
                        if achievement_id in existing_ids:
                            continue
                        defn = def_map.get(achievement_id) or {}
                        if not defn or not is_catalog_commemorative(defn):
                            continue
                        aud = normalize_audience(str(defn.get("audience") or "GM/PL"))
                        if expected_audience == "GM":
                            if aud not in ("GM", "GM/PL"):
                                continue
                        elif expected_audience == "PL":
                            if aud not in ("PL", "GM/PL"):
                                continue
                        else:
                            if aud != "GM/PL":
                                continue

                        spoiler_level = "mild" if bool(defn.get("is_spoiler")) else "none"
                        created = repositories.create_user_achievement_unlock_if_absent(
                            uid,
                            achievement_id,
                            unlocked_at=now,
                            visibility="private",
                            spoiler_level=spoiler_level,
                        )
                        if not created:
                            existing_ids.add(achievement_id)
                            continue
                        existing_ids.add(achievement_id)
                        unlocked += 1
                        try:
                            ach_title = str(defn.get("title") or achievement_id)
                            subtitle = "ネタバレ実績（プロフィールで確認）" if bool(defn.get("is_spoiler")) else ach_title
                            repositories.create_notification(
                                uid,
                                "celebrate",
                                "実績を獲得しました",
                                subtitle,
                                action_label="プロフィール",
                                action_target="/profile",
                                icon_type="trophy",
                            )
                        except Exception:
                            logger.exception("Failed to notify achievement unlock (commemorative)")
            except Exception:
                logger.exception("Commemorative achievement grant failed")

        # Grant other achievements (rule-based, if enabled).
        if grant_achievements:
            try:
                unlocked += _grant_achievements_for_completion(session_id, scenario_id, participants, gm_user_id)
            except Exception:
                logger.exception("Achievement auto-grant failed")

        repositories.mark_session_status(session_id, "completed")
        if not was_completed:
            try:
                repositories.increment_scenario_stats(scenario_id, {"session_completed_count": 1})
            except Exception:
                logger.exception("Failed to increment session_completed_count")

        # Notify participants
        try:
            for p in participants:
                uid = str(p.get("user_id") or "")
                if not uid or uid == gm_user_id:
                    continue
                repositories.create_notification(
                    uid,
                    "celebrate",
                    "セッションが完了しました",
                    str(session.get("title") or "セッション"),
                    action_label="プロフィール",
                    action_target="/profile",
                    icon_type="trophy",
                )
        except Exception:
            logger.exception("Failed to notify participants for completion")

        repositories.log_audit(
            session_id,
            "session_complete_ui",
            actor_id,
            {
                "record_history": record_history,
                "grant_achievements": grant_achievements,
                "selected_achievement_ids": selected_achievement_ids[:30] if selected_achievement_ids else None,
                "participant_survival_status": survival_statuses,
                "grant_roles": grant_roles,
                "unlocked": unlocked,
            },
        )

        return _response({"success": True, "sessionId": session_id, "unlocked": unlocked}, status=200)
    except Exception as exc:
        logger.exception("Complete failed")
        return _response({"error": str(exc)}, status=500)


def lambda_handler(event: dict, context: Any) -> dict:
    method = _get_method(event)
    path = _get_path(event)

    if method == "OPTIONS":
        return _response(None, status=204)

    if path == "/api/ping":
        return _response({"ok": True})

    if path == "/api/version":
        return _response({"backendBuildVersion": get_backend_build_version()}, status=200)

    if path == "/api/oauth/token":
        return _handle_oauth_token(event)

    if path == "/api/activity/login":
        return _handle_activity_login(event)

    if path == "/api/activity/me":
        return _handle_activity_me(event)

    if path == "/api/uploads/image":
        return _handle_upload_image(event)

    if path.startswith("/api/users/") and path.endswith("/avatar"):
        rest = path[len("/api/users/") :].strip("/")
        parts = [p for p in rest.split("/") if p]
        if len(parts) == 2 and parts[1] == "avatar" and parts[0]:
            return _handle_user_avatar(event, parts[0])

    if path == "/api/notifications":
        return _handle_notifications_list(event)

    if path == "/api/notifications/read":
        return _handle_notifications_read(event)

    if path == "/api/notifications/read_all":
        return _handle_notifications_read_all(event)

    if path == "/api/profile":
        return _handle_profile(event)

    if path == "/api/achievements":
        return _handle_achievements_list(event)

    if path == "/api/scenarios":
        return _handle_scenarios(event)

    if path == "/api/browse":
        return _handle_browse(event)

    if path.startswith("/api/scenario/"):
        rest = path.split("/api/scenario/", 1)[1].strip("/")
        parts = [p for p in rest.split("/") if p]
        if not parts:
            return _response({"error": "Missing scenario id"}, status=400)
        if len(parts) == 2 and parts[1] == "pref":
            return _handle_scenario_preference(event, parts[0])
        if len(parts) == 2 and parts[1] == "gm_register":
            return _handle_scenario_gm_register(event, parts[0])
        if len(parts) == 2 and parts[1] == "telemetry":
            return _handle_scenario_telemetry(event, parts[0])
        if len(parts) == 1:
            return _handle_scenario_detail(event, parts[0])
        return _response({"error": "not found"}, status=404)

    if path == "/api/sessions/create":
        return _handle_session_create(event)

    if path == "/api/sessions/join":
        return _handle_session_join(event)

    if path == "/api/sessions":
        return _handle_sessions_list(event)

    if path.startswith("/api/sessions/") and "/scheduling" in path:
        rest = path[len("/api/sessions/") :].strip("/")
        parts = [p for p in rest.split("/") if p]
        if len(parts) >= 2 and parts[1] == "scheduling":
            session_id = parts[0]
            sub = parts[2] if len(parts) >= 3 else ""
            if not session_id:
                return _response({"error": "Missing session id"}, status=400)
            if sub == "":
                return _handle_scheduling_get(event, session_id)
            if sub == "setup":
                return _handle_scheduling_setup(event, session_id)
            if sub == "vote":
                return _handle_scheduling_vote(event, session_id)
            if sub == "decide":
                return _handle_scheduling_decide(event, session_id)
            if sub == "comment":
                return _handle_scheduling_comment(event, session_id)
            if sub == "comment_edit":
                return _handle_scheduling_comment_edit(event, session_id)
            if sub == "comment_delete":
                return _handle_scheduling_comment_delete(event, session_id)

    if path.startswith("/api/sessions/"):
        rest = path[len("/api/sessions/") :].strip("/")
        parts = [p for p in rest.split("/") if p]
        if len(parts) == 2 and parts[1] == "claim_gm":
            return _handle_session_claim_gm(event, parts[0])
        if len(parts) == 3 and parts[1] == "recruiting" and parts[2] == "select_members":
            return _handle_recruiting_select_members(event, parts[0])
        if len(parts) == 3 and parts[1] == "handouts":
            if parts[2] == "assign":
                return _handle_session_handout_assign(event, parts[0])
            if parts[2] == "unassign":
                return _handle_session_handout_unassign(event, parts[0])
            if parts[2] == "secret":
                return _handle_session_handout_secret(event, parts[0])
            if parts[2] == "notify":
                return _handle_session_handout_notify(event, parts[0])
        if len(parts) == 2 and parts[1] == "character":
            return _handle_session_character_set(event, parts[0])
        if len(parts) == 2 and parts[1] == "reopen_recruiting":
            return _handle_session_reopen_recruiting(event, parts[0])
        if len(parts) == 2 and parts[1] == "add_schedule":
            return _handle_session_add_schedule(event, parts[0])
        if len(parts) == 2 and parts[1] == "reschedule":
            return _handle_session_reschedule(event, parts[0])
        if len(parts) == 2 and parts[1] == "complete":
            return _handle_session_complete(event, parts[0])
        if len(parts) == 2 and parts[1] == "cancel":
            return _handle_session_cancel(event, parts[0])

    if path.startswith("/api/sessions/"):
        session_id = path.split("/api/sessions/", 1)[1].strip("/")
        if not session_id:
            return _response({"error": "Missing session id"}, status=400)
        return _handle_session_detail(event, session_id)

    return _response({"error": "not found"}, status=404)
