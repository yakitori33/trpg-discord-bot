from __future__ import annotations

import base64
import json
import logging
from decimal import Decimal
from typing import Any

import requests

from trpg_bot import repositories
from trpg_bot.config import (
    get_discord_application_id,
    get_discord_client_secret,
    get_discord_oauth_redirect_uri,
    get_backend_build_version,
    get_log_level,
)
from trpg_bot.discord_api import API_BASE as DISCORD_API_BASE
from trpg_bot.discord_api import DiscordApiError, create_thread, get_channel, get_guild_member
from trpg_bot.routes import refresh_session_card

logger = logging.getLogger(__name__)
logger.setLevel(get_log_level())

ACTIVITY_SESSION_TOKEN_PREFIX = "trpg_act_"


def _cors_headers() -> dict[str, str]:
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    }


def _response(payload: dict | None, status: int = 200) -> dict:
    body = "" if payload is None else json.dumps(payload)
    headers = {"Content-Type": "application/json", **_cors_headers()}
    return {"statusCode": status, "headers": headers, "body": body}


def _get_method(event: dict) -> str:
    return ((event.get("requestContext") or {}).get("http") or {}).get("method") or event.get("httpMethod") or ""


def _get_path(event: dict) -> str:
    return event.get("rawPath") or event.get("path") or ""


def _get_query_params(event: dict) -> dict[str, Any]:
    return event.get("queryStringParameters") or {}


def _get_body(event: dict) -> str:
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        return base64.b64decode(body).decode("utf-8")
    return body


def _parse_json_body(event: dict) -> dict:
    raw = _get_body(event).strip()
    if not raw:
        return {}
    return json.loads(raw)


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
    user_id = me.get("id")
    avatar = me.get("avatar")
    if user_id and avatar:
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png?size=64"
    return None


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

        repositories.upsert_user(actor_id, str(actor_name), avatar_url=avatar_url)
        session_token = repositories.create_activity_session(actor_id, str(actor_name), avatar_url=avatar_url)
        return _response(
            {"sessionToken": session_token, "userId": actor_id, "displayName": str(actor_name), "avatarUrl": avatar_url},
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

    try:
        repositories.touch_activity_session(token)
    except Exception:
        logger.exception("Failed to touch activity session")

    user_id = session.get("discord_id") or ""
    display_name = session.get("display_name_cache") or user_id
    avatar_url = session.get("avatar_url") or None
    if user_id:
        try:
            repositories.ensure_user(str(user_id), str(display_name), avatar_url=str(avatar_url) if avatar_url else None)
        except Exception:
            logger.exception("Failed to ensure user profile on activity/me")
    return _response({"userId": user_id, "displayName": display_name, "avatarUrl": avatar_url}, status=200)


def _scenario_to_ui(s: dict) -> dict:
    scenario_id = s.get("scenario_id") or ""
    title = s.get("title") or ""
    system = s.get("system") or ""
    tags = s.get("tags") if isinstance(s.get("tags"), list) else []
    estimated_time = s.get("estimated_time") or ""
    notes = s.get("notes") or ""
    setting = s.get("setting") or ""
    cover_url = s.get("cover_url") or s.get("coverUrl") or ""
    loss_level = s.get("loss_level") or s.get("lossLevel") or "不明"
    loss_note = s.get("loss_note") or s.get("lossNote") or None
    recommended_skills = s.get("recommended_skills") if isinstance(s.get("recommended_skills"), list) else []
    not_recommended_skills = (
        s.get("not_recommended_skills") if isinstance(s.get("not_recommended_skills"), list) else []
    )
    players_min = s.get("players_min")
    players_max = s.get("players_max")
    players_text = "—"
    if isinstance(players_min, (int, float, Decimal)) and isinstance(players_max, (int, float, Decimal)):
        players_text = f"{int(players_min)}-{int(players_max)}人"
    return {
        "id": str(scenario_id),
        "title": str(title),
        "coverUrl": str(cover_url) if cover_url else "/placeholder.svg",
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
    }


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

    max_players = _parse_int(session.get("max_players"), default=0) or 0
    remaining_seats = max(0, int(max_players) - len(applicants))

    deadline = None
    try:
        poll = repositories.latest_poll_for_session(session_id)
        if poll and poll.get("deadline"):
            deadline = str(poll.get("deadline"))
    except Exception:
        deadline = None

    teaser_slots = session.get("teaser_slots") if isinstance(session.get("teaser_slots"), list) else None

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
        "gmName": gm_name,
    }
    if gm_user_id:
        summary["gmUserId"] = str(gm_user_id)
    if deadline:
        summary["deadline"] = deadline
    if teaser_slots:
        summary["teaserSlots"] = teaser_slots
    return summary


def _coerce_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return []


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

        recommended_skills = _coerce_str_list(body.get("recommendedSkills") or body.get("recommended_skills"))
        not_recommended_skills = _coerce_str_list(
            body.get("notRecommendedSkills") or body.get("not_recommended_skills")
        )

        players_min = _parse_int(body.get("playersMin") or body.get("players_min"))
        players_max = _parse_int(body.get("playersMax") or body.get("players_max"))
        if (players_min is None) != (players_max is None):
            return _response({"error": "playersMin/playersMax must be both set or both omitted"}, status=400)
        if players_min is not None and players_max is not None and (players_min < 1 or players_max < 1 or players_min > players_max):
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
                players_min=players_min,
                players_max=players_max,
            )
            created = repositories.get_scenario(scenario_id) or {"scenario_id": scenario_id, "title": title.strip()}
            return _response({"scenario": _scenario_to_ui(created)}, status=201)
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
            ui = _scenario_to_ui(s)
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
        _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Auth failed")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    qp = _get_query_params(event)
    raw_limit = qp.get("limit") if isinstance(qp, dict) else None
    try:
        limit = int(raw_limit) if raw_limit is not None else 200
    except Exception:
        limit = 200

    keyword = qp.get("q") if isinstance(qp, dict) else None
    try:
        recruiting_sessions: list[dict] = []
        try:
            recruiting_sessions = repositories.list_sessions_by_status("recruiting", limit=50)
        except Exception:
            recruiting_sessions = []

        recruiting_by_scenario: dict[str, dict] = {}
        for ses in recruiting_sessions:
            sid = str(ses.get("scenario_id") or "")
            if not sid:
                continue
            prev = recruiting_by_scenario.get(sid)
            if not prev or str(ses.get("created_at") or "") > str(prev.get("created_at") or ""):
                recruiting_by_scenario[sid] = ses

        items = _list_scenarios_for_ui(str(keyword) if keyword is not None else None, limit=limit)
        scenarios: list[dict] = []
        recruiting_scenarios: list[dict] = []
        for s in items:
            try:
                gm_count = len(repositories.list_capable_gms(str(s.get("scenario_id") or ""))) if s.get("scenario_id") else 0
            except Exception:
                gm_count = 0
            ui = _scenario_to_ui(s)
            ui["availableGmCount"] = gm_count
            scenario_id = str(s.get("scenario_id") or "")
            if scenario_id and scenario_id in recruiting_by_scenario:
                summary = _session_to_recruiting_summary(recruiting_by_scenario[scenario_id])
                if summary:
                    ui["recruiting"] = summary
                    recruiting_scenarios.append(ui)
            scenarios.append(ui)

        rows: list[dict[str, Any]] = []
        if recruiting_scenarios:
            rows.append({"id": "recruiting", "title": "募集中", "scenarios": recruiting_scenarios})
        rows.append({"id": "registered", "title": "登録済みのシナリオ", "scenarios": scenarios})
        return _response(
            {
                "rows": rows
            },
            status=200,
        )
    except Exception as exc:
        logger.exception("Browse failed")
        return _response({"error": str(exc)}, status=500)


def _handle_scenario_detail(event: dict, scenario_id: str) -> dict:
    if _get_method(event) != "GET":
        return _response({"error": "method not allowed"}, status=405)

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
        scenario = repositories.get_scenario(scenario_id)
        if not scenario:
            return _response({"error": "not found"}, status=404)
        ui = _scenario_to_ui(scenario)
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
        return _response({"scenario": ui}, status=200)
    except Exception as exc:
        logger.exception("Scenario detail failed")
        return _response({"error": str(exc)}, status=500)


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
    create_thread_flag = _coerce_bool(body.get("createThread") or body.get("create_thread"))

    try:
        actor_id, actor_name = _resolve_actor_from_auth_token(auth_token)
    except Exception as exc:
        logger.exception("Failed to resolve actor")
        return _response({"error": f"Unauthorized: {exc}"}, status=401)

    if scenario_id:
        try:
            if not repositories.get_scenario(str(scenario_id)):
                return _response({"error": "Scenario not found"}, status=400)
        except Exception as exc:
            logger.exception("Scenario lookup failed")
            return _response({"error": f"Scenario lookup failed: {exc}"}, status=500)

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
        )

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
        if actor_id not in participant_ids:
            max_players = int(session.get("max_players") or 0)
            if max_players > 0 and len(participant_ids) >= max_players:
                return _response({"error": "Session is full"}, status=409)
            repositories.add_participant(str(session_id), actor_id, str(actor_name), "PL")
        repositories.log_audit(str(session_id), "session_join_ui", actor_id, {})
        return _response({"success": True, "sessionId": str(session_id)}, status=200)
    except Exception as exc:
        logger.exception("Session join failed")
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

    if path == "/api/scenarios":
        return _handle_scenarios(event)

    if path == "/api/browse":
        return _handle_browse(event)

    if path.startswith("/api/scenario/"):
        scenario_id = path.split("/api/scenario/", 1)[1]
        scenario_id = scenario_id.strip("/")
        if not scenario_id:
            return _response({"error": "Missing scenario id"}, status=400)
        return _handle_scenario_detail(event, scenario_id)

    if path == "/api/sessions/create":
        return _handle_session_create(event)

    if path == "/api/sessions/join":
        return _handle_session_join(event)

    return _response({"error": "not found"}, status=404)
