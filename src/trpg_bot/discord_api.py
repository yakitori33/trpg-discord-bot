from __future__ import annotations

import random
import time

import requests

from trpg_bot.config import get_bot_token

API_BASE = "https://discord.com/api/v10"


class DiscordApiError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


_GLOBAL_RATE_LIMIT_UNTIL: float = 0.0


def _headers() -> dict[str, str]:
    token = get_bot_token()
    if not token:
        raise DiscordApiError("DISCORD_BOT_TOKEN is required for REST actions")
    return {
        "Authorization": f"Bot {token}",
        "Content-Type": "application/json",
    }


def _retry_after_seconds(response: requests.Response) -> float | None:
    try:
        data = response.json()
    except Exception:
        data = None

    if isinstance(data, dict):
        val = data.get("retry_after")
        try:
            if val is not None:
                return max(0.0, float(val))
        except Exception:
            pass

    hdr = response.headers.get("retry-after") or response.headers.get("Retry-After")
    if hdr:
        try:
            return max(0.0, float(hdr))
        except Exception:
            return None
    return None


def _request(method: str, path: str, *, json: dict | None = None) -> requests.Response:
    # Discord rate limits are per-route and sometimes global. For our Lambda use-case,
    # a small bounded retry is usually enough to ride out bursts.
    global _GLOBAL_RATE_LIMIT_UNTIL

    url = path if path.startswith("http://") or path.startswith("https://") else f"{API_BASE}{path}"
    max_retries = 5
    base_timeout = 10

    for attempt in range(max_retries):
        now = time.time()
        if _GLOBAL_RATE_LIMIT_UNTIL > now:
            time.sleep(_GLOBAL_RATE_LIMIT_UNTIL - now)

        response = requests.request(method, url, headers=_headers(), json=json, timeout=base_timeout)
        if response.status_code != 429:
            return response

        retry_after = _retry_after_seconds(response)
        if retry_after is None:
            return response

        # Discord recommends adding a small buffer; also add jitter to avoid thundering herd.
        sleep_for = min(60.0, retry_after + 0.25 + random.uniform(0.0, 0.25))
        is_global = (response.headers.get("x-ratelimit-global") or "").lower() == "true"
        if is_global:
            _GLOBAL_RATE_LIMIT_UNTIL = time.time() + sleep_for
        time.sleep(sleep_for)

    return response


def create_thread(channel_id: str, name: str) -> dict:
    payload = {"name": name, "type": 11}
    response = _request("POST", f"/channels/{channel_id}/threads", json=payload)
    if response.status_code >= 300:
        raise DiscordApiError(f"Thread create failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def send_message(channel_id: str, payload: dict) -> dict:
    response = _request("POST", f"/channels/{channel_id}/messages", json=payload)
    if response.status_code >= 300:
        raise DiscordApiError(f"Message send failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def pin_message(channel_id: str, message_id: str) -> None:
    response = _request("PUT", f"/channels/{channel_id}/pins/{message_id}")
    if response.status_code >= 300:
        raise DiscordApiError(f"Pin failed: {response.status_code} {response.text}", status_code=response.status_code)


def edit_message(channel_id: str, message_id: str, payload: dict) -> dict:
    response = _request("PATCH", f"/channels/{channel_id}/messages/{message_id}", json=payload)
    if response.status_code >= 300:
        raise DiscordApiError(f"Message edit failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def create_followup_message(application_id: str, token: str, payload: dict) -> dict:
    response = _request("POST", f"/webhooks/{application_id}/{token}", json=payload)
    if response.status_code >= 300:
        raise DiscordApiError(f"Follow-up failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def edit_original_interaction_response(application_id: str, token: str, payload: dict) -> dict:
    response = _request("PATCH", f"/webhooks/{application_id}/{token}/messages/@original", json=payload)
    if response.status_code >= 300:
        raise DiscordApiError(
            f"Edit original response failed: {response.status_code} {response.text}",
            status_code=response.status_code,
        )
    return response.json()


def get_channel(channel_id: str) -> dict:
    response = _request("GET", f"/channels/{channel_id}")
    if response.status_code >= 300:
        raise DiscordApiError(f"Get channel failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()

def get_user(user_id: str) -> dict:
    response = _request("GET", f"/users/{user_id}")
    if response.status_code >= 300:
        raise DiscordApiError(f"Get user failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def get_guild_member(guild_id: str, user_id: str) -> dict:
    response = _request("GET", f"/guilds/{guild_id}/members/{user_id}")
    if response.status_code >= 300:
        raise DiscordApiError(
            f"Get guild member failed: {response.status_code} {response.text}",
            status_code=response.status_code,
        )
    return response.json()
