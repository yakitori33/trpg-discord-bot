from __future__ import annotations

import requests

from trpg_bot.config import get_bot_token

API_BASE = "https://discord.com/api/v10"


class DiscordApiError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _headers() -> dict[str, str]:
    token = get_bot_token()
    if not token:
        raise DiscordApiError("DISCORD_BOT_TOKEN is required for REST actions")
    return {
        "Authorization": f"Bot {token}",
        "Content-Type": "application/json",
    }


def create_thread(channel_id: str, name: str) -> dict:
    url = f"{API_BASE}/channels/{channel_id}/threads"
    payload = {"name": name, "type": 11}
    response = requests.post(url, headers=_headers(), json=payload, timeout=10)
    if response.status_code >= 300:
        raise DiscordApiError(f"Thread create failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def send_message(channel_id: str, payload: dict) -> dict:
    url = f"{API_BASE}/channels/{channel_id}/messages"
    response = requests.post(url, headers=_headers(), json=payload, timeout=10)
    if response.status_code >= 300:
        raise DiscordApiError(f"Message send failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def pin_message(channel_id: str, message_id: str) -> None:
    url = f"{API_BASE}/channels/{channel_id}/pins/{message_id}"
    response = requests.put(url, headers=_headers(), timeout=10)
    if response.status_code >= 300:
        raise DiscordApiError(f"Pin failed: {response.status_code} {response.text}", status_code=response.status_code)


def edit_message(channel_id: str, message_id: str, payload: dict) -> dict:
    url = f"{API_BASE}/channels/{channel_id}/messages/{message_id}"
    response = requests.patch(url, headers=_headers(), json=payload, timeout=10)
    if response.status_code >= 300:
        raise DiscordApiError(f"Message edit failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def create_followup_message(application_id: str, token: str, payload: dict) -> dict:
    url = f"{API_BASE}/webhooks/{application_id}/{token}"
    response = requests.post(url, headers=_headers(), json=payload, timeout=10)
    if response.status_code >= 300:
        raise DiscordApiError(f"Follow-up failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def edit_original_interaction_response(application_id: str, token: str, payload: dict) -> dict:
    url = f"{API_BASE}/webhooks/{application_id}/{token}/messages/@original"
    response = requests.patch(url, headers=_headers(), json=payload, timeout=10)
    if response.status_code >= 300:
        raise DiscordApiError(
            f"Edit original response failed: {response.status_code} {response.text}",
            status_code=response.status_code,
        )
    return response.json()


def get_channel(channel_id: str) -> dict:
    url = f"{API_BASE}/channels/{channel_id}"
    response = requests.get(url, headers=_headers(), timeout=10)
    if response.status_code >= 300:
        raise DiscordApiError(f"Get channel failed: {response.status_code} {response.text}", status_code=response.status_code)
    return response.json()


def get_guild_member(guild_id: str, user_id: str) -> dict:
    url = f"{API_BASE}/guilds/{guild_id}/members/{user_id}"
    response = requests.get(url, headers=_headers(), timeout=10)
    if response.status_code >= 300:
        raise DiscordApiError(
            f"Get guild member failed: {response.status_code} {response.text}",
            status_code=response.status_code,
        )
    return response.json()
