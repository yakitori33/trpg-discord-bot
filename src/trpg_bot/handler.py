from __future__ import annotations

import base64
import json
import logging
from typing import Any

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from trpg_bot.config import get_discord_public_key, get_log_level
from trpg_bot.routes import handle_command

logger = logging.getLogger(__name__)
logger.setLevel(get_log_level())


class SignatureError(RuntimeError):
    pass


def _get_body(event: dict) -> str:
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        return base64.b64decode(body).decode("utf-8")
    return body


def _verify(headers: dict[str, Any], body: str) -> None:
    signature = headers.get("x-signature-ed25519") or headers.get("X-Signature-Ed25519")
    timestamp = headers.get("x-signature-timestamp") or headers.get("X-Signature-Timestamp")
    if not signature or not timestamp:
        raise SignatureError("Missing signature headers")
    verify_key = VerifyKey(bytes.fromhex(get_discord_public_key()))
    try:
        verify_key.verify(f"{timestamp}{body}".encode("utf-8"), bytes.fromhex(signature))
    except BadSignatureError as exc:
        raise SignatureError("Bad signature") from exc


def _response(payload: dict, status: int = 200) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload),
    }


def lambda_handler(event: dict, context: Any) -> dict:
    body = _get_body(event)
    headers = event.get("headers") or {}

    try:
        _verify(headers, body)
    except SignatureError as exc:
        logger.warning("Signature verification failed: %s", exc)
        return _response({"error": "invalid signature"}, status=401)

    interaction = json.loads(body)
    interaction_type = interaction.get("type")

    if interaction_type == 1:
        return _response({"type": 1})

    if interaction_type == 2:
        payload = handle_command(interaction)
        return _response(payload)

    return _response({"type": 4, "data": {"content": "Unhandled interaction."}})
