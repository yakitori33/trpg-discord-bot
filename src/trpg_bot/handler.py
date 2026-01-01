from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

import boto3
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from trpg_bot.config import get_discord_public_key, get_log_level
from trpg_bot.discord_api import edit_original_interaction_response
from trpg_bot.routes import handle_command, handle_component

logger = logging.getLogger(__name__)
logger.setLevel(get_log_level())

EPHEMERAL = 1 << 6


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


def _invoke_self_async(interaction: dict) -> None:
    function_name = os.getenv("AWS_LAMBDA_FUNCTION_NAME")
    if not function_name:
        raise RuntimeError("Missing AWS_LAMBDA_FUNCTION_NAME")
    boto3.client("lambda").invoke(
        FunctionName=function_name,
        InvocationType="Event",
        Payload=json.dumps({"__internal_task": "process_interaction", "interaction": interaction}).encode("utf-8"),
    )


def _webhook_edit_payload_from_interaction_response(interaction_response: dict) -> dict:
    if interaction_response.get("type") == 4:
        data = dict(interaction_response.get("data") or {})
        data.pop("flags", None)  # ephemeral is decided by the initial response; flags can't be edited here
        return data
    return {"content": "Unhandled response type from handler."}


def _handle_internal_task(event: dict) -> None:
    interaction = event.get("interaction") or {}
    interaction_type = interaction.get("type")
    if interaction_type == 2:
        response_payload = handle_command(interaction)
    elif interaction_type == 3:
        response_payload = handle_component(interaction)
    else:
        response_payload = {"type": 4, "data": {"content": "Unhandled interaction.", "flags": EPHEMERAL}}

    application_id = interaction.get("application_id")
    token = interaction.get("token")
    if not application_id or not token:
        logger.error("Missing application_id/token in interaction payload")
        return

    edit_original_interaction_response(
        application_id,
        token,
        _webhook_edit_payload_from_interaction_response(response_payload),
    )


def lambda_handler(event: dict, context: Any) -> dict:
    if event.get("__internal_task") == "process_interaction":
        try:
            _handle_internal_task(event)
        except Exception:
            logger.exception("Internal interaction processing failed")
            try:
                interaction = event.get("interaction") or {}
                application_id = interaction.get("application_id")
                token = interaction.get("token")
                if application_id and token:
                    edit_original_interaction_response(
                        application_id,
                        token,
                        {"content": "エラーが発生しました。少し待ってから再実行してください。"},
                    )
            except Exception:
                logger.exception("Failed to report error to Discord")
        return {"statusCode": 200, "headers": {"Content-Type": "text/plain"}, "body": "ok"}

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

    if interaction_type in (2, 3):
        try:
            _invoke_self_async(interaction)
        except Exception:
            logger.exception("Failed to start async processing; falling back to sync")
            payload = handle_command(interaction) if interaction_type == 2 else handle_component(interaction)
            return _response(payload)
        return _response({"type": 4, "data": {"content": "準備中です…", "flags": EPHEMERAL}})

    return _response({"type": 4, "data": {"content": "Unhandled interaction."}})
