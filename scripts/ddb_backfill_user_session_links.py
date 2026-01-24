#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr, Key


def _resolve_region(arg_region: str | None) -> str:
    if arg_region:
        return arg_region
    return os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"


def _resolve_table(arg_table: str | None) -> str:
    if arg_table:
        return arg_table
    return os.getenv("TABLE_NAME") or "trpg-discord-bot"


def _describe_key_schema(table: Any) -> tuple[str, str]:
    desc = table.meta.client.describe_table(TableName=table.name)["Table"]
    key_schema = desc.get("KeySchema") or []
    pk_attr = next((k.get("AttributeName") for k in key_schema if k.get("KeyType") == "HASH"), None)
    sk_attr = next((k.get("AttributeName") for k in key_schema if k.get("KeyType") == "RANGE"), None)
    if not pk_attr or not sk_attr:
        raise RuntimeError(f"Table must have partition+sort key: {key_schema}")
    return str(pk_attr), str(sk_attr)


def _upsert_user_session_link(
    table: Any,
    pk_attr: str,
    sk_attr: str,
    user_id: str,
    session_id: str,
    *,
    is_gm: bool | None = None,
    is_participant: bool | None = None,
    is_waitlisted: bool | None = None,
    yes: bool,
) -> None:
    if not user_id or not session_id:
        return

    update_parts = ["entity=:e", "user_id=:uid", "session_id=:sid", "updated_at=:u"]
    values: dict[str, Any] = {
        ":e": "user_session",
        ":uid": user_id,
        ":sid": session_id,
        ":u": datetime.now(timezone.utc).isoformat(),
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

    key = {pk_attr: f"USER#{user_id}", sk_attr: f"USESS#{session_id}"}

    if not yes:
        return

    table.update_item(
        Key=key,
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=values,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill USER#.../USESS#... link items for sessions.")
    parser.add_argument("--table", help="DynamoDB table name (or env TABLE_NAME).")
    parser.add_argument("--region", help="AWS region (or env AWS_REGION/AWS_DEFAULT_REGION).")
    parser.add_argument("--limit", type=int, default=0, help="Max sessions to process (0 = no limit).")
    parser.add_argument("--yes", action="store_true", help="Actually update items.")
    args = parser.parse_args()

    table_name = _resolve_table(args.table)
    region = _resolve_region(args.region)

    ddb = boto3.resource("dynamodb", region_name=region)
    table = ddb.Table(table_name)
    pk_attr, sk_attr = _describe_key_schema(table)

    print(f"Target table: {table_name} (region: {region})")
    print(f"Key schema: {pk_attr} (HASH), {sk_attr} (RANGE)")
    if not args.yes:
        print("Dry-run mode. Add --yes to write changes.")

    scanned = 0
    processed = 0
    created_links = 0
    start_key = None

    while True:
        scan_kwargs: dict[str, Any] = {
            "FilterExpression": Attr("entity").eq("session"),
            "ProjectionExpression": "session_id,gm_user_id",
        }
        if start_key:
            scan_kwargs["ExclusiveStartKey"] = start_key
        if args.limit and args.limit > 0:
            remaining = args.limit - processed
            if remaining <= 0:
                break
            scan_kwargs["Limit"] = min(remaining, 200)

        resp = table.scan(**scan_kwargs)
        items = resp.get("Items") or []
        scanned += len(items)

        for item in items:
            session_id = str(item.get("session_id") or "").strip()
            if not session_id:
                continue
            processed += 1
            gm_user_id = str(item.get("gm_user_id") or "").strip()

            if gm_user_id:
                _upsert_user_session_link(
                    table,
                    pk_attr,
                    sk_attr,
                    gm_user_id,
                    session_id,
                    is_gm=True,
                    yes=args.yes,
                )
                created_links += 1

            # Participants
            try:
                presp = table.query(
                    KeyConditionExpression=Key(pk_attr).eq(f"SESSION#{session_id}")
                    & Key(sk_attr).begins_with("PART#"),
                )
                for p in presp.get("Items", []) or []:
                    uid = str(p.get("user_id") or "").strip()
                    if not uid:
                        continue
                    _upsert_user_session_link(
                        table,
                        pk_attr,
                        sk_attr,
                        uid,
                        session_id,
                        is_participant=True,
                        yes=args.yes,
                    )
                    created_links += 1
            except Exception as exc:
                print(f"[WARN] participant query failed: session={session_id} err={exc}")

            # Waitlist
            try:
                wresp = table.query(
                    KeyConditionExpression=Key(pk_attr).eq(f"SESSION#{session_id}")
                    & Key(sk_attr).begins_with("WAIT#"),
                )
                for w in wresp.get("Items", []) or []:
                    uid = str(w.get("user_id") or "").strip()
                    if not uid:
                        continue
                    _upsert_user_session_link(
                        table,
                        pk_attr,
                        sk_attr,
                        uid,
                        session_id,
                        is_waitlisted=True,
                        yes=args.yes,
                    )
                    created_links += 1
            except Exception as exc:
                print(f"[WARN] waitlist query failed: session={session_id} err={exc}")

        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break

    print(f"Sessions scanned (returned): {scanned}")
    print(f"Sessions processed: {processed}")
    print(f"Link upserts attempted: {created_links}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

