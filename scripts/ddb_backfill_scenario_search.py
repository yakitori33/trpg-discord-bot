#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trpg_bot.repositories import (
    _scenario_pk,
    _scenario_search_sk,
    _scenario_token_gsi_pk,
    _scenario_token_gsi_sk,
    _tokenize_search_text,
)


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill scenario search index items.")
    parser.add_argument("--table", help="DynamoDB table name (or env TABLE_NAME).")
    parser.add_argument("--region", help="AWS region (or env AWS_REGION/AWS_DEFAULT_REGION).")
    parser.add_argument("--limit", type=int, default=0, help="Max items to update (0 = no limit).")
    parser.add_argument("--yes", action="store_true", help="Actually update items.")
    args = parser.parse_args()

    table_name = _resolve_table(args.table)
    region = _resolve_region(args.region)

    ddb = boto3.resource("dynamodb", region_name=region)
    table = ddb.Table(table_name)
    pk_attr, sk_attr = _describe_key_schema(table)

    print(f"Target table: {table_name} (region: {region})")
    print(f"Key schema: {pk_attr} (HASH), {sk_attr} (RANGE)")

    scanned = 0
    updated = 0
    start_key = None
    while True:
        scan_kwargs: dict[str, Any] = {
            "FilterExpression": Attr("entity").eq("scenario"),
            "ProjectionExpression": f"{pk_attr},{sk_attr},scenario_id,title,title_lower,created_at,search_tokens",
        }
        if start_key:
            scan_kwargs["ExclusiveStartKey"] = start_key
        if args.limit and args.limit > 0:
            remaining = args.limit - scanned
            if remaining <= 0:
                break
            scan_kwargs["Limit"] = min(remaining, 200)

        resp = table.scan(**scan_kwargs)
        items = resp.get("Items") or []
        scanned += len(items)

        for item in items:
            scenario_id = str(item.get("scenario_id") or "").strip()
            title = str(item.get("title") or "").strip()
            title_lower = str(item.get("title_lower") or title.lower()).strip()
            created_at = str(item.get("created_at") or "").strip()
            if not scenario_id or not title_lower or not created_at:
                continue

            tokens = _tokenize_search_text(title_lower)
            if not tokens:
                continue

            if not args.yes:
                print(f"[dry-run] {scenario_id} tokens={len(tokens)}")
                updated += 1
                continue

            table.update_item(
                Key={pk_attr: _scenario_pk(scenario_id), sk_attr: "META"},
                UpdateExpression="SET search_tokens=:st, title_lower=:tl",
                ExpressionAttributeValues={":st": tokens, ":tl": title_lower},
            )

            with table.batch_writer() as batch:
                for token in tokens:
                    search_item = {
                        "entity": "scenario_search",
                        "scenario_id": scenario_id,
                        "token": token,
                        "title": title,
                        "title_lower": title_lower,
                        "created_at": created_at,
                        "GSI2PK": _scenario_token_gsi_pk(token),
                        "GSI2SK": _scenario_token_gsi_sk(created_at, scenario_id),
                    }
                    batch.put_item(
                        Item={**search_item, pk_attr: _scenario_pk(scenario_id), sk_attr: _scenario_search_sk(token)}
                    )
            updated += 1

        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break

    print(f"Scanned items: {scanned}")
    print(f"Processed scenarios: {updated}")
    if not args.yes:
        print("Dry-run: add --yes to apply updates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
