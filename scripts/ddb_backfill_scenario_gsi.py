#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr


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


def _scenario_id_from_item(item: dict, pk_attr: str) -> str | None:
    scenario_id = str(item.get("scenario_id") or "").strip()
    if scenario_id:
        return scenario_id
    pk_val = str(item.get(pk_attr) or "")
    if pk_val.startswith("SCENARIO#"):
        return pk_val.split("#", 1)[1]
    return None


def _scenario_title_lower(item: dict) -> str | None:
    title_lower = str(item.get("title_lower") or "").strip()
    if title_lower:
        return title_lower
    title = str(item.get("title") or "").strip()
    if not title:
        return None
    return title.lower()


def _scenario_gsi_values(created_at: str, scenario_id: str, title_lower: str) -> dict[str, str]:
    return {
        "GSI1PK": "SCENARIO",
        "GSI1SK": f"CREATED#{created_at}#{scenario_id}",
        "GSI2PK": "SCENARIO",
        "GSI2SK": f"TITLE#{title_lower}#{scenario_id}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill GSI keys for scenario items.")
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
    skipped = 0
    start_key = None
    while True:
        scan_kwargs: dict[str, Any] = {
            "FilterExpression": Attr("entity").eq("scenario"),
            "ProjectionExpression": (
                f"{pk_attr},{sk_attr},scenario_id,created_at,title,title_lower,"
                "GSI1PK,GSI1SK,GSI2PK,GSI2SK"
            ),
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
            scenario_id = _scenario_id_from_item(item, pk_attr)
            created_at = str(item.get("created_at") or "").strip()
            title_lower = _scenario_title_lower(item)
            if not scenario_id or not created_at or not title_lower:
                skipped += 1
                continue

            desired = _scenario_gsi_values(created_at, scenario_id, title_lower)
            if all(item.get(k) == v for k, v in desired.items()):
                skipped += 1
                continue

            if not args.yes:
                print(f"[dry-run] {scenario_id} -> {desired}")
                updated += 1
                continue

            table.update_item(
                Key={pk_attr: item[pk_attr], sk_attr: item[sk_attr]},
                UpdateExpression="SET GSI1PK=:g1pk, GSI1SK=:g1sk, GSI2PK=:g2pk, GSI2SK=:g2sk",
                ExpressionAttributeValues={
                    ":g1pk": desired["GSI1PK"],
                    ":g1sk": desired["GSI1SK"],
                    ":g2pk": desired["GSI2PK"],
                    ":g2sk": desired["GSI2SK"],
                },
            )
            updated += 1

        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break

    print(f"Scanned items: {scanned}")
    print(f"Updated items: {updated}")
    print(f"Skipped items: {skipped}")
    if not args.yes:
        print("Dry-run: add --yes to apply updates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
