#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from typing import Any

import boto3


def _resolve_region(arg_region: str | None) -> str:
    if arg_region:
        return arg_region
    return (
        os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or "us-east-1"
    )


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
    parser = argparse.ArgumentParser(description="Purge all items from a DynamoDB table (dangerous).")
    parser.add_argument("--table", help="DynamoDB table name (or env TABLE_NAME).")
    parser.add_argument("--region", help="AWS region (or env AWS_REGION/AWS_DEFAULT_REGION).")
    parser.add_argument("--limit", type=int, default=0, help="Max items to delete (0 = no limit).")
    parser.add_argument("--yes", action="store_true", help="Actually delete (without this: dry-run).")
    args = parser.parse_args()

    table_name = _resolve_table(args.table)
    region = _resolve_region(args.region)

    ddb = boto3.resource("dynamodb", region_name=region)
    table = ddb.Table(table_name)
    pk_attr, sk_attr = _describe_key_schema(table)

    print(f"Target table: {table_name} (region: {region})")
    print(f"Key schema: {pk_attr} (HASH), {sk_attr} (RANGE)")

    scanned = 0
    keys: list[dict[str, Any]] = []
    start_key = None
    while True:
        scan_kwargs: dict[str, Any] = {
            "ProjectionExpression": f"{pk_attr},{sk_attr}",
        }
        if start_key:
            scan_kwargs["ExclusiveStartKey"] = start_key
        if args.limit and args.limit > 0:
            remaining = args.limit - scanned
            if remaining <= 0:
                break
            scan_kwargs["Limit"] = min(remaining, 1000)

        resp = table.scan(**scan_kwargs)
        items = resp.get("Items") or []
        keys.extend(items)
        scanned += len(items)
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break

    print(f"Found items: {len(keys)}")
    for i, k in enumerate(keys[:10]):
        print(f"- {i+1:02d} {pk_attr}={k.get(pk_attr)} {sk_attr}={k.get(sk_attr)}")
    if len(keys) > 10:
        print(f"... ({len(keys) - 10} more)")

    if not args.yes:
        print("Dry-run: add --yes to actually delete.")
        return 0

    if not keys:
        print("Nothing to delete.")
        return 0

    deleted = 0
    with table.batch_writer() as batch:
        for k in keys:
            batch.delete_item(Key={pk_attr: k[pk_attr], sk_attr: k[sk_attr]})
            deleted += 1
    print(f"Deleted items: {deleted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
