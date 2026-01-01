from __future__ import annotations

import os
import boto3
from functools import lru_cache
from trpg_bot.config import get_table_name, get_ddb_endpoint, get_region


@lru_cache
def _ddb_resource():
    kwargs = {"region_name": get_region()}
    endpoint = get_ddb_endpoint()
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    return boto3.resource("dynamodb", **kwargs)


@lru_cache
def get_table():
    return _ddb_resource().Table(get_table_name())


@lru_cache
def get_key_attribute_names() -> tuple[str, str]:
    env_pk = os.getenv("DDB_PK_NAME")
    env_sk = os.getenv("DDB_SK_NAME")
    if env_pk and env_sk:
        return env_pk, env_sk

    schema = get_table().key_schema or []
    pk = next((k.get("AttributeName") for k in schema if k.get("KeyType") == "HASH"), None)
    sk = next((k.get("AttributeName") for k in schema if k.get("KeyType") == "RANGE"), None)
    if not pk or not sk:
        raise RuntimeError("DynamoDB table must have both partition key and sort key")
    return pk, sk
