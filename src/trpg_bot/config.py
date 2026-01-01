import os


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def optional_env(name: str, default: str | None = None) -> str | None:
    return os.getenv(name, default)


def get_discord_public_key() -> str:
    return require_env("DISCORD_PUBLIC_KEY")


def get_discord_application_id() -> str:
    return require_env("DISCORD_APPLICATION_ID")


def get_discord_client_secret() -> str:
    return require_env("DISCORD_CLIENT_SECRET")


def get_discord_oauth_redirect_uri() -> str | None:
    # Discord OAuth2 token exchange requires `redirect_uri` to be present and to match the one used in authorize.
    # For Discord Activities, the common redirect is `https://discord.com/oauth2/authorized`.
    value = optional_env("DISCORD_OAUTH_REDIRECT_URI")
    return value or "https://discord.com/oauth2/authorized"


def get_bot_token() -> str | None:
    return optional_env("DISCORD_BOT_TOKEN")


def get_log_level() -> str:
    return optional_env("LOG_LEVEL", "INFO") or "INFO"


def get_table_name() -> str:
    return require_env("TABLE_NAME")


def get_ddb_endpoint() -> str | None:
    return optional_env("DYNAMODB_ENDPOINT")


def get_region() -> str:
    return optional_env("AWS_REGION") or optional_env("AWS_DEFAULT_REGION") or "ap-northeast-1"


def get_backend_build_version() -> str:
    return optional_env("BACKEND_BUILD_VERSION", "1.0.0") or "1.0.0"
