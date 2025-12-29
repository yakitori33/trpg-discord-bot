import os


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def optional_env(name: str, default: str | None = None) -> str | None:
    return os.getenv(name, default)


def get_database_url() -> str:
    return require_env("DATABASE_URL")


def get_discord_public_key() -> str:
    return require_env("DISCORD_PUBLIC_KEY")


def get_bot_token() -> str | None:
    return optional_env("DISCORD_BOT_TOKEN")


def get_log_level() -> str:
    return optional_env("LOG_LEVEL", "INFO") or "INFO"
