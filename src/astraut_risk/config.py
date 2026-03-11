"""Configuration and environment loading utilities."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

DEFAULT_MODEL = "llama-3.3-70b-versatile"
SUPPORTED_MODELS = {"llama-3.3-70b-versatile"}


class ConfigError(RuntimeError):
    """Base configuration error."""


class MissingApiKeyError(ConfigError):
    """Raised when GROQ_API_KEY is required but missing."""


@dataclass(frozen=True)
class RuntimeConfig:
    """Resolved runtime configuration."""

    groq_api_key: str | None


def load_environment() -> RuntimeConfig:
    """Load environment variables and return runtime config."""
    load_dotenv()
    return RuntimeConfig(groq_api_key=os.getenv("GROQ_API_KEY"))


def get_groq_api_key(required: bool = True) -> str | None:
    """Get GROQ API key, optionally requiring it."""
    key = os.getenv("GROQ_API_KEY")
    if required and not key:
        raise MissingApiKeyError(
            "Missing GROQ_API_KEY. Set it in your environment or .env file."
        )
    return key


def mask_key(key: str | None) -> str:
    """Return a masked representation for safe display."""
    if not key:
        return "Missing"
    if len(key) <= 12:
        return "Set"
    return f"{key[:6]}...{key[-4:]}"
