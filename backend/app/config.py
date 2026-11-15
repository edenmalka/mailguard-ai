"""Application settings, loaded from environment variables (prefix: MAILGUARD_).

Secrets are never hardcoded: the HMAC secret must come from the environment
(or a local, git-ignored `.env` file during development).
"""

import math

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET_LENGTH = 32
# Extra room for the JSON wrapper around the base64-encoded message.
REQUEST_OVERHEAD_BYTES = 4096


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MAILGUARD_", env_file=".env", extra="ignore")

    hmac_secret: SecretStr
    max_message_bytes: int = Field(default=2 * 1024 * 1024, gt=0, le=10 * 1024 * 1024)
    signature_max_age_seconds: int = Field(default=300, gt=0, le=3600)
    log_level: str = "INFO"
    enable_docs: bool = False

    @field_validator("hmac_secret")
    @classmethod
    def secret_must_be_strong(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SECRET_LENGTH:
            raise ValueError(f"must be at least {MIN_SECRET_LENGTH} characters")
        return value

    @property
    def max_request_bytes(self) -> int:
        """Largest acceptable HTTP body: the base64-encoded message plus JSON overhead."""
        base64_size = 4 * math.ceil(self.max_message_bytes / 3)
        return base64_size + REQUEST_OVERHEAD_BYTES
