"""Shared test fixtures: a test app with a known secret and a helper to send signed requests."""

import base64
import json
import time
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from app.config import Settings
from app.main import create_app
from app.security import SIGNATURE_HEADER, TIMESTAMP_HEADER, compute_signature

TEST_SECRET = "test-secret-that-is-at-least-32-characters-long"
SAMPLE_EMAIL = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hi\r\n\r\nHello!\r\n"


@pytest.fixture
def settings() -> Settings:
    return Settings(hmac_secret=TEST_SECRET, max_message_bytes=1024, _env_file=None)


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def encode_message(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def sign_headers(body: bytes, secret: str = TEST_SECRET, timestamp: int | None = None) -> dict:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    return {
        "Content-Type": "application/json",
        TIMESTAMP_HEADER: ts,
        SIGNATURE_HEADER: compute_signature(secret.encode(), ts, body),
    }


@pytest.fixture
def post_signed(client: TestClient) -> Callable[..., Response]:
    """POST a JSON payload to /analyze with a valid signature."""

    def _post(payload: dict) -> Response:
        body = json.dumps(payload).encode()
        return client.post("/analyze", content=body, headers=sign_headers(body))

    return _post
