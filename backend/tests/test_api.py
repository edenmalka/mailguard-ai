"""End-to-end tests for the HTTP API, through the full request pipeline."""

import json
import time

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from tests.conftest import SAMPLE_EMAIL, encode_message, sign_headers


def test_health_is_public(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_valid_signed_request_returns_result(post_signed) -> None:
    response = post_signed({"raw_message": encode_message(SAMPLE_EMAIL)})
    assert response.status_code == 200
    data = response.json()
    assert 0 <= data["score"] <= 100
    assert data["verdict"] in {"safe", "suspicious", "malicious"}
    assert isinstance(data["signals"], list)


def test_missing_signature_is_unauthorized(client: TestClient) -> None:
    response = client.post("/analyze", json={"raw_message": encode_message(SAMPLE_EMAIL)})
    assert response.status_code == 401


def test_wrong_secret_is_unauthorized(client: TestClient) -> None:
    body = json.dumps({"raw_message": encode_message(SAMPLE_EMAIL)}).encode()
    headers = sign_headers(body, secret="attacker-guess-of-the-secret-32-chars")
    assert client.post("/analyze", content=body, headers=headers).status_code == 401


def test_replayed_old_request_is_unauthorized(client: TestClient) -> None:
    body = json.dumps({"raw_message": encode_message(SAMPLE_EMAIL)}).encode()
    headers = sign_headers(body, timestamp=int(time.time()) - 3600)
    assert client.post("/analyze", content=body, headers=headers).status_code == 401


def test_invalid_json_is_rejected_after_auth(client: TestClient) -> None:
    body = b"{not json"
    assert client.post("/analyze", content=body, headers=sign_headers(body)).status_code == 422


def test_unknown_fields_are_rejected(post_signed) -> None:
    response = post_signed({"raw_message": encode_message(SAMPLE_EMAIL), "admin": True})
    assert response.status_code == 422


def test_invalid_base64_is_rejected(post_signed) -> None:
    assert post_signed({"raw_message": "not*base64!"}).status_code == 422


def test_error_details_are_not_leaked(post_signed) -> None:
    response = post_signed({"raw_message": "not*base64!"})
    assert response.json() == {"detail": "Invalid request payload"}


def test_oversized_request_body_is_rejected(client: TestClient, settings: Settings) -> None:
    body = b"x" * (settings.max_request_bytes + 1)
    assert client.post("/analyze", content=body, headers=sign_headers(body)).status_code == 413


def test_oversized_decoded_message_is_rejected(post_signed, settings: Settings) -> None:
    # Fits within the request limit when encoded, but exceeds the message limit when decoded.
    raw = b"A" * (settings.max_message_bytes + 1)
    assert post_signed({"raw_message": encode_message(raw)}).status_code == 413


def test_api_docs_are_disabled_by_default(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_weak_secret_is_refused_at_startup() -> None:
    with pytest.raises(ValidationError):
        Settings(hmac_secret="too-short", _env_file=None)
