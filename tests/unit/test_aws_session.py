"""AWS session resolution: stale credentials must not shadow SSO profiles."""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from signalsift.cloudwatch import client as client_module
from signalsift.config import Settings


class FakeStsClient:
    def __init__(self, valid: bool) -> None:
        self._valid = valid

    def get_caller_identity(self) -> dict[str, Any]:
        if self._valid:
            return {"Account": "123456789012"}
        raise ClientError(
            {"Error": {"Code": "ExpiredToken", "Message": "expired"}},
            "GetCallerIdentity",
        )


class FakeSession:
    """Stands in for boto3.Session; validity is scripted per profile."""

    # profile -> (has_credentials, sts_valid); None key = default chain
    scenario: dict[str | None, tuple[bool, bool]] = {}
    profiles: list[str] = []

    def __init__(self, profile_name: str | None = None, region_name: str | None = None):
        self.profile_name = profile_name
        self.region_name = region_name or "us-east-1"
        self._has_creds, self._valid = self.scenario.get(profile_name, (False, False))

    def get_credentials(self):
        return object() if self._has_creds else None

    @property
    def available_profiles(self) -> list[str]:
        return self.profiles

    def client(self, service: str, **kwargs: Any) -> FakeStsClient:
        assert service == "sts"
        return FakeStsClient(self._valid)


@pytest.fixture
def fake_boto3(monkeypatch):
    monkeypatch.setattr(boto3, "Session", FakeSession)
    yield FakeSession
    FakeSession.scenario = {}
    FakeSession.profiles = []


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_explicit_profile_used_verbatim(fake_boto3) -> None:
    fake_boto3.scenario = {"company": (True, True)}
    session = client_module.create_boto3_session(_settings(aws_profile="company"))
    assert session.profile_name == "company"


def test_valid_default_chain_kept(fake_boto3) -> None:
    fake_boto3.scenario = {None: (True, True)}
    session = client_module.create_boto3_session(_settings())
    assert session.profile_name is None


def test_stale_default_chain_falls_through_to_working_profile(fake_boto3) -> None:
    # The ExpiredToken scenario: default chain HAS creds but they're dead;
    # a fresh SSO login lives in the 'company' profile.
    fake_boto3.scenario = {
        None: (True, False),
        "old-static": (True, False),
        "company": (True, True),
    }
    fake_boto3.profiles = ["old-static", "company"]
    session = client_module.create_boto3_session(_settings())
    assert session.profile_name == "company"


def test_empty_chain_picks_working_profile(fake_boto3) -> None:
    fake_boto3.scenario = {None: (False, False), "company": (True, True)}
    fake_boto3.profiles = ["company"]
    session = client_module.create_boto3_session(_settings())
    assert session.profile_name == "company"


def test_nothing_works_returns_default_for_actionable_errors(fake_boto3) -> None:
    fake_boto3.scenario = {None: (True, False), "dead": (True, False)}
    fake_boto3.profiles = ["dead"]
    session = client_module.create_boto3_session(_settings())
    assert session.profile_name is None


def test_resolve_working_lists_all_authenticated(fake_boto3) -> None:
    # Your situation: several profiles configured, one has a live token.
    fake_boto3.scenario = {
        None: (True, False),  # stale default chain
        "398_Prod": (True, True),  # live SSO token
        "QA": (True, False),  # token missing/expired
        "PreProd": (False, False),  # no creds
    }
    fake_boto3.profiles = ["398_Prod", "PreProd", "QA"]
    from signalsift.cloudwatch.client import _resolve_working

    chosen, working = _resolve_working(_settings())
    assert chosen == "398_Prod"
    assert working == ["398_Prod"]  # only the authenticated one


def test_resolve_working_multiple_is_deterministic(fake_boto3) -> None:
    fake_boto3.scenario = {"aaa": (True, True), "zzz": (True, True), "mid": (False, False)}
    fake_boto3.profiles = ["zzz", "mid", "aaa"]
    from signalsift.cloudwatch.client import _resolve_working

    chosen, working = _resolve_working(_settings())
    assert working == ["aaa", "zzz"]  # sorted, deterministic
    assert chosen == "aaa"
