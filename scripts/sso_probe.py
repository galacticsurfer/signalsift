"""Diagnose (and optionally fix) AWS SSO token-cache key mismatches.

botocore never scans ~/.aws/sso/cache — it computes sha1(<key>) and opens
exactly that file. The key is the sso_session name (modern config) or the
sso_start_url (legacy config). When a token was written under one key and
is being read under another (mixed config, renamed sessions, CLI/botocore
version skew), the token "doesn't exist" despite sitting right there.

One pass:
1. classify every file in ~/.aws/sso/cache and ~/.aws/cli/cache
   (sso-token / client-registration / role-credentials / unknown),
   with startUrl, region, expiresAt and expiry status;
2. resolve every profile through botocore's OWN config resolver and
   compute every cache key it could ask for, marking present/missing;
3. --fix: symlink a live token onto each missing expected key
   (symlink, not copy, so normal refreshes propagate); refuses to guess
   when more than one unexpired token exists;
4. --verify: sts get-caller-identity per profile, reporting ok/fail.

Prints NO token or secret material. Account IDs are masked.

Usage:
    python3 scripts/sso_probe.py                 # report only
    python3 scripts/sso_probe.py --fix --verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

SSO_CACHE = Path.home() / ".aws" / "sso" / "cache"
CLI_CACHE = Path.home() / ".aws" / "cli" / "cache"


def _sha1(value: str) -> str:
    return hashlib.sha1(value.encode()).hexdigest()  # noqa: S324 - cache key, not crypto


def _mask(value: str | None) -> str:
    if not value:
        return "?"
    return value[:4] + "***"


def _parse_expiry(raw: str | None) -> tuple[str, bool | None]:
    """(display, expired?) — expired None when unparseable/absent."""
    if not raw:
        return "-", None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return raw, dt <= datetime.now(UTC)
    except ValueError:
        return raw, None


def classify(path: Path) -> dict:
    entry: dict = {"path": path, "kind": "unreadable", "expired": None}
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        entry["note"] = str(exc)
        return entry

    if "accessToken" in data:
        entry["kind"] = "sso-token"
        entry["startUrl"] = data.get("startUrl")
        entry["region"] = data.get("region")
        entry["expiresAt"], entry["expired"] = _parse_expiry(data.get("expiresAt"))
        stem = path.stem
        keyed_by = "NONE"
        url = data.get("startUrl")
        if url:
            if _sha1(url) == stem:
                keyed_by = "startUrl"
            elif _sha1(url.rstrip("/")) == stem or _sha1(url + "/") == stem:
                keyed_by = "startUrl(slash-variant)"
        for field in ("sessionName", "session_name"):
            if data.get(field) and _sha1(data[field]) == stem:
                keyed_by = f"sessionName={data[field]!r}"
        entry["keyed_by"] = keyed_by
    elif "clientId" in data or "clientSecret" in data:
        entry["kind"] = "client-registration"
        entry["expiresAt"], entry["expired"] = _parse_expiry(data.get("expiresAt"))
    elif "Credentials" in data or "AccessKeyId" in data:
        creds = data.get("Credentials", data)
        entry["kind"] = "role-credentials"
        entry["expiresAt"], entry["expired"] = _parse_expiry(creds.get("Expiration"))
    else:
        entry["kind"] = f"unknown (keys: {sorted(data)[:6]})"
    return entry


def expected_keys() -> list[dict]:
    """Every cache key botocore could look for, via its own resolver."""
    import boto3
    import botocore

    print(f"botocore {botocore.__version__}  boto3 {boto3.__version__}\n")
    session = boto3.Session()
    full_config = session._session.full_config  # noqa: SLF001 - the resolver's view
    sso_sessions = full_config.get("sso_sessions", {})
    expectations: list[dict] = []
    seen: set[str] = set()

    for profile_name, profile in full_config.get("profiles", {}).items():
        session_name = profile.get("sso_session")
        start_url = profile.get("sso_start_url")
        if session_name:
            key = _sha1(session_name)
            source = f"profile {profile_name!r} -> sso_session {session_name!r}"
        elif start_url:
            key = _sha1(start_url)
            source = f"profile {profile_name!r} -> legacy sso_start_url"
        else:
            continue
        if key not in seen:
            seen.add(key)
            expectations.append({"key": key, "source": source, "profile": profile_name})

    for session_name in sso_sessions:
        key = _sha1(session_name)
        if key not in seen:
            seen.add(key)
            expectations.append(
                {"key": key, "source": f"[sso-session {session_name}] block", "profile": None}
            )
    return expectations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true", help="Symlink a live token onto missing keys")
    parser.add_argument("--verify", action="store_true", help="sts get-caller-identity per profile")
    args = parser.parse_args()

    print("== Cache contents ==")
    entries: list[dict] = []
    for cache_dir in (SSO_CACHE, CLI_CACHE):
        if not cache_dir.is_dir():
            print(f"{cache_dir}: (absent)")
            continue
        for path in sorted(cache_dir.glob("*.json")):
            entry = classify(path)
            entries.append(entry)
            expired = {True: "EXPIRED", False: "live", None: ""}[entry["expired"]]
            detail = ""
            if entry["kind"] == "sso-token":
                detail = f"  startUrl={entry.get('startUrl')}  keyed_by={entry.get('keyed_by')}"
            print(
                f"{path.parent.name}/{path.name}\n"
                f"    {entry['kind']:<20} expiresAt={entry.get('expiresAt', '-')} "
                f"{expired}{detail}"
            )

    print("\n== Keys botocore will look for ==")
    expectations = expected_keys()
    if not expectations:
        print("No SSO-configured profiles or sso-session blocks found in ~/.aws/config.")
    missing = []
    for exp in expectations:
        present = (SSO_CACHE / f"{exp['key']}.json").exists()
        mark = "present" if present else "MISSING"
        print(f"{exp['key']}.json  [{mark}]  <- {exp['source']}")
        if not present:
            missing.append(exp)

    live_tokens = [
        e
        for e in entries
        if e["kind"] == "sso-token" and e["expired"] is False and e["path"].parent == SSO_CACHE
    ]

    if args.fix:
        print("\n== Fix ==")
        if not missing:
            print("Nothing missing — the cache is not the problem.")
        elif not live_tokens:
            print("No unexpired token to link. Run `aws sso login` first (watch it succeed).")
        elif len(live_tokens) > 1:
            print(
                f"{len(live_tokens)} live tokens found — refusing to guess which "
                "account maps to which key. Match startUrl/expiry above and link "
                "manually:  ln -sf <token>.json <expected-key>.json"
            )
        else:
            token = live_tokens[0]["path"]
            for exp in missing:
                target = SSO_CACHE / f"{exp['key']}.json"
                target.symlink_to(token)
                print(f"linked {target.name} -> {token.name}")

    if args.verify:
        print("\n== Verify (sts get-caller-identity) ==")
        import boto3

        profiles = (
            sorted({e["profile"] for e in expectations if e["profile"]})
            or boto3.Session().available_profiles
        )
        for profile in profiles:
            try:
                identity = boto3.Session(profile_name=profile).client("sts").get_caller_identity()
                print(f"{profile:<40} OK  account {_mask(identity.get('Account'))}")
            except Exception as exc:  # noqa: BLE001 - report, don't crash
                print(f"{profile:<40} FAIL  {type(exc).__name__}: {str(exc)[:90]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
