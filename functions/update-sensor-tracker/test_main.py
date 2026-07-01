"""
Tests for update-sensor-tracker.

Focus: the sliding-window standing logic -- specifically that exactly one
build holds each standing (n / n-1 / n-2) per platform, and that aged-out
builds are demoted to "untagged" instead of piling up.

The handler is registered on FUNC via the @FUNC.handler decorator (which
returns None), so it is invoked through FUNC._router.route(). The real
falconpy clients are replaced with in-memory fakes via monkeypatch.
"""

import json
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import main  # noqa: E402
from crowdstrike.foundry.function import Request  # noqa: E402

LOGGER = logging.getLogger("test")


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeStore:
    """In-memory stand-in for the CustomStorage service class."""

    def __init__(self, initial=None):
        # object_key -> record dict
        self.objects = {k: _copy(v) for k, v in (initial or {}).items()}
        self.put_keys = []  # order of PutObject calls

    def GetObject(self, collection_name=None, object_key=None, **kwargs):
        if object_key in self.objects:
            # Storage returns a fresh copy each read.
            return {"status_code": 200, "body": _copy(self.objects[object_key])}
        return {"status_code": 404}

    def PutObject(self, collection_name=None, object_key=None, body=None, **kwargs):
        self.objects[object_key] = _copy(body)
        self.put_keys.append(object_key)
        return {"status_code": 200}


class FakeSensor:
    """In-memory stand-in for SensorUpdatePolicies.query_combined_builds."""

    def __init__(self, builds_by_platform):
        self.builds_by_platform = builds_by_platform

    def query_combined_builds(self, platform, stage):
        return {
            "status_code": 200,
            "body": {"resources": self.builds_by_platform.get(platform, [])},
        }


def _copy(d):
    return json.loads(json.dumps(d))


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def api_build(version, build, platform="Linux"):
    """A resource as returned by query_combined_builds."""
    return {"platform": platform, "sensor_version": version, "build": build, "stage": "prod"}


def record(build_number, standing, platform="Linux", prev=None, updated=1000, first=1000):
    """A stored collection record."""
    raw = build_number if standing == "untagged" else f"{build_number}|{standing}|tagged|1"
    return {
        "platform": platform,
        "sensor_version": f"7.x.{build_number}",
        "release_standing": standing,
        "build_number": build_number,
        "raw_build_string": raw,
        "stage": "prod",
        "first_seen_timestamp": first,
        "standing_updated_timestamp": updated,
        "previous_standings": list(prev or []),
    }


def run_handler(monkeypatch, builds_by_platform, initial_store=None, platforms=None):
    monkeypatch.delenv("DEBUG_MODE", raising=False)
    store = FakeStore(initial_store)
    monkeypatch.setattr(main, "CustomStorage", lambda *a, **k:store)
    monkeypatch.setattr(main, "SensorUpdatePolicies", lambda *a, **k: FakeSensor(builds_by_platform))
    req = Request(
        method="POST",
        url="/update-sensor-tracker",
        body={"platforms": platforms or ["linux"], "stage": "prod"},
    )
    resp = main.FUNC._router.route(req, logger=LOGGER)
    return resp, store


def standings(store, platform="linux"):
    """Map build_number -> release_standing for one platform."""
    return {
        r["build_number"]: r["release_standing"]
        for r in store.objects.values()
        if r["platform"].lower() == platform
    }


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_parse_build_string_tagged():
    info = main.parse_build_string("18909|n-2|tagged|6")
    assert info == {"build_number": "18909", "release_standing": "n-2"}


def test_parse_build_string_untagged():
    info = main.parse_build_string("18909")
    assert info == {"build_number": "18909", "release_standing": "untagged"}


def test_get_object_key_lowercases_platform():
    assert main.get_object_key("Linux", "18909") == "linux_18909"


# ---------------------------------------------------------------------------
# Basic create / no-change
# ---------------------------------------------------------------------------

def test_new_tagged_build_is_created(monkeypatch):
    resp, store = run_handler(
        monkeypatch,
        {"linux": [api_build("7.36.18909", "18909|n-2|tagged|6")]},
    )
    assert resp.code == 200
    assert resp.body["summary"]["new_entries_created"] == 1
    assert standings(store) == {"18909": "n-2"}
    assert store.objects["linux_18909"]["previous_standings"] == []


def test_unchanged_standing_is_skipped_no_put(monkeypatch):
    initial = {"linux_18909": record("18909", "n-2", updated=500)}
    resp, store = run_handler(
        monkeypatch,
        {"linux": [api_build("7.36.18909", "18909|n-2|tagged|6")]},
        initial_store=initial,
    )
    assert resp.body["summary"]["existing_entries_skipped"] >= 1
    # No write happened, timestamp preserved.
    assert "linux_18909" not in store.put_keys
    assert store.objects["linux_18909"]["standing_updated_timestamp"] == 500


# ---------------------------------------------------------------------------
# In-response tagged/untagged duplicate must NOT clobber the tagged record
# (this is what line ~302's tagged_this_run skip protects -- verify removing
#  the old guard didn't break it)
# ---------------------------------------------------------------------------

def test_untagged_duplicate_does_not_clobber_new_build(monkeypatch):
    resp, store = run_handler(
        monkeypatch,
        {"linux": [
            api_build("7.36.18909", "18909|n-2|tagged|6"),  # tagged
            api_build("7.36.18909", "18909"),               # untagged dup, same run
        ]},
    )
    assert standings(store) == {"18909": "n-2"}


def test_untagged_duplicate_does_not_clobber_existing_build(monkeypatch):
    initial = {"linux_18909": record("18909", "n-2", updated=500)}
    resp, store = run_handler(
        monkeypatch,
        {"linux": [
            api_build("7.36.18909", "18909|n-2|tagged|6"),
            api_build("7.36.18909", "18909"),
        ]},
        initial_store=initial,
    )
    assert store.objects["linux_18909"]["release_standing"] == "n-2"


# ---------------------------------------------------------------------------
# Promotion through the window still works
# ---------------------------------------------------------------------------

def test_promotion_n1_to_n2_appends_history(monkeypatch):
    initial = {
        "linux_18803": record(
            "18803", "n-1", prev=[{"standing": "n", "timestamp": 100}], updated=500
        )
    }
    resp, store = run_handler(
        monkeypatch,
        {"linux": [api_build("7.35.18803", "18803|n-2|tagged|6")]},
        initial_store=initial,
    )
    rec = store.objects["linux_18803"]
    assert rec["release_standing"] == "n-2"
    assert [p["standing"] for p in rec["previous_standings"]] == ["n", "n-1"]


# ---------------------------------------------------------------------------
# THE FIX: aged-out builds get demoted to untagged instead of staying tagged
# ---------------------------------------------------------------------------

def test_aged_out_build_is_demoted_to_untagged(monkeypatch):
    # 18803 was n-2 last run; this run the API only reports it untagged
    # (it fell out of the window) and 18909 is the new n-2.
    initial = {"linux_18803": record("18803", "n-2", updated=500)}
    resp, store = run_handler(
        monkeypatch,
        {"linux": [
            api_build("7.36.18909", "18909|n-2|tagged|6"),  # new current n-2
            api_build("7.36.18909", "18909"),               # dup
            api_build("7.35.18803", "18803"),               # aged out -> untagged
        ]},
        initial_store=initial,
    )
    rec = store.objects["linux_18803"]
    assert rec["release_standing"] == "untagged"
    # History records the standing it aged out of.
    assert rec["previous_standings"][-1]["standing"] == "n-2"
    assert standings(store) == {"18803": "untagged", "18909": "n-2"}


def test_only_one_n2_after_full_window_run(monkeypatch):
    # Reproduces the reported bug: collection has FOUR stale n-2 records.
    initial = {
        "linux_18606": record("18606", "n-2"),
        "linux_18708": record("18708", "n-2"),
        "linux_18803": record("18803", "n-2"),
        "linux_18909": record("18909", "n-2"),
        "linux_19004": record("19004", "n-1"),
        "linux_19102": record("19102", "n"),
    }
    # Current window the API reports now: n=19102, n-1=19004, n-2=18909.
    # The three older builds now come back untagged.
    builds = {"linux": [
        api_build("7.38.19102", "19102|n|tagged|21"),
        api_build("7.37.19004", "19004|n-1|tagged|5"),
        api_build("7.36.18909", "18909|n-2|tagged|6"),
        api_build("7.35.18803", "18803"),
        api_build("7.34.18708", "18708"),
        api_build("7.33.18606", "18606"),
    ]}
    resp, store = run_handler(monkeypatch, builds, initial_store=initial)

    result = standings(store)
    n2_builds = [b for b, s in result.items() if s == "n-2"]
    assert n2_builds == ["18909"], f"expected one n-2, got {result}"
    assert result["18606"] == "untagged"
    assert result["18708"] == "untagged"
    assert result["18803"] == "untagged"
    assert result["19004"] == "n-1"
    assert result["19102"] == "n"


# ---------------------------------------------------------------------------
# Multi-platform isolation
# ---------------------------------------------------------------------------

def test_platforms_are_independent(monkeypatch):
    initial = {
        "linux_18803": record("18803", "n-2", platform="Linux", updated=500),
        "windows_20709": record("20709", "n-2", platform="Windows", updated=500),
    }
    builds = {
        "linux": [
            api_build("7.36.18909", "18909|n-2|tagged|6", platform="Linux"),
            api_build("7.35.18803", "18803", platform="Linux"),
        ],
        "windows": [
            api_build("7.36.20805", "20805|n-2|tagged|2", platform="Windows"),
            api_build("7.35.20709", "20709", platform="Windows"),
        ],
    }
    resp, store = run_handler(monkeypatch, builds, initial_store=initial,
                              platforms=["linux", "windows"])
    assert standings(store, "linux") == {"18803": "untagged", "18909": "n-2"}
    assert standings(store, "windows") == {"20709": "untagged", "20805": "n-2"}


# ---------------------------------------------------------------------------
# Coverage gaps added after live recon (error paths, storage shapes, validation)
# ---------------------------------------------------------------------------

class FakeSensorStatus:
    """query_combined_builds with a configurable status_code/body."""

    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self.body = body or {}

    def query_combined_builds(self, platform, stage):
        return {"status_code": self.status_code, "body": self.body}


class FakeStoreBadPut(FakeStore):
    """GetObject works; PutObject always fails with 500."""

    def PutObject(self, **kwargs):
        return {"status_code": 500}


class StoreBytesGet:
    """Real Foundry runtime returns the stored object as raw bytes."""

    def __init__(self, rec):
        self.rec = rec

    def GetObject(self, **kwargs):
        return json.dumps(self.rec).encode("utf-8")


class StoreGet200NoRecord:
    """A 200 whose body is NOT the stored record (e.g. a wrapped resources list)."""

    def GetObject(self, **kwargs):
        return {"status_code": 200, "body": {"resources": []}}


def test_api_failure_returns_error_response(monkeypatch):
    monkeypatch.delenv("DEBUG_MODE", raising=False)
    store = FakeStore()
    monkeypatch.setattr(main, "CustomStorage", lambda *a, **k:store)
    monkeypatch.setattr(
        main, "SensorUpdatePolicies",
        lambda *a, **k: FakeSensorStatus(500, {"errors": [{"message": "rate limited"}]}),
    )
    req = Request(method="POST", url="/update-sensor-tracker",
                  body={"platforms": ["linux"], "stage": "prod"})
    resp = main.FUNC._router.route(req, logger=LOGGER)

    assert resp.code == 500
    assert store.put_keys == []  # nothing written on API failure
    # The real reason is surfaced from body.errors (was lost as "Unknown error"
    # before the error-key fix).
    assert "rate limited" in resp.errors[0].message


def test_put_failure_records_error_and_207(monkeypatch):
    monkeypatch.delenv("DEBUG_MODE", raising=False)
    store = FakeStoreBadPut()
    monkeypatch.setattr(main, "CustomStorage", lambda *a, **k:store)
    monkeypatch.setattr(main, "SensorUpdatePolicies",
                        lambda *a, **k: FakeSensor({"linux": [api_build("7.36.18909", "18909|n-2|tagged|6")]}))
    req = Request(method="POST", url="/update-sensor-tracker",
                  body={"platforms": ["linux"], "stage": "prod"})
    resp = main.FUNC._router.route(req, logger=LOGGER)

    assert resp.code == 207
    assert resp.body["success"] is False
    assert resp.body["summary"]["errors"] == 1


def test_read_existing_record_bytes_path():
    rec = record("18909", "n-2")
    out = main.read_existing_record(StoreBytesGet(rec), main.COLLECTION_NAME,
                                    "linux_18909", LOGGER)
    assert out is not None
    assert out["release_standing"] == "n-2"


def test_read_existing_record_200_without_record_returns_none():
    # RISK documented: a 200 whose body isn't the record yields None, so the
    # caller treats the build as NEW and resets first_seen_timestamp -- which
    # silently restarts the enforce grace clock every run.
    out = main.read_existing_record(StoreGet200NoRecord(), main.COLLECTION_NAME,
                                    "linux_18909", LOGGER)
    assert out is None


def test_invalid_platform_returns_400(monkeypatch):
    resp, store = run_handler(monkeypatch, {"solaris": []}, platforms=["solaris"])
    assert resp.code == 400
    assert store.put_keys == []


def test_empty_platforms_returns_400(monkeypatch):
    monkeypatch.delenv("DEBUG_MODE", raising=False)
    monkeypatch.setattr(main, "CustomStorage", lambda *a, **k:FakeStore())
    monkeypatch.setattr(main, "SensorUpdatePolicies", lambda *a, **k: FakeSensor({}))
    req = Request(method="POST", url="/update-sensor-tracker", body={"platforms": []})
    resp = main.FUNC._router.route(req, logger=LOGGER)
    assert resp.code == 400


def test_first_seen_preserved_on_standing_change(monkeypatch):
    # first_seen must survive a standing change -- the enforce function measures
    # the grace period from this exact field.
    initial = {"linux_18803": record("18803", "n-1", first=100, updated=500)}
    resp, store = run_handler(
        monkeypatch,
        {"linux": [api_build("7.35.18803", "18803|n-2|tagged|6")]},
        initial_store=initial,
    )
    rec = store.objects["linux_18803"]
    assert rec["release_standing"] == "n-2"
    assert rec["first_seen_timestamp"] == 100           # preserved
    assert rec["standing_updated_timestamp"] != 500     # bumped to now


def test_lts_sensor_version_stored_verbatim(monkeypatch):
    # Live n builds look like '7.38.19102 (LTS)'.
    resp, store = run_handler(
        monkeypatch,
        {"linux": [api_build("7.38.19102 (LTS)", "19102|n|tagged|21")]},
    )
    assert store.objects["linux_19102"]["sensor_version"] == "7.38.19102 (LTS)"


def test_extract_error_message_body_none_no_crash():
    # Regression: falconpy can return {"status_code": 5xx, "body": None}. The {}
    # default only fires when 'body' is absent, not when it's present-but-None.
    assert main.extract_error_message({"status_code": 500, "body": None}) == "Unknown error"
    assert main.extract_error_message(
        {"body": {"errors": [{"message": "boom"}]}}) == "boom"


def test_build_fetch_error_without_status_code_surfaces_real_message(monkeypatch):
    # Regression: when the build-fetch response omits status_code, the error path
    # must not KeyError-crash into an opaque 500; it must report the upstream error.
    class SensorNoStatus:
        def query_combined_builds(self, platform, stage):
            return {"body": {"errors": [{"code": 503, "message": "upstream unavailable"}]}}
    monkeypatch.delenv("DEBUG_MODE", raising=False)
    monkeypatch.setattr(main, "CustomStorage", lambda *a, **k:FakeStore())
    monkeypatch.setattr(main, "SensorUpdatePolicies", lambda *a, **k: SensorNoStatus())
    req = Request(method="POST", url="/update-sensor-tracker",
                  body={"platforms": ["linux"], "stage": "prod"})
    resp = main.FUNC._router.route(req, logger=LOGGER)
    assert resp.code == 500
    msg = resp.errors[0].message
    assert "upstream unavailable" in msg
    assert "status_code" not in msg  # not the masked KeyError


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
