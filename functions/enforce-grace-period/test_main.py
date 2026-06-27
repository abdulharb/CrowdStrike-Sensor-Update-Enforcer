"""
Tests for enforce-grace-period (the disruptive function).

Field shapes here mirror what the live US-2 tenant actually returns
(verified by read-only recon):
  - sensor builds:    platform 'Windows'/'Mac'/'Linux', build '20805|n-2|tagged|2',
                      sensor_version '7.36.20805' (n builds carry ' (LTS)')
  - policies:         query_combined_policies_v2 has NO 'precedence' key; platform_name
                      capitalized; settings.build / settings.sensor_version
  - group members:    device_id, platform_name (capitalized), agent_version, hostname

Some tests DOCUMENT current behavior that the review flagged as risky
(empty agent_version -> treated stale -> force-updated). Those are marked
with `BEHAVIOR:` so a future fix flips the assertion intentionally, not by
accident.

The handler is registered on FUNC via @FUNC.handler; it's invoked through
FUNC._router.route(). falconpy clients are replaced with in-memory fakes.
"""

import json
import logging
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import main  # noqa: E402
from crowdstrike.foundry.function import Request  # noqa: E402

LOGGER = logging.getLogger("test-enforce")


def _copy(d):
    return json.loads(json.dumps(d))


# ---------------------------------------------------------------------------
# Fakes (falconpy-shaped responses)
# ---------------------------------------------------------------------------

def _resp(resources, total=None, status=200):
    if total is None:
        total = len(resources)
    return {
        "status_code": status,
        "body": {
            "resources": resources,
            "meta": {"pagination": {"total": total}},
        },
    }


class FakeSensor:
    """Stand-in for SensorUpdatePolicies."""

    def __init__(self, policies=None):
        self._policies = policies or []

    def query_combined_policies_v2(self, limit=200, offset=0):
        # Single page; pagination loop in _fetch_all_policies stops after this.
        if offset == 0:
            return _resp(self._policies, total=len(self._policies))
        return _resp([], total=len(self._policies))


class FakeHostGroup:
    """Stand-in for HostGroup. members_by_group: {group_id: [device, ...]}."""

    def __init__(self, members_by_group=None, action_status=200):
        self.members_by_group = members_by_group or {}
        self.action_status = action_status
        self.actions = []  # recorded perform_group_action calls

    def query_combined_group_members(self, id, limit=5000, offset=0, filter=None):
        members = self.members_by_group.get(id, [])
        if filter and "platform_name:" in filter:
            # crude parse of platform_name:'Windows'
            want = filter.split("platform_name:")[1].strip().strip("'").strip("()'")
            members = [m for m in members if m.get("platform_name") == want]
        if offset >= len(members):
            return _resp([], total=len(members))
        page = members[offset:offset + limit]
        return _resp(page, total=len(members))

    def perform_group_action(self, action_name, body):
        self.actions.append({"action": action_name, "body": _copy(body)})
        return {"status_code": self.action_status,
                "body": {} if self.action_status == 200
                else {"errors": [{"message": "boom"}]}}


class FakeStore:
    """Stand-in for APIHarnessV2 (collection SearchObjects/GetObject)."""

    def __init__(self, by_platform_standing=None):
        # {(platform_fql, standing): record}
        self.data = by_platform_standing or {}

    def command(self, op, **kwargs):
        if op == "SearchObjects":
            flt = kwargs.get("filter", "")
            # filter form: platform:'Windows'+release_standing:'n-2'
            plat = flt.split("platform:")[1].split("+")[0].strip("'")
            standing = flt.split("release_standing:")[1].strip("'")
            rec = self.data.get((plat, standing))
            return _resp([rec] if rec else [])
        raise AssertionError(f"unexpected store op: {op}")


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def policy(name, platform="Windows", build="20805|n-2|tagged|2",
           sensor_version="7.36.20805", groups=("SRC",), enabled=True):
    # Mirrors live shape: NO 'precedence' key.
    return {
        "id": f"pol_{name}",
        "name": name,
        "platform_name": platform,
        "enabled": enabled,
        "groups": [{"id": g} for g in groups],
        "settings": {"build": build, "sensor_version": sensor_version},
    }


def device(device_id, agent_version, platform_name="Windows", hostname="host"):
    return {
        "device_id": device_id,
        "agent_version": agent_version,
        "platform_name": platform_name,
        "hostname": hostname,
    }


def collection_record(sensor_version, first_seen, standing="n-2", policy_name="Force Update",
                      standing_updated=None):
    # The real tracker sets standing_updated_timestamp on every record (= first_seen
    # on creation, = promotion time on a standing change), so default it to first_seen.
    return {
        "sensor_version": sensor_version,
        "first_seen_timestamp": first_seen,
        "standing_updated_timestamp": first_seen if standing_updated is None else standing_updated,
        "release_standing": standing,
        "policy_name": policy_name,
    }


# ===========================================================================
# Pure helpers: version parsing / comparison
# ===========================================================================

def test_parse_version_basic():
    assert main.parse_version("7.36.20805") == (7, 36, 20805)


def test_parse_version_strips_lts_suffix():
    # n builds in the live tenant look like '7.38.21003 (LTS)'
    assert main.parse_version("7.38.21003 (LTS)") == (7, 38, 21003)


def test_parse_version_malformed_is_zero():
    assert main.parse_version("") == (0, 0, 0)
    assert main.parse_version("garbage") == (0, 0, 0)
    assert main.parse_version(None) == (0, 0, 0)


def test_is_current_true_when_equal_or_newer():
    assert main.is_current("7.36.20805", "7.36.20805") is True
    assert main.is_current("7.38.21003 (LTS)", "7.36.20805") is True


def test_is_current_false_when_behind():
    assert main.is_current("7.35.20505", "7.36.20805") is False


def test_parse_build_string_tagged_and_untagged():
    assert main.parse_build_string("20805|n-2|tagged|2") == {
        "build_number": "20805", "release_standing": "n-2"}
    assert main.parse_build_string("17807") == {
        "build_number": "17807", "release_standing": "untagged"}


# ===========================================================================
# get_source_policy_targets
# ===========================================================================

def test_source_policy_single_match_maps_standing():
    sensor = FakeSensor([policy("Force Update", groups=("SRC",))])
    targets = main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    assert "windows" in targets
    assert targets["windows"]["target_standing"] == "n-2"
    assert targets["windows"]["policy_sensor_version"] == "7.36.20805"


def test_source_policy_two_policies_same_platform_does_not_crash():
    # Live reality: precedence key absent -> both default to 9999.
    # Two Windows policies attached to the source group must NOT raise
    # (this is the exact US-2 config: 'Force Update' + 'Normal').
    sensor = FakeSensor([
        policy("Force Update", groups=("SRC",)),
        policy("Normal", groups=("SRC", "OTHER")),
    ])
    targets = main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    assert targets["windows"]["target_standing"] == "n-2"
    # BEHAVIOR: selection is first-returned-wins (precedence is non-functional
    # because the API omits it). If precedence handling is fixed, update this.
    assert targets["windows"]["policy_name"] == "Force Update"


def test_source_policy_ignores_unattached_policies():
    sensor = FakeSensor([policy("platform_default", groups=("OTHER",))])
    targets = main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    assert targets == {}


def test_source_policy_untagged_build_is_skipped():
    sensor = FakeSensor([policy("Pinned", build="20505", sensor_version="7.33.20505")])
    targets = main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    # Untagged/pinned policy can't be mapped to a standing -> not a target.
    assert targets == {}


def test_source_policy_target_standing_override():
    sensor = FakeSensor([policy("Force Update")])
    targets = main.get_source_policy_targets(sensor, "SRC", "n-1", LOGGER)
    assert targets["windows"]["target_standing"] == "n-1"


def test_source_policy_disabled_policy_currently_still_used():
    # BEHAVIOR: the code does NOT filter enabled=False. CrowdStrike ignores
    # disabled policies; this documents the current divergence.
    sensor = FakeSensor([policy("Disabled", enabled=False, groups=("SRC",))])
    targets = main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    assert "windows" in targets  # flip to `== {}` when enabled-filtering is added


# ===========================================================================
# find_hosts_to_cleanup  (Phase A candidate selection)
# ===========================================================================

def _targets(version="7.36.20805"):
    return {"windows": {"sensor_version": version}}


def test_cleanup_removes_host_at_target():
    members = [device("d1", "7.36.20805")]
    out = main.find_hosts_to_cleanup(members, _targets(), LOGGER)
    assert [d["device_id"] for d in out] == ["d1"]


def test_cleanup_keeps_host_below_target():
    members = [device("d1", "7.35.20505")]
    out = main.find_hosts_to_cleanup(members, _targets(), LOGGER)
    assert out == []


def test_cleanup_skips_untracked_platform():
    members = [device("d1", "1.2.3", platform_name="Android")]
    out = main.find_hosts_to_cleanup(members, _targets(), LOGGER)
    assert out == []


def test_cleanup_empty_agent_version_is_kept():
    # BEHAVIOR (safe direction): empty version -> (0,0,0) -> not current ->
    # NOT removed from force group. Stays under enforcement.
    members = [device("d1", "")]
    out = main.find_hosts_to_cleanup(members, _targets(), LOGGER)
    assert out == []


# ===========================================================================
# find_stale_hosts_in_source  (Phase B candidate selection)
# ===========================================================================

def test_stale_finds_behind_hosts():
    hg = FakeHostGroup({"SRC": [device("d1", "7.30.20000"), device("d2", "7.36.20805")]})
    out = main.find_stale_hosts_in_source(
        hg, "SRC", "windows", "7.36.20805", set(), LOGGER)
    assert [d["device_id"] for d in out] == ["d1"]


def test_stale_skips_hosts_already_in_force_group():
    hg = FakeHostGroup({"SRC": [device("d1", "7.30.20000")]})
    out = main.find_stale_hosts_in_source(
        hg, "SRC", "windows", "7.36.20805", {"d1"}, LOGGER)
    assert out == []


def test_stale_empty_agent_version_is_skipped():
    # E2 fix: blank/unparseable version -> NOT enforced (skip+log), instead of
    # being force-updated off (0,0,0).
    hg = FakeHostGroup({"SRC": [device("d1", ""), device("d2", "garbage"),
                                device("d3", "7.30.20000")]})
    out = main.find_stale_hosts_in_source(
        hg, "SRC", "windows", "7.36.20805", set(), LOGGER)
    # Only the host with a real, behind version is enforced.
    assert [d["device_id"] for d in out] == ["d3"]


def test_has_known_version():
    assert main.has_known_version("7.36.20805") is True
    assert main.has_known_version("") is False
    assert main.has_known_version("   ") is False
    assert main.has_known_version("garbage") is False
    assert main.has_known_version(None) is False


# ===========================================================================
# batch_modify_group
# ===========================================================================

def test_batch_dry_run_makes_no_calls():
    hg = FakeHostGroup()
    count, errors = main.batch_modify_group(
        hg, "FORCE", ["d1", "d2"], "add-hosts", dry_run=True, logger=LOGGER)
    assert count == 2
    assert errors == []
    assert hg.actions == []  # nothing actually performed


def test_batch_splits_into_500_chunks():
    hg = FakeHostGroup()
    ids = [f"d{i}" for i in range(600)]
    count, errors = main.batch_modify_group(
        hg, "FORCE", ids, "add-hosts", dry_run=False, logger=LOGGER)
    assert count == 600
    assert errors == []
    assert len(hg.actions) == 2  # 500 + 100


def test_batch_reports_errors_on_non_200():
    hg = FakeHostGroup(action_status=500)
    count, errors = main.batch_modify_group(
        hg, "FORCE", ["d1"], "remove-hosts", dry_run=False, logger=LOGGER)
    assert count == 0
    assert len(errors) == 1
    assert errors[0]["operation"] == "remove-hosts"


def test_batch_empty_list_noop():
    hg = FakeHostGroup()
    count, errors = main.batch_modify_group(
        hg, "FORCE", [], "add-hosts", dry_run=False, logger=LOGGER)
    assert (count, errors) == (0, [])
    assert hg.actions == []


# ===========================================================================
# Handler integration (all clients faked)
# ===========================================================================

def _route(monkeypatch, *, sensor, hg, store, body, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(main, "SensorUpdatePolicies", lambda *a, **k: sensor)
    monkeypatch.setattr(main, "HostGroup", lambda *a, **k: hg)
    monkeypatch.setattr(main, "APIHarnessV2", lambda *a, **k: store)
    req = Request(method="POST", url="/enforce-grace-period", body=body)
    return main.FUNC._router.route(req, logger=LOGGER)


BASE_ENV = {
    "SOURCE_GROUP_ID": "SRC",
    "FORCE_UPDATE_GROUP_ID": "FORCE",
    "GRACE_PERIOD_DAYS": "3",
    "PLATFORMS": "windows",
    "DEBUG_MODE": "false",
    "TARGET_STANDING": "",
}


def test_handler_missing_source_group_returns_400(monkeypatch):
    env = dict(BASE_ENV, SOURCE_GROUP_ID="")
    resp = _route(monkeypatch, sensor=FakeSensor([]), hg=FakeHostGroup(),
                  store=FakeStore(), body={}, env=env)
    assert resp.code == 400


def test_handler_no_policy_on_source_returns_400(monkeypatch):
    # Policy exists but not attached to the source group.
    sensor = FakeSensor([policy("platform_default", groups=("OTHER",))])
    resp = _route(monkeypatch, sensor=sensor, hg=FakeHostGroup(),
                  store=FakeStore(), body={}, env=BASE_ENV)
    assert resp.code == 400


def test_handler_full_cycle_cleanup_and_enforce(monkeypatch):
    # Grace expired (first_seen far in the past). Force group has one host at
    # target (cleanup) + one behind (stays). Source group has one stale host
    # (enforce-add) + one current (skip).
    sensor = FakeSensor([policy("Force Update", groups=("SRC",))])
    store = FakeStore({("Windows", "n-2"): collection_record("7.36.20805", first_seen=1)})
    hg = FakeHostGroup({
        "FORCE": [device("f_done", "7.36.20805"), device("f_behind", "7.35.20505")],
        "SRC": [device("s_stale", "7.30.20000"), device("s_ok", "7.36.20805")],
    })
    resp = _route(monkeypatch, sensor=sensor, hg=hg, store=store, body={}, env=BASE_ENV)

    assert resp.code == 200
    assert resp.body["success"] is True
    assert resp.body["cleanup"]["hosts_removed"] == 1
    assert resp.body["enforcement"]["hosts_added"] == 1
    removed = {h["device_id"] for h in resp.body["cleanup"]["removed_hosts"]}
    added = {h["device_id"] for h in resp.body["enforcement"]["added_hosts"]}
    assert removed == {"f_done"}
    assert added == {"s_stale"}
    # Two group actions actually performed (1 remove, 1 add).
    assert sorted(a["action"] for a in hg.actions) == ["add-hosts", "remove-hosts"]


def test_handler_dry_run_makes_no_changes(monkeypatch):
    sensor = FakeSensor([policy("Force Update", groups=("SRC",))])
    store = FakeStore({("Windows", "n-2"): collection_record("7.36.20805", first_seen=1)})
    hg = FakeHostGroup({
        "FORCE": [device("f_done", "7.36.20805")],
        "SRC": [device("s_stale", "7.30.20000")],
    })
    resp = _route(monkeypatch, sensor=sensor, hg=hg, store=store,
                  body={"dry_run": True}, env=BASE_ENV)

    assert resp.code == 200
    assert resp.body["dry_run"] is True
    # Counts still reported...
    assert resp.body["cleanup"]["hosts_removed"] == 1
    assert resp.body["enforcement"]["hosts_added"] == 1
    # ...but NO real group actions were performed.
    assert hg.actions == []


def test_grace_anchored_to_promotion_not_first_seen(monkeypatch):
    # E1 regression: build first appeared 60 days ago (as 'n') but was promoted
    # to the target standing TODAY. Grace must be ACTIVE (anchored to promotion),
    # even though first_seen is far in the past.
    now = int(time.time())
    sensor = FakeSensor([policy("Force Update", groups=("SRC",))])
    rec = collection_record("7.36.20805", first_seen=now - 60 * 86400)
    rec["standing_updated_timestamp"] = now  # just promoted to n-2
    store = FakeStore({("Windows", "n-2"): rec})
    hg = FakeHostGroup({"FORCE": [], "SRC": [device("s_stale", "7.30.20000")]})
    resp = _route(monkeypatch, sensor=sensor, hg=hg, store=store, body={}, env=BASE_ENV)

    detail = resp.body["enforcement"]["platform_details"][0]
    assert detail["grace_period_expired"] is False  # grace active despite old first_seen
    assert resp.body["enforcement"]["hosts_added"] == 0
    assert hg.actions == []


def test_handler_grace_not_expired_skips_enforcement(monkeypatch):
    # first_seen = now -> 0 days elapsed -> grace active -> no adds.
    now = int(time.time())
    sensor = FakeSensor([policy("Force Update", groups=("SRC",))])
    store = FakeStore({("Windows", "n-2"): collection_record("7.36.20805", first_seen=now)})
    hg = FakeHostGroup({
        "FORCE": [],
        "SRC": [device("s_stale", "7.30.20000")],
    })
    resp = _route(monkeypatch, sensor=sensor, hg=hg, store=store, body={}, env=BASE_ENV)

    assert resp.code == 200
    assert resp.body["enforcement"]["hosts_added"] == 0
    detail = resp.body["enforcement"]["platform_details"][0]
    assert detail["grace_period_expired"] is False
    assert hg.actions == []


def test_grace_legacy_record_without_promotion_ts_skips_enforcement(monkeypatch):
    # Regression: a legacy record predating standing_updated_timestamp (value 0)
    # must NOT fall back to first_seen and force-update instantly on deploy day.
    # Enforcement is skipped until the tracker re-stamps the promotion date.
    now = int(time.time())
    sensor = FakeSensor([policy("Force Update", groups=("SRC",))])
    rec = collection_record("7.36.20805", first_seen=now - 60 * 86400, standing_updated=0)
    store = FakeStore({("Windows", "n-2"): rec})
    hg = FakeHostGroup({"FORCE": [], "SRC": [device("s_stale", "7.30.20000")]})
    resp = _route(monkeypatch, sensor=sensor, hg=hg, store=store, body={}, env=BASE_ENV)

    assert resp.code == 200
    assert resp.body["enforcement"]["hosts_added"] == 0
    detail = resp.body["enforcement"]["platform_details"][0]
    assert detail["grace_period_expired"] is False
    assert detail["standing_updated_timestamp"] == 0
    assert hg.actions == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
