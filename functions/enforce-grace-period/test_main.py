"""
Tests for enforce-grace-period (the disruptive function).

Field shapes here mirror what the live US-2 tenant actually returns
(verified by read-only recon):
  - sensor builds:    platform 'Windows'/'Mac'/'Linux', build '20805|n-2|tagged|2',
                      sensor_version '7.36.20805' (n builds carry ' (LTS)')
  - policies:         query_combined_policies_v2 has NO 'precedence' key; platform_name
                      capitalized; settings.build / settings.sensor_version
  - group members:    device_id, platform_name (capitalized), agent_version, hostname

Some tests DOCUMENT deliberate behavior choices. Those are marked with
`BEHAVIOR:` so a future change flips the assertion intentionally, not by
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
    """Stand-in for SensorUpdatePolicies.

    Returns policies in the order given, standing in for the API's
    sort=precedence.asc ordering (the live response omits 'precedence', so
    the order is the only signal). Pass status to simulate an API failure.
    """

    def __init__(self, policies=None, status=200):
        self._policies = policies or []
        self.status = status
        self.sorts = []  # sort param of every call

    def query_combined_policies_v2(self, limit=200, offset=0, sort=None):
        self.sorts.append(sort)
        if self.status != 200:
            return {"status_code": self.status,
                    "body": {"errors": [{"message": "access denied"}]}}
        if offset == 0:
            return _resp(self._policies, total=len(self._policies))
        return _resp([], total=len(self._policies))


class FakeHostGroup:
    """Stand-in for HostGroup. members_by_group: {group_id: [device, ...]}."""

    def __init__(self, members_by_group=None, action_status=200, failing_groups=()):
        self.members_by_group = members_by_group or {}
        self.action_status = action_status
        self.failing_groups = set(failing_groups)  # member queries return 500
        self.actions = []  # recorded perform_group_action calls

    def query_combined_group_members(self, id, limit=5000, offset=0, filter=None):
        if id in self.failing_groups:
            return {"status_code": 500, "body": None}
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
        status = self.action_status
        if isinstance(status, dict):  # per-action status, e.g. {"add-hosts": 500}
            status = status.get(action_name, 200)
        return {"status_code": status,
                "body": {} if status == 200 else {"errors": [{"message": "boom"}]}}


class FakeStore:
    """Stand-in for CustomStorage (collection SearchObjects/GetObject)."""

    def __init__(self, by_platform_standing=None):
        # {(platform_fql, standing): record}
        self.data = by_platform_standing or {}

    def SearchObjects(self, collection_name=None, filter="", **kwargs):
        # filter form: platform:'Windows'+release_standing:'n-2'
        plat = filter.split("platform:")[1].split("+")[0].strip("'")
        standing = filter.split("release_standing:")[1].strip("'")
        rec = self.data.get((plat, standing))
        return _resp([rec] if rec else [])

    def GetObject(self, **kwargs):
        raise AssertionError("GetObject fallback should not be needed: "
                             "FakeStore records carry the full body")


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


def test_source_policy_requests_precedence_order():
    # The live response omits 'precedence', so ordering must come from the
    # API's sort parameter for "first policy wins" to match CrowdStrike.
    sensor = FakeSensor([policy("Force Update")])
    main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    assert sensor.sorts and all(s == "precedence.asc" for s in sensor.sorts)


def test_source_policy_two_policies_same_platform_highest_precedence_wins():
    # Two Windows policies attached to the source group (the exact US-2
    # config: 'Force Update' + 'Normal'). The API returns them in precedence
    # order, so the first one is what the hosts actually get.
    sensor = FakeSensor([
        policy("Force Update", groups=("SRC",)),
        policy("Normal", build="20703|n-1|tagged|2", groups=("SRC", "OTHER")),
    ])
    targets = main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    assert targets["windows"]["policy_name"] == "Force Update"
    assert targets["windows"]["target_standing"] == "n-2"


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


def test_source_policy_lower_precedence_pinned_policy_is_ignored():
    sensor = FakeSensor([
        policy("Force Update", groups=("SRC",)),
        policy("Pinned", build="20505", sensor_version="7.33.20505"),
    ])
    targets = main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    assert targets["windows"]["policy_name"] == "Force Update"
    assert targets["windows"]["target_standing"] == "n-2"


def test_source_policy_highest_precedence_pinned_policy_skips_platform():
    # BEHAVIOR: when the policy the hosts actually get pins a build, don't fall
    # back to a lower-precedence tagged policy -- enforcing that standing would
    # override the admin's pin. TARGET_STANDING opts back in.
    sensor = FakeSensor([
        policy("Pinned", build="20505", sensor_version="7.33.20505"),
        policy("Force Update", groups=("SRC",)),
    ])
    assert main.get_source_policy_targets(sensor, "SRC", None, LOGGER) == {}
    targets = main.get_source_policy_targets(sensor, "SRC", "n-1", LOGGER)
    assert targets["windows"]["policy_name"] == "Pinned"
    assert targets["windows"]["target_standing"] == "n-1"


def test_source_policy_disabled_policy_is_ignored():
    # CrowdStrike ignores disabled policies; so does the enforcer.
    sensor = FakeSensor([policy("Disabled", enabled=False, groups=("SRC",))])
    assert main.get_source_policy_targets(sensor, "SRC", None, LOGGER) == {}

    sensor = FakeSensor([
        policy("Disabled", build="20903|n|tagged|1", enabled=False),
        policy("Normal"),
    ])
    targets = main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    assert targets["windows"]["policy_name"] == "Normal"
    assert targets["windows"]["target_standing"] == "n-2"


def test_source_policy_query_failure_raises_with_api_message():
    sensor = FakeSensor(status=403)
    with pytest.raises(main.FalconAPIError) as exc:
        main.get_source_policy_targets(sensor, "SRC", None, LOGGER)
    assert exc.value.status_code == 403
    assert "access denied" in str(exc.value)


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


def test_cleanup_unparseable_target_skips_platform():
    # Empty/garbage target -> (0,0,0) -> every host would look "current" and
    # the whole force group would be emptied. Guard skips the platform instead.
    members = [device("d1", "7.30.20000"), device("d2", "7.36.20805")]
    assert main.find_hosts_to_cleanup(members, _targets(""), LOGGER) == []
    assert main.find_hosts_to_cleanup(members, _targets("garbage"), LOGGER) == []


# ===========================================================================
# find_stale_hosts  (Phase B candidate selection)
# ===========================================================================

def test_stale_finds_behind_hosts():
    members = [device("d1", "7.30.20000"), device("d2", "7.36.20805")]
    out = main.find_stale_hosts(members, "7.36.20805", set(), LOGGER)
    assert [d["device_id"] for d in out] == ["d1"]


def test_stale_skips_hosts_already_in_force_group():
    members = [device("d1", "7.30.20000")]
    out = main.find_stale_hosts(members, "7.36.20805", {"d1"}, LOGGER)
    assert out == []


def test_stale_empty_agent_version_is_skipped():
    # E2 fix: blank/unparseable version -> NOT enforced (skip+log), instead of
    # being force-updated off (0,0,0).
    members = [device("d1", ""), device("d2", "garbage"), device("d3", "7.30.20000")]
    out = main.find_stale_hosts(members, "7.36.20805", set(), LOGGER)
    # Only the host with a real, behind version is enforced.
    assert [d["device_id"] for d in out] == ["d3"]


def test_stale_skips_members_without_device_id():
    members = [device("", "7.30.20000"), device("d2", "7.30.20000")]
    out = main.find_stale_hosts(members, "7.36.20805", set(), LOGGER)
    assert [d["device_id"] for d in out] == ["d2"]


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
    done, errors = main.batch_modify_group(
        hg, "FORCE", ["d1", "d2"], "add-hosts", dry_run=True, logger=LOGGER)
    assert done == ["d1", "d2"]
    assert errors == []
    assert hg.actions == []  # nothing actually performed


def test_batch_splits_into_500_chunks():
    hg = FakeHostGroup()
    ids = [f"d{i}" for i in range(600)]
    done, errors = main.batch_modify_group(
        hg, "FORCE", ids, "add-hosts", dry_run=False, logger=LOGGER)
    assert done == ids
    assert errors == []
    assert len(hg.actions) == 2  # 500 + 100


def test_batch_reports_errors_on_non_200():
    hg = FakeHostGroup(action_status=500)
    done, errors = main.batch_modify_group(
        hg, "FORCE", ["d1"], "remove-hosts", dry_run=False, logger=LOGGER)
    assert done == []
    assert len(errors) == 1
    assert errors[0]["operation"] == "remove-hosts"
    assert "boom" in errors[0]["error"]  # the API's own message is surfaced


def test_batch_empty_list_noop():
    hg = FakeHostGroup()
    done, errors = main.batch_modify_group(
        hg, "FORCE", [], "add-hosts", dry_run=False, logger=LOGGER)
    assert (done, errors) == ([], [])
    assert hg.actions == []


# ===========================================================================
# Handler integration (all clients faked)
# ===========================================================================

def _route(monkeypatch, *, sensor, hg, store, body, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(main, "SensorUpdatePolicies", lambda *a, **k: sensor)
    monkeypatch.setattr(main, "HostGroup", lambda *a, **k: hg)
    monkeypatch.setattr(main, "CustomStorage", lambda *a, **k: store)
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


def test_handler_grace_period_out_of_range_returns_400(monkeypatch):
    for bad in (-1, 91):
        resp = _route(monkeypatch, sensor=FakeSensor([]), hg=FakeHostGroup(),
                      store=FakeStore(), body={"grace_period_days": bad}, env=BASE_ENV)
        assert resp.code == 400, f"grace_period_days={bad} should be rejected"


@pytest.mark.parametrize("env_override,body", [
    ({"FORCE_UPDATE_GROUP_ID": "SRC"}, {}),          # same group would gut the source group
    ({"GRACE_PERIOD_DAYS": "7d"}, {}),               # misconfig must not silently become 3
    ({"PLATFORMS": "windows,solaris"}, {}),
    ({"TARGET_STANDING": "N2"}, {}),
    ({}, {"dry_run": "false"}),                      # truthy string is not a boolean
    ({}, {"grace_period_days": True}),
    ({}, {"platforms": "windows"}),
    ({}, {"platforms": [1]}),
])
def test_handler_invalid_config_returns_400(monkeypatch, env_override, body):
    hg = FakeHostGroup()
    resp = _route(monkeypatch, sensor=FakeSensor([policy("Force Update")]), hg=hg,
                  store=FakeStore(), body=body, env=dict(BASE_ENV, **env_override))
    assert resp.code == 400
    assert hg.actions == []


def test_load_config_normalizes_platforms(monkeypatch):
    monkeypatch.setenv("SOURCE_GROUP_ID", "SRC")
    monkeypatch.setenv("FORCE_UPDATE_GROUP_ID", "FORCE")
    monkeypatch.setenv("PLATFORMS", " Windows, mac,windows ")
    monkeypatch.delenv("GRACE_PERIOD_DAYS", raising=False)
    cfg = main.load_config({}, LOGGER)
    assert cfg["platforms"] == ["windows", "mac"]
    assert cfg["grace_period_days"] == main.DEFAULT_GRACE_PERIOD_DAYS


def test_handler_policy_query_failure_surfaces_api_error(monkeypatch):
    hg = FakeHostGroup()
    resp = _route(monkeypatch, sensor=FakeSensor(status=403), hg=hg,
                  store=FakeStore(), body={}, env=BASE_ENV)
    # The API's own status and message, not a guessed "check SOURCE_GROUP_ID".
    assert resp.code == 403
    assert "access denied" in resp.errors[0].message
    assert hg.actions == []


def test_handler_force_group_query_failure_aborts(monkeypatch):
    sensor = FakeSensor([policy("Force Update", groups=("SRC",))])
    store = FakeStore({("Windows", "n-2"): collection_record("7.36.20805", first_seen=1)})
    hg = FakeHostGroup({"SRC": [device("s_stale", "7.30.20000")]}, failing_groups={"FORCE"})
    resp = _route(monkeypatch, sensor=sensor, hg=hg, store=store, body={}, env=BASE_ENV)
    assert resp.code == 500
    assert "force group" in resp.errors[0].message
    assert hg.actions == []


def test_handler_source_group_query_failure_is_partial(monkeypatch):
    sensor = FakeSensor([policy("Force Update", groups=("SRC",))])
    store = FakeStore({("Windows", "n-2"): collection_record("7.36.20805", first_seen=1)})
    hg = FakeHostGroup({"FORCE": [device("f_done", "7.36.20805")]}, failing_groups={"SRC"})
    resp = _route(monkeypatch, sensor=sensor, hg=hg, store=store, body={}, env=BASE_ENV)
    assert resp.code == 207
    assert resp.body["success"] is False
    assert resp.body["cleanup"]["hosts_removed"] == 1  # Phase A still ran
    assert resp.body["errors"][0]["operation"] == "query-source-group"


def test_handler_failed_add_is_not_reported_as_added(monkeypatch):
    sensor = FakeSensor([policy("Force Update", groups=("SRC",))])
    store = FakeStore({("Windows", "n-2"): collection_record("7.36.20805", first_seen=1)})
    hg = FakeHostGroup({
        "FORCE": [device("f_done", "7.36.20805")],
        "SRC": [device("s_stale", "7.30.20000")],
    }, action_status={"add-hosts": 500})
    resp = _route(monkeypatch, sensor=sensor, hg=hg, store=store, body={}, env=BASE_ENV)
    assert resp.code == 207
    assert resp.body["cleanup"]["hosts_removed"] == 1
    enforcement = resp.body["enforcement"]
    assert enforcement["platform_details"][0]["stale_hosts_found"] == 1
    assert enforcement["hosts_added"] == 0
    assert enforcement["added_hosts"] == []


def test_handler_unexpected_exception_returns_generic_500(monkeypatch):
    class ExplodingSensor:
        def query_combined_policies_v2(self, **kwargs):
            raise RuntimeError("secret internal detail")
    resp = _route(monkeypatch, sensor=ExplodingSensor(), hg=FakeHostGroup(),
                  store=FakeStore(), body={}, env=BASE_ENV)
    assert resp.code == 500
    assert "secret internal detail" not in resp.errors[0].message


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
