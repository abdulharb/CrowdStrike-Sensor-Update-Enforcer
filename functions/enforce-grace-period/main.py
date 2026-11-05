"""
CrowdStrike Foundry Function: enforce-grace-period

Enforces sensor update grace periods by managing force-update host group
membership. The source host group's sensor update policy is the source of
truth for what version hosts should be on.

Runs in two phases:
  Phase A (Cleanup): Removes hosts from the force group that have reached
                     the source policy's target version.
  Phase B (Enforcement): After the grace period expires, adds hosts from the
                         source group that are still behind to the force group
                         so they update on next cloud connection.
"""

import json
import os
import re
import time
from logging import Logger
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import CustomStorage, HostGroup, SensorUpdatePolicies

FUNC = Function.instance()

COLLECTION_NAME = "sensor_release_tracker"

# Maps collection/request platform keys to device API platform_name values
PLATFORM_FQL_MAP = {
    "windows": "Windows",
    "mac": "Mac",
    "linux": "Linux",
}
FQL_TO_COLLECTION_MAP = {v: k for k, v in PLATFORM_FQL_MAP.items()}
VALID_PLATFORMS = set(PLATFORM_FQL_MAP)

DEFAULT_GRACE_PERIOD_DAYS = 3
MAX_GRACE_PERIOD_DAYS = 90

# Max device IDs per perform_group_action call
BATCH_SIZE = 500

# Max results per policy / host-group query page (the API maximum)
PAGE_LIMIT = 5000


# ---------------------------------------------------------------------------
# Helpers (copied in update-sensor-tracker: Foundry functions can't share
# modules, so keep the two copies in sync)
# ---------------------------------------------------------------------------

def is_debug_mode() -> bool:
    return os.environ.get("DEBUG_MODE", "").lower() in ("true", "1", "yes")


def log_debug(logger: Logger, message: str) -> None:
    if is_debug_mode():
        logger.info(f"[DEBUG] {message}")


def get_headers() -> Dict[str, str]:
    app_id = os.environ.get("APP_ID")
    return {"X-CS-APP-ID": app_id} if app_id else {}


def response_body(response: Any) -> Dict[str, Any]:
    """The response body as a dict; falconpy can return body=None on errors."""
    body = response.get("body") if isinstance(response, dict) else None
    return body if isinstance(body, dict) else {}


def extract_error_message(response: Any) -> str:
    """Pull a human-readable message from a falconpy response's body.errors."""
    errors = response_body(response).get("errors")
    if isinstance(errors, list):
        msgs = [e["message"] for e in errors if isinstance(e, dict) and e.get("message")]
        if msgs:
            return "; ".join(msgs)
    return "Unknown error"


def error_response(code: int, message: str) -> Response:
    return Response(code=code, errors=[APIError(code=code, message=message)])


class FalconAPIError(Exception):
    """A Falcon API call failed. Carries the API's own status and message."""

    def __init__(self, operation: str, response: Any):
        status = response.get("status_code") if isinstance(response, dict) else None
        self.status_code = status if isinstance(status, int) and status >= 400 else 500
        super().__init__(f"{operation} failed ({status}): {extract_error_message(response)}")


def parse_build_string(build_string: str) -> Dict[str, str]:
    """
    Parse a raw build string from the API or policy settings.

    Format examples:
    - "20407|n-1|tagged|1" -> build_number: 20407, release_standing: n-1
    - "20503|n|tagged|18"  -> build_number: 20503, release_standing: n
    - "20103" (untagged)   -> build_number: 20103, release_standing: untagged
    """
    parts = (build_string or "").split("|")
    standing = parts[1] if len(parts) > 1 and parts[1] else "untagged"
    return {"build_number": parts[0], "release_standing": standing}


def paginate(
    query: Callable[..., Dict[str, Any]],
    operation: str,
    logger: Logger,
    **params: Any,
) -> List[Dict[str, Any]]:
    """Collect every page of an offset-paginated Falcon query.

    Raises FalconAPIError on the first failed page instead of returning a
    partial list that would look like a complete one.
    """
    items: List[Dict[str, Any]] = []
    while True:
        log_debug(logger, f"{operation}: offset={len(items)}")
        resp = query(limit=PAGE_LIMIT, offset=len(items), **params)
        if resp.get("status_code") != 200:
            raise FalconAPIError(operation, resp)
        body = response_body(resp)
        page = body.get("resources") or []
        items.extend(page)
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total", 0)
        if not page or len(items) >= total:
            return items


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _parse_grace_days(value: Any, source: str) -> int:
    invalid = f"{source} must be an integer between 0 and {MAX_GRACE_PERIOD_DAYS} (got {value!r})"
    if isinstance(value, bool):
        raise ValueError(invalid)
    try:
        days = int(value)
    except (TypeError, ValueError):
        raise ValueError(invalid) from None
    # Negative grace would mean "enforce immediately", which is never intended.
    if not 0 <= days <= MAX_GRACE_PERIOD_DAYS:
        raise ValueError(invalid)
    return days


def _parse_platforms(value: Any, source: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(p, str) for p in value):
        raise ValueError(f'{source} must be a list of platform names (e.g. ["windows", "mac", "linux"])')
    # Normalize and de-duplicate, keeping order.
    platforms = list(dict.fromkeys(p.strip().lower() for p in value if p.strip()))
    invalid = [p for p in platforms if p not in VALID_PLATFORMS]
    if invalid:
        raise ValueError(f"Invalid platform(s) in {source}: {invalid}. Allowed: {sorted(VALID_PLATFORMS)}")
    return platforms


def load_config(body: Dict[str, Any], logger: Logger) -> Dict[str, Any]:
    """
    Load configuration from env vars with optional request body overrides.

    Raises ValueError (returned to the caller as a 400) on any missing or
    invalid setting -- this function moves hosts between groups, so it never
    guesses at a misconfigured value.
    """
    source_group_id = os.environ.get("SOURCE_GROUP_ID", "").strip()
    if not source_group_id:
        raise ValueError("SOURCE_GROUP_ID environment variable is not set. "
                         "Set it to the host group ID for the normal maintenance-window policy.")

    force_group_id = os.environ.get("FORCE_UPDATE_GROUP_ID", "").strip()
    if not force_group_id:
        raise ValueError("FORCE_UPDATE_GROUP_ID environment variable is not set. "
                         "Set it to the host group ID for force updates.")

    # Cleanup removes hosts from the force group; if it were the source group,
    # every up-to-date host would be pulled out of its normal group.
    if source_group_id == force_group_id:
        raise ValueError("SOURCE_GROUP_ID and FORCE_UPDATE_GROUP_ID must be different host groups")

    if "grace_period_days" in body:
        grace_period_days = _parse_grace_days(body["grace_period_days"], "grace_period_days")
    else:
        env_grace = os.environ.get("GRACE_PERIOD_DAYS", "").strip() or DEFAULT_GRACE_PERIOD_DAYS
        grace_period_days = _parse_grace_days(env_grace, "GRACE_PERIOD_DAYS")

    if "platforms" in body:
        platforms = _parse_platforms(body["platforms"], "platforms")
    else:
        platforms = _parse_platforms(os.environ.get("PLATFORMS", "windows").split(","), "PLATFORMS")

    # Optional manual override for target standing (auto-detected from policy if empty)
    target_standing_override = os.environ.get("TARGET_STANDING", "").strip().lower() or None
    if target_standing_override and not re.fullmatch(r"n(-\d+)?", target_standing_override):
        raise ValueError(f"TARGET_STANDING must look like 'n', 'n-1' or 'n-2' "
                         f"(got {target_standing_override!r})")

    dry_run = body.get("dry_run", False)
    if not isinstance(dry_run, bool):
        raise ValueError(f"dry_run must be true or false (got {dry_run!r})")

    logger.info(f"Config: grace_period_days={grace_period_days}, platforms={platforms}, "
                f"dry_run={dry_run}, source_group={source_group_id[:8]}..., "
                f"force_group={force_group_id[:8]}..., "
                f"target_standing_override={target_standing_override}")
    return {
        "source_group_id": source_group_id,
        "force_group_id": force_group_id,
        "grace_period_days": grace_period_days,
        "platforms": platforms,
        "target_standing_override": target_standing_override,
        "dry_run": dry_run,
    }


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def parse_version(version_str: str) -> Tuple[int, ...]:
    """
    Parse a sensor version string into a comparable tuple.

    Handles formats like "7.14.20503", "7.14.20503 (LTS)", etc.
    Returns (0, 0, 0) on parse failure so the host is treated as stale.
    """
    try:
        cleaned = version_str.strip().split(" ")[0]  # Strip "(LTS)" or similar suffixes
        return tuple(int(p) for p in cleaned.split("."))
    except (ValueError, AttributeError):
        return (0, 0, 0)


def is_current(agent_version: str, target_version: str) -> bool:
    """Return True if agent_version >= target_version."""
    return parse_version(agent_version) >= parse_version(target_version)


def has_known_version(version: str) -> bool:
    """True only for a parseable, non-empty sensor version.

    Hosts with a missing or garbage agent_version are NOT enforced: forcing an
    update off absent data risks disrupting hosts whose version simply wasn't
    reported (e.g. long-offline devices with stale records). Such hosts are
    logged and skipped rather than added to the force group.
    """
    if not version or not version.strip():
        return False
    return parse_version(version) != (0, 0, 0)


# ---------------------------------------------------------------------------
# Source policy detection
# ---------------------------------------------------------------------------

def get_source_policy_targets(
    falcon_sensor: SensorUpdatePolicies,
    source_group_id: str,
    target_standing_override: Optional[str],
    logger: Logger
) -> Dict[str, Dict[str, Any]]:
    """
    Find the sensor update policy that governs the source host group on each
    platform, and the release standing it targets.

    Policies are requested in precedence order (highest priority first), so
    the first enabled policy attached to the source group for a platform is
    the one its hosts actually receive. If that policy is pinned to a specific
    build (no release standing), the platform is skipped rather than falling
    back to a lower-precedence policy the hosts don't get. TARGET_STANDING
    overrides the standing for every platform.

    Returns: {platform_key: {"target_standing": str, "policy_name": str, ...}}
    Raises FalconAPIError if the policy query fails.
    """
    policies = paginate(falcon_sensor.query_combined_policies_v2,
                        "Query sensor update policies", logger, sort="precedence.asc")
    logger.info(f"Fetched {len(policies)} sensor update policies")

    targets: Dict[str, Dict[str, Any]] = {}
    seen_platforms: Set[str] = set()
    for policy in policies:
        group_ids = {g.get("id") for g in policy.get("groups") or [] if isinstance(g, dict)}
        if source_group_id not in group_ids:
            continue

        policy_name = policy.get("name", "")
        platform_name = policy.get("platform_name", "")
        platform_key = FQL_TO_COLLECTION_MAP.get(platform_name, platform_name.lower())

        # CrowdStrike ignores disabled policies, so do we.
        if policy.get("enabled") is False:
            logger.info(f"{platform_key}: ignoring disabled policy '{policy_name}'")
            continue
        if platform_key in seen_platforms:
            log_debug(logger, f"{platform_key}: ignoring lower-precedence policy '{policy_name}'")
            continue
        seen_platforms.add(platform_key)

        settings = policy.get("settings") or {}
        build_str = settings.get("build", "")
        sensor_version = settings.get("sensor_version", "")

        if target_standing_override:
            standing = target_standing_override
            logger.info(f"{platform_key}: using TARGET_STANDING override '{standing}'")
        else:
            standing = parse_build_string(build_str)["release_standing"]
            log_debug(logger, f"{platform_key}: parsed build string '{build_str}' -> '{standing}'")

        if standing == "untagged":
            logger.warning(f"{platform_key}: policy '{policy_name}' is pinned to build "
                           f"'{build_str}' with no release standing - skipping this platform. "
                           f"Set the TARGET_STANDING env var to enforce a standing anyway.")
            continue

        targets[platform_key] = {
            "policy_id": policy.get("id", ""),
            "policy_name": policy_name,
            "target_standing": standing,
            "policy_sensor_version": sensor_version,
            "policy_build_string": build_str,
        }
        logger.info(f"{platform_key}: policy '{policy_name}' targets standing '{standing}' "
                    f"(build={build_str}, version={sensor_version})")

    if not targets:
        logger.error(f"No usable sensor update policy found for source group {source_group_id}")
    return targets


# ---------------------------------------------------------------------------
# Collection queries
# ---------------------------------------------------------------------------

def read_record(storage: CustomStorage, object_key: str) -> Dict[str, Any]:
    """Read a full collection record. GetObject returns raw bytes on success."""
    resp = storage.GetObject(collection_name=COLLECTION_NAME, object_key=object_key)
    if isinstance(resp, (bytes, bytearray)):
        return json.loads(resp.decode("utf-8"))
    body = response_body(resp)
    if isinstance(resp, dict) and resp.get("status_code") == 200 and "sensor_version" in body:
        return body
    raise FalconAPIError(f"Collection read of {object_key}", resp)


def get_target_versions(
    storage: CustomStorage,
    policy_targets: Dict[str, Dict[str, Any]],
    logger: Logger
) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, str]]]:
    """
    For each platform, look up the current build at the policy's target
    standing in the collection.

    Returns (target_versions, errors), where target_versions is
    {platform: {"sensor_version", "first_seen_timestamp",
                "standing_updated_timestamp", "target_standing", "policy_name"}}
    """
    target_versions: Dict[str, Dict[str, Any]] = {}
    errors: List[Dict[str, str]] = []

    for platform, target_info in policy_targets.items():
        standing = target_info["target_standing"]
        # The tracker stores the builds API's capitalized platform name ("Windows").
        platform_fql = PLATFORM_FQL_MAP.get(platform, platform)
        log_debug(logger, f"Querying collection for current '{standing}' build on {platform}")

        try:
            resp = storage.SearchObjects(
                filter=f"platform:'{platform_fql}'+release_standing:'{standing}'",
                sort="first_seen_timestamp|desc",
                collection_name=COLLECTION_NAME,
                limit=1,
            )
            if resp.get("status_code") != 200:
                raise FalconAPIError(f"Collection search for {platform}/{standing}", resp)

            resources = response_body(resp).get("resources") or []
            if not resources:
                logger.warning(f"{platform}: No '{standing}' version found in collection. "
                               f"Has update-sensor-tracker run?")
                continue

            entry = resources[0]
            # SearchObjects may return only metadata (object_key); if so,
            # fetch the full record.
            if "sensor_version" not in entry:
                log_debug(logger, f"SearchObjects returned metadata only - "
                          f"fetching full record: {entry.get('object_key')}")
                entry = read_record(storage, entry.get("object_key", ""))
        except FalconAPIError as e:
            logger.error(str(e))
            errors.append({"operation": "collection-lookup", "error": str(e)})
            continue

        # Grace is measured from when the build REACHED the target standing
        # (its promotion) -- standing_updated_timestamp -- not when it first
        # appeared (which, for an n-1/n-2 target, predates the promotion by
        # weeks and would make grace a no-op). Do NOT fall back to first_seen:
        # legacy records without this field have no reliable promotion date,
        # and anchoring to first_seen would make grace expire instantly.
        # promoted_at==0 makes Phase B skip the platform until
        # update-sensor-tracker re-stamps it.
        first_seen = entry.get("first_seen_timestamp", 0)
        promoted_at = entry.get("standing_updated_timestamp", 0)
        target_versions[platform] = {
            "sensor_version": entry.get("sensor_version", ""),
            "first_seen_timestamp": first_seen,
            "standing_updated_timestamp": promoted_at,
            "target_standing": standing,
            "policy_name": target_info.get("policy_name", ""),
        }
        logger.info(f"{platform}: Current '{standing}' is version "
                    f"{target_versions[platform]['sensor_version']} "
                    f"(promoted: {promoted_at}, first seen: {first_seen})")

    return target_versions, errors


def get_cleanup_targets(
    policy_targets: Dict[str, Dict[str, Any]],
    target_versions: Dict[str, Dict[str, Any]],
    logger: Logger
) -> Dict[str, Dict[str, Any]]:
    """Phase A targets: the collection's build when known, otherwise the
    policy's own sensor_version, so cleanup still runs when the collection is
    empty or stale."""
    cleanup_targets = {}
    for platform, target_info in policy_targets.items():
        if platform in target_versions:
            cleanup_targets[platform] = target_versions[platform]
        elif target_info.get("policy_sensor_version"):
            cleanup_targets[platform] = {"sensor_version": target_info["policy_sensor_version"]}
            logger.warning(f"{platform}: Collection has no data for standing "
                           f"'{target_info['target_standing']}'. Using policy "
                           f"sensor_version '{target_info['policy_sensor_version']}' "
                           f"as fallback for cleanup.")
    return cleanup_targets


# ---------------------------------------------------------------------------
# Host groups
# ---------------------------------------------------------------------------

def get_group_members(
    falcon_hg: HostGroup,
    group_id: str,
    logger: Logger,
    label: str = "group",
    fql_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """All members of a host group with device details. Raises FalconAPIError."""
    params: Dict[str, Any] = {"id": group_id}
    if fql_filter:
        params["filter"] = fql_filter
    members = paginate(falcon_hg.query_combined_group_members,
                       f"Query {label} members", logger, **params)
    logger.info(f"{label} has {len(members)} members")
    return members


def batch_modify_group(
    falcon_hg: HostGroup,
    group_id: str,
    device_ids: List[str],
    action: str,
    dry_run: bool,
    logger: Logger
) -> Tuple[List[str], List[Dict[str, str]]]:
    """
    Add or remove hosts from a host group in batches.

    action: "add-hosts" or "remove-hosts"
    Returns (device_ids_modified, errors). In a dry run every ID counts as
    modified and no call is made.
    """
    if not device_ids:
        return [], []
    if dry_run:
        logger.info(f"[DRY RUN] Would {action} {len(device_ids)} hosts")
        return list(device_ids), []

    modified: List[str] = []
    errors: List[Dict[str, str]] = []
    for i in range(0, len(device_ids), BATCH_SIZE):
        batch = device_ids[i:i + BATCH_SIZE]
        id_filter = ",".join(f"'{did}'" for did in batch)
        log_debug(logger, f"{action} batch {i // BATCH_SIZE + 1}: {len(batch)} hosts")
        resp = falcon_hg.perform_group_action(
            action_name=action,
            body={
                "ids": [group_id],
                "action_parameters": [{"name": "filter", "value": f"(device_id:[{id_filter}])"}],
            },
        )
        if resp.get("status_code") == 200:
            modified.extend(batch)
        else:
            message = (f"Batch at offset {i} ({len(batch)} hosts) failed "
                       f"({resp.get('status_code')}): {extract_error_message(resp)}")
            errors.append({"operation": action, "error": message})
            logger.error(f"{action}: {message}")

    logger.info(f"{action}: {len(modified)}/{len(device_ids)} succeeded")
    return modified, errors


def _host_summary(device: Dict[str, Any]) -> Dict[str, str]:
    """Extract the fields we include in response host lists."""
    return {
        "device_id": device["device_id"],
        "hostname": device.get("hostname", ""),
        "platform": device.get("platform_name", ""),
        "agent_version": device.get("agent_version", ""),
    }


# ---------------------------------------------------------------------------
# Phase A: Cleanup
# ---------------------------------------------------------------------------

def find_hosts_to_cleanup(
    members: List[Dict[str, Any]],
    target_versions: Dict[str, Dict[str, Any]],
    logger: Logger
) -> List[Dict[str, Any]]:
    """Identify force-group members whose sensor version now meets the source policy target."""
    # An unparseable target ((0,0,0)) would make every host "current" and empty
    # the force group in one run. Skip cleanup for that platform instead.
    usable = {}
    for platform_key, info in target_versions.items():
        if has_known_version(info.get("sensor_version", "")):
            usable[platform_key] = info["sensor_version"]
        else:
            logger.warning(f"{platform_key}: target version "
                           f"{info.get('sensor_version', '')!r} is unparseable - "
                           f"skipping cleanup for this platform")

    to_remove = []
    for device in members:
        platform_name = device.get("platform_name", "")
        target = usable.get(FQL_TO_COLLECTION_MAP.get(platform_name))
        if not target:
            log_debug(logger, f"Skipping {device.get('hostname', '?')} - "
                      f"platform '{platform_name}' not tracked")
            continue
        if not device.get("device_id"):
            continue

        agent_ver = device.get("agent_version", "")
        if is_current(agent_ver, target):
            to_remove.append(device)
            log_debug(logger, f"Cleanup candidate: {device.get('hostname', '?')} "
                      f"({agent_ver} >= {target})")

    logger.info(f"Found {len(to_remove)} hosts to remove from force group (now at baseline)")
    return to_remove


# ---------------------------------------------------------------------------
# Phase B: Enforcement
# ---------------------------------------------------------------------------

def find_stale_hosts(
    members: List[Dict[str, Any]],
    target_version: str,
    exclude_ids: Set[str],
    logger: Logger
) -> List[Dict[str, Any]]:
    """Source-group members behind target_version that aren't already in the force group."""
    stale = []
    for device in members:
        device_id = device.get("device_id", "")
        if not device_id or device_id in exclude_ids:
            continue

        # Don't enforce on hosts with no reliable version data -- skip+log
        # instead of force-updating off (0,0,0).
        agent_ver = device.get("agent_version", "")
        if not has_known_version(agent_ver):
            logger.warning(f"Skipping {device.get('hostname', '?')} "
                           f"({device_id[:8]}) - missing/unparseable "
                           f"agent_version {agent_ver!r}; not enforcing")
            continue

        if not is_current(agent_ver, target_version):
            stale.append(device)

    logger.info(f"Found {len(stale)} stale hosts behind {target_version}")
    return stale


def enforce_platform(
    falcon_hg: HostGroup,
    cfg: Dict[str, Any],
    platform: str,
    policy_target: Dict[str, Any],
    version_info: Dict[str, Any],
    force_member_ids: Set[str],
    now: int,
    logger: Logger
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, str]]]:
    """Phase B for one platform. Returns (platform_detail, added_devices, errors)."""
    target_version = version_info.get("sensor_version", "")
    promoted_at = version_info.get("standing_updated_timestamp", 0)
    detail = {
        "platform": platform,
        "target_standing": policy_target.get("target_standing", ""),
        "target_version": target_version,
        "policy_name": policy_target.get("policy_name", ""),
        "first_seen_timestamp": version_info.get("first_seen_timestamp", 0),
        "standing_updated_timestamp": promoted_at,
        "grace_period_expired": False,
        "days_since_release": 0,
        "stale_hosts_found": 0,
        "hosts_added": 0,
    }

    if not version_info:
        # No policy target or no collection data; already logged.
        return detail, [], []

    # No reliable promotion date (legacy record predating this field): skip
    # rather than force-update off unknown data. The next standing change
    # re-stamps standing_updated_timestamp and enforcement resumes.
    if not promoted_at:
        logger.warning(f"{platform}: no standing_updated_timestamp on target build "
                       f"{target_version} - skipping enforcement until "
                       f"update-sensor-tracker re-stamps the promotion date")
        return detail, [], []

    # An unparseable target would make every host look current; nothing to do.
    if not has_known_version(target_version):
        logger.warning(f"{platform}: target version {target_version!r} is unparseable - "
                       f"skipping enforcement")
        return detail, [], []

    grace_period_days = cfg["grace_period_days"]
    elapsed = now - promoted_at
    detail["days_since_release"] = round(elapsed / 86400, 1)
    detail["grace_period_expired"] = elapsed >= grace_period_days * 86400
    if not detail["grace_period_expired"]:
        logger.info(f"{platform}: grace period active ({detail['days_since_release']} days / "
                    f"{grace_period_days} days) - skipping enforcement")
        return detail, [], []

    logger.info(f"{platform}: grace period expired ({detail['days_since_release']} days >= "
                f"{grace_period_days} days) - finding stale hosts in source group")
    try:
        members = get_group_members(
            falcon_hg, cfg["source_group_id"], logger,
            label=f"source group ({platform})",
            fql_filter=f"platform_name:'{PLATFORM_FQL_MAP[platform]}'",
        )
    except FalconAPIError as e:
        logger.error(str(e))
        return detail, [], [{"operation": "query-source-group", "error": str(e)}]

    stale = find_stale_hosts(members, target_version, force_member_ids, logger)
    detail["stale_hosts_found"] = len(stale)

    added_ids, errors = batch_modify_group(
        falcon_hg, cfg["force_group_id"], [d["device_id"] for d in stale],
        "add-hosts", cfg["dry_run"], logger
    )
    added_set = set(added_ids)
    added = [d for d in stale if d["device_id"] in added_set]
    detail["hosts_added"] = len(added)
    return detail, added, errors


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def run_enforcement(cfg: Dict[str, Any], logger: Logger) -> Response:
    now = int(time.time())
    dry_run = cfg["dry_run"]
    platforms = cfg["platforms"]

    # FalconPy clients are built per request: context auth only has a token
    # while a request is being handled. CustomStorage (not the Uber class) lets
    # the Foundry functions editor auto-detect OAuth scopes; ext_headers
    # applies X-CS-APP-ID to every request.
    storage = CustomStorage(ext_headers=get_headers())
    falcon_hg = HostGroup()
    falcon_sensor = SensorUpdatePolicies()

    # --- Detect source policy targets ---
    policy_targets = get_source_policy_targets(
        falcon_sensor, cfg["source_group_id"], cfg["target_standing_override"], logger
    )
    if not policy_targets:
        return error_response(
            400,
            "No enabled sensor update policy with a release standing is attached to "
            "SOURCE_GROUP_ID. Check the group ID and its policy, or set TARGET_STANDING "
            "if the policy pins a specific build."
        )
    policy_targets = {k: v for k, v in policy_targets.items() if k in platforms}

    # --- Look up current builds at the target standings from the collection ---
    target_versions, errors = get_target_versions(storage, policy_targets, logger)

    # ===============================================================
    # PHASE A: CLEANUP - Remove hosts that now meet the source target.
    # Runs even without collection data, using the policy version.
    # ===============================================================
    logger.info("=== Phase A: Cleanup ===")
    force_members = get_group_members(falcon_hg, cfg["force_group_id"], logger, label="force group")
    hosts_to_remove = find_hosts_to_cleanup(
        force_members, get_cleanup_targets(policy_targets, target_versions, logger), logger
    )
    removed_ids, remove_errors = batch_modify_group(
        falcon_hg, cfg["force_group_id"], [d["device_id"] for d in hosts_to_remove],
        "remove-hosts", dry_run, logger
    )
    errors.extend(remove_errors)
    removed_set = set(removed_ids)
    cleanup_result = {
        "hosts_evaluated": len(force_members),
        "hosts_removed": len(removed_ids),
        "removed_hosts": [_host_summary(d) for d in hosts_to_remove if d["device_id"] in removed_set],
    }

    # ===============================================================
    # PHASE B: ENFORCEMENT - Add stale source group hosts after grace.
    # Needs collection data for the promotion timestamp; a platform
    # without it is skipped (Phase A still ran).
    # ===============================================================
    logger.info("=== Phase B: Enforcement ===")
    # Hosts just removed in Phase A are at the target, so they can't be stale;
    # excluding every current force-group member is enough.
    force_member_ids = {m["device_id"] for m in force_members if m.get("device_id")}
    platform_details = []
    added_hosts = []
    for platform in platforms:
        detail, added, platform_errors = enforce_platform(
            falcon_hg, cfg, platform, policy_targets.get(platform, {}),
            target_versions.get(platform, {}), force_member_ids, now, logger
        )
        platform_details.append(detail)
        added_hosts.extend(_host_summary(d) for d in added)
        errors.extend(platform_errors)

    enforcement_result = {
        "platforms_checked": len(platforms),
        "platforms_expired": sum(1 for d in platform_details if d["grace_period_expired"]),
        "hosts_added": len(added_hosts),
        "platform_details": platform_details,
        "added_hosts": added_hosts,
    }

    success = not errors
    logger.info(f"Done - cleanup removed {len(removed_ids)}, enforcement added {len(added_hosts)}, "
                f"errors: {len(errors)}, dry_run: {dry_run}")
    return Response(
        code=200 if success else 207,
        body={
            "success": success,
            "dry_run": dry_run,
            "timestamp": now,
            "grace_period_days": cfg["grace_period_days"],
            "policy_targets": {k: v["target_standing"] for k, v in policy_targets.items()},
            "cleanup": cleanup_result,
            "enforcement": enforcement_result,
            "errors": errors or None,
        },
    )


@FUNC.handler(method="POST", path="/enforce-grace-period")
def enforce_grace_period_handler(
    request: Request,
    config: Optional[Dict[str, object]],
    logger: Logger
) -> Response:
    _ = config
    logger.info("Starting enforce-grace-period")

    body = request.body or {}
    if not isinstance(body, dict):
        logger.warning("Rejected request: body is not a JSON object")
        return error_response(400, "Request body must be a JSON object")

    try:
        cfg = load_config(body, logger)
    except ValueError as e:
        logger.warning(f"Rejected request: {e}")
        return error_response(400, str(e))

    try:
        return run_enforcement(cfg, logger)
    except FalconAPIError as e:
        # A read the run can't proceed without (policies, force group) failed.
        logger.error(str(e))
        return error_response(e.status_code, str(e))
    except Exception:
        logger.exception("Unexpected error in enforce-grace-period")
        return error_response(
            500, f"Internal error (trace_id={request.trace_id or 'n/a'}); see function logs"
        )


if __name__ == "__main__":
    FUNC.run()
