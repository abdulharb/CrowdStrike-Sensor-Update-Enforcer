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
import time
from logging import Logger
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import CustomStorage, HostGroup, SensorUpdatePolicies

FUNC = Function.instance()

COLLECTION_NAME = "sensor_release_tracker"

# Maps collection platform names to device API platform_name values
PLATFORM_FQL_MAP = {
    "windows": "Windows",
    "mac": "Mac",
    "linux": "Linux",
}

# Reverse mapping for cleanup/policy detection
FQL_TO_COLLECTION_MAP = {v: k for k, v in PLATFORM_FQL_MAP.items()}

VALID_PLATFORMS = set(PLATFORM_FQL_MAP.keys())

# Max device IDs per perform_group_action call
BATCH_SIZE = 500

# Max results per device/host-group query page
PAGE_LIMIT = 5000

# Max results per sensor-update-policy query page
POLICY_PAGE_LIMIT = 200

SECONDS_PER_DAY = 86400

DEFAULT_GRACE_PERIOD_DAYS = 3
MAX_GRACE_PERIOD_DAYS = 90


# ---------------------------------------------------------------------------
# Helpers (same patterns as update-sensor-tracker)
# ---------------------------------------------------------------------------

def is_debug_mode() -> bool:
    debug_value = os.environ.get("DEBUG_MODE", "").lower()
    return debug_value in ("true", "1", "yes")


def log_debug(logger: Logger, message: str) -> None:
    if is_debug_mode():
        logger.info(f"[DEBUG] {message}")


def get_headers() -> Dict[str, str]:
    headers = {}
    if os.environ.get("APP_ID"):
        headers = {"X-CS-APP-ID": os.environ.get("APP_ID")}
    return headers


def error_response(code: int, message: str) -> Response:
    """Build the FDK error envelope used for every non-2xx return."""
    return Response(code=code, errors=[APIError(code=code, message=message)])


def api_errors(resp: Dict[str, Any]) -> Any:
    """Pull body.errors out of a falconpy response for logging."""
    body = resp.get("body") or {}
    return body.get("errors", body) if isinstance(body, dict) else body


def parse_build_string(build_string: str) -> Dict[str, str]:
    """
    Parse a raw build string from the API or policy settings.

    Format examples:
    - "20407|n-1|tagged|1" -> build_number: 20407, release_standing: n-1
    - "20503|n|tagged|18"  -> build_number: 20503, release_standing: n
    - "20103" (untagged)   -> build_number: 20103, release_standing: untagged
    """
    if "|" in build_string:
        parts = build_string.split("|")
        build_number = parts[0]
        release_standing = parts[1] if len(parts) > 1 else "untagged"
    else:
        build_number = build_string
        release_standing = "untagged"

    return {
        "build_number": build_number,
        "release_standing": release_standing,
    }


def decode_object(resp: Any) -> Optional[Dict[str, Any]]:
    """
    Normalise a CustomStorage.GetObject reply to the stored record.

    The Foundry runtime returns the raw object bytes; the local SDK returns a
    {status_code, body} envelope. Anything else (404, 5xx) yields None.
    """
    if isinstance(resp, (bytes, bytearray)):
        return json.loads(resp.decode("utf-8"))
    if isinstance(resp, dict) and resp.get("status_code") == 200:
        body = resp.get("body")
        return body if isinstance(body, dict) else None
    return None


def paginate(
    fetch_page: Callable[[int], Dict[str, Any]],
    label: str,
    logger: Logger,
) -> List[Dict[str, Any]]:
    """
    Collect every resource from an offset-paginated falconpy query.

    fetch_page(offset) performs one request. Stops on the first non-200 page
    (logged, partial results returned), an empty page, or once the offset
    reaches meta.pagination.total.
    """
    items: List[Dict[str, Any]] = []
    offset = 0
    while True:
        log_debug(logger, f"Querying {label} offset={offset}")
        resp = fetch_page(offset)
        if resp.get("status_code") != 200:
            logger.error(f"Failed to query {label}: {resp.get('status_code')} {api_errors(resp)}")
            break

        body = resp.get("body") or {}
        resources = body.get("resources") or []
        if not resources:
            break
        items.extend(resources)

        total = body.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(resources)
        if offset >= total:
            break

    logger.info(f"{label}: {len(items)} results")
    return items


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class ConfigError(ValueError):
    """Raised by load_config for anything the caller must fix (-> HTTP 400)."""


def _require_env(name: str, hint: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} environment variable is not set. {hint}")
    return value


def load_config(body: Dict[str, Any], logger: Logger) -> Dict[str, Any]:
    """Load configuration from env vars with optional request body overrides."""
    source_group_id = _require_env(
        "SOURCE_GROUP_ID",
        "Set it to the host group ID for the normal maintenance-window policy.")
    force_group_id = _require_env(
        "FORCE_UPDATE_GROUP_ID",
        "Set it to the host group ID for force updates.")

    # Grace period: env var default, request body override
    raw_grace = os.environ.get("GRACE_PERIOD_DAYS", str(DEFAULT_GRACE_PERIOD_DAYS))
    try:
        grace_period_days = int(raw_grace)
    except ValueError:
        logger.warning(f"GRACE_PERIOD_DAYS={raw_grace!r} is not a number; "
                       f"using default {DEFAULT_GRACE_PERIOD_DAYS}")
        grace_period_days = DEFAULT_GRACE_PERIOD_DAYS

    if "grace_period_days" in body:
        try:
            grace_period_days = int(body["grace_period_days"])
        except (ValueError, TypeError):
            raise ConfigError(f"grace_period_days must be a number (0-{MAX_GRACE_PERIOD_DAYS})")

    # Covers both the env default and the body override. Negative grace would
    # mean "enforce immediately", which is never intended.
    if not 0 <= grace_period_days <= MAX_GRACE_PERIOD_DAYS:
        raise ConfigError(f"grace_period_days must be between 0 and {MAX_GRACE_PERIOD_DAYS} "
                          f"(got {grace_period_days})")

    # Platforms: env var default, request body override
    platforms = [p.strip() for p in os.environ.get("PLATFORMS", "windows").split(",") if p.strip()]
    if "platforms" in body:
        if not isinstance(body["platforms"], list):
            raise ConfigError("platforms must be an array of strings "
                              "(e.g. [\"windows\", \"mac\", \"linux\"])")
        platforms = body["platforms"]

    invalid = [p for p in platforms if p not in VALID_PLATFORMS]
    if invalid:
        raise ConfigError(f"Invalid platform(s): {invalid}. Allowed: {sorted(VALID_PLATFORMS)}")

    config = {
        "source_group_id": source_group_id,
        "force_group_id": force_group_id,
        "grace_period_days": grace_period_days,
        "platforms": platforms,
        # Optional manual override for target standing (auto-detected from policy if empty)
        "target_standing_override": os.environ.get("TARGET_STANDING", "").strip() or None,
        "dry_run": bool(body.get("dry_run", False)),
    }
    logger.info(f"Config: grace_period_days={grace_period_days}, platforms={platforms}, "
                f"dry_run={config['dry_run']}, source_group={source_group_id[:8]}..., "
                f"force_group={force_group_id[:8]}..., "
                f"target_standing_override={config['target_standing_override']}")
    return config


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

UNKNOWN_VERSION = (0, 0, 0)


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
        return UNKNOWN_VERSION


def is_current(agent_version: str, target_version: str) -> bool:
    """Return True if agent_version >= target_version."""
    return parse_version(agent_version) >= parse_version(target_version)


def has_known_version(agent_version: str) -> bool:
    """True only if the host reported a parseable, non-empty sensor version.

    Hosts with a missing or garbage agent_version are NOT enforced: forcing an
    update off absent data risks disrupting hosts whose version simply wasn't
    reported (e.g. long-offline devices with stale records). Such hosts are
    logged and skipped rather than added to the force group.
    """
    if not agent_version or not agent_version.strip():
        return False
    return parse_version(agent_version) != UNKNOWN_VERSION


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
    Query sensor update policies to find those attached to the source host group.
    Extracts the target standing per platform from each matching policy.

    Disabled policies are ignored (CrowdStrike does not apply them). If more
    than one enabled policy for the same platform is attached to the source
    group, the first one the API returns wins and the others are logged: the
    combined-policies API does not expose precedence, so the app cannot tell
    which one the sensor would actually honour.

    Returns: {platform_key: {"target_standing": str, "policy_name": str, ...}}
    """
    targets: Dict[str, Dict[str, Any]] = {}

    logger.info("Querying sensor update policies to detect source group targets")
    all_policies = paginate(
        lambda offset: falcon_sensor.query_combined_policies_v2(
            limit=POLICY_PAGE_LIMIT, offset=offset),
        "sensor update policies", logger)

    for policy in all_policies:
        group_ids = [g.get("id") for g in policy.get("groups", [])]
        if source_group_id not in group_ids:
            continue

        policy_name = policy.get("name", "")
        platform_name = policy.get("platform_name", "")
        platform_key = FQL_TO_COLLECTION_MAP.get(platform_name, platform_name.lower())

        if not policy.get("enabled", True):
            logger.info(f"{platform_key}: Ignoring disabled policy '{policy_name}'")
            continue

        settings = policy.get("settings", {})
        build_str = settings.get("build", "")
        sensor_version = settings.get("sensor_version", "")

        if target_standing_override:
            standing = target_standing_override
            logger.info(f"{platform_key}: Using TARGET_STANDING override: '{standing}'")
        else:
            standing = parse_build_string(build_str)["release_standing"]
            log_debug(logger, f"{platform_key}: Parsed build string '{build_str}' -> "
                      f"standing='{standing}'")

        if not standing or standing == "untagged":
            kept = ""
            if platform_key in targets:
                kept = (f" Keeping existing target from policy "
                        f"'{targets[platform_key]['policy_name']}'.")
            logger.warning(f"{platform_key}: Could not determine target standing from "
                           f"policy '{policy_name}' (build='{build_str}'). "
                           f"Set TARGET_STANDING env var to override.{kept}")
            continue

        if platform_key in targets:
            logger.warning(f"{platform_key}: Source group is also attached to policy "
                           f"'{policy_name}' (standing '{standing}'); keeping the first "
                           f"match '{targets[platform_key]['policy_name']}'. Attach a "
                           f"single enabled policy per platform to the source group.")
            continue

        targets[platform_key] = {
            "policy_id": policy.get("id", ""),
            "policy_name": policy_name,
            "target_standing": standing,
            "policy_sensor_version": sensor_version,
            "policy_build_string": build_str,
        }
        logger.info(f"{platform_key}: Policy '{policy_name}' targets standing '{standing}' "
                    f"(build={build_str}, version={sensor_version})")

    if not targets:
        logger.error(f"No sensor update policies found attached to source group "
                     f"{source_group_id}")

    return targets


# ---------------------------------------------------------------------------
# Collection queries
# ---------------------------------------------------------------------------

def _fetch_target_record(
    storage: CustomStorage,
    platform_fql: str,
    standing: str,
    logger: Logger
) -> Optional[Dict[str, Any]]:
    """Return the newest collection record at (platform, standing), or None."""
    resp = storage.SearchObjects(
        filter=f"platform:'{platform_fql}'+release_standing:'{standing}'",
        sort="first_seen_timestamp|desc",
        collection_name=COLLECTION_NAME,
        limit=1,
    )
    if resp.get("status_code") != 200:
        logger.error(f"Failed to query collection for {platform_fql}/{standing}: "
                     f"{resp.get('status_code')} {api_errors(resp)}")
        return None

    resources = resp.get("body", {}).get("resources", [])
    if not resources:
        return None
    entry = resources[0]

    # SearchObjects may return only metadata (object_key). If the record body
    # is missing, fetch it with GetObject.
    if "sensor_version" not in entry and "object_key" in entry:
        log_debug(logger, f"SearchObjects returned key only - fetching full record: "
                  f"{entry['object_key']}")
        full = decode_object(storage.GetObject(
            collection_name=COLLECTION_NAME, object_key=entry["object_key"]))
        if full and "sensor_version" in full:
            entry = full
    return entry


def get_target_versions(
    storage: CustomStorage,
    policy_targets: Dict[str, Dict[str, Any]],
    logger: Logger
) -> Dict[str, Dict[str, Any]]:
    """
    For each platform, look up the current build at the policy's target standing
    in the collection.

    Returns: {platform: {"sensor_version": str, "first_seen_timestamp": int,
                          "standing_updated_timestamp": int,
                          "target_standing": str, "policy_name": str}}
    """
    target_versions = {}

    for platform, target_info in policy_targets.items():
        standing = target_info["target_standing"]
        log_debug(logger, f"Querying collection for current '{standing}' build on {platform}")

        # The sensor builds API stores capitalized platform names (e.g. "Windows").
        platform_fql = PLATFORM_FQL_MAP.get(platform, platform)
        entry = _fetch_target_record(storage, platform_fql, standing, logger)
        if entry is None:
            logger.warning(f"{platform}: No '{standing}' version found in collection. "
                           f"Has update-sensor-tracker run?")
            continue

        # Grace is measured from when the build REACHED the target standing
        # (its promotion) -- standing_updated_timestamp -- not when it first
        # appeared (which, for an n-1/n-2 target, predates the promotion by
        # weeks and would make grace a no-op). Do NOT fall back to first_seen:
        # legacy records without this field have no reliable promotion date.
        # promoted_at==0 is handled by the handler, which skips enforcement
        # until update-sensor-tracker re-stamps it.
        first_seen = entry.get("first_seen_timestamp") or 0
        promoted_at = entry.get("standing_updated_timestamp") or 0
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

    return target_versions


# ---------------------------------------------------------------------------
# Host group access
# ---------------------------------------------------------------------------

def get_group_members(
    falcon_hg: HostGroup,
    group_id: str,
    logger: Logger,
    label: str = "group",
    fql_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Paginate through all members of a host group with full device details."""
    extra = {"filter": fql_filter} if fql_filter else {}
    return paginate(
        lambda offset: falcon_hg.query_combined_group_members(
            id=group_id, limit=PAGE_LIMIT, offset=offset, **extra),
        f"{label} members", logger)


def _host_summary(device: Dict[str, Any]) -> Dict[str, str]:
    """Extract the fields we include in response host lists."""
    return {
        "device_id": device["device_id"],
        "hostname": device.get("hostname", ""),
        "platform": device.get("platform_name", ""),
        "agent_version": device.get("agent_version", ""),
    }


def batch_modify_group(
    falcon_hg: HostGroup,
    group_id: str,
    device_ids: List[str],
    action: str,
    dry_run: bool,
    logger: Logger
) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Add or remove hosts from a host group in batches.

    action: "add-hosts" or "remove-hosts"
    Returns (count_modified, errors).
    """
    if not device_ids:
        return 0, []
    if dry_run:
        logger.info(f"[DRY RUN] Would {action} {len(device_ids)} hosts")
        return len(device_ids), []

    errors = []
    modified = 0

    for i in range(0, len(device_ids), BATCH_SIZE):
        batch = device_ids[i:i + BATCH_SIZE]
        id_filter = ",".join(f"'{did}'" for did in batch)

        log_debug(logger, f"{action} batch {i // BATCH_SIZE + 1}: {len(batch)} hosts")
        resp = falcon_hg.perform_group_action(
            action_name=action,
            body={
                "ids": [group_id],
                "action_parameters": [
                    {"name": "filter", "value": f"(device_id:[{id_filter}])"}
                ]
            }
        )

        if resp.get("status_code") == 200:
            modified += len(batch)
        else:
            err_detail = api_errors(resp)
            errors.append({
                "operation": action,
                "error": f"Batch at offset {i} failed: {err_detail}"
            })
            logger.error(f"{action} batch failed: {err_detail}")

    logger.info(f"{action}: {modified}/{len(device_ids)} succeeded")
    return modified, errors


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
        if parse_version(info.get("sensor_version", "")) == UNKNOWN_VERSION:
            logger.warning(f"{platform_key}: target version "
                           f"{info.get('sensor_version', '')!r} is unparseable - "
                           f"skipping cleanup for this platform")
        else:
            usable[platform_key] = info

    to_remove = []
    for device in members:
        platform_name = device.get("platform_name", "")
        platform_key = FQL_TO_COLLECTION_MAP.get(platform_name)
        if not platform_key or platform_key not in usable:
            log_debug(logger, f"Skipping {device.get('hostname', '?')} - "
                      f"platform '{platform_name}' not tracked")
            continue

        target = usable[platform_key]["sensor_version"]
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
    existing_force_member_ids: Set[str],
    logger: Logger
) -> List[Dict[str, Any]]:
    """
    From a list of source-group members, pick those whose sensor version is
    behind the target and that are not already in the force group.
    """
    stale_hosts = []
    for device in members:
        device_id = device.get("device_id", "")
        if device_id in existing_force_member_ids:
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
            stale_hosts.append(device)

    logger.info(f"Found {len(stale_hosts)} stale hosts")
    return stale_hosts


def _platform_detail(platform: str, info: Dict[str, Any], **overrides: Any) -> Dict[str, Any]:
    """One entry of enforcement.platform_details; `info` may be a policy target or a collection target."""
    detail = {
        "platform": platform,
        "target_standing": info.get("target_standing", ""),
        "target_version": info.get("sensor_version", ""),
        "policy_name": info.get("policy_name", ""),
        "first_seen_timestamp": info.get("first_seen_timestamp") or 0,
        "standing_updated_timestamp": info.get("standing_updated_timestamp") or 0,
        "grace_period_expired": False,
        "days_since_release": 0,
        "stale_hosts_found": 0,
        "hosts_added": 0,
    }
    detail.update(overrides)
    return detail


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

@FUNC.handler(method="POST", path="/enforce-grace-period")
def enforce_grace_period_handler(
    request: Request,
    config: Optional[Dict[str, object]],
    logger: Logger
) -> Response:
    _ = config

    try:
        logger.info("Starting enforce-grace-period")
        now = int(time.time())

        # --- Config ---
        try:
            cfg = load_config(request.body or {}, logger)
        except ConfigError as e:
            logger.warning(f"Rejecting request: {e}")
            return error_response(400, str(e))

        source_group_id = cfg["source_group_id"]
        force_group_id = cfg["force_group_id"]
        grace_period_days = cfg["grace_period_days"]
        platforms = cfg["platforms"]
        dry_run = cfg["dry_run"]

        # --- Init clients ---
        # CustomStorage service class (not the Uber class): the Foundry
        # functions editor auto-detects OAuth scopes from this import.
        # ext_headers applies X-CS-APP-ID to every request.
        storage = CustomStorage(ext_headers=get_headers())
        falcon_hg = HostGroup()
        falcon_sensor = SensorUpdatePolicies()

        # --- Detect source policy targets ---
        policy_targets = get_source_policy_targets(
            falcon_sensor, source_group_id, cfg["target_standing_override"], logger
        )
        if not policy_targets:
            return error_response(
                400,
                "Could not detect target standing from source group's policy. "
                "Verify SOURCE_GROUP_ID is correct and has a sensor update policy "
                "attached, or set TARGET_STANDING env var manually.")

        # Filter to only requested platforms
        policy_targets = {k: v for k, v in policy_targets.items() if k in platforms}

        # --- Look up current builds at the target standings from collection ---
        target_versions = get_target_versions(storage, policy_targets, logger)

        # Build cleanup targets: prefer collection data, fall back to policy's
        # own sensor_version so Phase A can always run even if the collection
        # is empty or stale.
        cleanup_targets = {}
        for platform, target_info in policy_targets.items():
            if platform in target_versions:
                cleanup_targets[platform] = target_versions[platform]
            elif target_info.get("policy_sensor_version"):
                cleanup_targets[platform] = {
                    "sensor_version": target_info["policy_sensor_version"],
                    "target_standing": target_info["target_standing"],
                    "policy_name": target_info["policy_name"],
                    "first_seen_timestamp": 0,
                }
                logger.warning(f"{platform}: Collection has no data for standing "
                               f"'{target_info['target_standing']}'. Using policy "
                               f"sensor_version '{target_info['policy_sensor_version']}' "
                               f"as fallback for cleanup.")

        all_errors: List[Dict[str, Any]] = []

        # ===============================================================
        # PHASE A: CLEANUP - Remove hosts that now meet the source target
        # (Always runs if the force group has members, even without
        #  collection data, using the policy version as fallback.)
        # ===============================================================
        logger.info("=== Phase A: Cleanup ===")
        force_members = get_group_members(falcon_hg, force_group_id, logger, label="force group")
        hosts_to_remove = find_hosts_to_cleanup(force_members, cleanup_targets, logger)

        remove_ids = {d["device_id"] for d in hosts_to_remove}
        removed_count, remove_errors = batch_modify_group(
            falcon_hg, force_group_id, list(remove_ids), "remove-hosts", dry_run, logger
        )
        all_errors.extend(remove_errors)

        cleanup_result = {
            "hosts_evaluated": len(force_members),
            "hosts_removed": removed_count,
            "removed_hosts": [_host_summary(d) for d in hosts_to_remove],
        }

        # ===============================================================
        # PHASE B: ENFORCEMENT - Add stale source group hosts after grace
        # (Requires collection data for grace period timestamps. If the
        #  collection is empty, Phase B is skipped but Phase A still ran.)
        # ===============================================================
        logger.info("=== Phase B: Enforcement ===")

        # Device IDs currently in the force group (excluding those just removed)
        existing_force_ids: Set[str] = {
            m["device_id"] for m in force_members
            if m.get("device_id") and m["device_id"] not in remove_ids
        }

        grace_seconds = grace_period_days * SECONDS_PER_DAY
        platform_details = []
        all_added_hosts = []
        total_added = 0

        for platform in platforms:
            if platform not in target_versions:
                platform_details.append(
                    _platform_detail(platform, policy_targets.get(platform, {})))
                continue

            version_info = target_versions[platform]
            # Grace counts from when the build was promoted to the target
            # standing, so GRACE_PERIOD_DAYS actually applies for n-1/n-2 targets.
            promoted_at = version_info["standing_updated_timestamp"]

            # No reliable promotion date (legacy record predating this field):
            # skip rather than force-update off unknown data. The next standing
            # change re-stamps standing_updated_timestamp and enforcement resumes.
            if not promoted_at:
                logger.warning(f"{platform}: no standing_updated_timestamp on target build "
                               f"{version_info['sensor_version']} - skipping enforcement until "
                               f"update-sensor-tracker re-stamps the promotion date")
                platform_details.append(_platform_detail(platform, version_info))
                continue

            elapsed = now - promoted_at
            days_since = round(elapsed / SECONDS_PER_DAY, 1)
            expired = elapsed >= grace_seconds
            detail = _platform_detail(platform, version_info,
                                      grace_period_expired=expired,
                                      days_since_release=days_since)
            platform_details.append(detail)

            if not expired:
                logger.info(f"{platform}: grace period active ({days_since} days / "
                            f"{grace_period_days} days) - skipping enforcement")
                continue

            logger.info(f"{platform}: grace period expired ({days_since} days >= "
                        f"{grace_period_days} days) - finding stale hosts in source group")

            members = get_group_members(
                falcon_hg, source_group_id, logger,
                label=f"source group ({platform})",
                fql_filter=f"platform_name:'{PLATFORM_FQL_MAP[platform]}'")
            stale = find_stale_hosts(
                members, version_info["sensor_version"], existing_force_ids, logger)
            detail["stale_hosts_found"] = len(stale)
            if not stale:
                continue

            added, add_errors = batch_modify_group(
                falcon_hg, force_group_id, [d["device_id"] for d in stale],
                "add-hosts", dry_run, logger
            )
            detail["hosts_added"] = added
            total_added += added
            all_errors.extend(add_errors)

            for d in stale:
                all_added_hosts.append(_host_summary(d))
                existing_force_ids.add(d["device_id"])

        enforcement_result = {
            "platforms_checked": len(platforms),
            "platforms_expired": sum(1 for d in platform_details if d["grace_period_expired"]),
            "hosts_added": total_added,
            "platform_details": platform_details,
            "added_hosts": all_added_hosts,
        }

        # --- Build response ---
        success = not all_errors
        response_body = {
            "success": success,
            "dry_run": dry_run,
            "timestamp": now,
            "grace_period_days": grace_period_days,
            "policy_targets": {k: v["target_standing"] for k, v in policy_targets.items()},
            "cleanup": cleanup_result,
            "enforcement": enforcement_result,
            "errors": all_errors,
        }

        logger.info(f"Done - cleanup removed {removed_count}, enforcement added {total_added}, "
                    f"errors: {len(all_errors)}, dry_run: {dry_run}")
        return Response(body=response_body, code=200 if success else 207)

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return error_response(500, f"Internal error: {str(e)}")


if __name__ == "__main__":
    FUNC.run()
