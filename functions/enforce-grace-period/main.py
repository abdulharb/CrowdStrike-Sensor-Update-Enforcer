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
from typing import Dict, Any, List, Optional, Set, Tuple

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import APIHarnessV2, HostGroup, SensorUpdatePolicies

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


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(body: Dict[str, Any], logger: Logger) -> Tuple[Optional[Dict[str, Any]], Optional[Response]]:
    """
    Load configuration from env vars with optional request body overrides.

    Returns (config_dict, error_response).
    """
    source_group_id = os.environ.get("SOURCE_GROUP_ID", "").strip()
    if not source_group_id:
        return None, Response(
            code=400,
            errors=[APIError(
                code=400,
                message="SOURCE_GROUP_ID environment variable is not set. "
                        "Set it to the host group ID for the normal maintenance-window policy."
            )]
        )

    force_group_id = os.environ.get("FORCE_UPDATE_GROUP_ID", "").strip()
    if not force_group_id:
        return None, Response(
            code=400,
            errors=[APIError(
                code=400,
                message="FORCE_UPDATE_GROUP_ID environment variable is not set. "
                        "Set it to the host group ID for force updates."
            )]
        )

    # Grace period: env var default, request body override
    try:
        grace_period_days = int(os.environ.get("GRACE_PERIOD_DAYS", "3"))
    except ValueError:
        grace_period_days = 3

    if "grace_period_days" in body:
        try:
            grace_period_days = int(body["grace_period_days"])
        except (ValueError, TypeError):
            return None, Response(
                code=400,
                errors=[APIError(
                    code=400,
                    message="grace_period_days must be a number (0-90)"
                )]
            )

    # Platforms: env var default, request body override
    platforms = [p.strip() for p in os.environ.get("PLATFORMS", "windows").split(",") if p.strip()]
    if "platforms" in body:
        if not isinstance(body["platforms"], list):
            return None, Response(
                code=400,
                errors=[APIError(
                    code=400,
                    message="platforms must be an array of strings (e.g. [\"windows\", \"mac\", \"linux\"])"
                )]
            )
        platforms = body["platforms"]

    invalid = [p for p in platforms if p not in VALID_PLATFORMS]
    if invalid:
        return None, Response(
            code=400,
            errors=[APIError(
                code=400,
                message=f"Invalid platform(s): {invalid}. Allowed: {sorted(VALID_PLATFORMS)}"
            )]
        )

    # Optional manual override for target standing (auto-detected from policy if empty)
    target_standing_override = os.environ.get("TARGET_STANDING", "").strip() or None

    dry_run = body.get("dry_run", False)

    config = {
        "source_group_id": source_group_id,
        "force_group_id": force_group_id,
        "grace_period_days": grace_period_days,
        "platforms": platforms,
        "target_standing_override": target_standing_override,
        "dry_run": dry_run,
    }
    logger.info(f"Config: grace_period_days={grace_period_days}, platforms={platforms}, "
                f"dry_run={dry_run}, source_group={source_group_id[:8]}..., "
                f"force_group={force_group_id[:8]}..., "
                f"target_standing_override={target_standing_override}")
    return config, None


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


# ---------------------------------------------------------------------------
# Source policy detection
# ---------------------------------------------------------------------------

def _fetch_all_policies(
    falcon_sensor: SensorUpdatePolicies,
    logger: Logger
) -> List[Dict[str, Any]]:
    """Paginate through all sensor update policies."""
    all_policies = []
    offset = 0
    limit = 200
    while True:
        log_debug(logger, f"Querying sensor update policies offset={offset}")
        resp = falcon_sensor.query_combined_policies_v2(limit=limit, offset=offset)
        if resp.get("status_code") != 200:
            logger.error(f"Failed to query sensor update policies: {resp.get('status_code')} "
                         f"{resp.get('body', {}).get('errors', [])}")
            break

        resources = resp.get("body", {}).get("resources", [])
        if not resources:
            break
        all_policies.extend(resources)

        total = resp.get("body", {}).get("meta", {}).get("pagination", {}).get("total", 0)
        offset += limit
        if offset >= total:
            break

    logger.info(f"Fetched {len(all_policies)} sensor update policies")
    return all_policies


def get_source_policy_targets(
    falcon_sensor: SensorUpdatePolicies,
    source_group_id: str,
    target_standing_override: Optional[str],
    logger: Logger
) -> Dict[str, Dict[str, Any]]:
    """
    Query sensor update policies to find those attached to the source host group.
    Extracts the target standing per platform from each matching policy.

    If multiple policies match the same platform, the one with the highest
    precedence (lowest precedence number) wins -- matching CrowdStrike's
    actual policy evaluation order.

    Returns: {platform_key: {"target_standing": str, "policy_name": str, ...}}
    """
    targets = {}

    logger.info("Querying sensor update policies to detect source group targets")
    all_policies = _fetch_all_policies(falcon_sensor, logger)

    for policy in all_policies:
        # Check if this policy is attached to our source group
        groups = policy.get("groups", [])
        group_ids = [g.get("id") for g in groups]
        if source_group_id not in group_ids:
            continue

        # This policy is attached to the source group
        platform_name = policy.get("platform_name", "")
        platform_key = FQL_TO_COLLECTION_MAP.get(platform_name, platform_name.lower())
        policy_name = policy.get("name", "")
        precedence = policy.get("precedence", 9999)

        # If we already have a match for this platform, keep the higher-precedence
        # one (lower number = higher priority, matching CrowdStrike evaluation order)
        if platform_key in targets:
            existing_precedence = targets[platform_key].get("precedence", 9999)
            if precedence >= existing_precedence:
                log_debug(logger, f"{platform_key}: Skipping policy '{policy_name}' "
                          f"(precedence {precedence}) - already have higher-precedence "
                          f"policy '{targets[platform_key]['policy_name']}' "
                          f"(precedence {existing_precedence})")
                continue
            else:
                logger.info(f"{platform_key}: Replacing policy "
                            f"'{targets[platform_key]['policy_name']}' "
                            f"(precedence {existing_precedence}) with "
                            f"'{policy_name}' (precedence {precedence})")

        settings = policy.get("settings", {})
        build_str = settings.get("build", "")
        sensor_version = settings.get("sensor_version", "")

        # Determine target standing
        if target_standing_override:
            standing = target_standing_override
            logger.info(f"{platform_key}: Using TARGET_STANDING override: '{standing}'")
        else:
            build_info = parse_build_string(build_str)
            standing = build_info.get("release_standing", "")
            log_debug(logger, f"{platform_key}: Parsed build string '{build_str}' -> "
                      f"standing='{standing}'")

        if not standing or standing == "untagged":
            logger.warning(f"{platform_key}: Could not determine target standing from "
                           f"policy '{policy_name}' (build='{build_str}'). "
                           f"Set TARGET_STANDING env var to override.")
            continue

        targets[platform_key] = {
            "policy_id": policy.get("id", ""),
            "policy_name": policy_name,
            "target_standing": standing,
            "policy_sensor_version": sensor_version,
            "policy_build_string": build_str,
            "precedence": precedence,
        }
        logger.info(f"{platform_key}: Policy '{policy_name}' (precedence {precedence}) "
                    f"targets standing '{standing}' "
                    f"(build={build_str}, version={sensor_version})")

    if not targets:
        logger.error(f"No sensor update policies found attached to source group "
                     f"{source_group_id}")

    return targets


# ---------------------------------------------------------------------------
# Collection queries
# ---------------------------------------------------------------------------

def get_target_versions(
    api_client: APIHarnessV2,
    policy_targets: Dict[str, Dict[str, Any]],
    headers: Dict[str, str],
    logger: Logger
) -> Dict[str, Dict[str, Any]]:
    """
    For each platform, look up the current build at the policy's target standing
    in the collection.

    Returns: {platform: {"sensor_version": str, "first_seen_timestamp": int,
                          "target_standing": str, "policy_name": str}}
    """
    target_versions = {}

    for platform, target_info in policy_targets.items():
        standing = target_info["target_standing"]
        log_debug(logger, f"Querying collection for current '{standing}' build on {platform}")

        # The sensor builds API stores capitalized platform names (e.g. "Windows").
        # Use PLATFORM_FQL_MAP to match the stored value.
        platform_fql = PLATFORM_FQL_MAP.get(platform, platform)

        resp = api_client.command(
            "SearchObjects",
            filter=f"platform:'{platform_fql}'+release_standing:'{standing}'",
            sort="first_seen_timestamp|desc",
            collection_name=COLLECTION_NAME,
            limit=1,
            headers=headers
        )

        if resp.get("status_code") == 200:
            resources = resp.get("body", {}).get("resources", [])
            if resources:
                entry = resources[0]

                # SearchObjects may return only metadata (object_key) when
                # called outside the Foundry runtime. If the full record body
                # is missing, fetch it with GetObject.
                if "sensor_version" not in entry and "object_key" in entry:
                    log_debug(logger, f"SearchObjects returned key only — "
                              f"fetching full record: {entry['object_key']}")
                    get_resp = api_client.command(
                        "GetObject",
                        collection_name=COLLECTION_NAME,
                        object_key=entry["object_key"],
                        headers=headers,
                    )
                    if isinstance(get_resp, bytes):
                        entry = json.loads(get_resp.decode("utf-8"))
                    elif isinstance(get_resp, dict) and get_resp.get("status_code") == 200:
                        body = get_resp.get("body", {})
                        if isinstance(body, dict) and "sensor_version" in body:
                            entry = body

                target_versions[platform] = {
                    "sensor_version": entry.get("sensor_version", ""),
                    "first_seen_timestamp": entry.get("first_seen_timestamp", 0),
                    "target_standing": standing,
                    "policy_name": target_info.get("policy_name", ""),
                }
                logger.info(f"{platform}: Current '{standing}' is version "
                            f"{target_versions[platform]['sensor_version']} "
                            f"(first seen: {target_versions[platform]['first_seen_timestamp']})")
            else:
                logger.warning(f"{platform}: No '{standing}' version found in collection. "
                               f"Has update-sensor-tracker run?")
        else:
            logger.error(f"Failed to query collection for {platform}/{standing}: "
                         f"{resp.get('status_code')}")

    return target_versions


# ---------------------------------------------------------------------------
# Phase A: Cleanup
# ---------------------------------------------------------------------------

def get_group_members(
    falcon_hg: HostGroup,
    group_id: str,
    logger: Logger,
    label: str = "group"
) -> List[Dict[str, Any]]:
    """Paginate through all members of a host group with full device details."""
    all_members = []
    offset = 0
    while True:
        log_debug(logger, f"Querying {label} members offset={offset}")
        resp = falcon_hg.query_combined_group_members(
            id=group_id, limit=PAGE_LIMIT, offset=offset
        )
        if resp.get("status_code") != 200:
            logger.error(f"Failed to query {label} members: {resp.get('status_code')} "
                         f"{resp.get('body', {}).get('errors', [])}")
            break

        resources = resp.get("body", {}).get("resources", [])
        if not resources:
            break
        all_members.extend(resources)

        total = resp.get("body", {}).get("meta", {}).get("pagination", {}).get("total", 0)
        offset += PAGE_LIMIT
        if offset >= total:
            break

    logger.info(f"{label} has {len(all_members)} members")
    return all_members


def find_hosts_to_cleanup(
    members: List[Dict[str, Any]],
    target_versions: Dict[str, Dict[str, Any]],
    logger: Logger
) -> List[Dict[str, Any]]:
    """Identify force-group members whose sensor version now meets the source policy target."""
    to_remove = []
    for device in members:
        platform_name = device.get("platform_name", "")
        platform_key = FQL_TO_COLLECTION_MAP.get(platform_name)
        if not platform_key or platform_key not in target_versions:
            log_debug(logger, f"Skipping {device.get('hostname', '?')} - "
                      f"platform '{platform_name}' not tracked")
            continue

        target = target_versions[platform_key]["sensor_version"]
        agent_ver = device.get("agent_version", "")

        if is_current(agent_ver, target):
            to_remove.append(device)
            log_debug(logger, f"Cleanup candidate: {device.get('hostname', '?')} "
                      f"({agent_ver} >= {target})")

    logger.info(f"Found {len(to_remove)} hosts to remove from force group (now at baseline)")
    return to_remove


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
        filter_str = f"(device_id:[{id_filter}])"

        log_debug(logger, f"{action} batch {i // BATCH_SIZE + 1}: {len(batch)} hosts")
        resp = falcon_hg.perform_group_action(
            action_name=action,
            body={
                "ids": [group_id],
                "action_parameters": [
                    {"name": "filter", "value": filter_str}
                ]
            }
        )

        if resp.get("status_code") == 200:
            modified += len(batch)
        else:
            err_detail = resp.get("body", {}).get("errors", resp.get("body", {}))
            errors.append({
                "operation": action,
                "error": f"Batch at offset {i} failed: {err_detail}"
            })
            logger.error(f"{action} batch failed: {err_detail}")

    logger.info(f"{action}: {modified}/{len(device_ids)} succeeded")
    return modified, errors


# ---------------------------------------------------------------------------
# Phase B: Enforcement
# ---------------------------------------------------------------------------

def find_stale_hosts_in_source(
    falcon_hg: HostGroup,
    source_group_id: str,
    platform_key: str,
    target_version: str,
    existing_force_member_ids: Set[str],
    logger: Logger
) -> List[Dict[str, Any]]:
    """
    Find hosts in the source group whose sensor version is behind the target
    and are not already in the force group.

    Queries source group members directly (scoped, efficient) rather than
    scanning all devices in the environment.
    """
    fql_platform = PLATFORM_FQL_MAP[platform_key]
    stale_hosts = []
    offset = 0

    while True:
        log_debug(logger, f"Querying source group members for {platform_key}, offset={offset}")
        resp = falcon_hg.query_combined_group_members(
            id=source_group_id,
            filter=f"platform_name:'{fql_platform}'",
            limit=PAGE_LIMIT,
            offset=offset
        )

        if resp.get("status_code") != 200:
            logger.error(f"Failed to query source group members: {resp.get('status_code')} "
                         f"{resp.get('body', {}).get('errors', [])}")
            break

        resources = resp.get("body", {}).get("resources", [])
        if not resources:
            break

        for device in resources:
            device_id = device.get("device_id", "")

            # Skip if already in the force group
            if device_id in existing_force_member_ids:
                continue

            # Check if the host is behind the target version
            agent_ver = device.get("agent_version", "")
            if not is_current(agent_ver, target_version):
                stale_hosts.append(device)

        total = resp.get("body", {}).get("meta", {}).get("pagination", {}).get("total", 0)
        offset += PAGE_LIMIT
        if offset >= total:
            break

    logger.info(f"Found {len(stale_hosts)} stale hosts in source group on {platform_key}")
    return stale_hosts


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
        body = request.body if request.body else {}
        cfg, err = load_config(body, logger)
        if err:
            return err

        source_group_id = cfg["source_group_id"]
        force_group_id = cfg["force_group_id"]
        grace_period_days = cfg["grace_period_days"]
        platforms = cfg["platforms"]
        target_standing_override = cfg["target_standing_override"]
        dry_run = cfg["dry_run"]

        # --- Init clients ---
        api_client = APIHarnessV2()
        falcon_hg = HostGroup()
        falcon_sensor = SensorUpdatePolicies()
        headers = get_headers()

        # --- Detect source policy targets ---
        policy_targets = get_source_policy_targets(
            falcon_sensor, source_group_id, target_standing_override, logger
        )
        if not policy_targets:
            return Response(
                code=400,
                errors=[APIError(
                    code=400,
                    message="Could not detect target standing from source group's policy. "
                            "Verify SOURCE_GROUP_ID is correct and has a sensor update policy "
                            "attached, or set TARGET_STANDING env var manually."
                )]
            )

        # Filter to only requested platforms
        policy_targets = {k: v for k, v in policy_targets.items() if k in platforms}

        # --- Look up current builds at the target standings from collection ---
        target_versions = get_target_versions(api_client, policy_targets, headers, logger)

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

        all_errors = []

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

        # Build set of device IDs currently in force group (excluding those just removed)
        existing_force_ids: Set[str] = set()
        for m in force_members:
            mid = m.get("device_id", "")
            if mid and mid not in remove_ids:
                existing_force_ids.add(mid)

        grace_seconds = grace_period_days * 86400
        platform_details = []
        all_added_hosts = []
        total_added = 0

        for platform in platforms:
            if platform not in target_versions:
                platform_details.append({
                    "platform": platform,
                    "target_standing": policy_targets.get(platform, {}).get("target_standing", ""),
                    "target_version": "",
                    "policy_name": policy_targets.get(platform, {}).get("policy_name", ""),
                    "first_seen_timestamp": 0,
                    "grace_period_expired": False,
                    "days_since_release": 0,
                    "stale_hosts_found": 0,
                    "hosts_added": 0,
                })
                continue

            version_info = target_versions[platform]
            first_seen = version_info["first_seen_timestamp"]
            elapsed = now - first_seen
            days_since = round(elapsed / 86400, 1)
            expired = elapsed >= grace_seconds

            detail = {
                "platform": platform,
                "target_standing": version_info["target_standing"],
                "target_version": version_info["sensor_version"],
                "policy_name": version_info.get("policy_name", ""),
                "first_seen_timestamp": first_seen,
                "grace_period_expired": expired,
                "days_since_release": days_since,
                "stale_hosts_found": 0,
                "hosts_added": 0,
            }

            if not expired:
                logger.info(f"{platform}: grace period active ({days_since} days / "
                            f"{grace_period_days} days) - skipping enforcement")
                platform_details.append(detail)
                continue

            logger.info(f"{platform}: grace period expired ({days_since} days >= "
                        f"{grace_period_days} days) - finding stale hosts in source group")

            stale = find_stale_hosts_in_source(
                falcon_hg, source_group_id, platform,
                version_info["sensor_version"], existing_force_ids, logger
            )
            detail["stale_hosts_found"] = len(stale)

            if stale:
                stale_ids = [d["device_id"] for d in stale]
                added, add_errors = batch_modify_group(
                    falcon_hg, force_group_id, stale_ids, "add-hosts", dry_run, logger
                )
                detail["hosts_added"] = added
                total_added += added
                all_errors.extend(add_errors)

                for d in stale:
                    all_added_hosts.append(_host_summary(d))
                    existing_force_ids.add(d["device_id"])

            platform_details.append(detail)

        enforcement_result = {
            "platforms_checked": len(platforms),
            "platforms_expired": sum(1 for d in platform_details if d["grace_period_expired"]),
            "hosts_added": total_added,
            "platform_details": platform_details,
            "added_hosts": all_added_hosts,
        }

        # --- Build response ---
        success = len(all_errors) == 0
        response_body = {
            "success": success,
            "dry_run": dry_run,
            "timestamp": now,
            "grace_period_days": grace_period_days,
            "policy_targets": {k: v["target_standing"] for k, v in policy_targets.items()},
            "cleanup": cleanup_result,
            "enforcement": enforcement_result,
            "errors": all_errors if all_errors else None,
        }
        response_code = 200 if success else 207

        logger.info(f"Done - cleanup removed {removed_count}, enforcement added {total_added}, "
                    f"errors: {len(all_errors)}, dry_run: {dry_run}")
        return Response(body=response_body, code=response_code)

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return Response(
            code=500,
            errors=[APIError(code=500, message=f"Internal error: {str(e)}")]
        )


if __name__ == "__main__":
    FUNC.run()
