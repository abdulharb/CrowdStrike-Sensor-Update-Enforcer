"""
CrowdStrike Foundry Function: update-sensor-tracker

Updates the sensor_release_tracker collection with data from the CrowdStrike
sensor builds API. Uses "living records" keyed by {platform}_{build_number}.
When a build's standing changes (e.g., n → n-1), the record is updated in
place and the old standing is preserved in previous_standings for audit.
"""

import json
import os
import time
from logging import Logger
from typing import Any, Dict, List, Optional, Set, Tuple

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import CustomStorage, SensorUpdatePolicies

FUNC = Function.instance()

COLLECTION_NAME = "sensor_release_tracker"
VALID_PLATFORMS = {"windows", "mac", "linux"}

# Tagged standings (n, n-1, n-2) are processed before untagged builds. The API
# returns the same build twice -- once tagged and once untagged -- so handling
# tagged first means the real standing is set before the duplicate shows up.
STANDING_PRIORITY = {"n": 0, "n-1": 1, "n-2": 2}
UNTAGGED = "untagged"


def is_debug_mode() -> bool:
    debug_value = os.environ.get("DEBUG_MODE", "").lower()
    return debug_value in ("true", "1", "yes")


def log_debug(logger: Logger, message: str) -> None:
    if is_debug_mode():
        logger.info(f"[DEBUG] {message}")


def error_response(code: int, message: str) -> Response:
    """Build the FDK error envelope used for every non-2xx return."""
    return Response(code=code, errors=[APIError(code=code, message=message)])


def parse_build_string(build_string: str) -> Dict[str, str]:
    """
    Parse the raw build string from the API.

    Format examples:
    - "20407|n-1|tagged|1" -> build: 20407, release_standing: n-1
    - "20503|n|tagged|18"  -> build: 20503, release_standing: n
    - "20103"              -> build: 20103, release_standing: untagged
    """
    if "|" in build_string:
        parts = build_string.split("|")
        build_number = parts[0]
        release_standing = parts[1] if len(parts) > 1 else UNTAGGED
    else:
        build_number = build_string
        release_standing = UNTAGGED

    return {
        "build_number": build_number,
        "release_standing": release_standing,
    }


def get_object_key(platform: str, build_number: str) -> str:
    """
    Generate the object key for a collection entry.

    Format: {platform}_{build_number}
    Example: windows_20403

    Each build has exactly one record per platform.
    """
    return f"{platform.lower()}_{build_number}"


def get_current_timestamp() -> int:
    return int(time.time())


def get_headers() -> Dict[str, str]:
    headers = {}
    if os.environ.get("APP_ID"):
        headers = {"X-CS-APP-ID": os.environ.get("APP_ID")}
    return headers


def extract_error_message(response: Dict[str, Any]) -> str:
    """Pull a human-readable message from a falconpy response.

    Errors live under body.errors (a list of {code, message}); there is no
    top-level "error" key, so reading response["error"] always yields nothing.
    """
    if not isinstance(response, dict):
        return "Unknown error"
    errors = (response.get("body") or {}).get("errors", [])
    if isinstance(errors, list) and errors:
        msgs = [e.get("message", "") for e in errors
                if isinstance(e, dict) and e.get("message")]
        if msgs:
            return "; ".join(msgs)
    return "Unknown error"


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


def put_succeeded(resp: Any) -> bool:
    """PutObject returns bytes in the Foundry runtime and an envelope locally."""
    return isinstance(resp, (bytes, bytearray)) or (
        isinstance(resp, dict) and resp.get("status_code") == 200)


def read_existing_record(
    storage: CustomStorage,
    collection_name: str,
    object_key: str,
    logger: Logger,
) -> Optional[Dict[str, Any]]:
    """
    Read the full record from the collection. Returns None if not found.

    A 200 whose body is not the stored record (no "platform" field) is also
    treated as not found, so the caller never merges into a wrapper envelope.
    """
    try:
        log_debug(logger, f"Reading record: {object_key}")
        record = decode_object(storage.GetObject(
            collection_name=collection_name, object_key=object_key))
        return record if record and "platform" in record else None
    except Exception as e:
        log_debug(logger, f"Record not found: {object_key} - {e}")
        return None


def fetch_sensor_builds(
    falcon_sensor: SensorUpdatePolicies,
    platforms: List[str],
    stage: str,
    logger: Logger,
) -> Tuple[List[Dict[str, Any]], Optional[Response]]:
    """
    Fetch sensor builds for every platform, sorted tagged-first.

    Returns (resources, error_response). The first failed platform aborts the
    whole run: a partial tracker update would demote builds on the platforms
    that did load while leaving the failed platform stale.
    """
    resources: List[Dict[str, Any]] = []
    for platform in platforms:
        logger.info(f"Fetching sensor builds for platform={platform}, stage={stage}")
        resp = falcon_sensor.query_combined_builds(platform=platform, stage=stage)
        if resp.get("status_code") != 200:
            message = extract_error_message(resp)
            logger.error(f"Failed to fetch sensor builds for {platform}: {message}")
            code = resp.get("status_code", 500)
            return [], error_response(code, f"Failed to fetch sensor builds for {platform}: {message}")

        platform_resources = resp.get("body", {}).get("resources", [])
        logger.info(f"Retrieved {len(platform_resources)} sensor builds for {platform}")
        resources.extend(platform_resources)

    logger.info(f"Total resources across all platforms: {len(resources)}")
    resources.sort(key=lambda r: STANDING_PRIORITY.get(
        parse_build_string(r.get("build", ""))["release_standing"], 99))
    return resources, None


def _entry_summary(object_key: str, platform: str, standing: str, build_number: str) -> Dict[str, Any]:
    return {
        "object_key": object_key,
        "platform": platform,
        "release_standing": standing,
        "build_number": build_number,
    }


def upsert_build_record(
    storage: CustomStorage,
    resource: Dict[str, Any],
    now: int,
    tagged_this_run: Set[str],
    logger: Logger,
) -> Tuple[str, Dict[str, Any]]:
    """
    Reconcile one API build resource with its collection record.

    Returns (outcome, entry) where outcome is one of
    "new", "updated", "skipped" or "error", and entry is the summary that goes
    into the matching response list.
    """
    platform = resource.get("platform", "")
    sensor_version = resource.get("sensor_version", "")
    raw_build_string = resource.get("build", "")
    build_info = parse_build_string(raw_build_string)
    build_number = build_info["build_number"]
    release_standing = build_info["release_standing"]
    object_key = get_object_key(platform, build_number)
    summary = _entry_summary(object_key, platform, release_standing, build_number)

    log_debug(logger, f"Processing {object_key} standing={release_standing}")

    # The API lists a still-tagged build a second time as untagged. If this
    # run already recorded a tagged standing for it, skip the duplicate.
    if release_standing == UNTAGGED and object_key in tagged_this_run:
        log_debug(logger, f"Skipping untagged duplicate (already tagged this run): {object_key}")
        return "skipped", summary
    if release_standing != UNTAGGED:
        tagged_this_run.add(object_key)

    existing = read_existing_record(storage, COLLECTION_NAME, object_key, logger)

    if existing is None:
        log_debug(logger, f"Creating new entry: {object_key}")
        record = {
            "platform": platform,
            "sensor_version": sensor_version,
            "release_standing": release_standing,
            "build_number": build_number,
            "raw_build_string": raw_build_string,
            "stage": resource.get("stage", ""),
            "first_seen_timestamp": now,
            "standing_updated_timestamp": now,
            "previous_standings": [],
        }
        put_resp = storage.PutObject(body=record, collection_name=COLLECTION_NAME,
                                     object_key=object_key)
        if not put_succeeded(put_resp):
            message = extract_error_message(put_resp)
            logger.error(f"Failed to store {object_key}: {message}")
            return "error", {"object_key": object_key, "error": f"Failed to store: {message}"}
        logger.info(f"Created new entry: {object_key}")
        return "new", dict(summary, sensor_version=sensor_version, first_seen_timestamp=now)

    old_standing = existing.get("release_standing", "")
    if old_standing == release_standing:
        log_debug(logger, f"Skipping (no change): {object_key}")
        return "skipped", summary

    # Standing changed -- update the record in place, keeping the original
    # first_seen_timestamp and sensor_version. An untagged build reaching
    # here with a tagged stored standing has genuinely aged out of the
    # n/n-1/n-2 window (the in-run duplicate was skipped above), so it is
    # demoted to untagged. This keeps exactly one build per standing.
    logger.info(f"Standing changed for {object_key}: {old_standing} -> {release_standing}")
    prev = existing.get("previous_standings", [])
    if not isinstance(prev, list):
        prev = []
    prev.append({
        "standing": old_standing,
        "timestamp": existing.get("standing_updated_timestamp")
        or existing.get("first_seen_timestamp", now),
    })
    existing["release_standing"] = release_standing
    existing["raw_build_string"] = raw_build_string
    existing["previous_standings"] = prev
    existing["standing_updated_timestamp"] = now

    put_resp = storage.PutObject(body=existing, collection_name=COLLECTION_NAME,
                                 object_key=object_key)
    if not put_succeeded(put_resp):
        message = extract_error_message(put_resp)
        logger.error(f"Failed to update {object_key}: {message}")
        return "error", {"object_key": object_key, "error": f"Failed to update: {message}"}
    return "updated", {
        "object_key": object_key,
        "platform": platform,
        "old_standing": old_standing,
        "new_standing": release_standing,
        "build_number": build_number,
    }


@FUNC.handler(method="POST", path="/update-sensor-tracker")
def update_sensor_tracker_handler(
    request: Request,
    config: Optional[Dict[str, object]],
    logger: Logger,
) -> Response:
    """
    Update the sensor_release_tracker collection with current sensor build data.

    Uses living records keyed by {platform}_{build_number}. When a build's
    standing changes, the record is updated in place with the new standing
    and the old standing is appended to previous_standings for audit.
    """
    _ = config

    try:
        logger.info("Starting sensor release tracker update")
        log_debug(logger, f"DEBUG_MODE: {os.environ.get('DEBUG_MODE', 'not set')}")

        body = request.body or {}
        platforms = body.get("platforms", ["windows"])
        stage = body.get("stage", "prod")

        if not isinstance(platforms, list) or not platforms:
            return error_response(
                400, "'platforms' must be a non-empty array of strings (windows, mac, linux)")

        invalid_platforms = [p for p in platforms if p not in VALID_PLATFORMS]
        if invalid_platforms:
            return error_response(
                400, f"Invalid platform(s): {invalid_platforms}. Allowed: windows, mac, linux")

        logger.info(f"Querying platforms: {platforms}, stage: {stage}")

        falcon_sensor = SensorUpdatePolicies()
        # CustomStorage service class (not the Uber class): the Foundry
        # functions editor auto-detects OAuth scopes from this import.
        # ext_headers applies X-CS-APP-ID to every request.
        storage = CustomStorage(ext_headers=get_headers())

        resources, err = fetch_sensor_builds(falcon_sensor, platforms, stage, logger)
        if err:
            return err

        now = get_current_timestamp()
        tagged_this_run: Set[str] = set()
        results: Dict[str, List[Dict[str, Any]]] = {
            "new": [], "updated": [], "skipped": [], "error": []}

        for resource in resources:
            try:
                outcome, entry = upsert_build_record(storage, resource, now, tagged_this_run, logger)
            except Exception as e:
                outcome, entry = "error", {"resource": resource, "error": str(e)}
                logger.error(f"Error processing resource: {e}", exc_info=True)
            results[outcome].append(entry)

        errors = results["error"]
        logger.info(
            f"Complete - new: {len(results['new'])}, updated: {len(results['updated'])}, "
            f"skipped: {len(results['skipped'])}, errors: {len(errors)}"
        )

        response_body = {
            "success": not errors,
            "timestamp": now,
            "summary": {
                "total_api_records": len(resources),
                "new_entries_created": len(results["new"]),
                "entries_updated": len(results["updated"]),
                "existing_entries_skipped": len(results["skipped"]),
                "errors": len(errors),
            },
            "new_entries": results["new"],
            "updated_entries": results["updated"],
            "skipped_entries": results["skipped"],
            "errors": errors,
        }
        return Response(body=response_body, code=200 if not errors else 207)

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return error_response(500, f"Internal error: {e}")


if __name__ == "__main__":
    FUNC.run()
