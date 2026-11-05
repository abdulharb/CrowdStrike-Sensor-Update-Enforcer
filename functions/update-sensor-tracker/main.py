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
from typing import Any, Dict, List, Optional, Tuple

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import CustomStorage, SensorUpdatePolicies

FUNC = Function.instance()

COLLECTION_NAME = "sensor_release_tracker"
VALID_PLATFORMS = {"windows", "mac", "linux"}

# Lower ranks win when the same build appears more than once. The builds API
# lists each tagged build twice -- once tagged and once untagged -- and the
# tagged copy carries the real standing. Anything else ("untagged") ranks last.
STANDING_PRIORITY = {"n": 0, "n-1": 1, "n-2": 2}


# ---------------------------------------------------------------------------
# Helpers (copied in enforce-grace-period: Foundry functions can't share
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


def parse_build_string(build_string: str) -> Dict[str, str]:
    """
    Parse the raw build string from the API.

    Format examples:
    - "20407|n-1|tagged|1" -> build: 20407, release_standing: n-1
    - "20503|n|tagged|18"  -> build: 20503, release_standing: n
    - "20103"              -> build: 20103, release_standing: untagged
    """
    parts = (build_string or "").split("|")
    standing = parts[1] if len(parts) > 1 and parts[1] else "untagged"
    return {"build_number": parts[0], "release_standing": standing}


def get_object_key(platform: str, build_number: str) -> str:
    """
    Generate the object key for a collection entry.

    Format: {platform}_{build_number}
    Example: windows_20403

    Each build has exactly one record per platform.
    """
    return f"{platform.lower()}_{build_number}"


# ---------------------------------------------------------------------------
# Collection access
# ---------------------------------------------------------------------------

def read_existing_record(
    storage: CustomStorage,
    collection_name: str,
    object_key: str,
    logger: Logger,
) -> Optional[Dict[str, Any]]:
    """
    Read the full record from the collection. Returns None only when the key
    does not exist (404).

    Any other failure raises: treating a transient read error as "not found"
    would recreate the record, resetting standing_updated_timestamp (the
    enforcer's grace clock) and wiping previous_standings.
    """
    log_debug(logger, f"Reading record: {object_key}")
    response = storage.GetObject(collection_name=collection_name, object_key=object_key)

    # GetObject returns the stored JSON as raw bytes on success.
    if isinstance(response, (bytes, bytearray)):
        return json.loads(response.decode("utf-8"))

    status = response.get("status_code") if isinstance(response, dict) else None
    if status == 404:
        return None
    body = response_body(response)
    if status == 200 and "platform" in body:
        return body
    raise RuntimeError(f"Failed to read {object_key} ({status}): {extract_error_message(response)}")


def write_record(storage: CustomStorage, object_key: str, record: Dict[str, Any]) -> None:
    """PutObject (create or overwrite). Raises with the API's message on failure."""
    response = storage.PutObject(body=record, collection_name=COLLECTION_NAME, object_key=object_key)
    if isinstance(response, (bytes, bytearray)):
        return
    status = response.get("status_code") if isinstance(response, dict) else None
    if status != 200:
        raise RuntimeError(f"Failed to write {object_key} ({status}): {extract_error_message(response)}")


# ---------------------------------------------------------------------------
# Build processing
# ---------------------------------------------------------------------------

def dedupe_builds(
    resources: List[Dict[str, Any]],
) -> List[Tuple[str, Dict[str, Any], Dict[str, str]]]:
    """
    Collapse the API's resources to one entry per build, keeping the copy with
    the best standing (so a build's tagged copy beats its untagged duplicate).

    Returns [(object_key, resource, build_info)] in API order.
    """
    best: Dict[str, Tuple[int, Dict[str, Any], Dict[str, str]]] = {}
    for resource in resources:
        info = parse_build_string(resource.get("build", ""))
        key = get_object_key(resource.get("platform", ""), info["build_number"])
        rank = STANDING_PRIORITY.get(info["release_standing"], len(STANDING_PRIORITY))
        if key not in best or rank < best[key][0]:
            best[key] = (rank, resource, info)
    return [(key, resource, info) for key, (_, resource, info) in best.items()]


def new_record(resource: Dict[str, Any], info: Dict[str, str], now: int) -> Dict[str, Any]:
    return {
        "platform": resource.get("platform", ""),
        "sensor_version": resource.get("sensor_version", ""),
        "release_standing": info["release_standing"],
        "build_number": info["build_number"],
        "raw_build_string": resource.get("build", ""),
        "stage": resource.get("stage", ""),
        "first_seen_timestamp": now,
        "standing_updated_timestamp": now,
        "previous_standings": [],
    }


def apply_standing_change(
    record: Dict[str, Any], standing: str, raw_build_string: str, now: int
) -> Dict[str, Any]:
    """Move a record to a new standing in place, appending the old standing to
    previous_standings. first_seen_timestamp and sensor_version are kept."""
    history = record.get("previous_standings")
    if not isinstance(history, list):
        history = []
    history.append({
        "standing": record.get("release_standing", ""),
        "timestamp": record.get("standing_updated_timestamp") or record.get("first_seen_timestamp", now),
    })
    record.update(
        release_standing=standing,
        raw_build_string=raw_build_string,
        previous_standings=history,
        standing_updated_timestamp=now,
    )
    return record


def track_builds(platforms: List[str], stage: str, logger: Logger) -> Response:
    # FalconPy clients are built per request: context auth only has a token
    # while a request is being handled. CustomStorage (not the Uber class) lets
    # the Foundry functions editor auto-detect OAuth scopes; ext_headers
    # applies X-CS-APP-ID to every request.
    falcon_sensor = SensorUpdatePolicies()
    storage = CustomStorage(ext_headers=get_headers())

    # Fetch every platform before writing anything, so a failed fetch leaves
    # the collection untouched.
    resources: List[Dict[str, Any]] = []
    for platform in platforms:
        logger.info(f"Fetching sensor builds for platform={platform}, stage={stage}")
        response = falcon_sensor.query_combined_builds(platform=platform, stage=stage)
        status = response.get("status_code")
        if status != 200:
            message = f"Failed to fetch sensor builds for {platform}: {extract_error_message(response)}"
            logger.error(f"{message} (status {status})")
            return error_response(status if isinstance(status, int) and status >= 400 else 500, message)

        platform_resources = response_body(response).get("resources") or []
        logger.info(f"Retrieved {len(platform_resources)} sensor builds for {platform}")
        resources.extend(platform_resources)

    builds = dedupe_builds(resources)
    logger.info(f"Total resources across all platforms: {len(resources)} "
                f"({len(builds)} unique builds)")

    now = int(time.time())
    new_entries: List[Dict[str, Any]] = []
    updated_entries: List[Dict[str, Any]] = []
    skipped_entries: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for idx, (object_key, resource, info) in enumerate(builds, 1):
        standing = info["release_standing"]
        entry = {
            "object_key": object_key,
            "platform": resource.get("platform", ""),
            "build_number": info["build_number"],
        }
        log_debug(logger, f"Processing {idx}/{len(builds)}: {object_key} standing={standing}")

        try:
            existing = read_existing_record(storage, COLLECTION_NAME, object_key, logger)

            if existing is None:
                record = new_record(resource, info, now)
                write_record(storage, object_key, record)
                new_entries.append({**entry, "release_standing": standing,
                                    "sensor_version": record["sensor_version"],
                                    "first_seen_timestamp": now})
                logger.info(f"Created new entry: {object_key}")
                continue

            old_standing = existing.get("release_standing", "")
            if old_standing == standing:
                skipped_entries.append({**entry, "release_standing": standing})
                log_debug(logger, f"Skipping (no change): {object_key}")
                continue

            # A build the API now reports only as untagged, while its stored
            # standing is tagged, has aged out of the n/n-1/n-2 window and is
            # demoted here. That keeps exactly one build per standing instead
            # of letting aged-out builds pile up.
            logger.info(f"Standing changed for {object_key}: {old_standing} -> {standing}")
            write_record(storage, object_key,
                         apply_standing_change(existing, standing, resource.get("build", ""), now))
            updated_entries.append({**entry, "old_standing": old_standing, "new_standing": standing})

        except Exception as e:  # one bad build must not stop the rest
            errors.append({"object_key": object_key, "error": str(e)})
            logger.error(f"Error processing {object_key}: {e}", exc_info=True)

    logger.info(
        f"Complete - new: {len(new_entries)}, updated: {len(updated_entries)}, "
        f"skipped: {len(skipped_entries)}, errors: {len(errors)}"
    )

    success = not errors
    return Response(
        code=200 if success else 207,
        body={
            "success": success,
            "timestamp": now,
            "summary": {
                "total_api_records": len(resources),
                "new_entries_created": len(new_entries),
                "entries_updated": len(updated_entries),
                "existing_entries_skipped": len(skipped_entries),
                "errors": len(errors),
            },
            "new_entries": new_entries,
            "updated_entries": updated_entries,
            "skipped_entries": skipped_entries,
            "errors": errors or None,
        },
    )


def parse_request(body: Any) -> Tuple[List[str], str]:
    """Validate the request body into (platforms, stage). Raises ValueError (-> 400)."""
    if not isinstance(body, dict):
        raise ValueError("Request body must be a JSON object")

    platforms = body.get("platforms", ["windows"])
    if not isinstance(platforms, list) or not platforms or not all(isinstance(p, str) for p in platforms):
        raise ValueError("'platforms' must be a non-empty array of strings (windows, mac, linux)")
    platforms = list(dict.fromkeys(p.strip().lower() for p in platforms))  # normalize + de-dupe
    invalid = [p for p in platforms if p not in VALID_PLATFORMS]
    if invalid:
        raise ValueError(f"Invalid platform(s): {invalid}. Allowed: windows, mac, linux")

    stage = body.get("stage", "prod")
    if not isinstance(stage, str) or not stage.strip():
        raise ValueError("'stage' must be a non-empty string (e.g. \"prod\")")
    return platforms, stage.strip()


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
    logger.info("Starting sensor release tracker update")

    try:
        platforms, stage = parse_request(request.body or {})
    except ValueError as e:
        logger.warning(f"Rejected request: {e}")
        return error_response(400, str(e))
    logger.info(f"Querying platforms: {platforms}, stage: {stage}")

    try:
        return track_builds(platforms, stage, logger)
    except Exception:
        logger.exception("Unexpected error in update-sensor-tracker")
        return error_response(
            500, f"Internal error (trace_id={request.trace_id or 'n/a'}); see function logs"
        )


if __name__ == "__main__":
    FUNC.run()
