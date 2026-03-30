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
from typing import Dict, Any, List, Optional

from crowdstrike.foundry.function import Function, Request, Response, APIError
from falconpy import APIHarnessV2, SensorUpdatePolicies

FUNC = Function.instance()

COLLECTION_NAME = "sensor_release_tracker"
VALID_PLATFORMS = {"windows", "mac", "linux"}


def is_debug_mode() -> bool:
    debug_value = os.environ.get("DEBUG_MODE", "").lower()
    return debug_value in ("true", "1", "yes")


def log_debug(logger: Logger, message: str) -> None:
    if is_debug_mode():
        logger.info(f"[DEBUG] {message}")


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
        release_standing = parts[1] if len(parts) > 1 else "untagged"
    else:
        build_number = build_string
        release_standing = "untagged"

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


def read_existing_record(
    api_client: APIHarnessV2,
    collection_name: str,
    object_key: str,
    headers: Dict[str, str],
    logger: Logger,
) -> Optional[Dict[str, Any]]:
    """
    Read the full record from the collection. Returns None if not found.
    """
    try:
        log_debug(logger, f"Reading record: {object_key}")
        response = api_client.command(
            "GetObject",
            collection_name=collection_name,
            object_key=object_key,
            headers=headers,
        )

        if isinstance(response, bytes):
            return json.loads(response.decode("utf-8"))
        if isinstance(response, dict):
            if response.get("status_code") == 200:
                body = response.get("body", response)
                return body if isinstance(body, dict) and "platform" in body else None
            return None
        return None
    except Exception as e:
        log_debug(logger, f"Record not found: {object_key} - {e}")
        return None


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

        body = request.body if request.body else {}
        platforms = body.get("platforms", ["windows"])
        stage = body.get("stage", "prod")

        if not isinstance(platforms, list) or len(platforms) == 0:
            return Response(
                code=400,
                errors=[
                    APIError(
                        code=400,
                        message="'platforms' must be a non-empty array of strings (windows, mac, linux)",
                    )
                ],
            )

        invalid_platforms = [p for p in platforms if p not in VALID_PLATFORMS]
        if invalid_platforms:
            return Response(
                code=400,
                errors=[
                    APIError(
                        code=400,
                        message=f"Invalid platform(s): {invalid_platforms}. Allowed: windows, mac, linux",
                    )
                ],
            )

        logger.info(f"Querying platforms: {platforms}, stage: {stage}")

        falcon_sensor = SensorUpdatePolicies()
        api_client = APIHarnessV2()
        headers = get_headers()

        # Fetch sensor builds from API
        resources = []
        for platform in platforms:
            logger.info(f"Fetching sensor builds for platform={platform}, stage={stage}")
            sensor_response = falcon_sensor.query_combined_builds(
                platform=platform, stage=stage
            )

            if sensor_response["status_code"] != 200:
                error_message = (
                    sensor_response.get("error", {}).get("message", "Unknown error")
                )
                logger.error(f"Failed to fetch sensor builds for {platform}: {error_message}")
                return Response(
                    code=sensor_response["status_code"],
                    errors=[
                        APIError(
                            code=sensor_response["status_code"],
                            message=f"Failed to fetch sensor builds for {platform}: {error_message}",
                        )
                    ],
                )

            platform_resources = sensor_response.get("body", {}).get("resources", [])
            logger.info(f"Retrieved {len(platform_resources)} sensor builds for {platform}")
            resources.extend(platform_resources)

        logger.info(f"Total resources across all platforms: {len(resources)}")

        # Sort resources: tagged standings (n, n-1, n-2) first, untagged last.
        # The API returns the same build twice -- once tagged and once untagged.
        # Processing tagged first ensures we set the real standing before seeing
        # the untagged duplicate.
        STANDING_PRIORITY = {"n": 0, "n-1": 1, "n-2": 2}

        def resource_sort_key(r):
            info = parse_build_string(r.get("build", ""))
            return STANDING_PRIORITY.get(info["release_standing"], 99)

        resources.sort(key=resource_sort_key)
        logger.info("Sorted resources: tagged standings first, untagged last")

        # Track which builds we've already set a tagged standing for in this run,
        # so we don't let the untagged duplicate overwrite it.
        tagged_this_run = set()

        # Track results
        new_entries = []
        updated_entries = []
        skipped_entries = []
        errors = []
        current_timestamp = get_current_timestamp()

        # Process each sensor build
        for idx, resource in enumerate(resources):
            try:
                platform = resource.get("platform", "")
                sensor_version = resource.get("sensor_version", "")
                raw_build_string = resource.get("build", "")
                resource_stage = resource.get("stage", "")

                build_info = parse_build_string(raw_build_string)
                build_number = build_info["build_number"]
                release_standing = build_info["release_standing"]

                object_key = get_object_key(platform, build_number)
                log_debug(logger, f"Processing {idx + 1}/{len(resources)}: {object_key} standing={release_standing}")

                # If this build already got a tagged standing in this run,
                # skip the untagged duplicate from the API.
                if release_standing == "untagged" and object_key in tagged_this_run:
                    log_debug(logger, f"Skipping untagged duplicate (already tagged this run): {object_key}")
                    skipped_entries.append({
                        "object_key": object_key,
                        "platform": platform,
                        "release_standing": release_standing,
                        "build_number": build_number,
                    })
                    continue

                # Track tagged standings set in this run
                if release_standing != "untagged":
                    tagged_this_run.add(object_key)

                # Read existing record
                existing = read_existing_record(
                    api_client, COLLECTION_NAME, object_key, headers, logger
                )

                if existing is not None:
                    old_standing = existing.get("release_standing", "")

                    # Never downgrade a tagged standing to untagged.
                    # The API returns builds in both tagged and untagged form.
                    if release_standing == "untagged" and old_standing in STANDING_PRIORITY:
                        log_debug(logger, f"Skipping downgrade {old_standing} -> untagged: {object_key}")
                        skipped_entries.append({
                            "object_key": object_key,
                            "platform": platform,
                            "release_standing": old_standing,
                            "build_number": build_number,
                        })
                        continue

                    if old_standing == release_standing:
                        # No change
                        skipped_entries.append({
                            "object_key": object_key,
                            "platform": platform,
                            "release_standing": release_standing,
                            "build_number": build_number,
                        })
                        log_debug(logger, f"Skipping (no change): {object_key}")
                        continue

                    # Standing changed -- update the record
                    logger.info(f"Standing changed for {object_key}: {old_standing} -> {release_standing}")

                    prev = existing.get("previous_standings", [])
                    if not isinstance(prev, list):
                        prev = []

                    # Append old standing to history
                    old_timestamp = existing.get("standing_updated_timestamp") or existing.get("first_seen_timestamp", current_timestamp)
                    prev.append({
                        "standing": old_standing,
                        "timestamp": old_timestamp,
                    })

                    # Update record in place
                    existing["release_standing"] = release_standing
                    existing["raw_build_string"] = raw_build_string
                    existing["previous_standings"] = prev
                    existing["standing_updated_timestamp"] = current_timestamp
                    # Keep original first_seen_timestamp and sensor_version

                    put_response = api_client.command(
                        "PutObject",
                        body=existing,
                        collection_name=COLLECTION_NAME,
                        object_key=object_key,
                        headers=headers,
                    )

                    if isinstance(put_response, bytes) or put_response.get("status_code") == 200:
                        updated_entries.append({
                            "object_key": object_key,
                            "platform": platform,
                            "old_standing": old_standing,
                            "new_standing": release_standing,
                            "build_number": build_number,
                        })
                    else:
                        error_msg = put_response.get("error", {}).get("message", "Unknown error")
                        errors.append({"object_key": object_key, "error": f"Failed to update: {error_msg}"})
                        logger.error(f"Failed to update {object_key}: {error_msg}")
                else:
                    # New record
                    log_debug(logger, f"Creating new entry: {object_key}")
                    collection_entry = {
                        "platform": platform,
                        "sensor_version": sensor_version,
                        "release_standing": release_standing,
                        "build_number": build_number,
                        "raw_build_string": raw_build_string,
                        "stage": resource_stage,
                        "first_seen_timestamp": current_timestamp,
                        "standing_updated_timestamp": current_timestamp,
                        "previous_standings": [],
                    }

                    put_response = api_client.command(
                        "PutObject",
                        body=collection_entry,
                        collection_name=COLLECTION_NAME,
                        object_key=object_key,
                        headers=headers,
                    )

                    if isinstance(put_response, bytes) or put_response.get("status_code") == 200:
                        new_entries.append({
                            "object_key": object_key,
                            "platform": platform,
                            "release_standing": release_standing,
                            "build_number": build_number,
                            "sensor_version": sensor_version,
                            "first_seen_timestamp": current_timestamp,
                        })
                        logger.info(f"Created new entry: {object_key}")
                    else:
                        error_msg = put_response.get("error", {}).get("message", "Unknown error")
                        errors.append({"object_key": object_key, "error": f"Failed to store: {error_msg}"})
                        logger.error(f"Failed to store {object_key}: {error_msg}")

            except Exception as e:
                errors.append({"resource": resource, "error": str(e)})
                logger.error(f"Error processing resource: {e}", exc_info=True)

        logger.info(
            f"Complete - new: {len(new_entries)}, updated: {len(updated_entries)}, "
            f"skipped: {len(skipped_entries)}, errors: {len(errors)}"
        )

        response_body = {
            "success": len(errors) == 0,
            "timestamp": current_timestamp,
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
            "errors": errors if errors else None,
        }

        return Response(
            body=response_body,
            code=200 if len(errors) == 0 else 207,
        )

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return Response(
            code=500,
            errors=[APIError(code=500, message=f"Internal error: {e}")],
        )


if __name__ == "__main__":
    FUNC.run()
