# Sensor Update Enforcer

> [!CAUTION]
> This project is a work in prog-mess. I haven't had the chance to fully battle test this code yet and it's likely missing some things, so **please don't use this in production**. If you do, it's at your own risk -- the code may behave in unexpected ways. I'm hoping to have everything fully complete and tested in the next 2-3 weeks. For now I'm putting this out there just to get something on the internet.

A [CrowdStrike Falcon Foundry](https://www.crowdstrike.com/en-us/platform/next-gen-siem/falcon-foundry/) app that ensures hosts stay up-to-date with their sensor update policy, even when they're only online during blackout windows.

Built with Falcon Foundry Functions (Python) and Foundry Collections for state management. Runs as scheduled Foundry workflows -- no external infrastructure required.

## The Problem

You have a sensor update policy with a maintenance window (e.g., no updates between 9AM-5PM). Some users are only online during those business hours -- their laptops are closed outside of work. These hosts never hit the maintenance window and fall behind on sensor versions indefinitely.

## The Solution

This app gives hosts a configurable grace period after a new sensor version appears at the policy's target standing. If a host hasn't updated by the time the grace period expires, it gets added to a "force update" host group whose policy pushes the update on the next cloud connection -- regardless of time of day.

Once the host is updated, the app automatically removes it from the force group.

```
Source Group (maintenance window)     Force Group (no blackout)
+---------------------------------+   +---------------------------+
| Policy: N-2, blackout 9AM-5PM  |   | Policy: N-2, no blackout  |
| All managed hosts live here     |   | Only stragglers land here |
+---------------------------------+   +---------------------------+
         |                                       ^
         | Host misses maintenance               | Phase B adds
         | window for 3+ days                    | stale hosts
         +---------------------------------------+
                                                 |
         +---------------------------------------+
         | Phase A removes host once             |
         | it reaches the target version         v
         +---------------------------------------+
```

## How It Works

Two Foundry Functions run on a scheduled workflow (recommended: every 4-6 hours):

### 1. update-sensor-tracker

Polls the CrowdStrike sensor builds API and records when new versions appear at each release standing (N, N-1, N-2) in a Foundry Collection with timestamps. This collection is the source of truth for when a version first appeared -- which is how the grace period is calculated.

### 2. enforce-grace-period

Reads the source host group's sensor update policy to determine the target standing (e.g., N-2), then runs in two phases:

**Phase A - Cleanup (always runs):** Checks hosts in the force update group. If a host's sensor version now meets the source policy's target, it gets removed from the force group -- back to the normal maintenance-window-only policy.

**Phase B - Enforcement (after grace period):** Looks up when the current build at the target standing first appeared in the collection. If the grace period has expired, finds hosts in the source group that are still behind and adds them to the force update group in batches.

See [ARCHITECTURE.md](ARCHITECTURE.md) for a detailed flow diagram.

---

## Setup Guide

### Prerequisites

You need two CrowdStrike sensor update policies and two host groups. If you already have a maintenance-window policy and host group, you only need to create the force-update side.

### Step 1: Create the Force Update Policy

1. Go to **Host setup and management > Sensor update policies**
2. Create a new policy (e.g., "Force Update - Windows")
3. Set the **target standing** to the **same standing** as your existing source policy (e.g., N-2)
4. **Do not set a maintenance window** -- this policy should update hosts on any cloud connection
5. Set the **precedence higher** (lower number) than your existing source policy -- this ensures when a host is in both groups, the force policy wins

### Step 2: Create the Force Update Host Group

1. Go to **Host setup and management > Host groups**
2. Create a new **static** host group (e.g., "Force Update Hosts")
3. Attach the force update policy from Step 1 to this group
4. Leave the group empty -- the app manages its membership automatically
5. Copy the **Host Group ID** from the group details

### Step 3: Get the Source Host Group ID

1. Find your existing host group that has the maintenance-window sensor update policy attached
2. Copy its **Host Group ID**

### Step 4: Configure Environment Variables

In `manifest.yml`, set the environment variables under the `enforce-grace-period` function:

```yaml
environment_variables:
  SOURCE_GROUP_ID: "your-source-group-id-here"
  FORCE_UPDATE_GROUP_ID: "your-force-group-id-here"
  GRACE_PERIOD_DAYS: "3"
  PLATFORMS: "windows"
  DEBUG_MODE: "false"
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SOURCE_GROUP_ID` | Yes | | Host group ID with the maintenance-window policy |
| `FORCE_UPDATE_GROUP_ID` | Yes | | Host group ID with the force-update policy (no blackout) |
| `GRACE_PERIOD_DAYS` | No | `3` | Days to wait after a new version appears before forcing updates |
| `PLATFORMS` | No | `windows` | Comma-separated platforms to enforce: `windows`, `mac`, `linux` |
| `DEBUG_MODE` | No | `false` | Enable verbose debug logging |

### Step 5: Deploy

```bash
cd "Sensor Update Enforcer"
foundry apps deploy
```

### Step 6: Create Scheduled Workflows

After deploying, create two scheduled Foundry workflows:

**Workflow 1 -- Track Sensor Releases:**
- Trigger: Schedule (every 4-6 hours)
- Action: `update-sensor-tracker`
- Body: `{"platforms": ["windows"]}` (add `"mac"`, `"linux"` as needed)

**Workflow 2 -- Enforce Grace Period:**
- Trigger: Schedule (every 4-6 hours, offset from Workflow 1)
- Action: `enforce-grace-period`
- Body: `{}` (uses env var defaults)

Run Workflow 1 at least once before Workflow 2 so the collection has version data to work with.

### Step 7: Verify with Dry Run

Test what enforcement would do without actually moving hosts:

```json
POST /enforce-grace-period
{
  "dry_run": true
}
```

---

## Usage

### Dry Run

See what would happen without making changes:

```json
POST /enforce-grace-period
{
    "dry_run": true
}
```

### Override Grace Period

Setting `grace_period_days` to `0` triggers immediate enforcement -- useful for testing:

```json
POST /enforce-grace-period
{
    "grace_period_days": 0
}
```

### Override Platforms

```json
POST /enforce-grace-period
{
    "platforms": ["windows", "mac"]
}
```

### Track All Platforms

```json
POST /update-sensor-tracker
{
    "platforms": ["windows", "mac", "linux"]
}
```

---

## Response Examples

### update-sensor-tracker

```json
{
    "success": true,
    "timestamp": 1711756800,
    "summary": {
        "total_api_records": 13,
        "new_entries_created": 1,
        "entries_updated": 2,
        "existing_entries_skipped": 10,
        "errors": 0
    },
    "new_entries": [...],
    "updated_entries": [...],
    "skipped_entries": [...],
    "errors": null
}
```

### enforce-grace-period

```json
{
    "success": true,
    "dry_run": false,
    "timestamp": 1711756800,
    "grace_period_days": 3,
    "policy_targets": {
        "windows": "n-2"
    },
    "cleanup": {
        "hosts_evaluated": 5,
        "hosts_removed": 2,
        "removed_hosts": [
            {"device_id": "abc123", "hostname": "LAPTOP-1", "platform": "Windows", "agent_version": "7.14.20407"}
        ]
    },
    "enforcement": {
        "platforms_checked": 1,
        "platforms_expired": 1,
        "hosts_added": 3,
        "platform_details": [{
            "platform": "windows",
            "target_standing": "n-2",
            "target_version": "7.14.20407",
            "grace_period_expired": true,
            "days_since_release": 4.2,
            "stale_hosts_found": 3,
            "hosts_added": 3
        }],
        "added_hosts": [
            {"device_id": "def456", "hostname": "LAPTOP-2", "platform": "Windows", "agent_version": "7.13.20103"}
        ]
    },
    "errors": null
}
```

---

## API Scopes

The app requires these OAuth scopes (configured in `manifest.yml`):

| Scope | Purpose |
|-------|---------|
| `sensor-update-policies:read` | Detect source policy target standing and fetch sensor builds |
| `devices:read` | Query host details and sensor versions |
| `host-group:read` | Query group membership |
| `host-group:write` | Add/remove hosts from the force update group |

---

## Pre-Production Checklist

- [ ] Source host group has a sensor update policy with a maintenance window
- [ ] Force host group has a sensor update policy with **no** maintenance window
- [ ] Both policies target the **same standing** (e.g., N-2)
- [ ] Force policy has **higher precedence** (lower number) than the source policy
- [ ] `SOURCE_GROUP_ID` is set to the correct host group ID
- [ ] `FORCE_UPDATE_GROUP_ID` is set to the correct host group ID
- [ ] App deployed with `foundry apps deploy`
- [ ] `update-sensor-tracker` has been run at least once (collection has data)
- [ ] Dry run of `enforce-grace-period` returns expected results
- [ ] Both scheduled workflows are created and active

---

## Troubleshooting

**Phase B never runs / "No version found in collection"**
- Run `update-sensor-tracker` first to populate the collection
- Verify the source group's policy has a tagged build string (not untagged)

**Hosts aren't being added to the force group**
- Check that `GRACE_PERIOD_DAYS` has elapsed since the version first appeared
- Use `dry_run: true` to see what the app would do
- Verify `SOURCE_GROUP_ID` points to the correct group
- Check that the source policy is actually attached to the source group

**Hosts aren't being removed after updating**
- Phase A cleanup runs every cycle -- it will catch up on the next scheduled run
- Verify the host's `agent_version` actually meets the target (check the response)
- Hosts on platforms not listed in `PLATFORMS` are skipped

**Response shows 207 (partial success)**
- Some API operations failed. Check the `errors` array in the response
- Common cause: rate limiting on very large batch operations (thousands of hosts)

---

## Project Structure

```
Sensor Update Enforcer/
├── manifest.yml                           # Foundry app manifest
├── README.md
├── ARCHITECTURE.md                        # Detailed flow diagram (Mermaid)
├── collections/
│   └── sensor_release_tracker.json        # Foundry Collection schema
└── functions/
    ├── update-sensor-tracker/             # Foundry Function: version tracking
    │   ├── main.py
    │   ├── requirements.txt
    │   ├── request_schema.json
    │   └── response_schema.json
    └── enforce-grace-period/              # Foundry Function: grace period enforcement
        ├── main.py
        ├── requirements.txt
        ├── request_schema.json
        └── response_schema.json
```
