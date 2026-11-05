# Sensor Update Enforcer - Architecture

## Overview

This Falcon Foundry app ensures hosts stay up-to-date with the sensor version targeted by their source host group's policy, even if they're only online during business hours when updates are blacked out.

The app is built entirely on Foundry primitives: **Foundry Functions** (Python) for the logic, a **Foundry Collection** for persistent state, a bundled **Foundry Workflow** for scheduling, and a **Foundry UI Page** (React + Vite, the app homepage) that visualizes the collection as a release-standings dashboard. No external infrastructure is required.

## Architecture Diagram

```mermaid
flowchart TD
    subgraph Trigger["Bundled Foundry Workflow (every 4 hours, provisions on install)"]
        CRON["Schedule Trigger"] --> SLEEP["update-sensor-tracker,<br/>then sleep 10 minutes,<br/>then enforce-grace-period"]
    end

    CRON --> F1
    SLEEP --> F2

    subgraph F1["Foundry Function: update-sensor-tracker"]
        F1_START["POST /update-sensor-tracker"] --> F1_FETCH["Fetch sensor builds per platform<br/>SensorUpdatePolicies.query_combined_builds()"]
        F1_FETCH --> F1_PARSE["Parse build strings<br/>Extract release_standing: n, n-1, n-2, untagged<br/>Extract build_number"]
        F1_PARSE --> F1_DEDUP["One entry per build (tagged copy wins)<br/>Read its record: {platform}_{build_number}"]
        F1_DEDUP -->|New build| F1_STORE["Create record<br/>first_seen_timestamp = now()<br/>standing_updated_timestamp = now()"]
        F1_DEDUP -->|Standing changed| F1_UPDATE["Update in place<br/>append old standing to previous_standings<br/>standing_updated_timestamp = now()"]
        F1_DEDUP -->|Unchanged| F1_SKIP["Skip"]
    end

    F1_STORE --> COLLECTION
    F1_UPDATE --> COLLECTION
    F1_SKIP -.-> COLLECTION

    subgraph COLLECTION["Foundry Collection: sensor_release_tracker"]
        COL_DATA["Example entry (key windows_20407):<br/>platform: 'Windows'<br/>sensor_version: '7.14.20407'<br/>release_standing: 'n-2'<br/>build_number: '20407'<br/>first_seen_timestamp: 1709251200<br/>standing_updated_timestamp: 1711670400<br/>previous_standings: [n, n-1]"]
    end

    subgraph F2["Foundry Function: enforce-grace-period"]
        F2_START["POST /enforce-grace-period"] --> F2_CONFIG["Load config from env vars<br/>SOURCE_GROUP_ID<br/>FORCE_UPDATE_GROUP_ID<br/>GRACE_PERIOD_DAYS<br/>PLATFORMS<br/>TARGET_STANDING (optional)"]

        F2_CONFIG --> F2_POLICY["Query sensor update policies<br/>SensorUpdatePolicies.query_combined_policies_v2(sort=precedence.asc)<br/>Highest-precedence enabled policy<br/>attached to SOURCE_GROUP_ID, per platform"]

        F2_POLICY --> F2_TARGET["Extract target standing from policy<br/>e.g. 'n-2'"]

        F2_TARGET --> F2_COLLECTION["Query collection for current build<br/>at THAT standing per platform<br/>filter: platform:'Windows'+release_standing:'n-2'<br/>sort: first_seen_timestamp desc"]

        COLLECTION -.->|read| F2_COLLECTION

        F2_COLLECTION --> F2_RESULT["Now we know:<br/>Target version: 7.14.20407 (current n-2)<br/>Promoted to n-2 at: 1711670400<br/>Grace period threshold: standing_updated_timestamp + 3 days"]

        F2_RESULT --> PHASE_A
        F2_RESULT --> PHASE_B

        subgraph PHASE_A["Phase A: Cleanup (always runs)"]
            A1["Get all members of FORCE group<br/>with device details"] --> A2["For each member:<br/>Is agent_version >= source policy target?"]
            A2 -->|Yes: at baseline| A3["Remove from FORCE group<br/>Host is back to SOURCE-only"]
            A2 -->|No: still behind| A4["Keep in FORCE group<br/>Still needs to update"]
        end

        subgraph PHASE_B["Phase B: Enforcement (if grace period expired)"]
            B0{"now - standing_updated_timestamp<br/>>= GRACE_PERIOD_DAYS * 86400?"}
            B0 -->|"No: grace period active<br/>(normal policy still has time)"| B_SKIP["Skip - let maintenance<br/>window handle it"]
            B0 -->|"Yes: grace period expired<br/>(host missed its window)"| B1["Get members of SOURCE group<br/>filtered by platform"]
            B1 --> B2["For each member:<br/>- Skip if already in FORCE group<br/>- Skip if no usable agent_version<br/>- Skip if already at target version"]
            B2 --> B3["Add stale hosts to FORCE group<br/>in batches of 500"]
        end
    end

    subgraph CS_GROUPS["CrowdStrike Host Groups"]
        SOURCE_GROUP["SOURCE Host Group<br/>(e.g. 'Windows Prod Sensors')<br/>Has blackout: 9AM-5PM<br/>All managed hosts live here"]
        FORCE_GROUP["FORCE Host Group<br/>(e.g. 'Force Update - Windows')<br/>No blackout window<br/>Updates on next connection<br/>Only contains stragglers"]
    end

    subgraph CS_POLICIES["Sensor Update Policies"]
        NORMAL_POLICY["Source Policy<br/>Target: N-2<br/>Blackout: 9AM-5PM<br/>Lower precedence"]
        FORCE_POLICY["Force Policy<br/>Target: N-2 (same version)<br/>No blackout<br/>Higher precedence"]
    end

    SOURCE_GROUP ---|attached to| NORMAL_POLICY
    FORCE_GROUP ---|attached to| FORCE_POLICY
    F2_POLICY -.->|"reads target standing"| NORMAL_POLICY

    A3 -->|"remove from"| FORCE_GROUP
    B3 -->|"add to"| FORCE_GROUP
    B1 -.->|"query members"| SOURCE_GROUP

    subgraph LIFECYCLE["Host Lifecycle"]
        direction LR
        L1["Host in SOURCE group<br/>On version N-3<br/>(behind policy target N-2)"]
        L2["Normal policy tries<br/>to update during<br/>maintenance window"]
        L3{"Updated within<br/>grace period?"}
        L4["Host stays in<br/>SOURCE group only"]
        L5["Grace period expires<br/>Phase B adds to FORCE group<br/>Host now in BOTH groups"]
        L6["Force policy pushes<br/>update on next<br/>cloud connection"]
        L7["Host reaches N-2 baseline<br/>Phase A removes from FORCE<br/>Back to SOURCE only"]

        L1 --> L2 --> L3
        L3 -->|Yes| L4
        L3 -->|No| L5 --> L6 --> L7
        L7 -.->|"cycle repeats<br/>on next release"| L1
    end

    style COLLECTION fill:#2d5a3d,stroke:#4a9,color:#fff
    style PHASE_A fill:#1a3a5c,stroke:#4a9,color:#fff
    style PHASE_B fill:#4a2a1a,stroke:#e94,color:#fff
    style FORCE_GROUP fill:#5a2a1a,stroke:#e94,color:#fff
    style SOURCE_GROUP fill:#1a3a5c,stroke:#4a9,color:#fff
    style FORCE_POLICY fill:#5a2a1a,stroke:#e94,color:#fff
    style NORMAL_POLICY fill:#1a3a5c,stroke:#4a9,color:#fff
    style F2_TARGET fill:#4a3a1a,stroke:#ea4,color:#fff
    style LIFECYCLE fill:#1a2a3a,stroke:#68a,color:#fff
```

## Foundry Components

| Component | Type | Purpose |
|-----------|------|---------|
| `update-sensor-tracker` | Foundry Function (Python) | Polls sensor builds API, tracks version standings in collection |
| `enforce-grace-period` | Foundry Function (Python) | Manages force-group membership based on grace period |
| `sensor_release_tracker` | Foundry Collection | One record per build: current standing, `standing_updated_timestamp` (grace period anchor), and standing history |
| Sensor Update Enforcer - Scheduled | Foundry Workflow (bundled, provisions on install) | Every 4 hours: tracker, 10-minute sleep, then enforcement |
| Sensor Release Tracker | Foundry UI Page (React + Vite) | App homepage; dashboard of release standings and update history from the collection |

## Configuration and Setup

Environment variables, the policy and host group prerequisites, and the
pre-production checklist live in the [README](README.md#setup-guide).

## Failure Handling

- **Can't read the source policies or the force group:** the run stops before
  changing anything and returns the Falcon API's own status and message.
- **A collection lookup, source-group query, or add/remove batch fails:** that
  step is recorded in `errors`, the rest of the run continues, and the response
  is a 207. Only hosts whose add/remove call succeeded are reported as moved.
- **update-sensor-tracker can't read a record:** that build is skipped and
  reported, never recreated -- recreating it would reset its
  `standing_updated_timestamp` and restart the grace period.
