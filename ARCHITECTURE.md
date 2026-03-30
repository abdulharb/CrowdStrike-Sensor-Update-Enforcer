# Sensor Update Enforcer - Architecture

## Overview

This Falcon Foundry app ensures hosts stay up-to-date with the sensor version targeted by their source host group's policy, even if they're only online during business hours when updates are blacked out.

The app is built entirely on Foundry primitives: **Foundry Functions** (Python) for the logic, a **Foundry Collection** for persistent state, and **Foundry Workflows** for scheduling. No external infrastructure is required.

## Architecture Diagram

```mermaid
flowchart TD
    subgraph Trigger["Scheduled Foundry Workflow (e.g. every 4-6 hours)"]
        CRON["Schedule Trigger"]
    end

    CRON --> F1
    CRON --> F2

    subgraph F1["Foundry Function: update-sensor-tracker"]
        F1_START["POST /update-sensor-tracker"] --> F1_FETCH["Fetch sensor builds per platform<br/>SensorUpdatePolicies.query_combined_builds()"]
        F1_FETCH --> F1_PARSE["Parse build strings<br/>Extract release_standing: n, n-1, n-2, untagged<br/>Extract build_number"]
        F1_PARSE --> F1_DEDUP["Check collection for existing entries"]
        F1_DEDUP -->|New version at standing| F1_STORE["Store in collection<br/>first_seen_timestamp = now()"]
        F1_DEDUP -->|Already exists| F1_SKIP["Skip"]
    end

    F1_STORE --> COLLECTION
    F1_SKIP -.-> COLLECTION

    subgraph COLLECTION["Foundry Collection: sensor_release_tracker"]
        COL_DATA["Example entry:<br/>platform: 'Windows'<br/>sensor_version: '7.14.20407'<br/>release_standing: 'n-2'<br/>build_number: '20407'<br/>first_seen_timestamp: 1711670400"]
    end

    subgraph F2["Foundry Function: enforce-grace-period"]
        F2_START["POST /enforce-grace-period"] --> F2_CONFIG["Load config from env vars<br/>SOURCE_GROUP_ID<br/>FORCE_UPDATE_GROUP_ID<br/>GRACE_PERIOD_DAYS<br/>PLATFORMS"]

        F2_CONFIG --> F2_POLICY["Query source group's sensor update policy<br/>SensorUpdatePolicies.query_combined_policies_v2()<br/>Find policy attached to SOURCE_GROUP_ID"]

        F2_POLICY --> F2_TARGET["Extract target standing from policy<br/>e.g. 'n-2'"]

        F2_TARGET --> F2_COLLECTION["Query collection for current build<br/>at THAT standing per platform<br/>filter: platform:'Windows'+release_standing:'n-2'<br/>sort: first_seen_timestamp desc"]

        COLLECTION -.->|read| F2_COLLECTION

        F2_COLLECTION --> F2_RESULT["Now we know:<br/>Target version: 7.14.20407 (current n-2)<br/>First seen: 1711670400<br/>Grace period threshold: first_seen + 3 days"]

        F2_RESULT --> PHASE_A
        F2_RESULT --> PHASE_B

        subgraph PHASE_A["Phase A: Cleanup (always runs)"]
            A1["Get all members of FORCE group<br/>with device details"] --> A2["For each member:<br/>Is agent_version >= source policy target?"]
            A2 -->|Yes: at baseline| A3["Remove from FORCE group<br/>Host is back to SOURCE-only"]
            A2 -->|No: still behind| A4["Keep in FORCE group<br/>Still needs to update"]
        end

        subgraph PHASE_B["Phase B: Enforcement (if grace period expired)"]
            B0{"now - first_seen_timestamp<br/>>= GRACE_PERIOD_DAYS * 86400?"}
            B0 -->|"No: grace period active<br/>(normal policy still has time)"| B_SKIP["Skip - let maintenance<br/>window handle it"]
            B0 -->|"Yes: grace period expired<br/>(host missed its window)"| B1["Get members of SOURCE group<br/>filtered by platform"]
            B1 --> B2["For each member:<br/>- Skip if already in FORCE group<br/>- Skip if already at target version"]
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
| `sensor_release_tracker` | Foundry Collection | Stores version records with `first_seen_timestamp` for grace period math |
| Scheduled workflows | Foundry Workflow | Triggers both functions on a recurring schedule |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SOURCE_GROUP_ID` | Yes | | Host group ID with the normal maintenance-window policy |
| `FORCE_UPDATE_GROUP_ID` | Yes | | Host group ID with the force-update (no blackout) policy |
| `GRACE_PERIOD_DAYS` | No | `3` | Days to wait after a new version appears before forcing updates |
| `PLATFORMS` | No | `windows` | Comma-separated platforms to enforce |
| `DEBUG_MODE` | No | `false` | Enable verbose debug logging |

## Prerequisites

1. Create a **source sensor update policy** with a maintenance window (e.g. blackout 9AM-5PM) targeting a specific standing (e.g. N-2)
2. Create a **source host group** and attach it to the source policy. All managed hosts live here.
3. Create a **force update policy** targeting the **same standing** but with **no blackout window**
4. Create a **force update host group** and attach it to the force policy. This starts empty.
5. Set `SOURCE_GROUP_ID` and `FORCE_UPDATE_GROUP_ID` env vars to the respective host group IDs
6. Ensure the force policy has **higher precedence** (lower number) than the source policy
