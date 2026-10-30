# Agent Kernel Strata, Current Gaps, and Re-Architecture Plan

## Purpose

This document disambiguates the overloaded term "agent kernel" into explicit
strata and maps those strata to the current repository implementation.
It also records the architectural gaps that must be closed for Shards-Kernel to
function as a full microkernel-style substrate rather than a governance-focused
framework with a thin runtime.

## Four Kernel Strata (Canonical Taxonomy)

| Stratum | Responsibility | Typical primitives |
|---|---|---|
| **Memory Kernel** | Persistence lifecycle and retrieval semantics | working/episodic/semantic/procedural memory, TTL, confidence, provenance |
| **Runtime Kernel** | Execution mediation between agent intent and tools | syscall interface, dispatcher, budget enforcement, retries, tracing |
| **Governance Kernel** | Policy and permit enforcement | authorization, deny/allow decisions, jurisdiction rules, safety guardrails |
| **Multi-Agent Kernel** | Agent-to-agent contracts and orchestration | capability schemas, registries, message protocols, coordination semantics |

## Current Repository Mapping

| Repository area | Primary stratum | Status |
|---|---|---|
| `shards_kernel/jurisdiction/*`, `shards_kernel/permits.py`, kernel variants | Governance | **Strong** |
| `shards_kernel/audit/*`, replay tests | Governance / verification | **Strong** |
| `shards_kernel/execution/*`, adapters under `shards_kernel/integrations/*` | Runtime | **Partial** |
| `shards_kernel/state/*` | Control-flow state only | **Partial** |
| Dedicated memory modules | Memory | **Missing** |
| Dedicated multi-agent contracts/protocols | Multi-agent | **Missing** |

## Structural Fractures (Second-Order)

### 1) Runtime choke point is not explicit enough

A strict kernel requires one authoritative execution path:

`agent -> kernel syscall -> policy/budget/event/audit -> tool dispatch`

Any direct `agent -> tool` path (including adapter shortcuts) weakens
invariants and observability.

### 2) Event model is implied but not first-class

Replay quality depends on a versioned event schema and append-only event stream.
Without this, replay can drift into best-effort behavior.

### 3) Memory kernel is absent

State machine + audit history are not substitutes for memory primitives.
The system currently lacks explicit memory classes with lifecycle controls
(TTL, confidence, provenance, mutation policy).

### 4) Variant behavior risks fragmentation

Variants should primarily be policy profiles, not alternate core logic paths.
If core invariants vary by variant implementation, formal reasoning cost grows
non-linearly.

### 5) Resource model is under-specified

Permits without token/time/cost accounting cannot enforce operational budgets
or bound runaway execution behavior.

## Mandatory Boundary Rules

1. **All tool execution must cross a syscall boundary**.
2. **Governance must execute on the hot path** (not post-hoc).
3. **All executions must emit typed, versioned events**.
4. **Replay inputs must be sufficient for deterministic verification**.
5. **Memory types must be explicit and lifecycle-managed**.
6. **Variants may tune policy thresholds, not bypass invariants**.

## Minimum Event Spine (v1)

- `task.started`
- `task.completed`
- `tool.called`
- `tool.completed`
- `policy.denied`
- `error.raised`

Each event should include: `event_id`, `event_type`, `schema_version`,
`trace_id`, `timestamp`, `actor`, and deterministic payload fields.

## Re-Architecture Plan (Not Patch-Level)

### Phase 1: Establish kernel core choke point

Create a core execution entrypoint that every adapter and workflow must use.

Suggested layout:

- `shards_kernel/core/runtime.py`
- `shards_kernel/core/syscall.py`

Core path responsibilities:

1. Validate call contract
2. Enforce permit + policy + budget
3. Emit pre/post execution events
4. Dispatch tool call
5. Record audit ledger entry

### Phase 2: Introduce event subsystem

Suggested layout:

- `shards_kernel/events/schema.py`
- `shards_kernel/events/bus.py`
- `shards_kernel/events/store.py`

Requirements:

- versioned event schemas
- append-only event storage semantics
- subscription hooks for observability and streaming integrations

### Phase 3: Add memory kernel

Suggested layout:

- `shards_kernel/memory/working.py`
- `shards_kernel/memory/episodic.py`
- `shards_kernel/memory/semantic.py`
- `shards_kernel/memory/procedural.py`

Minimum metadata per memory record:

- `ttl`
- `confidence`
- `provenance`
- `version`

### Phase 4: Convert variants into policy profiles

Preserve a single invariant core and load variant behavior via configuration
presets instead of logic forks.

### Phase 5: Add multi-agent contracts

Introduce:

- capability schema
- agent registry
- interaction protocol contract

## Design Heuristic

If a component does not enforce invariants or mediate interaction boundaries,
it is framework/application logic and should not live in the authoritative
kernel surface.
