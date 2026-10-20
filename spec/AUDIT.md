# Audit Specification

**Version:** 0.1.0

## 1. Overview

The audit system maintains an append-only, hash-chained ledger of all kernel operations. This specification defines the ledger structure, entry schema, and verification procedures.

## 2. Ledger Properties

### 2.1 Append-Only

The ledger MUST be append-only:
- Entries MUST NOT be modified after creation
- Entries MUST NOT be deleted
- New entries MUST be appended to the end

### 2.2 Hash-Chained

The ledger MUST be hash-chained:
- Each entry MUST include the hash of the previous entry
- The first entry MUST reference the genesis hash
- The chain MUST be verifiable through replay

### 2.3 Persistence

The reference `AuditLedger` is in memory. Appending an entry links it into the process-local hash chain and then returns. That is the barrier the kernel uses before execution: the intent record is in the chain, or the tool does not run.

The reference ledger does not open a file and does not fsync. Entries live until the process drops them or the caller exports a bundle. `implementations/storage.py` is a separate sample store. The kernel does not write intent records there. A future persistent backend must flush the intent record, with fsync or an equivalent barrier, before execution. This specification does not add that backend.

### 2.4 Deterministic

The ledger MUST be deterministic:
- Same inputs MUST produce same hashes
- Serialization MUST use sorted keys
- Hash algorithm MUST be SHA-256

## 3. Entry Schema

### 3.1 Required Fields

Every audit entry MUST contain:

| Field       | Type        | Description                              |
|-------------|-------------|------------------------------------------|
| prev_hash   | string      | SHA-256 hash of previous entry (64 hex)  |
| entry_hash  | string      | SHA-256 hash of this entry (64 hex)      |
| ts_ms       | integer     | Timestamp in milliseconds since epoch    |
| request_id  | string      | Unique identifier of the request         |
| actor       | string      | Actor who submitted the request          |
| intent      | string      | Intent description from request          |
| decision    | Decision    | Decision made (ALLOW, DENY, HALT)        |
| state_from  | KernelState | State before the operation               |
| state_to    | KernelState | State after the operation                |

### 3.2 Optional Fields

Audit entries MAY contain:

| Field         | Type   | Description                              |
|---------------|--------|------------------------------------------|
| tool_name     | string | Name of tool invoked, if any             |
| params_hash   | string | SHA-256 hash of parameters, if any       |
| evidence_hash | string | SHA-256 hash of evidence, if any         |
| error         | string | Error message, if operation failed       |

### 3.3 Field Constraints

- prev_hash MUST be exactly 64 hexadecimal characters
- entry_hash MUST be exactly 64 hexadecimal characters
- ts_ms MUST be a non-negative integer
- request_id MUST be a non-empty string
- actor MUST be a non-empty string

## 4. Hash Computation

### 4.1 Genesis Hash

The genesis hash is the prev_hash for the first entry:

```
genesis_hash = "0" * 64
```

### 4.2 Entry Data Serialization

Entry data MUST be serialized for hashing as follows:

```json
{
  "decision": "<decision_value>",
  "error": <error_or_null>,
  "evidence_hash": <hash_or_null>,
  "intent": "<intent>",
  "params_hash": <hash_or_null>,
  "request_id": "<request_id>",
  "state_from": "<state_from_value>",
  "state_to": "<state_to_value>",
  "tool_name": <name_or_null>,
  "ts_ms": <timestamp>
}
```

Keys MUST be sorted alphabetically. No whitespace between elements.

### 4.3 Entry Hash Computation

The entry hash MUST be computed as:

```
entry_data = serialize_deterministic(entry_fields)
combined = prev_hash + ":" + entry_data
entry_hash = sha256(combined.encode("utf-8")).hexdigest()
```

### 4.4 Parameter Hash Computation

If params is present:

```
params_hash = sha256(serialize_deterministic(params).encode("utf-8")).hexdigest()
```

### 4.5 Evidence Hash Computation

If evidence is present:

```
evidence_dict = {"evidence": evidence_string}
evidence_hash = sha256(serialize_deterministic(evidence_dict).encode("utf-8")).hexdigest()
```

## 5. Evidence Bundle

### 5.1 Bundle Structure

An evidence bundle MUST contain:

| Field          | Type              | Description                    |
|----------------|-------------------|--------------------------------|
| ledger_entries | List[AuditEntry]  | All entries in order           |
| root_hash      | string            | Hash of last entry             |
| exported_at_ms | integer           | Export timestamp               |
| kernel_id      | string            | Identifier of source kernel    |
| variant        | string            | Variant of source kernel       |

### 5.2 Root Hash

The root_hash MUST equal the entry_hash of the last entry in ledger_entries. For an empty ledger, root_hash MUST equal genesis_hash.

## 6. Verification

### 6.1 Replay Verification Algorithm

```
function replay_and_verify(entries, expected_root_hash):
    prev_hash = genesis_hash
    errors = []
    
    for i, entry in enumerate(entries):
        # Verify chain link
        if entry.prev_hash != prev_hash:
            errors.append(f"Entry {i}: prev_hash mismatch")
        
        # Recompute entry hash
        entry_data = serialize_entry_data(entry)
        computed_hash = sha256(prev_hash + ":" + entry_data)
        
        if computed_hash != entry.entry_hash:
            errors.append(f"Entry {i}: entry_hash mismatch")
        
        prev_hash = entry.entry_hash
    
    # Verify root hash
    if expected_root_hash and prev_hash != expected_root_hash:
        errors.append("Root hash mismatch")
    
    return len(errors) == 0, errors
```

### 6.2 Verification Requirements

A conforming verifier MUST:
- Check every entry in sequence
- Recompute every hash
- Report all errors found
- Not short-circuit on first error

### 6.3 Verification Result

Verification MUST return:
- Boolean indicating validity
- List of all errors found
- Number of entries verified
- Computed root hash

## 7. Ledger Operations

### 7.1 Append

To append an entry:

1. Compute params_hash if params present
2. Compute evidence_hash if evidence present
3. Serialize entry data
4. Compute entry_hash using prev_hash and entry_data
5. Create AuditEntry with all fields
6. Append to entries list
7. Update last_hash to entry_hash

### 7.2 Export

To export evidence bundle:

1. Copy all entries
2. Get root_hash (last entry hash or genesis)
3. Record export timestamp
4. Include kernel_id and variant
5. Return EvidenceBundle

### 7.3 Serialization

To serialize ledger for storage:

1. Convert each entry to dictionary
2. Convert enum values to strings
3. Serialize as JSON with sorted keys
