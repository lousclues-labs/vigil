# Acknowledgments

Acknowledgments let operators add context to historical doctor events.
They do not hide events and do not suppress future events.

## Model

Doctor rows that report historical events (for example, hook invocation
failures) remain visible until they age out. An acknowledgment records:

- which event was acknowledged
- who acknowledged it (UID/PID/exe/argv)
- when acknowledgment happened
- optional operator note
- whether it is an `acknowledge` or `revoke` action

All acknowledgment actions are stored in the audit chain as
`vigil:operator_acknowledgment` records.

## Commands

```bash
vigil ack <kind> [--sequence <N>] [--note "<text>"]
vigil ack list
vigil ack revoke <kind> [--sequence <N>]
vigil ack show <sequence>
```

Supported kinds:

- `hooks`
- `baseline-refresh`
- `chain-break`
- `retention`
- `degraded`

### `vigil ack <kind>`

Acknowledges the most recent unacknowledged event of that kind.
Use `--sequence` to target a specific event instead.

### `vigil ack list`

Shows current unacknowledged events and recent acknowledgment records.

### `vigil ack revoke <kind>`

Writes a revocation record. The referenced event returns to its
natural doctor severity/state for rendering.

### `vigil ack show <sequence>`

Displays full audit-record details for one acknowledgment entry.

## Recurrence Behavior

Acknowledgments are per-event, not per-category.

If event `E1` is acknowledged and event `E2` (same kind) occurs later,
`E2` is still actionable and visible. You must explicitly acknowledge
`E2` if desired.

## Aging Behavior

Aging is deterministic and computed at render time.

Default doctor windows:

- `event_warn_window = "7d"`
- `event_inform_window = "30d"`
- `event_hide_window = "90d"`

Events eventually leave doctor by aging out, not by suppression.
All records remain in the audit log.

## No-Suppression Rule

Doctor is an operational truth surface. Operators can add context, but
cannot configure doctor to omit whole categories.

There is intentionally no `--suppress`, `--ignore`, or blanket silence
flag on `vigil ack`.

If an operator wants to stop a class of events, they should disable the
integration that produces them at the source (for example,
`vigil hooks disable`).

## Examples

### Stale Hook Failure, Investigated

1. `vigil doctor` shows a historical hook failure.
2. Operator verifies hook integrity: `vigil hooks verify`.
3. Operator records context:
   `vigil ack hooks --note "investigated; hooks match canonical"`.
4. Event remains visible as historical context with acknowledgment metadata.

### Integration-Level Opt-Out

1. Operator decides to disable package-manager hook integration.
2. Runs `vigil hooks disable`.
3. Doctor reflects `disabled` state instead of repeated hook activity.
4. Operator can restore later with `vigil hooks enable`.
