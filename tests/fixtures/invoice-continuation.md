# Let customers download invoices as CSV

> Reduced durability fallback: Beads is unavailable or not in use.

## Work Items

### demo: Let customers download invoices as CSV

- Type: `epic`
- Status: `open`
- Lane: `epic`
- Labels: `orchestration`
- Depends on lanes: none

### demo-16: Build the invoice CSV export

- Type: `task`
- Status: `done`
- Lane: `export`
- Labels: `implementation`
- Depends on lanes: none

### demo-17: Verify exported totals match the invoice

- Type: `task`
- Status: `open`
- Lane: `validation`
- Labels: `validation`
- Depends on lanes: `export`

### demo-18: Enable customer invoice downloads

- Type: `task`
- Status: `open`
- Lane: `rollout`
- Labels: `implementation`
- Depends on lanes: `validation`
