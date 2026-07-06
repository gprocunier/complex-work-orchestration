# Markdown Workgraph Fallback

> Reduced durability fallback: Beads is unavailable or not in use. This
> Markdown workgraph preserves the task shape for operator resume, but it does
> not provide ready-work filtering, shared comments, contractor-only semantics,
> dependency enforcement, or durable external handoff.

Generated workgraphs should use this structure:

```markdown
# <workgraph title>

## Resume

- Treat this file as temporary fallback state until Beads or an equivalent tracker is available.
- Resume with `python3 scripts/summarize_resume_state.py --markdown-workgraph <path>`.
- Move the work into Beads before claiming shared durable handoff or contractor dispatch readiness.

## Work Items

### <lane-key>: <title>

- Type: `<epic|task>`
- Lane: `<lane>`
- Labels: `<label>`, `<label>`
- Depends on lanes: `<lane>`, `<lane>`
- Skills: `<skill>`, `<skill>`

#### Acceptance

<acceptance criteria>

#### Design

<design constraints>

#### Notes

<route notes, execution notes, and residual risk>
```

Use Beads for normal CWO work. Use this fallback only when `bd` is missing,
the repository has no usable `.beads` state, or an operator needs a temporary
handoff file before Beads can be initialized.
