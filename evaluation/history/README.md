# Retired three-arm study

The [frozen three-arm protocol](three-arm/PROTOCOL.md) was designed for
the retired Candidate E prompt. No study arm ever ran. The 18 rehearsal
records are synthetic, both build slots are unbound, and the study produced
no comparison results.

The `three-arm/` directory preserves the original files and their relative
paths. In a current source checkout, `validate` checks the frozen 75-file
roster, file digests and both unbound build slots. `run` exits 3 before
reading the archive.

```sh
python3 -B scripts/comparative_evaluation.py --root evaluation/history/three-arm validate
```

Use `v1.33.0` (commit `e4dfa8eb5dfc41fb722bccbee97c811750e51e67`) for
the full offline verifier and its tests. Historical locks bind the original
`evaluation/three-arm/` paths and exact source bytes. In a clone that has
the release, check out the pinned source separately from your current work.

```sh
git worktree add --detach ../cwo-study-v1.33.0 e4dfa8eb5dfc41fb722bccbee97c811750e51e67
cd ../cwo-study-v1.33.0
python3 -B scripts/comparative_evaluation.py validate
python3 -B -m unittest discover -s tests -p 'test_comparative_evaluation*.py'
```

See the [frozen protocol](three-arm/PROTOCOL.md#offline-harness) for the
`digest`, `schedule`, `lock`, `score` and `template` commands at that release.
