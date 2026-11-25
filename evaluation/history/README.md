# Retired three-arm study

The [frozen three-arm protocol](three-arm/PROTOCOL.md) was designed for
the retired Candidate E prompt. No study arm ever ran. The 18 rehearsal
records are synthetic, both build slots are unbound, and the study produced
no comparison results.

The `three-arm/` directory preserves the original files and their relative
paths. From the root of a current source checkout, use the explicit archive
path to validate the frozen protocol.

```sh
python3 -B scripts/comparative_evaluation.py --root evaluation/history/three-arm validate
```

Use the `v1.33.0` source checkout for the frozen protocol's `lock` and
`score` examples. Historical locks bind the original `evaluation/three-arm/`
paths and exact source bytes. The CLI refuses `run` before reading the
protocol.
