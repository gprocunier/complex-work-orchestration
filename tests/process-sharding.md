# Process sharding for slow unittest modules

`scripts/run_parallel_unittest.py` keeps the ordinary unittest subprocess
interface and its default of eight concurrent workers. An explicit `--workers`
sets the maximum number of active child processes. Workunit count can exceed
that limit; completed children release slots for the next unit.

The twelve files in `METHOD_SHARDED_TEST_FILES` use method groups. A separate
discovery child uses unittest's original FILE argument conversion without
running fixtures, then every discovered case ID enters exactly one group.
Discovery errors and duplicate IDs refuse the run. New methods are discovered
normally even when the cost file has no entry for them. Other parallel files
retain file-level balancing. The five `SERIAL_TEST_FILES` retain their original
ordered, single-process invocation after every parallel unit finishes.

`policy/unittest-shard-costs.json` contains portable case IDs and seconds used
only for packing. Groups retain discovery order within each module and aim for
75 seconds, avoiding groups estimated above 90 seconds when a split is possible.
A single method, including all its subtests and intrinsic concurrency, remains
atomic even when it exceeds 90 seconds. Fixture overhead can also exceed this
planning goal. Missing weights use a module-average fallback; missing fixture
estimates reserve five seconds, an allowance rather than a measured guarantee.

Each workunit starts a fresh Python interpreter with its own temporary root and
preserved log. HOME is inherited, and the original test-directory PYTHONPATH
prepend remains. Ordinary unittest runs module/class setup, teardown and
cleanups in every process that selects that fixture. Lazy class-level source
initialization also repeats when selected cases enter separate processes; it
must not be mistaken for a one-time whole-module cost.

Workers use unbuffered Python output. Diagnostic stdout remains in the raw
log in execution order before the real unittest footer, rather than flushing
after it at interpreter exit. The original unittest arguments and every
diagnostic byte remain; output is neither suppressed nor rewritten.

Report accumulated work across processes separately from elapsed command time;
repeated fixtures contribute to the former. A shorter workunit does not establish
a shorter complete job. The runner tests exercise discovery, packing, process
width, repeated fixtures, serial ordering and child failure propagation.
