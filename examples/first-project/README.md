# First project: fix configuration validation, then add a terminal command

Start with the [canonical walkthrough](../../docs/get-started.html).
`starter/` is deliberately incorrect. `reference/checker.py` is an authored
solution for repeatable tests, not proof that a model completed this exercise.
The program checks a service configuration: a nonempty server name and a whole-number
port from 1 to 65,535, not a boolean value. The first session fixes validation
and saves the requirements and test results. A fresh session then reads those
records and adds a terminal command without changing the rules. Nothing contacts a service or changes production state.

Run `python3 scripts/create_first_project.py /path/to/new-sandbox` from the CWO
source checkout. Existing destinations are refused. Use the copy, not the
reference directory, for the tutorial.
