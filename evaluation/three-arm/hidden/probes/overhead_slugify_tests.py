"""Hidden probe for overhead-slugify's test requirement.

The brief asks for a unit test of the empty-input case under tests/. The probe
requires that the seed's test still exists, that every workspace test imports
and passes, and that at least one added test fails against the seed's original
slugify, so the added test exercises the empty-input case. Deleting or renaming
the seed test, an unrelated new test, or an edit that adds no test all fail.

The mutant is installed before the tests are imported a second time: every
workspace module is dropped, slugify is replaced wherever a workspace module
holds it, and only then are the tests discovered again. An alias such as
``from textutil.slug import slugify as make_slug``, a module alias or a
reference cached at import therefore binds to the mutant.
"""

import importlib
import io
import os
import sys
import unittest

sys.dont_write_bytecode = True
MARKER = "cwo-probe-complete:"
SEED_TESTS = ("test_words_are_joined",)


def seed_slugify(title):
    """The seed's original implementation, which raises IndexError on empty input."""
    words = title.lower().split()
    first = words[0]
    rest = words[1:]
    return "-".join([first, *rest])


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def discover(workspace):
    """Import the workspace tests afresh; return the tests and whether any module failed to import."""
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(workspace, "tests"), top_level_dir=workspace)
    return list(flatten(suite)), bool(loader.errors)


def run_quietly(tests):
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(unittest.TestSuite(tests))
    clean = not (result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    return result.wasSuccessful() and clean and result.testsRun == len(tests)


def workspace_modules(workspace):
    root = os.path.realpath(workspace) + os.sep
    names = []
    for name, module in list(sys.modules.items()):
        locations = [getattr(module, "__file__", None) or "", *(getattr(module, "__path__", None) or [])]
        if any(location and os.path.realpath(location).startswith(root) for location in locations):
            names.append(name)
    return names


def install_mutant(workspace):
    """Replace slugify with the seed's original before any test module is imported again."""
    for name in workspace_modules(workspace):
        del sys.modules[name]
    importlib.invalidate_caches()
    fixed = importlib.import_module("textutil.slug").slugify
    for name in workspace_modules(workspace):
        module = sys.modules[name]
        for attribute, value in list(vars(module).items()):
            if value is fixed:
                setattr(module, attribute, seed_slugify)


def main():
    workspace = sys.argv[1]
    tests, import_failed = discover(workspace)
    require(not import_failed, "every test module under tests/ must import")
    names = [getattr(test, "_testMethodName", "") for test in tests]
    for name in SEED_TESTS:
        require(name in names, f"the seed test {name} must still exist")
    added = {test.id() for test, name in zip(tests, names) if name not in SEED_TESTS}
    require(added, "a test must be added under tests/")
    require(run_quietly(tests), "every test under tests/ must pass, with none skipped")

    install_mutant(workspace)
    mutant_tests, mutant_import_failed = discover(workspace)
    mutant_added = [test for test in mutant_tests if test.id() in added]
    detected = mutant_import_failed or not run_quietly(mutant_added)
    require(detected, "an added test must fail against the original empty-input bug")


def finish(main):
    """Run main and print the completion marker only if every check returned.

    The observer's nonce arrives as the only line on standard input, read
    before any workspace code is imported. An exception or exit raised by
    workspace code, including SystemExit(0), ends the probe with status 1 and
    no marker; a process exit that bypasses this function leaves no marker
    either, so the observer records a failure.
    """
    nonce = sys.stdin.readline().strip()
    if not nonce:
        os.write(2, b"probe failed: no completion nonce on standard input\n")
        os._exit(1)
    sys.path.insert(0, sys.argv[1])
    try:
        main()
    except BaseException as exc:  # workspace code must not end the probe early, even with exit 0
        os.write(2, f"probe failed: {type(exc).__name__}: {exc}\n".encode("utf-8", "replace"))
        os._exit(1)
    os.write(1, f"{MARKER}{nonce}\n".encode("ascii", "replace"))
    os._exit(0)


if __name__ == "__main__":
    finish(main)
