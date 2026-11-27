"""Offline authority custody with actual Linux UID and socket permissions."""

from __future__ import annotations

from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from cwo_core import lead_authority as authority


class AuthorityControlTests(unittest.TestCase):
    def test_same_uid_and_root_lead_are_refused(self):
        with self.assertRaisesRegex(authority.AuthorityError, "separate unprivileged lead"):
            authority.AuthorityLayout(23001, 23001, Path("/source"), Path("/config"), Path("/state"), Path("/run/cwo/a"))
        with self.assertRaisesRegex(authority.AuthorityError, "separate unprivileged lead"):
            authority.AuthorityLayout(23001, 0, Path("/source"), Path("/config"), Path("/state"), Path("/run/cwo/a"))
        with self.assertRaisesRegex(authority.AuthorityError, "separate host UID"):
            authority.AuthorityClient(Path("/run/cwo/a"), os.geteuid()).request("synthesis", "a" * 64)

    def test_reference_and_frame_shape(self):
        client = authority.AuthorityClient(Path("/run/cwo/a"), 23001)
        for reference in ("../reference", "A" * 64, "a" * 65, 4):
            with self.subTest(reference=reference), self.assertRaisesRegex(authority.AuthorityError, "invalid approval reference"):
                client.request("synthesis", reference)
        for raw in (b'{"reference":1,"reference":2}', b'{"size":1e500}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(authority.AuthorityError):
                authority._decode(raw)

    @unittest.skipUnless(sys.platform == "linux", "requires Linux peer credentials")
    def test_descriptors_and_peer_credentials_under_distinct_uids(self):
        prefix = []
        if os.geteuid() != 0:
            prefix = ["unshare", "--user", "--map-root-user", "--map-auto", "--mount"]
            if shutil.which(prefix[0]) is None:
                self.skipTest("requires root or a disposable subordinate UID namespace")
            probe = subprocess.run([*prefix, "true"], capture_output=True, timeout=5)
            if probe.returncode:
                self.skipTest("subordinate UID namespace unavailable")
        with tempfile.TemporaryDirectory(prefix="cwo-lead-authority-") as root:
            result = subprocess.run([*prefix, sys.executable, "-B", str(Path(__file__).resolve()), "--exercise",
                                     root, "namespace" if prefix else "direct"],
                                    capture_output=True, text=True, timeout=20)
        if result.returncode == 77:
            self.skipTest(result.stderr.strip())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(sys.platform == "linux", "requires Linux peer credentials")
    def test_documented_authority_commands_under_distinct_uids(self):
        if not shutil.which("unshare") or not shutil.which("mount"):
            self.skipTest("requires a private mount namespace")
        prefix = ["unshare", "--mount", "--propagation", "private"]
        if os.geteuid() != 0:
            prefix += ["--user", "--map-root-user", "--map-auto"]
        probe = subprocess.run([*prefix, "true"], capture_output=True, timeout=5)
        if probe.returncode:
            self.skipTest("private mount namespace unavailable")
        parent_namespace = os.stat("/proc/self/ns/mnt").st_ino
        with tempfile.TemporaryDirectory(prefix="cwo-lead-authority-cli-") as root:
            result = subprocess.run([*prefix, sys.executable, "-B", str(Path(__file__).resolve()),
                                     "--exercise-cli", root, str(parent_namespace)],
                                    capture_output=True, text=True, timeout=40)
        if result.returncode == 77:
            self.skipTest(result.stderr.strip())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def _drop(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def _write_fixture(root):
    root.chmod(0o755)
    source = root / "source"
    shutil.copytree(SCRIPTS / "cwo_core", source / "scripts/cwo_core", ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("lead_authority_host.py", "evaluate_synthesis.py"):
        shutil.copy2(SCRIPTS / name, source / "scripts")
    for name in ("policy", "schemas"):
        shutil.copytree(SCRIPTS.parent / name, source / name)
    (source / "policy/workspace-host-state.json").write_text(json.dumps(
        {"schema_version": 1, "host_state_root": "../state"}))
    config = root / "etc" / "cwo"
    config.mkdir(parents=True)
    (root / "state").mkdir(mode=0o700)
    (root / "run").mkdir(mode=0o755)
    os.chown(root / "state", 101, 101)
    os.chown(root / "run", 101, 101)


def _write_configuration(root):
    config_file = root / "etc/cwo/lead-authority.json"
    config_file.write_text(json.dumps(dict(schema_version=1, host_uid=101, lead_uid=102,
        source_root=str(root / "source"), state_root=str(root / "state"), socket_path=str(root / "run/authority.sock"))))
    config_file.chmod(0o644)
    return config_file


def _load_fixture(root):
    sys.path.insert(0, str(root / "source/scripts"))
    for name in tuple(sys.modules):
        if name in ("cwo_core", "lead_authority_host", "evaluate_synthesis") or name.startswith("cwo_core."):
            del sys.modules[name]
    return importlib.import_module("cwo_core.lead_authority")


def _fixture(root, namespace):
    _write_fixture(root)
    if namespace:
        # Load standard-library dependencies before chroot. Reload CWO below
        # so the controller itself runs from the protected fixture installation.
        for name in ("lead_authority_host", "cwo_core.audit_segments", "cwo_core.host_record_inventory",
                     "cwo_core.host_record_quarantine"):
            importlib.import_module(name)
        proc = root / "proc"
        proc.mkdir()
        mount = subprocess.run(["mount", "--rbind", "/proc", str(proc)], capture_output=True)
        if mount.returncode:
            sys.stderr.write("private proc mount unavailable for subordinate UID fixture\n")
            sys.exit(77)
        os.chroot(root)
        os.chdir("/")
        root = Path("/")
    config_file = _write_configuration(root)
    fixture = _load_fixture(root)
    if not namespace:
        fixture._CONFIG_FILE = config_file
    return fixture


def _host(module, report):
    _drop(101)
    runner = importlib.import_module("lead_authority_host")
    layout = module.configured_authority_layout()
    store = module.ApprovalStore(layout)
    panel = _approved_panel(runner.configured_store())
    reference = store.publish("synthesis", panel)
    other_reference = store.publish("outbound-approval", {"destination": "test"})
    assert module.configured_approval("synthesis", reference) == panel

    class ReadyHost(module.AuthorityHost):
        def __enter__(self):
            host = super().__enter__()
            report.write(json.dumps([reference, other_reference]) + "\n")
            report.flush()
            return host

    runner.AuthorityHost = ReadyHost
    sys.argv = [runner.__file__, "serve"]
    runner.main()


def _approved_panel(store):
    from cwo_core.host_acceptance import record_received_evaluation
    from cwo_core.host_return_intake import record_received_return

    dispatch = dict(dispatch_id="original", bead_id="fixture", executor="codex_architecture_critic",
                    provider_key="internal_codex", packet_sha256="b" * 64)
    identity = dict(provider="openai", model_family="gpt", model_id="fixture-model",
                    reasoning_effort="high", session_id="fixture-session")
    prepared = store.write_dispatch(**dispatch, dispatch_role="executor", **identity)
    store.write_observed_dispatch(dispatch["dispatch_id"], prepared_record_sha256=prepared,
                                  observation_sha256="c" * 64, **identity)
    report = "A synthetic local critic observation."
    record_received_return(store, dispatch["dispatch_id"], report.encode())
    evaluation = dict(dispatch, verdict="accept", implementation_blocked=False,
                      accepted_for_use=True, evidence_use_hold=False, provider_external=False,
                      peer_review_required=False)
    reference = record_received_evaluation(report, evaluation)
    claim = dict(category="crypto", key="retry-log", value="approved", evidence="Fixture observation")
    return dict(candidate="approved", scope="fixture", adjudications=[],
                inputs=[dict(evaluation_record_sha256=reference, zero_trust_claims=[claim])])


def _lead(module, root, reference, other_reference):
    _drop(102)
    client = module.configured_authority_client()
    result = client.request("synthesis", reference)
    assert result["candidate"] == "approved" and result["provenance_basis"] == "operator-authorized", result
    assert result["zero_trust_consensus"]["independent_trust_domains"] == ["openai"], result
    assert result["zero_trust_consensus"]["consensus_status"] == "blocked", result
    for operation, selection in (("publish", reference), ("synthesis", other_reference), ("synthesis", "a" * 64)):
        with unittest.TestCase().assertRaisesRegex(module.AuthorityError, "request refused"):
            client.request(operation, selection)
    endpoint = root / "run/authority.sock"
    state = root / "state"
    stored = state / (reference + ".json")
    for mutate in (lambda: stored.write_text("forged"), lambda: stored.read_bytes(),
                   lambda: state.chmod(0o777), lambda: endpoint.unlink(),
                   lambda: (root / "etc/cwo/lead-authority.json").write_text("forged"),
                   lambda: (root / "source/scripts/cwo_core/lead_authority.py").write_text("forged")):
        with unittest.TestCase().assertRaises(PermissionError):
            mutate()
    layout = module._configured_layout()
    with unittest.TestCase().assertRaisesRegex(module.AuthorityError, "wrong authority principal"):
        module.ApprovalStore(layout)
    with unittest.TestCase().assertRaisesRegex(module.AuthorityError, "separate unprivileged lead"):
        replace(layout, host_uid=102)
    forged = json.dumps({"operation": "synthesis", "reference": reference, "payload": {}}).encode()
    for frame in (_frame(9000), _frame(69, b'{}'), _frame(len(forged), forged)):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(endpoint))
            connection.sendall(frame)
            connection.shutdown(socket.SHUT_WR)
            assert module._receive(connection, 512) == {"error": "authority request refused"}


def _frame(size, content=b""):
    return size.to_bytes(4, "big") + content


def _start(run):
    pid = os.fork()
    if pid:
        return pid
    try:
        run()
    except BaseException:
        traceback.print_exc()
        os._exit(1)
    os._exit(0)


def _wait(pid):
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, f"fixture child failed with status {status}"


def _exercise(root, namespace):
    directory = os.open(root, os.O_DIRECTORY)
    try:
        module = _fixture(root, namespace)
        root = Path("/") if namespace else root
        _exercise_peers(module, root)
    finally:
        for name in ("state", "run"):
            shutil.rmtree(name, dir_fd=directory)
        os.close(directory)


def _exercise_peers(module, root):
    _reject_counterfeit_peer(module, root)
    reader, writer = os.pipe()
    with os.fdopen(reader, "r") as incoming, os.fdopen(writer, "w") as outgoing:
        def host():
            incoming.close()
            _host(module, outgoing)

        server = _start(host)
        outgoing.close()
        reaped = False
        try:
            reference, other_reference = json.loads(incoming.readline())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unapproved:
                unapproved.settimeout(5)
                unapproved.connect(str(root / "run/authority.sock"))
                assert unapproved.recv(1) == b""
            _wait(_start(lambda: _lead(module, root, reference, other_reference)))
            os.kill(server, signal.SIGTERM)
            reaped = True
            _wait(server)
            assert not (root / "run/authority.sock").exists()
        finally:
            if not reaped:
                os.kill(server, 9)
                os.waitpid(server, 0)


def _reject_counterfeit_peer(module, root):
    endpoint = root / "run/counterfeit.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as counterfeit:
        counterfeit.bind(str(endpoint))
        os.chown(endpoint, 101, 101)
        endpoint.chmod(0o666)
        counterfeit.listen(1)

        def request():
            _drop(102)
            with unittest.TestCase().assertRaisesRegex(module.AuthorityError, "host UID does not match"):
                module.AuthorityClient(endpoint, 101).request("synthesis", "a" * 64)

        _wait(_start(request))
    endpoint.unlink()


def _exercise_cli(root, parent_namespace):
    assert os.stat("/proc/self/ns/mnt").st_ino != parent_namespace, "requires an isolated mount namespace"
    os.umask(0o022)
    _write_fixture(root)
    directory = os.open(root, os.O_DIRECTORY)
    try:
        python = _bind_cli_runtime(root)
        (root / "tmp").mkdir()
        os.chroot(root)
        os.chdir("/")
        root = Path("/")
        _write_configuration(root)
        _load_fixture(root)
        _exercise_cli_commands(root, python)
    finally:
        for name in ("state", "run"):
            shutil.rmtree(name, dir_fd=directory)
        os.close(directory)


def _bind_cli_runtime(root):
    executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    paths = [Path(name) for name in ("/usr", "/lib", "/lib64", "/proc")]
    if not executable.is_relative_to(Path("/usr")):
        paths.append(Path(sys.base_prefix).resolve())
    for path in paths:
        target = root / path.relative_to("/")
        if path.is_symlink():
            target.symlink_to(path.readlink())
        elif path.is_dir():
            target.mkdir(parents=True)
            mounted = subprocess.run(["mount", "--rbind", str(path), str(target)],
                                     capture_output=True, text=True, timeout=5)
            if mounted.returncode:
                print(f"private runtime mount unavailable for {path}: {mounted.stderr.strip()}", file=sys.stderr)
                sys.exit(77)
    # Some Python builds need the entropy device during interpreter startup.
    entropy = root / "dev/urandom"
    entropy.parent.mkdir()
    entropy.touch()
    mounted = subprocess.run(["mount", "--bind", "-o", "ro", "/dev/urandom", str(entropy)],
                             capture_output=True, text=True, timeout=5)
    assert mounted.returncode == 0, mounted.stderr
    return str(executable)


def _seed_cli_panel():
    with tempfile.TemporaryFile(mode="w+") as output:
        def prepare():
            _drop(101)
            from cwo_core.host_records import configured_store

            json.dump(_approved_panel(configured_store()), output)
            output.flush()

        _wait(_start(prepare))
        output.seek(0)
        return json.load(output)


def _cli(python, source, uid, *arguments, payload=None):
    return subprocess.run([python, "-E", "-s", "-B", *arguments],
                          cwd=source, user=uid, group=uid, extra_groups=[],
                          input=json.dumps(payload) if payload is not None else None,
                          capture_output=True, text=True, timeout=6)


def _publish_cli(python, source, operation, payload):
    arguments = ("scripts/lead_authority_host.py", "publish", operation)
    rejected = _cli(python, source, 102, *arguments, payload=payload)
    assert rejected.returncode == 1 and "wrong authority principal" in rejected.stderr, rejected
    assert not rejected.stdout, rejected
    published = _cli(python, source, 101, *arguments, payload=payload)
    assert published.returncode == 0, published
    reference = published.stdout.strip()
    assert authority._REFERENCE.fullmatch(reference), published
    return reference


def _wait_for_service(endpoint, service):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and service.poll() is None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            try:
                probe.connect(str(endpoint))
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.02)
            else:
                return
    raise AssertionError("authority service did not start")


def _exercise_cli_commands(root, python):
    source = root / "source"
    lead = root / "lead"
    shutil.copytree(source, lead)
    (lead / "policy/workspace-host-state.json").write_text(json.dumps(
        {"schema_version": 1, "host_state_root": "../lead-state"}))
    endpoint = root / "run/authority.sock"
    grant = dict(project=str(lead), bead_id="fixture", epic_id=None, executor="claude_code_manual",
                 provider_key="anthropic_manual", maximum_share_boundary="redacted-packet")
    outbound = _publish_cli(python, source, "outbound-approval", grant)
    synthesis = _publish_cli(python, source, "synthesis", _seed_cli_panel())
    reject = _cli(python, source, 102, "scripts/lead_authority_host.py", "serve")
    assert reject.returncode == 1 and "wrong authority principal" in reject.stderr, reject
    with subprocess.Popen([python, "-E", "-s", "-B", "scripts/lead_authority_host.py", "serve"],
                          cwd=source, user=101, group=101, extra_groups=[],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as service:
        try:
            _wait_for_service(endpoint, service)
            _check_cli_results(python, lead, synthesis, outbound, grant)
        finally:
            service.terminate()
            try:
                stdout, stderr = service.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                service.kill()
                service.communicate()
                raise
    assert service.returncode == 0, stdout + stderr
    assert not endpoint.exists()
    assert not (root / "lead-state").exists()


def _check_cli_results(python, lead, synthesis, outbound, grant):
    report = _cli(python, lead, 102, "scripts/evaluate_synthesis.py", "--protected-review", synthesis)
    assert report.returncode == 0, report
    result = json.loads(report.stdout)
    assert result["candidate"] == "approved" and result["provenance_basis"] == "operator-authorized", result
    assert result["zero_trust_consensus"]["independent_trust_domains"] == ["openai"], result
    read_grant = ("import json, sys\nfrom cwo_core.lead_authority import configured_approval\n"
                  "print(json.dumps(configured_approval('outbound-approval', sys.argv[1])))")
    response = _cli(python, lead / "scripts", 102, "-c", read_grant, outbound)
    assert response.returncode == 0 and json.loads(response.stdout) == grant, response


if __name__ == "__main__":
    if sys.argv[1:2] == ["--exercise"]:
        _exercise(Path(sys.argv[2]), sys.argv[3] == "namespace")
    elif sys.argv[1:2] == ["--exercise-cli"]:
        _exercise_cli(Path(sys.argv[2]), int(sys.argv[3]))
    else:
        unittest.main()
