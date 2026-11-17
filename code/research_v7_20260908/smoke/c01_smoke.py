"""Capture one native C01 unwrap in an isolated Linux container, never judge Phi.

No expected LEK/reference/fixture truth argument is accepted. This module is
DEVELOPMENT_SMOKE_NOT_FORMAL. See README.md for required independent validation.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import dataclasses
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import signal
import socket
import stat
import struct
import sys
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from collector.tcp_relay import CaptureRelay, UnixCaptureRelay
    from runtime.native_output import decode_native_capture, standard_base64, strict_json
else:
    from ..collector.tcp_relay import CaptureRelay, UnixCaptureRelay
    from ..runtime.native_output import decode_native_capture, standard_base64, strict_json


SCOPE = "DEVELOPMENT_SMOKE_NOT_FORMAL"
RESOURCE = "kbs:///default/attestflow-v7/kek-a"
RESOURCE_API = "/kbs/v0/resource/default/attestflow-v7/kek-a"
AA_SOCKET = Path("/run/confidential-containers/attestation-agent/attestation-agent.sock")
BINARY_NAMES = ("kbs", "ttrpc-aa", "ttrpc-cdh", "ttrpc-cdh-tool")
TEE_PATHS = (
    "/dev/tdx_guest", "/dev/tdx-guest", "/dev/sev", "/dev/sev-guest",
    "/dev/sgx_enclave", "/dev/sgx/enclave", "/dev/tpm0", "/dev/tpmrm0", "/dev/tsi",
)

# Public policies copied from pinned Trustee integration-tests/tests/get_resource.rs:
# CHECK_CONTRAINDICATED_POLICY and EAR_RV_ATTESTATION_POLICY. No observed EAR is
# assigned here: these are only configuration input bytes to the real admin API.
CHECK_CONTRA = b'''\npackage policy
import rego.v1

default allow = false

allow if {
    input["submods"]["cpu0"]["ear.status"] != "contraindicated"
}
'''
EAR_RV = b'''\npackage policy
import rego.v1

default hardware := 97
default executables := 33
default configuration := 36
default file_system := 0
default instance_identity := 0
default runtime_opaque := 0
default storage_opaque := 0
default sourced_data := 0

trust_claims := {
\t"executables": executables,
\t"hardware": hardware,
\t"configuration": configuration,
\t"file-system": file_system,
\t"instance-identity": instance_identity,
\t"runtime-opaque": runtime_opaque,
\t"storage-opaque": storage_opaque,
\t"sourced-data": sourced_data,
}

hardware := 2 if {
    input.sample.svn in query_reference_value("svn")
}
'''
REFERENCE_VALUES = {"svn": ["1"], "launch_digest": ["abcde"],
                    "major_version": 1, "minimum_minor_version": 1}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def error(exc: BaseException) -> dict:
    return {"type": type(exc).__name__, "message": str(exc)}


def write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        if stream.write(data) != len(data):
            raise OSError("short write")
        stream.flush()
        os.fsync(stream.fileno())


def publish(path: Path, value) -> None:
    partial = path.with_name(path.name + ".partial")
    write_new(partial, json_bytes(value))
    os.link(partial, path)
    partial.unlink()  # this publish operation's own temporary link only


def sanitized_env(role: str) -> dict[str, str]:
    if role not in ("kbs", "aa", "cdh", "client"):
        raise ValueError("unknown native role")
    # Deliberately do not inherit os.environ, HOME, LD_*, proxies, hardware flags,
    # KBS_CONFIG_FILE, KBS_CERT, registry credentials, or sample-device flags.
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC", "RUST_LOG": "info"}
    if role == "cdh":
        env["AA_KBC_PARAMS"] = "cc_kbc::http://127.0.0.1:8081"
    return env


def validate_preflight(facts: dict) -> None:
    if facts["system"] != "Linux" or facts["machine"] not in ("aarch64", "arm64"):
        raise RuntimeError("requires the isolated Linux ARM64 container")
    if facts["interfaces"] != ["lo"]:
        raise RuntimeError("network-none guard requires exactly the loopback interface")
    if not facts["docker_marker"]:
        raise RuntimeError("requires the task's disposable Docker container, not a host /run")
    if facts["kernel_cdh_resources_present"]:
        raise RuntimeError("kernel cdh.kbs_resources is forbidden in this smoke")
    if facts["aa_socket_exists"]:
        raise FileExistsError("existing AA default socket must not be removed or reused")
    if facts["tee_paths_present"]:
        raise RuntimeError("real TEE/TPM device paths are outside this dummy smoke")


def collect_preflight() -> dict:
    cmdline = Path("/proc/cmdline").read_bytes()
    facts = {"system": platform.system(), "machine": platform.machine(),
             "interfaces": sorted(p.name for p in Path("/sys/class/net").iterdir()),
             "docker_marker": Path("/.dockerenv").is_file(),
             "kernel_cmdline_sha256": sha(cmdline),
             "kernel_cdh_resources_present": any(p.startswith(b"cdh.kbs_resources=") for p in cmdline.split()),
             "aa_socket_exists": os.path.lexists(AA_SOCKET),
             "tee_paths_present": [p for p in TEE_PATHS if os.path.lexists(p)],
             "pid": os.getpid(), "uid": os.getuid(), "collected_unix_ns": time.time_ns()}
    return facts


def require_ports_free() -> dict:
    held = []
    try:
        for port in (8081, 8082):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held.append(sock)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(1)
        return {"ports": [8081, 8082], "available_at_check": True}
    finally:
        for sock in held:
            sock.close()


def load_c01_inputs(client_input: Path, broker_dir: Path) -> tuple[bytes, bytes, dict]:
    if client_input.name != "unwrap-input.json" or client_input.parent.name != "C01" or broker_dir.name != "C01":
        raise ValueError("this runner accepts only client_inputs/C01/unwrap-input.json and broker_inputs/C01")
    if client_input.is_symlink() or broker_dir.is_symlink():
        raise ValueError("input symlinks are not accepted")
    if set(p.name for p in broker_dir.iterdir()) != {"resources.json", "kek-a.bin"}:
        raise ValueError("C01 broker directory must contain exactly resources.json and kek-a.bin")
    for path in (client_input, broker_dir / "resources.json", broker_dir / "kek-a.bin"):
        if path.is_symlink() or not path.is_file():
            raise ValueError("inputs must be regular non-symlink files")
    raw = client_input.read_bytes()
    index_raw = (broker_dir / "resources.json").read_bytes()
    kek = (broker_dir / "kek-a.bin").read_bytes()
    if len(raw) > 8192 or len(index_raw) > 1024 or len(kek) != 32:
        raise ValueError("C01 input size or 32-byte dummy KEK contract violated")
    if strict_json(index_raw) != {RESOURCE: "kek-a.bin"}:
        raise ValueError("exactly the single C01 KEK resource is allowed")
    obj = strict_json(raw)
    if (type(obj) is not dict or set(obj) != {"op", "keywrapparams", "keyunwrapparams"}
            or obj["op"] != "keyunwrap" or obj["keywrapparams"] != {"ec": None, "optsdata": None}):
        raise ValueError("only the normal public KeyProviderInput unwrap envelope is allowed")
    params = obj["keyunwrapparams"]
    if type(params) is not dict or set(params) != {"dc", "annotation"} or params["dc"] is not None:
        raise ValueError("unexpected unwrap parameters")
    if type(params["annotation"]) is not str:
        raise ValueError("annotation must be a base64 string")
    annotation_raw = standard_base64(params["annotation"].encode("ascii"))
    annotation = strict_json(annotation_raw)
    if (type(annotation) is not dict or set(annotation) != {
            "version", "provider", "kid", "wrapped_data", "iv", "wrap_type", "provider_settings", "annotations"}
            or annotation["version"] != "0.1.0" or annotation["provider"] != "kbs"
            or annotation["kid"] != RESOURCE or annotation["wrap_type"] != "A256GCM"
            or annotation["provider_settings"] != {} or annotation["annotations"] != {}):
        raise ValueError("not the single-resource C01 kbs/A256GCM annotation")
    if (type(annotation["iv"]) is not str or type(annotation["wrapped_data"]) is not str
            or len(standard_base64(annotation["iv"].encode("ascii"))) != 12
            or len(standard_base64(annotation["wrapped_data"].encode("ascii"))) != 48):
        raise ValueError("expected 12-byte IV and 32-byte wrapped payload plus 16-byte tag")
    return raw, kek, {"client_input_sha256": sha(raw), "annotation_sha256": sha(annotation_raw),
                      "broker_index_sha256": sha(index_raw), "dummy_kek_sha256": sha(kek),
                      "resource": RESOURCE,
                      "boundary": "shape/scope checks only; no fixture truth read or local LEK decryption"}


def inspect_binaries(bin_dir: Path) -> dict:
    records = {}
    for name in BINARY_NAMES:
        path = bin_dir / name
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(f"missing regular executable native binary: {name}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            header = stream.read(64)
            if (header[:6] != b"\x7fELF\x02\x01" or len(header) < 20
                    or struct.unpack("<H", header[18:20])[0] != 183):
                raise ValueError(f"{name} must be a Linux ARM64 ELF64 binary")
            digest.update(header)
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        records[name] = {"path": str(path.resolve()), "sha256": digest.hexdigest(), "size": path.stat().st_size}
    return records


def write_signer(private_dir: Path, public_dir: Path) -> dict:
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    numbers = key.public_key().public_numbers()
    b64url = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    jwk = {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
           "x": b64url(numbers.x.to_bytes(32, "big")), "y": b64url(numbers.y.to_bytes(32, "big"))}
    write_new(private_dir / "as-signing-key.pem", private)
    write_new(public_dir / "as-signing-public.pem", public)
    publish(public_dir / "as-signing-public.jwk.json", jwk)
    metadata = {"dummy_ephemeral_only": True, "algorithm": "P-256 / ES256",
                "private_key_path": str(private_dir / "as-signing-key.pem"),
                "private_key_sha256": sha(private), "public_pem_sha256": sha(public),
                "public_spki_der_sha256": sha(der),
                "boundary": "local run-created trust anchor; not independent external endorsement"}
    publish(public_dir / "SIGNER.json", metadata)
    return metadata


def configuration_texts(output: Path, rpc_dir: Path) -> dict[str, str]:
    quote = lambda p: json.dumps(str(p))  # compatible basic TOML strings
    kbs = f'''[http_server]
sockets = ["127.0.0.1:8082"]
insecure_http = true
worker_count = 2

[attestation_token]
insecure_header_jwk = true

[attestation_service]
type = "coco_as_builtin"
timeout = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[attestation_service.attestation_token_broker]
duration_min = 5
verbose_token = true

[attestation_service.attestation_token_broker.signer]
key_path = {quote(output / 'private' / 'as-signing-key.pem')}

[admin]
authorization_mode = "InsecureAllowAll"

[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = {quote(output / 'kbs-storage')}

[[plugins]]
name = "resource"
storage_backend_type = "kvstorage"
'''
    aa = '''[token_configs.kbs]
url = "http://127.0.0.1:8081"
tee_key_algorithm = "ECDH-ES+A256KW-P256"

[eventlog_config]
init_pcr = 17
enable_eventlog = false

[log]
level = "info"
'''
    cdh = f'''socket = {quote('unix://' + str(rpc_dir / 'back.sock'))}
credentials = []
skip_sealed_secret_verification = false

[kbc]
name = "cc_kbc"
url = "http://127.0.0.1:8081"

[image]
work_dir = {quote(output / 'image-unused')}

[log]
level = "info"
'''
    return {"kbs.toml": kbs, "aa.toml": aa, "cdh.toml": cdh}


class ProcessManager:
    """Only signals process objects created and registered by this manager."""
    def __init__(self, root: Path, *, stream_limit: int = 32 * 1024 * 1024):
        self.root = root
        self.stream_limit = stream_limit
        self.records: dict[str, dict] = {}
        self.handles: dict[str, asyncio.subprocess.Process] = {}
        self.pumps: dict[str, list[asyncio.Task]] = {}

    async def start(self, name: str, argv: list[str], env: dict[str, str], cwd: Path):
        if name in self.records or not name.replace("-", "").isalnum():
            raise ValueError("process names must be new safe identifiers")
        directory = self.root / name
        directory.mkdir(mode=0o700, exist_ok=False)
        record = {"name": name, "argv": argv, "env": env, "cwd": str(cwd),
                  "started_unix_ns": time.time_ns(), "pid": None, "returncode": None,
                  "process_closed": False, "capture_complete": False, "timed_out": False,
                  "signals": [], "errors": [], "streams": {}}
        self.records[name] = record
        publish(directory / "START.json", record)
        try:
            process = await asyncio.create_subprocess_exec(*argv, env=env, cwd=cwd,
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, start_new_session=True)
            self.handles[name] = process
            record["pid"] = process.pid
            self.pumps[name] = [asyncio.create_task(self._pump(name, stream, label))
                                for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr"))]
            publish(directory / "PROCESS.json", {"pid": process.pid, "observed_unix_ns": time.time_ns()})
        except BaseException as exc:
            record["errors"].append(error(exc))
            if name not in self.handles:
                publish(directory / "END.json", record)
            raise
        return process

    async def _pump(self, name, stream, label):
        record = self.records[name]
        path = self.root / name / (label + ".bin")
        state = {"eof": False, "bytes": 0, "sha256": None}
        record["streams"][label] = state
        digest = hashlib.sha256()
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as dest:
                while chunk := await stream.read(65536):
                    if state["bytes"] + len(chunk) > self.stream_limit:
                        raise RuntimeError("native log capture byte limit exceeded")
                    if dest.write(chunk) != len(chunk):
                        raise OSError("short native log write")
                    dest.flush()
                    state["bytes"] += len(chunk)
                    digest.update(chunk)
                state["eof"] = True
                dest.flush()
                os.fsync(dest.fileno())
            state["sha256"] = digest.hexdigest()
        except BaseException as exc:
            record["errors"].append({"stream": label, **error(exc)})
            process = self.handles[name]
            if process.returncode is None:
                try:
                    process.terminate()
                    record["signals"].append({"signal": "SIGTERM", "reason": "capture_failure", "unix_ns": time.time_ns()})
                except ProcessLookupError:
                    pass

    async def _finish(self, name):
        record, process = self.records[name], self.handles[name]
        if record["process_closed"]:
            return record
        await process.wait()
        await asyncio.wait_for(asyncio.gather(*self.pumps[name]), 5)
        record["returncode"] = process.returncode
        record["process_closed"] = True
        record["ended_unix_ns"] = time.time_ns()
        record["capture_complete"] = not record["errors"] and all(
            record["streams"].get(label, {}).get("eof") is True for label in ("stdout", "stderr"))
        publish(self.root / name / "END.json", record)
        return record

    async def wait(self, name: str, timeout: float):
        if name not in self.handles:
            raise KeyError("only registered child processes may be waited on")
        try:
            await asyncio.wait_for(asyncio.shield(self.handles[name].wait()), timeout)
        except TimeoutError:
            self.records[name]["timed_out"] = True
            self.records[name]["errors"].append({"type": "ProcessTimeout", "message": f"timeout {timeout}s"})
            return await self.stop(name, grace=2)
        return await self._finish(name)

    async def stop(self, name: str, *, grace: float = 5):
        if name not in self.handles:
            raise KeyError("only registered child processes may be signaled")
        record, process = self.records[name], self.handles[name]
        if record["process_closed"]:
            return record
        if process.returncode is None:
            sig = signal.SIGTERM if name == "kbs" else signal.SIGINT
            record["signals"].append({"signal": sig.name, "reason": "registered_child_cleanup", "unix_ns": time.time_ns()})
            try:
                process.send_signal(sig)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(asyncio.shield(process.wait()), grace)
            except TimeoutError:
                record["signals"].append({"signal": "SIGKILL", "reason": "cleanup_grace_expired", "unix_ns": time.time_ns()})
                record["errors"].append({"type": "ForcedKill", "message": "registered child exceeded shutdown grace"})
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await asyncio.wait_for(process.wait(), 3)
        return await self._finish(name)


def _http(method: str, path: str, body: bytes, content_type: str) -> dict:
    if method not in ("GET", "POST") or path not in {
            "/kbs/v0/resource-policy", "/kbs/v0/attestation-policy", "/kbs/v0/reference-value", RESOURCE_API}:
        raise ValueError("admin request outside the fixed local C01 provisioning API")
    connection = http.client.HTTPConnection("127.0.0.1", 8082, timeout=5)
    result = {"method": method, "path": path, "host": "127.0.0.1", "port": 8082,
              "request_body_sha256": sha(body), "response_status": None, "response_body": b"",
              "response_headers": [], "complete": False, "error": None}
    try:
        connection.request(method, path, body=body,
                           headers={"Content-Type": content_type, "Connection": "close"})
        response = connection.getresponse()
        result["response_status"] = response.status
        result["response_headers"] = response.getheaders()
        while True:
            try:
                chunk = response.read1(min(65536, 262145 - len(result["response_body"])))
            except http.client.IncompleteRead as exc:
                result["response_body"] += exc.partial
                raise
            if not chunk:
                if response.length not in (None, 0):
                    raise RuntimeError("admin response ended before Content-Length was satisfied")
                break
            result["response_body"] += chunk
            if len(result["response_body"]) > 262144:
                raise RuntimeError("admin response capture limit exceeded")
        result["complete"] = True
    except Exception as exc:
        result["error"] = error(exc)
    finally:
        connection.close()
    return result


async def admin_call(root: Path, name: str, method: str, path: str, body=b"", content_type="application/json"):
    directory = root / name
    directory.mkdir(mode=0o700, exist_ok=False)
    write_new(directory / "request-body.bin", body)
    publish(directory / "REQUEST.json", {"method": method, "url": "http://127.0.0.1:8082" + path,
            "content_type": content_type, "body_sha256": sha(body), "sent_unix_ns": time.time_ns(),
            "admin_auth": "explicit InsecureAllowAll inside network-none dummy container"})
    # Blocking stdlib HTTP lives on a worker thread, so inline relays keep moving.
    result = await asyncio.to_thread(_http, method, path, body, content_type)
    response_body = result.pop("response_body")
    write_new(directory / "response-body.bin", response_body)
    result["response_body_sha256"] = sha(response_body)
    result["received_unix_ns"] = time.time_ns()
    publish(directory / "RESPONSE.json", result)
    return result


async def wait_socket(path: Path, process, timeout=15) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.returncode is not None:
            raise RuntimeError("native service exited before its socket became ready")
        if os.path.lexists(path):
            info = path.lstat()
            if stat.S_ISSOCK(info.st_mode):
                return {"path": str(path), "device": info.st_dev, "inode": info.st_ino,
                        "observed_unix_ns": time.time_ns()}
            raise RuntimeError("native socket path is not a socket")
        await asyncio.sleep(0.05)
    raise TimeoutError("native Unix socket readiness timeout")


def cleanup_socket(identity: dict) -> dict:
    path = Path(identity["path"])
    if not os.path.lexists(path):
        return {"path": str(path), "status": "already_absent"}
    info = path.lstat()
    if (info.st_dev, info.st_ino) != (identity["device"], identity["inode"]) or not stat.S_ISSOCK(info.st_mode):
        return {"path": str(path), "status": "identity_changed_not_removed"}
    path.unlink()  # exact socket first observed from this run; never a broad path
    return {"path": str(path), "status": "removed_own_socket"}


def service_exit_issues(processes: dict) -> list[dict]:
    """Preserve a captured output without certifying abnormal service shutdown.

    This is a local process-record check, not proof of the cause of an exit.
    KBS may terminate through the explicitly requested SIGTERM; AA/CDH handle
    the configured SIGINT and are expected to return zero in this profile.
    """
    issues = []
    for name in ("aa", "cdh", "kbs"):
        if name not in processes:
            continue
        record = processes[name]
        rc = record.get("returncode")
        requested_kbs_term = name == "kbs" and any(
            item.get("signal") == "SIGTERM" and item.get("reason") == "registered_child_cleanup"
            for item in record.get("signals", []))
        if type(rc) is not int or not (rc == 0 or (rc == -15 and requested_kbs_term)):
            issues.append({"type": "UnexpectedServiceExit", "service": name,
                           "returncode": rc, "message": "raw capture retained; normal service completion not established"})
    return issues


async def execute(args) -> dict:
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    publish(output / "BEGIN.json", {"scope": SCOPE, "started_unix_ns": time.time_ns(), "control": "C01",
            "boundary": "configuration is not actual EAR; no Phi or expected-LEK comparison"})
    errors, sockets, relays, cleanup = [], [], [], []
    manager = None
    rpc_dir = None
    observation = None
    admitted = False
    try:
        facts = collect_preflight()
        publish(output / "PREFLIGHT.json", facts)
        validate_preflight(facts)
        admitted = True
        publish(output / "PORT_PREFLIGHT.json", require_ports_free())
        raw, kek, inputs = load_c01_inputs(args.client_input, args.broker_dir)
        publish(output / "INPUTS.json", inputs)
        binaries = inspect_binaries(args.bin_dir)
        publish(output / "BINARIES.json", binaries)
        for name in ("private", "public", "config", "processes", "admin", "client", "kbs-storage", "image-unused"):
            (output / name).mkdir(mode=0o700)
        write_new(output / "client" / "unwrap-input.json", raw)
        rpc_dir = Path(tempfile.mkdtemp(prefix="attestflow-v7-rpc-"))
        publish(output / "RPC_DIRECTORY.json", {"path": str(rpc_dir), "uid": os.getuid(), "mode": "0700"})
        signer = write_signer(output / "private", output / "public")
        for name, text in configuration_texts(output, rpc_dir).items():
            write_new(output / "config" / name, text.encode())
        write_new(output / "config" / "checkContra.rego", CHECK_CONTRA)
        write_new(output / "config" / "ear-reference-supported.rego", EAR_RV)
        publish(output / "CONFIGURATION_BOUNDARY.json", {
            "profile": "reference-supported/checkContra", "observed_ear": None,
            "http": "plaintext loopback only", "admin": "InsecureAllowAll",
            "token_trust": "insecure_header_jwk=true; public configured signer separately retained",
            "signer_public_spki_sha256": signer["public_spki_der_sha256"], "scope": SCOPE})
        manager = ProcessManager(output / "processes")
        kbs = await manager.start("kbs", [binaries["kbs"]["path"], "--config-file", str(output / "config/kbs.toml")],
                                  sanitized_env("kbs"), output)
        ready = False
        for attempt in range(30):
            if kbs.returncode is not None:
                raise RuntimeError("KBS exited before admin readiness")
            response = await admin_call(output / "admin", f"ready-{attempt:03d}", "GET", "/kbs/v0/resource-policy")
            if response["complete"] is True and response["response_status"] == 200:
                ready = True
                break
            await asyncio.sleep(0.2)
        if not ready:
            raise TimeoutError("KBS admin readiness failed")
        b64url = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
        provisioning = [
            ("resource-policy", "/kbs/v0/resource-policy", json_bytes({"policy": b64url(CHECK_CONTRA)}), "application/json"),
            ("attestation-policy", "/kbs/v0/attestation-policy", json_bytes({"type": "rego", "policy_id": "default_cpu", "policy": b64url(EAR_RV)}), "application/json"),
            ("reference-values", "/kbs/v0/reference-value", json_bytes({"version": "0.1.0", "type": "sample", "payload": base64.b64encode(json_bytes(REFERENCE_VALUES)).decode("ascii")}), "application/json"),
            ("dummy-kek", RESOURCE_API, kek, "application/octet-stream"),
        ]
        for name, path, body, content_type in provisioning:
            response = await admin_call(output / "admin", name, "POST", path, body, content_type)
            if response["complete"] is not True or response["response_status"] != 200:
                raise RuntimeError(f"native admin provisioning failed: {name}")
        tcp = CaptureRelay(output / "tcp-capture", idle_timeout=90, connect_timeout=5)
        relays.append(tcp)
        await tcp.start()
        # Repeat immediately before native AA startup: the public daemon unlinks
        # a preexisting socket, so the runner must never knowingly let it do so.
        if os.path.lexists(AA_SOCKET):
            raise FileExistsError("AA socket appeared after preflight; refusing native startup")
        aa = await manager.start("aa", [binaries["ttrpc-aa"]["path"], "--config-file", str(output / "config/aa.toml"),
                "--attestation_sock", "unix://" + str(AA_SOCKET)], sanitized_env("aa"), output)
        sockets.append(await wait_socket(AA_SOCKET, aa))
        if os.path.lexists(rpc_dir / "back.sock"):
            raise FileExistsError("CDH back socket must be absent before native startup")
        cdh = await manager.start("cdh", [binaries["ttrpc-cdh"]["path"], "-c", str(output / "config/cdh.toml")],
                                  sanitized_env("cdh"), output)
        sockets.append(await wait_socket(rpc_dir / "back.sock", cdh))
        rpc = UnixCaptureRelay(output / "rpc-capture", private_socket_dir=rpc_dir, idle_timeout=90)
        relays.append(rpc)
        await rpc.start()
        info = (rpc_dir / "front.sock").lstat()
        sockets.append({"path": str(rpc_dir / "front.sock"), "device": info.st_dev, "inode": info.st_ino})
        publish(output / "SOCKET_IDENTITIES.json", sockets)
        await manager.start("client", [binaries["ttrpc-cdh-tool"]["path"], "--socket", "unix://" + str(rpc_dir / "front.sock"),
                "--timeout", "50", "unwrap-key", "--annotation-path", str(output / "client/unwrap-input.json")],
                sanitized_env("client"), output)
        client = await manager.wait("client", 60)
        observed = decode_native_capture(operation_id="C01-native-unwrap", stdout=(output / "processes/client/stdout.bin").read_bytes(),
                stderr=(output / "processes/client/stderr.bin").read_bytes(), returncode=client["returncode"],
                process_closed=client["process_closed"], capture_complete=client["capture_complete"])
        observation = dataclasses.asdict(observed)
        for field in ("output_bytes", "reply_json"):
            data = observation.pop(field)
            observation[field + "_base64"] = None if data is None else base64.b64encode(data).decode("ascii")
        observation["scope"] = SCOPE
        observation["phi"] = None
        observation["target_comparison"] = "NOT_PERFORMED"
        publish(output / "NATIVE_OBSERVATION.json", observation)
        if client["returncode"] != 0 or observed.successful_output is not True:
            raise RuntimeError("native C01 command did not produce a cleanly encoded success output; not a safety verdict")
    except BaseException as exc:
        errors.append(error(exc))
    finally:
        if manager:
            for name in ("client", "cdh", "aa", "kbs"):
                if name in manager.handles:
                    try:
                        await manager.stop(name)
                    except BaseException as exc:
                        errors.append({"cleanup_process": name, **error(exc)})
        # All upstream/client owners are stopped before asking relays to close.
        deadline = time.monotonic() + 5
        while any(relay.tasks for relay in relays) and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        for relay in reversed(relays):
            try:
                summary = await relay.close()
                if summary["capture_complete"] is not True:
                    errors.append({"type": "IncompleteRelayCapture", "message": str(relay.output_dir)})
            except BaseException as exc:
                errors.append({"cleanup_relay": str(relay.output_dir), **error(exc)})
        for identity in reversed(sockets):
            try:
                cleanup.append(cleanup_socket(identity))
            except BaseException as exc:
                cleanup.append({"path": identity["path"], "status": "cleanup_error", "error": error(exc)})
        if rpc_dir:
            try:
                rpc_dir.rmdir()  # only the exact newly-created directory, only when empty
                cleanup.append({"path": str(rpc_dir), "status": "removed_own_empty_directory"})
            except OSError as exc:
                cleanup.append({"path": str(rpc_dir), "status": "residual_retained", "error": error(exc)})
        final_ports = None
        if admitted:
            try:
                final_ports = require_ports_free()
            except BaseException as exc:
                errors.append({"cleanup_ports": [8081, 8082], **error(exc)})
        if any(c["status"] in ("identity_changed_not_removed", "cleanup_error", "residual_retained") for c in cleanup):
            errors.append({"type": "CleanupIncomplete", "message": "inspect retained exact-path residuals"})
        if admitted and os.path.lexists(AA_SOCKET):
            errors.append({"type": "AASocketResidual", "message": str(AA_SOCKET)})
        processes = {} if not manager else manager.records
        errors.extend(service_exit_issues(processes))
        if any(p["errors"] or not p["process_closed"] or not p["capture_complete"] for p in processes.values()):
            errors.append({"type": "ProcessRecordIncomplete", "message": "inspect per-process records"})
        result = {"scope": SCOPE, "status": "SMOKE_CAPTURED_REQUIRES_INDEPENDENT_VALIDATION" if not errors else "DEVELOPMENT_SMOKE_FAILED",
                  "errors": errors, "processes": processes, "cleanup": cleanup, "final_ports": final_ports,
                  "observation_present": observation is not None, "ended_unix_ns": time.time_ns(),
                  "boundary": "no Phi, target LEK comparison, token verification or pipeline finding inferred"}
        try:
            publish(output / "RESULT.json", result)
            payloads = {str(p.relative_to(output)): sha(p.read_bytes()) for p in sorted(output.rglob("*")) if p.is_file()}
            publish(output / "MANIFEST.json", {"scope": SCOPE, "payload_sha256": payloads,
                    "private_files": [p for p in payloads if p.startswith("private/")],
                    "boundary": "private dummy signing key retained locally, not a public-release manifest"})
        except BaseException as exc:
            result["status"] = "DEVELOPMENT_SMOKE_FAILED"
            result["errors"].append({"final_publication": True, **error(exc)})
            print("C01 final publication failed; partial output retained", file=sys.stderr, flush=True)
    return result


async def run_with_signals(args):
    task = asyncio.current_task()
    cancelled = False
    def stop_once():
        nonlocal cancelled
        if not cancelled:
            cancelled = True
            task.cancel()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_once)
    try:
        return await execute(args)
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path)
    parser.add_argument("--client-input", required=True, type=Path)
    parser.add_argument("--broker-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(run_with_signals(args))
        print(json.dumps({"scope": SCOPE, "status": result["status"], "output": str(args.output.absolute())}), flush=True)
        return 0 if result["status"] == "SMOKE_CAPTURED_REQUIRES_INDEPENDENT_VALIDATION" else 2
    except BaseException as exc:
        print(f"C01 runner failed before complete result: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
