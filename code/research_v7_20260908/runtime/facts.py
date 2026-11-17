"""Basic V7 propositions, separated from case expectations and wire decoding.

This is not a monitor, native collector, source authenticator, or new finite model.
Qualified error evidence must be established by a separate scope-aware collector.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib

from .native_output import MAX_CAPTURE_BYTES, NativeObservation, require_bool, standard_base64, strict_json


class EvidenceConflict(ValueError):
    pass


def _maybe_bool(value: object, name: str) -> None:
    if value is not None:
        require_bool(value, name)


def evaluate_phi_output(*, actual_contra: bool | None, successful_output: bool | None) -> bool | None:
    """not(contra and successful output), using only actual qualified facts."""
    _maybe_bool(actual_contra, "actual_contra")
    _maybe_bool(successful_output, "successful_output")
    if actual_contra is False or successful_output is False:
        return True
    if actual_contra is True and successful_output is True:
        return False
    return None


@dataclass(frozen=True)
class QualifiedRpcError:
    """Declared external evidence, not established by constructing this object.

    Collector must prove this is the completed error response for operation_id,
    not a local timeout, panic, transport error or another operation's response.
    raw_response is retained for source-to-claim inspection. Caller qualification
    is an explicit trust assumption, not a built-in verification result.
    """
    operation_id: str
    raw_response: bytes
    qualification_reference: str

    def __post_init__(self) -> None:
        if type(self.operation_id) is not str or not self.operation_id.strip():
            raise ValueError("nonempty operation_id required")
        if type(self.raw_response) is not bytes or not 0 < len(self.raw_response) <= MAX_CAPTURE_BYTES:
            raise ValueError("raw completed RPC error response required")
        if type(self.qualification_reference) is not str or not self.qualification_reference.strip():
            raise ValueError("external qualification reference required")


def output_fact(observation: NativeObservation, *, rpc_error: QualifiedRpcError | None = None) -> bool | None:
    if type(observation) is not NativeObservation:
        raise TypeError("NativeObservation required")
    if rpc_error is None:
        return observation.successful_output
    if type(rpc_error) is not QualifiedRpcError:
        raise TypeError("QualifiedRpcError required")
    if observation.operation_id != rpc_error.operation_id:
        raise EvidenceConflict("RPC error belongs to another operation")
    if observation.successful_output is True:
        raise EvidenceConflict("success payload and qualified terminal error conflict")
    if not observation.process_closed or not observation.capture_complete:
        return None
    if observation.stdout_sha256 != hashlib.sha256(b"").hexdigest():
        return None  # nonempty malformed/error stdout does not prove no output
    if observation.returncode == 0:
        raise EvidenceConflict("qualified error disagrees with native client's zero exit")
    return False


class ReferenceKind(str, Enum):
    VALID = "VALID"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    INVALID_INPUT = "INVALID_INPUT"


@dataclass(frozen=True)
class GcmReference:
    kind: ReferenceKind
    plaintext: bytes | None
    reason: str

    def __post_init__(self) -> None:
        if type(self.kind) is not ReferenceKind:
            raise TypeError("ReferenceKind enum required")
        if type(self.reason) is not str or not self.reason:
            raise ValueError("reference reason required")
        if self.kind is ReferenceKind.VALID:
            if type(self.plaintext) is not bytes or len(self.plaintext) != 32:
                raise ValueError("valid fixture reference must contain 32-byte plaintext")
        elif self.plaintext is not None:
            raise ValueError("invalid/auth-failed reference must not contain plaintext")


def check_gcm_reference(*, annotation_json: bytes, resources: dict[str, bytes]) -> GcmReference:
    """Local AEAD reference, NOT a native CDH result or independent crypto proof.

    cryptography AESGCM may share OpenSSL with the selected CDH backend. The
    resources map is reference-only input, never an input to native decoding.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if type(resources) is not dict or any(type(k) is not str or type(v) is not bytes or len(v) != 32 for k, v in resources.items()):
        raise TypeError("resources must map URI strings to 32-byte dummy KEKs")
    try:
        a = strict_json(annotation_json)
        fields = {"version", "provider", "kid", "iv", "wrapped_data", "wrap_type", "provider_settings", "annotations"}
        if type(a) is not dict or set(a) != fields:
            raise ValueError("unexpected annotation schema")
        if a["version"] != "0.1.0" or a["provider"] != "kbs" or a["wrap_type"] != "A256GCM":
            raise ValueError("unsupported version/provider/wrap type")
        if a["provider_settings"] != {} or a["annotations"] != {}:
            raise ValueError("unexpected provider fields")
        if type(a["kid"]) is not str or a["kid"] not in resources:
            raise ValueError("unknown reference resource")
        if type(a["iv"]) is not str or type(a["wrapped_data"]) is not str:
            raise ValueError("IV/ciphertext must be base64 strings")
        iv = standard_base64(a["iv"].encode("ascii"))
        ciphertext = standard_base64(a["wrapped_data"].encode("ascii"))
        if len(iv) != 12 or len(ciphertext) != 48:
            raise ValueError("expected 12-byte IV and 32-byte ciphertext plus 16-byte tag")
    except (ValueError, UnicodeError) as exc:
        return GcmReference(ReferenceKind.INVALID_INPUT, None, str(exc))
    try:
        plaintext = AESGCM(resources[a["kid"]]).decrypt(iv, ciphertext, b"")
    except InvalidTag:
        return GcmReference(ReferenceKind.AUTHENTICATION_FAILURE, None, "local AEAD authentication failed")
    return GcmReference(ReferenceKind.VALID, plaintext, "local reference decrypted with current kid's KEK and empty AAD")


def evaluate_gcm_correctness(*, successful_output: bool | None, output_bytes: bytes | None, reference: GcmReference) -> bool | None:
    """Return-only integrity obligation; a known no-output result is vacuous true.

    This does not classify availability, actual native error cause, or Phi_output.
    """
    _maybe_bool(successful_output, "successful_output")
    if type(reference) is not GcmReference:
        raise TypeError("GcmReference required")
    if output_bytes is not None and type(output_bytes) is not bytes:
        raise TypeError("output_bytes must be bytes or None")
    if successful_output is not True and output_bytes is not None:
        raise EvidenceConflict("output bytes require a positive output fact")
    if successful_output is True and output_bytes is None:
        raise EvidenceConflict("positive output fact requires actual bytes")
    if successful_output is False:
        return True
    if successful_output is None or reference.kind is ReferenceKind.INVALID_INPUT:
        return None
    if reference.kind is ReferenceKind.AUTHENTICATION_FAILURE:
        return False
    return output_bytes == reference.plaintext


def target_match(observation: NativeObservation, *, expected_lek: bytes) -> bool | None:
    """Optional reference comparison; not a Phi_output or decoding input."""
    if type(observation) is not NativeObservation:
        raise TypeError("NativeObservation required")
    if type(expected_lek) is not bytes or len(expected_lek) != 32:
        raise ValueError("expected_lek must be 32 dummy bytes")
    if observation.successful_output is not True:
        return None
    return observation.output_bytes == expected_lek
