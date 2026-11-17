"""Decode one pinned ttRPC unary UnWrapKey exchange, without expected labels.

This establishes wire syntax/association only. The caller must separately trust
the relay's endpoint/process identity, forwarding/completeness and native source.
An error frame is not a policy-denial classifier or proof of no global leakage.
"""
from dataclasses import dataclass
import hashlib
import struct

LIMIT = 4 << 20


class CaptureError(ValueError):
    pass


def utf8(raw, label):
    try:
        return raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        raise CaptureError('invalid protobuf UTF-8: ' + label) from exc


def varint(raw, offset):
    result = 0
    for index in range(10):
        if offset >= len(raw):
            raise CaptureError('truncated varint')
        value = raw[offset]
        offset += 1
        if index == 9 and value > 1:
            raise CaptureError('uint64 overflow')
        result |= (value & 127) << (index * 7)
        if not value & 128:
            return result, offset
    raise CaptureError('overlong varint')


def fields(raw, schema, repeated=()):
    """Strict bounded protobuf subset; unknown/duplicate singular fields reject.

    Rejection means unsupported/invalid evidence, not a negative native effect.
    Noncanonical but legal protobuf field ordering is accepted.
    """
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise CaptureError('invalid protobuf byte input')
    result = {}
    offset = 0
    count = 0
    while offset < len(raw):
        count += 1
        if count > 4096:
            raise CaptureError('field budget exceeded')
        tag, offset = varint(raw, offset)
        number, wire = tag >> 3, tag & 7
        if number not in schema or wire != schema[number]:
            raise CaptureError('unknown field or incompatible wire type')
        if wire == 0:
            value, offset = varint(raw, offset)
        elif wire == 2:
            size, offset = varint(raw, offset)
            if size > LIMIT or offset + size > len(raw):
                raise CaptureError('truncated or oversized field')
            value, offset = raw[offset:offset + size], offset + size
        else:
            raise CaptureError('unsupported wire type')
        if number in repeated:
            result.setdefault(number, []).append(value)
        elif number in result:
            raise CaptureError('duplicate singular field')
        else:
            result[number] = value
    return result


def unary_frame(raw, wanted_type):
    if type(raw) is not bytes or len(raw) < 10:
        raise CaptureError('missing complete ttRPC header')
    size, stream_id, type_, flags = struct.unpack('>IIBB', raw[:10])
    if size > LIMIT or len(raw) != size + 10:
        raise CaptureError('incomplete, oversized or multiple frames')
    if type_ != wanted_type or flags != 0:
        raise CaptureError('not the declared zero-flag unary frame')
    if stream_id == 0 or stream_id % 2 != 1:
        raise CaptureError('invalid client stream identifier')
    return stream_id, raw[10:]


@dataclass(frozen=True)
class UnaryObservation:
    stream_id: int
    request_input: bytes
    status_code: int
    status_message: str
    response_json: bytes | None
    request_sha256: str
    response_sha256: str


def decode_unwrap_exchange(client_to_server, server_to_client, *, expected_request_input):
    """Associate one response with the exact actual native request bytes.

    expected_request_input is the pre-recorded RPC input, NOT LEK or a case label.
    No result is inferred from EOF, timeout, missing bytes or malformed encoding.
    """
    if type(expected_request_input) is not bytes:
        raise TypeError('request input must be bytes')
    request_id, request_raw = unary_frame(client_to_server, 1)
    response_id, response_raw = unary_frame(server_to_client, 2)
    if request_id != response_id:
        raise CaptureError('request/response stream mismatch')
    request = fields(request_raw, {1: 2, 2: 2, 3: 2, 4: 0, 5: 2}, repeated=(5,))
    if request.get(1) != b'keyprovider.KeyProviderService' or request.get(2) != b'UnWrapKey':
        raise CaptureError('wrong service or method')
    for metadata in request.get(5, []):
        item = fields(metadata, {1: 2, 2: 2})
        for value in item.values():
            utf8(value, 'metadata')
    request_wrapper = fields(request.get(3, b''), {1: 2})
    input_bytes = request_wrapper.get(1, b'')
    if input_bytes != expected_request_input:
        raise CaptureError('actual RPC input differs from declared input')
    response = fields(response_raw, {1: 2, 2: 2})
    if 1 not in response:
        raise CaptureError('no explicit Status message in response')
    status = fields(response[1], {1: 0, 2: 2, 3: 2}, repeated=(3,))
    code = status.get(1, 0)
    if code not in range(17):
        raise CaptureError('unknown status code')
    message = utf8(status.get(2, b''), 'status.message')
    for detail in status.get(3, []):
        any_message = fields(detail, {1: 2, 2: 2})
        utf8(any_message.get(1, b''), 'Status.details.type_url')
    payload = response.get(2, b'')
    if code != 0:
        if payload:
            raise CaptureError('error status with nonempty payload is ambiguous')
        reply_json = None
    else:
        wrapper = fields(payload, {1: 2})
        if 1 not in wrapper:
            raise CaptureError('success without wrapped output')
        reply_json = wrapper[1]
    return UnaryObservation(request_id, input_bytes, code, message, reply_json,
                            hashlib.sha256(client_to_server).hexdigest(),
                            hashlib.sha256(server_to_client).hexdigest())
