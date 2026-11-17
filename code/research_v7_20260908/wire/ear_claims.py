"""Offline ES256/EAR check against a separately supplied P-256 public key.

The key must be obtained through the declared trusted local launch/config chain,
not from this JWT's own jwk header. No URL fetch, case label, expected EAR, nonce
renaming or effect judgment occurs here. Successful signature verification does
not establish that a KBS request selected this token or prove hardware identity.
"""
import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


class EarEvidenceError(ValueError):
    pass


def _b64(raw):
    if type(raw) is not bytes or not raw or len(raw) > (1 << 20):
        raise EarEvidenceError('missing or oversized base64url')
    try:
        decoded = base64.b64decode(raw + b'=' * (-len(raw) % 4), altchars=b'-_', validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EarEvidenceError('invalid base64url') from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b'=') != raw:
        raise EarEvidenceError('noncanonical unpadded base64url')
    return decoded


def _json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise EarEvidenceError('duplicate JSON member')
            out[key] = value
        return out
    def constant(value):
        raise EarEvidenceError('non-finite JSON number')
    try:
        out = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise EarEvidenceError('invalid JWT JSON') from exc
    if type(out) is not dict:
        raise EarEvidenceError('JWT header/payload must be objects')
    return out


@dataclass(frozen=True)
class EarObservation:
    token_sha256: str
    public_key_spki_sha256: str
    cpu_status: str
    is_contraindicated: bool
    header: dict
    claims: dict
    observed_at_unix: int
    boundary: str = 'signature/time under supplied key; request selection and key provenance external'


def verify_ear_with_pinned_key(*, token: bytes, public_key_pem: bytes,
                               expected_issuer: str, observed_at_unix: int):
    if type(token) is not bytes or not 0 < len(token) <= (1 << 20):
        raise EarEvidenceError('invalid compact JWT bytes')
    if type(public_key_pem) is not bytes or len(public_key_pem) > 65536:
        raise EarEvidenceError('invalid public-key input')
    if type(expected_issuer) is not str or not expected_issuer:
        raise EarEvidenceError('explicit expected issuer required')
    if type(observed_at_unix) is not int or observed_at_unix < 0:
        raise EarEvidenceError('explicit integer observation time required')
    parts = token.split(b'.')
    if len(parts) != 3:
        raise EarEvidenceError('not a compact signed JWT')
    header, claims = _json(_b64(parts[0])), _json(_b64(parts[1]))
    if header.get('alg') != 'ES256' or 'crit' in header or 'b64' in header:
        raise EarEvidenceError('unsupported algorithm or critical header semantics')
    if header.get('typ', 'JWT') != 'JWT':
        raise EarEvidenceError('unexpected token type')
    signature = _b64(parts[2])
    if len(signature) != 64:
        raise EarEvidenceError('ES256 requires 64-byte R||S signature')
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as exc:
        raise EarEvidenceError('cannot load supplied public key') from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise EarEvidenceError('supplied key must be P-256')
    # The header's key is not an authority; if present require agreement with the
    # external pinned key rather than silently verifying under the self-key.
    if 'jwk' in header:
        jwk = header['jwk']
        if (type(jwk) is not dict or jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256'
                or jwk.get('alg', 'ES256') != 'ES256' or 'd' in jwk):
            raise EarEvidenceError('invalid public header JWK')
        try:
            x, y = _b64(jwk['x'].encode('ascii')), _b64(jwk['y'].encode('ascii'))
        except (KeyError, AttributeError, UnicodeError) as exc:
            raise EarEvidenceError('missing or invalid JWK coordinates') from exc
        if len(x) != 32 or len(y) != 32:
            raise EarEvidenceError('P-256 coordinates must have fixed length')
        numbers = key.public_numbers()
        if (int.from_bytes(x, 'big'), int.from_bytes(y, 'big')) != (numbers.x, numbers.y):
            raise EarEvidenceError('self-header key disagrees with supplied pinned key')
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big'))
    try:
        key.verify(der, parts[0] + b'.' + parts[1], ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise EarEvidenceError('signature verification failed under pinned key') from exc
    if claims.get('iss') != expected_issuer:
        raise EarEvidenceError('issuer mismatch')
    if any(type(claims.get(k)) is not int for k in ('iat', 'exp')):
        raise EarEvidenceError('this profile requires integer iat and exp')
    if not 0 <= claims['iat'] <= observed_at_unix < claims['exp']:
        raise EarEvidenceError('outside declared token validity interval')
    if 'nbf' in claims and (type(claims['nbf']) is not int or not 0 <= claims['nbf'] <= observed_at_unix):
        raise EarEvidenceError('not-before requirement unsatisfied')
    try:
        status = claims['submods']['cpu0']['ear.status']
    except (KeyError, TypeError) as exc:
        raise EarEvidenceError('missing CPU EAR status') from exc
    if type(status) is not str or status not in ('none', 'affirming', 'warning', 'contraindicated'):
        raise EarEvidenceError('unsupported EAR status')
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return EarObservation(hashlib.sha256(token).hexdigest(), hashlib.sha256(spki).hexdigest(),
                          status, status == 'contraindicated', header, claims, observed_at_unix)
