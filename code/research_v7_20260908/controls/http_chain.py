"""Qualify the pinned cold token-provider HTTP chain, not a policy verdict.

All connections and retries are consumed. The final refresh after the third 401
is retained even though its token is never selected by a resource GET.
"""
from dataclasses import dataclass
from pathlib import Path

from ..smoke.validate_c01 import need, read_regular, record, sha
from ..runtime.native_output import strict_json
from ..wire.http_capture import ParseState, parse_http1_connection
from ..wire.ear_claims import verify_ear_with_pinned_key

AUTH = "/kbs/v0/auth"
ATTEST = "/kbs/v0/attest"
POLICY_DENY = "https://github.com/confidential-containers/kbs/errors/PolicyDeny"


@dataclass(frozen=True)
class Exchange:
    connection: str
    request: object
    response: object
    request_mono: tuple[int, int]
    response_mono: tuple[int, int]
    request_wall: tuple[int, int]
    response_wall: tuple[int, int]


def covered_span(event_raw, clocks, direction, start, end):
    need(type(start) is int and type(end) is int and 0 <= start < end, "invalid HTTP offset span")
    selected = []
    for line in event_raw.splitlines(keepends=True):
        event = strict_json(line)
        if (event["event"] == "CAPTURED" and event["direction"] == direction
                and event["offset"] < end and event["offset"] + event["size"] > start):
            selected.append((event, clocks[sha(line)]))
    need(selected and selected[0][0]["offset"] <= start
         and selected[-1][0]["offset"] + selected[-1][0]["size"] >= end, "HTTP span is not fully captured")
    return ((selected[0][0]["monotonic_ns"], selected[-1][0]["monotonic_ns"]),
            (selected[0][1]["wall_before_ns"], selected[-1][1]["wall_after_ns"]))


def collect_exchanges(tcp_dir, relay, clocks):
    need(relay.qualified, "whole TCP relay must qualify first")
    exchanges = []
    for conn in relay.connections:
        parsed = parse_http1_connection(connection_id=conn.connection_id,
            client_to_server=conn.client_to_upstream, server_to_client=conn.upstream_to_client,
            client_capture_complete=conn.qualified, server_capture_complete=conn.qualified,
            server_eof=conn.upstream_eof_observed)
        need(parsed.state == ParseState.COMPLETE and parsed.client_consumed == len(conn.client_to_upstream)
             and parsed.server_consumed == len(conn.upstream_to_client), "HTTP has an unparsed/incomplete/unsupported suffix")
        events = read_regular(tcp_dir / conn.connection_id / "events.jsonl", 4 << 20)
        for pair in parsed.exchanges:
            req, res = pair.request, pair.response
            need(pair.pairing_qualified and res is not None, "HTTP request/response pairing not qualified")
            need(not pair.interim_responses, "interim 1xx responses require a separately declared timing profile")
            need(not req.header_values(b"content-encoding") and not res.header_values(b"content-encoding"),
                 "encoded HTTP bodies are outside this frozen profile")
            need(req.header_values(b"host") == (b"127.0.0.1:8081",), "unadmitted actual HTTP Host")
            rm, rw = covered_span(events, clocks, "client_to_upstream", req.start, req.end)
            sm, sw = covered_span(events, clocks, "upstream_to_client", res.start, res.end)
            need(rm[1] < sm[0] and rw[1] <= sw[0], "response is not strictly after complete request")
            exchanges.append(Exchange(conn.connection_id, req, res, rm, sm, rw, sw))
    need(3 <= len(exchanges) <= 11, "unsupported cold-chain exchange count")
    exchanges.sort(key=lambda item: item.request_mono[0])
    for before, after in zip(exchanges, exchanges[1:]):
        need(before.response_mono[1] < after.request_mono[0], "overlapping or ambiguous cold HTTP chronology")
    return exchanges


def signed_interval(token, public_key, issuer, lower_ns, upper_ns):
    need(type(lower_ns) is int and type(upper_ns) is int and 0 <= lower_ns <= upper_ns,
         "invalid observed token interval")
    lower = verify_ear_with_pinned_key(token=token, public_key_pem=public_key,
        expected_issuer=issuer, observed_at_unix=lower_ns // 1_000_000_000)
    upper = verify_ear_with_pinned_key(token=token, public_key_pem=public_key,
        expected_issuer=issuer, observed_at_unix=upper_ns // 1_000_000_000)
    need(lower.token_sha256 == upper.token_sha256, "token interval verification changed token")
    return lower


def qualify_chain(exchanges, *, resource_api, public_key, issuer):
    """No expected EAR, active policy, control id or fixture outcome is accepted."""
    need(resource_api in ("/kbs/v0/resource/default/attestflow-v7/kek-a",
                          "/kbs/v0/resource/default/attestflow-v7/kek-b"), "unadmitted resource URI")
    need(3 <= len(exchanges) <= 11, "cold-chain exchange budget")
    pos, get_count = 0, 0
    handshakes, gets = [], []
    seen_tokens, seen_nonces, seen_cookies = set(), set(), set()
    last_status = None
    while pos < len(exchanges):
        need(pos + 1 < len(exchanges), "incomplete final handshake")
        auth, attest = exchanges[pos], exchanges[pos + 1]
        need((auth.request.method, auth.request.target, auth.response.status) == ("POST", AUTH, 200)
             and (attest.request.method, attest.request.target, attest.response.status) == ("POST", ATTEST, 200),
             "expected complete actual auth/attest handshake")
        need(auth.connection == attest.connection, "auth and attest must share their observed session connection")
        need(auth.request.cookie is None and auth.request.authorization is None,
             "cold auth unexpectedly carries prior credentials")
        auth_body = strict_json(auth.request.body)
        need(type(auth_body) is dict and auth_body.get("tee") == "sample", "this local native profile requires actual sample evidence")
        challenge, attestation = strict_json(auth.response.body), strict_json(attest.request.body)
        nonce = challenge.get("nonce")
        need(type(nonce) is str and nonce and nonce not in seen_nonces
             and attestation.get("runtime-data", {}).get("nonce") == nonce, "challenge nonce missing/reused/unassociated")
        seen_nonces.add(nonce)
        cookies = auth.response.header_values(b"set-cookie")
        need(len(cookies) == 1, "exactly one actual auth cookie required")
        cookie = cookies[0].split(b";", 1)[0]
        need(b"=" in cookie and cookie not in seen_cookies and attest.request.cookie == cookie
             and attest.request.authorization is None, "fresh auth/attest cookie association failed")
        seen_cookies.add(cookie)
        obj = strict_json(attest.response.body)
        need(type(obj) is dict and set(obj) == {"token"} and type(obj["token"]) is str,
             "unsupported actual attest token response")
        token = obj["token"].encode("ascii")
        digest = sha(token)
        need(digest not in seen_tokens, "fresh token identity is ambiguous/reused")
        seen_tokens.add(digest)
        # Validate the unused final refresh too, at the interval of its actual
        # response. Issuance claims never supply the observation timestamp.
        ear = signed_interval(token, public_key, issuer, *attest.response_wall)
        hs = {"connection": auth.connection, "token_sha256": digest,
              "actual_cpu_ear_status": ear.cpu_status, "used_by_resource_get": False,
              "attest_response_wall_interval_ns": list(attest.response_wall)}
        handshakes.append(hs)
        pos += 2
        if pos == len(exchanges):
            need(get_count == 3 and last_status == 401, "unexplained unused handshake")
            break
        get = exchanges[pos]
        need(get_count < 3 and (get.request.method, get.request.target) == ("GET", resource_api),
             "unexpected extra/missing/wrong-resource GET")
        need(get.connection != auth.connection and get.request.cookie is None
             and get.request.authorization == b"Bearer " + token and get.request.bearer_token == token,
             "resource GET does not select exact current handshake Bearer with Cookie absent")
        need(get.request.body == b"", "resource GET body is outside this profile")
        actual = signed_interval(token, public_key, issuer, get.request_wall[0], get.response_wall[1])
        hs["used_by_resource_get"] = True
        status = get.response.status
        classification = "HTTP_200_RESOURCE_RESPONSE" if status == 200 else "OTHER_HTTP_ERROR"
        error_type, error_detail = None, None
        if status != 200:
            info = strict_json(get.response.body)
            need(type(info) is dict and set(info) == {"type", "detail"}
                 and type(info["type"]) is str and type(info["detail"]) is str, "unsupported actual KBS error body")
            error_type, error_detail = info["type"], info["detail"]
            if status == 401 and error_type == POLICY_DENY and error_detail == "Access denied by policy":
                classification = "EXPLICIT_POLICY_DENY"
        gets.append({"connection": get.connection, "token_sha256": digest,
                     "actual_cpu_ear_status": actual.cpu_status, "http_status": status,
                     "classification": classification, "error_type": error_type, "error_detail": error_detail,
                     "request_to_response_wall_interval_ns": [get.request_wall[0], get.response_wall[1]],
                     "cookie_absent": True, "response_body_sha256": sha(get.response.body)})
        get_count += 1
        last_status = status
        pos += 1
        if status != 401:
            need(pos == len(exchanges), "extra traffic after terminal resource result")
            break
        need(pos < len(exchanges), "401 must retain the client's next refresh, including after the third GET")
    need(get_count > 0 and pos == len(exchanges), "HTTP chain not exhausted")
    used_statuses = {g["actual_cpu_ear_status"] for g in gets}
    contra = None if len(used_statuses) != 1 else next(iter(used_statuses)) == "contraindicated"
    return {"handshakes": handshakes, "resource_gets": gets,
            "all_get_count": get_count, "http_exchange_count": len(exchanges),
            "actual_cpu_ear_statuses": sorted(used_statuses), "actual_contra": contra,
            "all_gets_explicit_policy_deny": all(g["classification"] == "EXPLICIT_POLICY_DENY" for g in gets),
            "any_resource_http_200": any(g["http_status"] == 200 for g in gets),
            "first_http_monotonic_ns": exchanges[0].request_mono[0],
            "last_http_monotonic_ns": exchanges[-1].response_mono[1],
            "http_messages": [{"connection": e.connection, "method": e.request.method, "target": e.request.target,
                "status": e.response.status, "request_offsets": [e.request.start, e.request.end],
                "response_offsets": [e.response.start, e.response.end],
                "request_sha256": e.request.raw_sha256, "response_sha256": e.response.raw_sha256}
                for e in exchanges],
            "boundary": "Signed EAR associated with every actual GET; HTTP 200 alone establishes neither JWE structure nor direct KEK plaintext observation."}
