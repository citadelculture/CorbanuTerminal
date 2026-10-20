"""Inert synthetic fixtures; no policy generator, dispatcher, or import actions.

Only a future separately admitted controller may call start() or probe().
No existing failed profile is changed or accepted by this module.
"""
import errno
import hashlib
import ipaddress
import selectors
import socket
import threading
import time

TRANSPORTS = ("tcp", "udp")
DESTINATIONS = (
    ("allowed_ipv4", "127.0.0.1", "P", "allow"),
    ("ipv6_loopback", "::1", "P", "deny"),
    ("ipv4_mapped", "::ffff:127.0.0.1", "P", "deny"),
    ("owned_nonloopback", "OWNED_RFC1918", "P", "deny"),
    ("other_port", "127.0.0.1", "Q", "deny"),
)
CASES = tuple(
    {"id": transport + "_" + name, "transport": transport,
     "host": host, "portLabel": port, "expected": expected}
    for transport in TRANSPORTS
    for name, host, port, expected in DESTINATIONS
)
SOCKET_SECONDS = 2.0
FIXTURE_SECONDS = 90.0
MAX_EVENTS = 96
DENIAL_ERRNOS = frozenset((errno.EACCES, errno.EPERM))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical_owned_ipv4(value):
    address = ipaddress.IPv4Address(value)
    require(str(address) == value, "Use a canonical numeric owned IPv4 address")
    require(any(address in ipaddress.IPv4Network(network) for network in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
            "Only an explicitly reviewed local RFC1918 interface is supported")
    return value


def endpoint(case, manifest):
    require(case in CASES, "Unknown case")
    require(manifest["P"] != manifest["Q"], "Port control is not distinct")
    host = manifest["ownedIpv4"] if case["host"] == "OWNED_RFC1918" else case["host"]
    if case["host"] == "OWNED_RFC1918":
        canonical_owned_ipv4(host)
    port = manifest[case["portLabel"]]
    require(type(port) is int and 1024 <= port <= 65535, "Invalid unprivileged port")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    address = (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
    kind = socket.SOCK_STREAM if case["transport"] == "tcp" else socket.SOCK_DGRAM
    return family, kind, address


def probe(case, manifest, token):
    """One numeric endpoint attempt; timeouts/refusal never count as denial."""
    require(type(token) is str and len(token) == 32
            and all(c in "0123456789abcdef" for c in token), "Invalid synthetic token")
    family, kind, address = endpoint(case, manifest)
    payload = ("NBF3:" + token).encode("ascii")
    result = {"case": case["id"], "transport": case["transport"],
              "status": "incomplete", "errno": None, "operation": "create"}
    started = time.monotonic()

    def remaining():
        seconds = SOCKET_SECONDS - (time.monotonic() - started)
        if seconds <= 0:
            raise TimeoutError("Synthetic endpoint attempt deadline")
        return seconds

    try:
        with socket.socket(family, kind) as client:
            client.settimeout(remaining())
            result["operation"] = "connect"
            client.connect(address)
            result["operation"] = "send"
            client.settimeout(remaining())
            client.sendall(payload)
            result["operation"] = "receive"
            expected = b"ACK:" + payload
            response = b""
            while len(response) < len(expected):
                client.settimeout(remaining())
                block = client.recv(len(expected) - len(response))
                if not block:
                    break
                response += block
                if kind == socket.SOCK_DGRAM:
                    break
            result["status"] = "connected" if response == expected else "wrong_reply"
    except OSError as exc:
        result["errno"] = exc.errno
        result["status"] = (
            "permission_denied" if exc.errno in DENIAL_ERRNOS
            and result["operation"] in ("connect", "send") else "error"
        )
    result["elapsedSeconds"] = time.monotonic() - started
    return result


class OwnedEndpoints:
    """Eight exact-address sockets; IPv4-mapped cases use the IPv4 P listener.

    A successful bind is necessary, not independent proof of interface ownership.
    The future controller must bind the supplied numeric address to current host
    interface evidence. Missing IPv6/address support is a hold, not a skipped pass.
    No wildcard bind, DNS, socket reuse option, or port-allocation retry is used.
    """

    def __init__(self, owned_ipv4, expected_tokens):
        self.owned_ipv4 = canonical_owned_ipv4(owned_ipv4)
        require(len(expected_tokens) == 30 and len(set(expected_tokens)) == 30,
                "Require distinct before/subject/after tokens for ten cases")
        require(all(type(t) is str and len(t) == 32
                    and all(c in "0123456789abcdef" for c in t) for t in expected_tokens),
                "Invalid token set")
        self.expected = {("NBF3:" + token).encode("ascii") for token in expected_tokens}
        self.sockets = []
        self.events = []
        self.error = None
        self.manifest = None
        self.thread = None
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.selector = selectors.DefaultSelector()

    def _bind(self, host, port, transport, label):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        kind = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
        sock = socket.socket(family, kind)
        self.sockets.append(sock)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            require(sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1,
                    "IPv6 listener must not absorb IPv4")
        sock.bind((host, port))
        sock.settimeout(0.2)
        if transport == "tcp":
            sock.listen(4)
        self.selector.register(sock, selectors.EVENT_READ, (transport, label))
        return sock.getsockname()[1]

    def start(self):
        require(self.thread is None and not self.sockets, "One fixture start only")
        try:
            p = self._bind("127.0.0.1", 0, "tcp", "ipv4_P")
            self._bind("127.0.0.1", p, "udp", "ipv4_P")
            for host, label in (("::1", "ipv6_P"), (self.owned_ipv4, "interface_P")):
                for transport in TRANSPORTS:
                    self._bind(host, p, transport, label)
            q = self._bind("127.0.0.1", 0, "tcp", "ipv4_Q")
            self._bind("127.0.0.1", q, "udp", "ipv4_Q")
            require(p != q and p >= 1024 and q >= 1024, "Port admission failed")
            self.manifest = {"P": p, "Q": q, "ownedIpv4": self.owned_ipv4,
                             "fixedCaseIds": [case["id"] for case in CASES]}
            self.deadline = time.monotonic() + FIXTURE_SECONDS
            self.thread = threading.Thread(target=self._serve, name="owned-boundary-fixtures")
            self.thread.start()
            return dict(self.manifest)
        except BaseException:
            self.close()
            raise

    def _record(self, transport, listener, event, payload=b""):
        with self.lock:
            require(len(self.events) < MAX_EVENTS, "Synthetic fixture event cap")
            self.events.append({"transport": transport, "listener": listener,
                                "event": event,
                                "payloadSha256": hashlib.sha256(payload).hexdigest()})

    def _serve(self):
        try:
            while not self.stop.is_set():
                require(time.monotonic() < self.deadline, "Fixture lifetime expired")
                for key, _ in self.selector.select(0.05):
                    transport, label = key.data
                    if transport == "tcp":
                        conn, _ = key.fileobj.accept()
                        with conn:
                            conn.settimeout(0.2)
                            self._record(transport, label, "accepted")
                            payload = b""
                            while len(payload) < 37:
                                block = conn.recv(37 - len(payload))
                                if not block:
                                    break
                                payload += block
                            require(payload in self.expected, "Unexpected synthetic TCP payload")
                            self._record(transport, label, "received", payload)
                            conn.sendall(b"ACK:" + payload)
                    else:
                        payload, sender = key.fileobj.recvfrom(128)
                        self._record(transport, label, "received", payload)
                        require(payload in self.expected, "Unexpected synthetic UDP payload")
                        key.fileobj.sendto(b"ACK:" + payload, sender)
        except BaseException as exc:
            self.error = type(exc).__name__ + ": " + str(exc)

    def snapshot(self):
        require(self.error is None, "Fixture server failed: " + str(self.error))
        require(self.thread is not None and self.thread.is_alive(), "Fixture is not live")
        with self.lock:
            return [dict(row) for row in self.events]

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=3)
        for sock in self.sockets:
            sock.close()
        self.selector.close()
        return {"listenersClosed": all(sock.fileno() == -1 for sock in self.sockets),
                "serverThreadStopped": self.thread is None or not self.thread.is_alive(),
                "serverError": self.error}


def assess_case(case, before, subject, after, subject_events):
    """Pure evidence comparison; a timeout or missing fixture is never a pass."""
    require(case in CASES, "Unknown case")
    controls_ok = all(row.get("case") == case["id"]
                      and row.get("transport") == case["transport"]
                      and row.get("status") == "connected" for row in (before, after))
    subject_ok = (subject.get("case") == case["id"]
                  and subject.get("transport") == case["transport"]
                  and subject.get("inheritedMarkersMatched") is True)
    if case["expected"] == "allow":
        subject_ok = subject_ok and subject.get("status") == "connected"
    else:
        subject_ok = (subject_ok and subject.get("status") == "permission_denied"
                      and subject.get("errno") in DENIAL_ERRNOS
                      and subject.get("operation") in ("connect", "send")
                      and subject_events == [])
    return {"case": case["id"], "controlsPassed": controls_ok,
            "subjectPassed": subject_ok, "passed": controls_ok and subject_ok,
            "canaryAdmitted": False}


if __name__ == "__main__":
    raise SystemExit("Inert fixture module: no policy or runtime dispatcher is admitted.")
