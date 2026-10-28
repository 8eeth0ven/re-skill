import hashlib
import ipaddress
import struct
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..errors import BudgetExceeded, Cancelled, InvalidInput
from ..models import Asset, ProfileResult
from ..safety import Budget, load_json, open_regular, public_url, read_bytes
from ..scope import ScopePolicy


def packet_metadata(packet: bytes, linktype: int) -> dict:
    offset = 0
    if linktype == 1:
        if len(packet) < 14:
            return {"malformed": "ethernet"}
        protocol = struct.unpack_from(">H", packet, 12)[0]
        offset = 14
        for _ in range(2):
            if protocol not in (0x8100, 0x88A8):
                break
            if offset + 4 > len(packet):
                return {"malformed": "vlan"}
            protocol = struct.unpack_from(">H", packet, offset + 2)[0]
            offset += 4
        if protocol not in (0x0800, 0x86DD):
            return {"protocol": f"ethernet:{protocol:04x}"}
    elif linktype in (101, 228, 229):
        pass
    elif linktype == 113:
        if len(packet) < 16:
            return {"malformed": "linux-sll"}
        protocol = struct.unpack_from(">H", packet, 14)[0]
        offset = 16
        if protocol not in (0x0800, 0x86DD):
            return {"protocol": f"sll:{protocol:04x}"}
    elif linktype == 127:
        if len(packet) < 8:
            return {"malformed": "radiotap"}
        header_size = struct.unpack_from("<H", packet, 2)[0]
        if header_size > len(packet):
            return {"malformed": "radiotap-length"}
        return {"protocol": "802.11-radiotap", "radiotap_bytes": header_size}
    else:
        return {"protocol": f"linktype:{linktype}", "unsupported_linktype": True}
    data = packet[offset:]
    if not data:
        return {"malformed": "empty-ip"}
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return {"malformed": "ipv4"}
        size = (data[0] & 15) * 4
        total = struct.unpack_from(">H", data, 2)[0]
        if size < 20 or size > len(data) or total < size:
            return {"malformed": "ipv4-header-size"}
        source = str(ipaddress.ip_address(data[12:16]))
        destination = str(ipaddress.ip_address(data[16:20]))
        transport = data[9]
        fragmented = bool(struct.unpack_from(">H", data, 6)[0] & 0x3FFF)
    elif version == 6:
        if len(data) < 40:
            return {"malformed": "ipv6"}
        source, destination = str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40]))
        transport, size, fragmented = data[6], 40, False
    else:
        return {"malformed": "ip-version"}
    result = {"source": source, "destination": destination, "ip_version": version, "protocol": {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(transport, f"ip:{transport}"), "fragmented": fragmented}
    payload = data[size:]
    if transport in (6, 17) and not fragmented:
        if len(payload) < 4:
            result["malformed"] = "transport-header"
        else:
            result["source_port"], result["destination_port"] = struct.unpack_from(">HH", payload)
    return result


def pcap(data: bytes, budget: Budget) -> dict:
    if len(data) < 24:
        raise InvalidInput("Truncated PCAP header")
    mapping = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if data[:4] not in mapping:
        raise InvalidInput("Invalid PCAP magic")
    endian, divisor = mapping[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack_from(endian + "HHIIII", data, 4)
    if (major, minor) != (2, 4) or not 1 <= snaplen <= 16_777_216:
        raise InvalidInput("Unsupported PCAP version/snaplen")
    offset, packets, count = 24, [], 0
    while offset < len(data):
        budget.check()
        if offset + 16 > len(data):
            raise InvalidInput("Truncated PCAP packet header")
        seconds, fraction, included, original = struct.unpack_from(endian + "IIII", data, offset)
        if included > snaplen or included > original or offset + 16 + included > len(data) or fraction >= divisor:
            raise InvalidInput("Invalid PCAP packet length/timestamp")
        packet = data[offset + 16:offset + 16 + included]
        count += 1
        if count > 200000:
            raise BudgetExceeded("PCAP packet count budget exceeded")
        packets.append({"index": count - 1, "offset": offset + 16, "captured_bytes": included, "original_bytes": original, "timestamp": seconds + fraction / divisor, **packet_metadata(packet, linktype)})
        offset += 16 + included
    return {"format": "pcap", "linktype": linktype, "packet_count": count, "packets": packets}


def pcapng(data: bytes, budget: Budget) -> dict:
    offset, endian, interfaces, packets, sections = 0, "<", [], [], 0
    while offset < len(data):
        budget.check()
        if offset + 12 > len(data):
            raise InvalidInput("Truncated PCAPNG block")
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            if offset + 28 > len(data):
                raise InvalidInput("Truncated PCAPNG section")
            bom = data[offset + 8:offset + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else ""
            if not endian:
                raise InvalidInput("Invalid PCAPNG byte-order magic")
            interfaces, sections = [], sections + 1
        elif sections == 0:
            raise InvalidInput("PCAPNG needs a section header")
        kind, size = struct.unpack_from(endian + "II", data, offset)
        if size < 12 or size % 4 or offset + size > len(data) or struct.unpack_from(endian + "I", data, offset + size - 4)[0] != size:
            raise InvalidInput("Invalid PCAPNG block length/trailer")
        body = data[offset + 8:offset + size - 4]
        if kind == 1:
            if len(body) < 8 or len(interfaces) >= 1000:
                raise InvalidInput("Invalid PCAPNG interface block")
            linktype, _, snaplen = struct.unpack_from(endian + "HHI", body)
            interfaces.append({"linktype": linktype, "snaplen": snaplen})
        elif kind == 6:
            if len(body) < 20:
                raise InvalidInput("Invalid PCAPNG packet block")
            interface, high, low, included, original = struct.unpack_from(endian + "IIIII", body)
            if interface >= len(interfaces) or included > original or 20 + included > len(body):
                raise InvalidInput("Invalid PCAPNG interface/packet bounds")
            if interfaces[interface]["snaplen"] and included > interfaces[interface]["snaplen"]:
                raise InvalidInput("PCAPNG packet exceeds snaplen")
            if len(packets) >= 200000:
                raise BudgetExceeded("PCAPNG packet count exceeded")
            packets.append({"index": len(packets), "section": sections - 1, "offset": offset + 28, "captured_bytes": included, "original_bytes": original, "timestamp_ticks": (high << 32) | low, **packet_metadata(body[20:20 + included], interfaces[interface]["linktype"])})
        elif kind == 3:
            if not interfaces or len(body) < 4:
                raise InvalidInput("Invalid simple packet block")
            original = struct.unpack_from(endian + "I", body)[0]
            included = min(original, interfaces[0]["snaplen"] or original)
            if included > len(body) - 4:
                raise InvalidInput("Truncated simple packet block")
            packets.append({"index": len(packets), "offset": offset + 12, "captured_bytes": included, "original_bytes": original, **packet_metadata(body[4:4 + included], interfaces[0]["linktype"])})
        offset += size
    return {"format": "pcapng", "sections": sections, "packet_count": len(packets), "packets": packets}


HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")
# Deep-layer bounds: the base index already bounds its own packet walk; these
# keep the second (scapy) pass inside the same order of magnitude.
MAX_DEEP_PACKETS = 200_000
MAX_STREAMS = 1_000
MAX_STREAM_BYTES = 1_048_576
MAX_REPORTED_STREAMS = 200
MAX_HEADER_LINES = 32
SIGNATURE_CHARS = 400


def _redact_target(target: str) -> str:
    """Request targets with query strings get HAR-grade value redaction: query
    values frequently carry PII/secrets even when their names do not."""
    try:
        parts = urlsplit(target)
    except ValueError:
        return "[INVALID URL]"
    if parts.scheme:
        return public_url(target)
    query = urlencode([(key, "[REDACTED]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit(("", "", parts.path, query, ""))[:2048]


def _signature(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) > SIGNATURE_CHARS:
        return collapsed[:SIGNATURE_CHARS] + "..."
    return collapsed


def _reassemble(segments: dict[int, bytes]) -> tuple[bytes, int, bool]:
    """Order TCP segments by sequence number; count sequence gaps and report
    whether the reassembled payload hit the per-stream byte cap."""
    payload: bytearray = bytearray()
    expected: int | None = None
    gaps = 0
    for sequence in sorted(segments):
        data = segments[sequence]
        if expected is None:
            payload.extend(data)
            expected = sequence + len(data)
            continue
        if sequence + len(data) <= expected:
            continue  # full retransmission of covered bytes
        if sequence > expected:
            gaps += 1
        payload.extend(data[expected - sequence:])
        expected = sequence + len(data)
    return bytes(payload[:MAX_STREAM_BYTES]), gaps, len(payload) > MAX_STREAM_BYTES


def _parse_http_head(head: bytes, direction_bytes: int, segments: int, gaps: int, truncated: bool) -> dict | None:
    """Extract redacted request/response metadata from one reassembled direction.

    Only structure survives here: methods, paths (query-redacted), hosts,
    status codes and header NAMES. Values of sensitive headers are never read,
    so no token can leak into the analysis even before report redaction.
    """
    separator = head.find(b"\r\n\r\n")
    if separator < 0:
        return None
    lines = head[:separator].split(b"\r\n")
    if not lines:
        return None
    names: list[str] = []
    host = None
    for line in lines[1:1 + MAX_HEADER_LINES]:
        name, colon, value = line.partition(b":")
        if not colon or not name.strip():
            continue
        clean = name.strip().decode("latin-1", "replace")
        names.append(clean[:128])
        if clean.lower() == "host" and host is None:
            host = value.strip().decode("latin-1", "replace")[:255]
    lowered = {name.lower() for name in names}
    record = {
        "header_names": names,
        "credentials_present": bool(lowered & {"authorization", "proxy-authorization", "cookie"}),
        "bytes": direction_bytes, "segments": segments, "sequence_gaps": gaps, "truncated": truncated,
    }
    start = lines[0].decode("latin-1", "replace").strip()
    method = start.split(" ", 1)[0]
    if method in HTTP_METHODS:
        fields = start.split(" ")
        if len(fields) < 2:
            return None
        record.update({
            "type": "request", "method": method, "path": _redact_target(fields[1]),
            "host": host,
        })
        return record
    if start.startswith("HTTP/") and len(start.split(" ")) >= 2:
        status_field = start.split(" ")[1]
        record.update({
            "type": "response", "protocol": start.split(" ")[0][:16],
            "status": int(status_field) if status_field.isdigit() else None,
        })
        return record
    return None


def _http_streams(segments: dict[tuple, dict[int, bytes]], order: dict[tuple, int]) -> list[dict]:
    """Pair reassembled directions into connections and keep only HTTP ones."""
    connections: dict[tuple, dict] = {}
    sequence: list[tuple] = []
    for key in sorted(segments, key=lambda item: order.get(item, 0)):
        payload, gaps, truncated = _reassemble(segments[key])
        head = _parse_http_head(payload, len(payload), len(segments[key]), gaps, truncated)
        peer = (key[2], key[3], key[0], key[1])
        connection = tuple(sorted((key, peer)))
        if connection not in connections:
            connections[connection] = {"source": None, "destination": None, "request": None, "response": None}
            sequence.append(connection)
        entry = connections[connection]
        if head is None:
            continue
        if head["type"] == "request":
            entry["request"] = head
            entry["source"] = f"{key[0]}:{key[1]}"
            entry["destination"] = f"{key[2]}:{key[3]}"
        else:
            entry["response"] = head
            if entry["source"] is None:
                entry["source"] = f"{key[2]}:{key[3]}"
                entry["destination"] = f"{key[0]}:{key[1]}"
    streams = []
    for connection in sequence:
        entry = connections[connection]
        if entry["request"] is None and entry["response"] is None:
            continue  # TLS, binary or non-HTTP payloads are not reported
        entry["stream"] = len(streams)
        streams.append(entry)
        if len(streams) >= MAX_REPORTED_STREAMS:
            break
    return streams


def deep_reassembly(path: Path, budget: Budget) -> dict | None:
    """Optional scapy TCP-reassembly layer (pyproject extra: traffic-deep).

    Returns None when scapy is unavailable so the caller records an honest
    skip; scapy dissection failures degrade with a signature instead of
    crashing the profile. Runs beside (never instead of) the built-in header
    index, and never decrypts anything: TLS streams carry no key material.
    """
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether  # noqa: F401 -- registers DLT 1 in conf.l2types so PcapReader dissects Ethernet instead of yielding Raw payloads
        from scapy.utils import PcapReader
    except Exception as exc:  # missing extra or a broken import: honest skip with the real cause
        deep_reassembly.last_import_error = f"{type(exc).__name__}: {exc}"
        return None
    deep_reassembly.last_import_error = None
    segments: dict[tuple, dict[int, bytes]] = {}
    order: dict[tuple, int] = {}
    packets = 0
    try:
        # The file object is opened (and closed) here, not inside scapy: its
        # reader leaks the handle when its constructor fails mid-header, and a
        # leaked handle would wedge the run directory on Windows.
        with open_regular(path) as stream, PcapReader(stream) as reader:
            for packet in reader:
                budget.check()
                packets += 1
                if packets > MAX_DEEP_PACKETS:
                    raise BudgetExceeded("Deep-reassembly packet budget exceeded")
                tcp = packet.getlayer(TCP)
                if tcp is None:
                    continue
                payload = bytes(tcp.payload)
                if not payload:
                    continue
                network = packet.getlayer(IP) or packet.getlayer(IPv6)
                if network is None:
                    continue
                key = (str(network.src), int(tcp.sport), str(network.dst), int(tcp.dport))
                if len(segments) < MAX_STREAMS or key in segments:
                    segments.setdefault(key, {})[int(tcp.seq)] = payload
                if key not in order:
                    order[key] = len(order)
    except (Cancelled, BudgetExceeded):
        raise
    except Exception as exc:
        return {
            "status": "degraded", "streams": _http_streams(segments, order),
            "packets": packets,
            "error": f"scapy reassembly stopped early: {type(exc).__name__}: {_signature(str(exc))}",
        }
    return {"status": "succeeded", "streams": _http_streams(segments, order), "packets": packets, "error": None}


def har(path: Path) -> dict:
    value = load_json(path)
    if not isinstance(value, dict) or not isinstance(value.get("log"), dict) or not isinstance(value["log"].get("entries"), list):
        raise InvalidInput("HAR requires log.entries")
    entries = value["log"]["entries"]
    if len(entries) > 20000:
        raise BudgetExceeded("HAR entry count exceeded")
    records = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict) or not isinstance(entry.get("response"), dict):
            raise InvalidInput("HAR entry requires request/response")
        request, response = entry["request"], entry["response"]
        url = request.get("url", "")
        body = response.get("content", {})
        records.append({
            "index": index, "url": public_url(url), "method": request.get("method"),
            "status": response.get("status"), "started": entry.get("startedDateTime"),
            "request_header_names": [x.get("name") for x in request.get("headers", []) if isinstance(x, dict)],
            "response_header_names": [x.get("name") for x in response.get("headers", []) if isinstance(x, dict)],
            "credentials_present": bool(request.get("cookies")) or any(str(x.get("name", "")).lower() in ("authorization", "cookie") for x in request.get("headers", []) if isinstance(x, dict)),
            "mime_type": body.get("mimeType"), "response_body_size": body.get("size"),
            "response_body_sha256": hashlib.sha256(str(body.get("text", "")).encode("utf-8")).hexdigest(),
        })
    return {"format": "har", "entry_count": len(records), "entries": records, "bodies_in_report": False}


def analyze(asset: Asset, path: Path | None, output: Path, scope: ScopePolicy, budget: Budget) -> ProfileResult:
    if path is None or path.is_dir():
        raise InvalidInput("Traffic profile needs a PCAP/PCAPNG/HAR file")
    if asset.format == "har" or path.suffix == ".har":
        analysis = har(path)
        result = ProfileResult(analysis=analysis)
        result.check("har-request-response-index")
        for entry in analysis["entries"]:
            if entry["credentials_present"] and entry["url"].startswith("http://"):
                result.candidate("har-cleartext-credentials", "Recorded HTTP request carries credentials", "HAR contains Authorization/Cookie or cookie metadata on an HTTP URL; source capture and actual transport need contextual review.", location=f"HAR entry {entry['index']}", severity="high", remediation="Use HTTPS and prevent secrets from entering shared traffic exports.")
        result.limitations.append("HAR header names and response hashes are indexed; bodies, cookie values and authentication values are omitted.")
        return result
    data = read_bytes(path, budget.limits["max_input_bytes"])
    analysis = pcapng(data, budget) if data[:4] == b"\x0a\x0d\x0d\x0a" else pcap(data, budget)
    protocols = Counter(packet.get("protocol", "malformed") for packet in analysis["packets"])
    flows = Counter((packet.get("source"), packet.get("source_port"), packet.get("destination"), packet.get("destination_port"), packet.get("protocol")) for packet in analysis["packets"] if packet.get("source"))
    analysis["protocols"] = dict(protocols)
    analysis["flows"] = [{"source": key[0], "source_port": key[1], "destination": key[2], "destination_port": key[3], "protocol": key[4], "packets": count} for key, count in flows.items()]
    result = ProfileResult(analysis=analysis)
    result.check("packet-container-and-flow-index")
    malformed = sum(1 for packet in analysis["packets"] if "malformed" in packet)
    if malformed:
        result.check("packet-payload-headers", "degraded", f"{malformed} malformed/truncated packet payloads")
    # Optional second layer (parallel to the built-in index, never replacing
    # it): scapy TCP reassembly with redacted HTTP request/response extraction.
    deep = deep_reassembly(path, budget)
    if deep is None:
        cause = deep_reassembly.last_import_error or "scapy is not installed"
        result.check("traffic-deep-reassembly", "skipped", f"scapy unavailable ({cause}); install re-skill-runner[traffic-deep] for TCP stream reassembly")
    else:
        analysis["http_streams"] = deep["streams"]
        analysis["http_stream_count"] = len(deep["streams"])
        analysis["deep_packets_scanned"] = deep["packets"]
        detail = deep.get("error") or f"{len(deep['streams'])} HTTP stream(s) reassembled from {deep['packets']} packets"
        result.check("traffic-deep-reassembly", deep["status"], detail)
    result.limitations.append("Indexes link/IP/TCP/UDP headers and radiotap capture identity; TLS decryption (no key material is available), IPv6 extension traversal and wireless frame decoding are never performed. Recorded endpoints are not probed.")
    result.limitations.append("When scapy is installed, a best-effort TCP reassembly layer adds redacted HTTP request/response records (methods, query-redacted paths, header names, credential presence); it proves capture content only and never contacts the recorded endpoints.")
    return result
