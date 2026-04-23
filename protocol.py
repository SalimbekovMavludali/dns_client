import struct
import socket
import random
from enum import IntEnum

class QTYPE(IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    OPT = 41 # EDNS0

def encode_dns_name(domain: str) -> bytes:
    parts = domain.rstrip('.').split('.')
    encoded = b""
    for part in parts:
        encoded += bytes([len(part)]) + part.encode("ascii")
    return encoded + b'\x00'

def decode_dns_name(data: bytes, offset: int, max_jumps: int=2) -> tuple[str, int]:
    labels = []
    jumps = 0
    original_offset = offset

    while True:
        if offset >= len(data):
            raise ValueError("Truncated DNS name")
        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if jumps >= max_jumps:
                raise ValueError("DNS compression loop detected")
            pointer = struct.unpack_from("!H", data, offset[0]) & 0x3FFF
            if jumps == 0:
                original_offset = offset + 2
            offset = pointer
            jumps += 1
        else:
            offset += 1
            if offset + length > len(data):
                raise ValueError("Truncated DNS label")
            labels.append(data[offset:offset + length].decode("ascii"))
            offset += length

    if jumps == 0:
        original_offset = offset
    return ".".join(labels), original_offset

def build_opt_rr(udp_payload: int = 4096, version: int = 0, extended_rcode: int = 0, flags: int = 0) -> bytes:
    ttl = (extended_rcode << 24) | (version << 16) | flags
    return b"\x00" + struct.pack("!HHIH", QTYPE.OPT, udp_payload, ttl, 0)

def build_dns_query(domain: str, qtype: int = QTYPE.A) -> tuple[bytes, int]:
    tx_id = random.randint(0, 65535)
    # Flags: 0x0100 = Recursion Desired (RD)
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 1) # ARCOUNT = 1 for EDNS0
    question = encode_dns_name(domain) + struct.pack("!HH", qtype, 1)
    opt = build_opt_rr()
    return header + question + opt, tx_id

def parse_dns_response(data: bytes, expected_id: int) -> dict:
    if len(data) < 12:
        raise ValueError("Response too short")

    tx_id, flags, qdcount, ancount, _, arcount = struct.unpack_from("!HHHHHH", data, 0)
    rcode = flags & 0x000F

    if tx_id != expected_id:
        raise ValueError("Transaction ID mismatch")
    if rcode != 0:
        raise ValueError(f"DNS Error: RCODE={rcode}")

    offset = 12
    # skip questions
    for _ in range(qdcount):
        _, offset = decode_dns_name(data, offset)
        offset += 4

    answers = []
    for _ in range(ancount):
        name, offset = decode_dns_name(data, offset)
        qtype, qclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength

        if qtype == QTYPE.A:
            answers.append({"name": name, "type": "A", "value": socket.inet_ntoa(rdata), "ttl": ttl})
        elif qtype == QTYPE.AAAA:
            answers.append(
                {"name": name, "type": "AAAA", "value": socket.inet_ntop(socket.AF_INET6, rdata), "ttl": ttl})
        else:
            answers.append({"name": name, "type": qtype, "value": rdata.hex(), "ttl": ttl})

    # Skip additional section (OPT RR, etc.)
    for _ in range(arcount):
        _, offset = decode_dns_name(data, offset)
        offset += 8 # TYPE+CLASS+TTL+RDLENGTH
        rdlength = struct.unpack_from("!H", data, offset - 2)[0]
        offset += rdlength

    return {"anwsers": answers, "flags": flags, "ancount": ancount}