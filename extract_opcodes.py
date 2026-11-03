"""Extract the packet-wrapper table layout established through IDA.

This accepts only the exact constant-ID getter and string getter instruction
forms verified in IDA, never infers IDs from schema order or field numbers.
"""
import argparse
import collections
import hashlib
import json
import re
import struct
from pathlib import Path
from decode_packets import load_schemas, resolve_schema


class PE:
    def __init__(self, data):
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3c)[0]
        if data[pe:pe+4] != b"PE\0\0":
            raise ValueError("Invalid PE")
        count = struct.unpack_from("<H", data, pe+6)[0]
        optional_size = struct.unpack_from("<H", data, pe+20)[0]
        self.base = struct.unpack_from("<Q", data, pe+24+24)[0]
        self.sections = {}
        for i in range(count):
            pos = pe + 24 + optional_size + 40*i
            name = data[pos:pos+8].rstrip(b"\0").decode()
            vs, va, rs, raw = struct.unpack_from("<IIII", data, pos+8)
            self.sections.setdefault(name, []).append((self.base+va, raw, min(rs, len(data)-raw), vs))

    def read(self, va, count):
        for sections in self.sections.values():
            for start, raw, size, _ in sections:
                if start <= va and va+count <= start+size:
                    return self.data[raw+va-start:raw+va-start+count]
        return b""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    pe = PE(data)
    rva, raw, size, _ = pe.sections[".rdata"][0]
    rdata = data[raw:raw+size]
    text_va, text_raw, text_size, _ = pe.sections[".text"][0]
    text = data[text_raw:text_raw+text_size]
    names = {}
    pattern = rb"(?:P\x00)(?:(?:C\x002\x00(?:S|F|A)\x00(?:E\x00)?)|(?:(?:S|F|A)\x00(?:E\x00)?2\x00C\x00))_\x00(?:[A-Za-z0-9_]\x00){1,160}\x00\x00"
    for hit in re.finditer(pattern, rdata):
        names[rva+hit.start()] = hit.group()[:-2].decode("utf-16le")
    getters = {}
    for hit in re.finditer(rb"\x48\x8d\x05[\s\S]{4}\xc3", text):
        function = text_va+hit.start()
        target = function+7+struct.unpack_from("<i", hit.group(), 3)[0]
        if target in names:
            getters[function] = (names[target], target)
    rows = []
    for offset in range(16, len(rdata)-48, 8):
        getter = struct.unpack_from("<Q", rdata, offset)[0]
        if getter not in getters:
            continue
        destructor, id_getter = struct.unpack_from("<QQ", rdata, offset-16)
        if not text_va <= destructor < text_va+text_size:
            continue
        code = pe.read(id_getter, 6)
        if len(code) != 6 or code[0] != 0xb8 or code[5] != 0xc3:
            continue
        opcode = struct.unpack_from("<I", code, 1)[0]
        if not 0 <= opcode <= 65535:
            continue
        name, name_va = getters[getter]
        rows.append({"packet": name, "opcode": opcode, "opcode_hex": hex(opcode),
                     "family": name.split("_", 1)[0], "message_basename": name.split("_", 1)[1],
                     "vtable_va": hex(rva+offset-16), "id_getter_va": hex(id_getter),
                     "name_getter_va": hex(getter), "name_va": hex(name_va),
                     "id_getter_bytes": code.hex(),
                     "evidence": "wrapper vtable slot 1 constant ID; slot 2 exact UTF-16 packet name"})
    unique = {}
    for row in rows:
        old = unique.get(row["packet"])
        if old and old["opcode"] != row["opcode"]:
            raise ValueError("Conflicting opcode: " + row["packet"])
        unique[row["packet"]] = row
    rows = sorted(unique.values(), key=lambda r: (r["family"], r["opcode"]))
    if (args.output / "descriptors.normalized.pb").exists():
        _, schema_names = load_schemas(args.output / "descriptors.normalized.pb")
        for row in rows:
            schema = resolve_schema(row, schema_names)
            row["schema_file"] = schema[0] if schema else None
            row["schema"] = schema[1] if schema else None
    args.output.mkdir(parents=True, exist_ok=True)
    unresolved = sorted(set(names.values()) - {r["packet"] for r in rows})
    (args.output/"opcodes.json").write_text(json.dumps({"source": str(args.binary), "source_sha256": hashlib.sha256(data).hexdigest(),
        "method": "IDA-established wrapper getter layout; constants only, no inferred numbering",
        "unresolved_named_packets": unresolved, "entries": rows}, indent=2), encoding="utf-8")
    print(json.dumps({"named_strings": len(names), "name_getters": len(getters), "opcode_entries": len(rows),
                      "families": dict(collections.Counter(r["family"] for r in rows)),
                      "schema_linked": sum(bool(r.get("schema")) for r in rows),
                      "examples": [{k:r[k] for k in ("packet", "opcode", "vtable_va", "id_getter_va")} for r in rows if r["packet"] in ("PC2S_StartSkillReq","PS2C_UnitAddNoti","PS2C_DamageNoti","PC2S_Ping")]}, indent=2))


if __name__ == "__main__":
    main()
