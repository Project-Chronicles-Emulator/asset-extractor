"""Decode native Chronicles packet logs using recovered opcode getters/schemas."""
import argparse
import collections
import csv
import hashlib
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory, json_format


def load_schemas(path):
    desc_set = descriptor_pb2.FileDescriptorSet.FromString(path.read_bytes())
    pool = descriptor_pool.DescriptorPool()
    pending = list(desc_set.file)
    while pending:
        loaded = []
        errors = {}
        for proto in pending:
            try:
                pool.Add(proto)
                loaded.append(proto)
            except Exception as exc:
                errors[proto.name] = str(exc)
        if not loaded:
            raise ValueError(errors)
        pending = [p for p in pending if p not in loaded]
    names = collections.defaultdict(list)
    for proto in desc_set.file:
        for msg in proto.message_type:
            names[msg.name].append((proto.name, proto.package + "." + msg.name))
    return pool, names


def resolve_schema(row, names):
    family = {"PC2S": "p_c2s", "PS2C": "p_s2c"}.get(row["family"])
    candidates = names[row["message_basename"]]
    filtered = [p for p in candidates if family and p[0].startswith(family)]
    if not filtered:
        # Time sync and shared system replies live outside the direction files.
        # Accept only an exact, unique x5.pb message name; never guess by fields.
        filtered = [p for p in candidates if p[1].startswith("x5.pb.")]
    return filtered[0] if len(filtered) == 1 else None


def frames(data):
    if len(data) < 57 or data[40] != 0 or any(c not in b"0123456789abcdef" for c in data[:40]):
        raise ValueError("Unexpected native-log build header")
    pos = 57
    while pos + 8 <= len(data):
        elapsed_ms, length, opcode = struct.unpack_from("<IHH", data, pos)
        if length < 4:
            raise ValueError(f"Invalid record length {length} at {pos}")
        end = pos + 4 + length
        if end > len(data):
            return
        yield pos, end, elapsed_ms, opcode, data[pos + 8:end]
        pos = end


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("protocol", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--live-start-offset", type=int)
    args = parser.parse_args()
    data = args.log.read_bytes()
    pool, names = load_schemas(args.protocol / "descriptors.normalized.pb")
    source_map = json.loads((args.protocol / "opcodes.json").read_text())
    opcodes = {}
    for row in source_map["entries"]:
        if row["opcode"] in opcodes:
            raise ValueError("Opcode collision; must introduce transport namespaces")
        opcodes[row["opcode"]] = row
    args.output.mkdir(parents=True, exist_ok=True)
    statuses = collections.Counter()
    live_statuses = collections.Counter()
    counts = collections.Counter()
    live_counts = collections.Counter()
    first_tick = last_tick = None
    complete_end = 57
    new_frames = 0
    examples = {}
    with (args.output / "packets.decoded.jsonl").open("w", encoding="utf-8") as all_stream, \
            (args.output / "packets.live.jsonl").open("w", encoding="utf-8") as live_stream:
        for start, end, elapsed, opcode, payload in frames(data):
            complete_end = end
            first_tick = elapsed if first_tick is None else first_tick
            last_tick = elapsed
            during = args.live_start_offset is not None and start >= args.live_start_offset
            result = {"log_offset": start, "record_end": end, "elapsed_ms": elapsed, "opcode": opcode,
                      "recorded_after_initial_snapshot": during, "packet_bytes": end-start-4}
            row = opcodes.get(opcode)
            if row is None:
                result.update(status="unknown_opcode", payload_hex=payload.hex())
            else:
                result.update(packet=row["packet"], family=row["family"])
                schema = resolve_schema(row, names)
                if row["family"] == "PC2S":
                    if len(payload) < 4:
                        raise ValueError("C2S record lacks its uint32 sequence field")
                    result["sequence"] = struct.unpack_from("<I", payload)[0]
                    payload = payload[4:]
                result["protobuf_bytes"] = len(payload)
                if schema is None:
                    result.update(status="unresolved_schema", payload_hex=payload.hex())
                else:
                    file, name = schema
                    result.update(schema=name, schema_file=file)
                    message = message_factory.GetMessageClass(pool.FindMessageTypeByName(name))()
                    try:
                        consumed = message.ParseFromString(payload)
                        if consumed != len(payload):
                            raise ValueError("Incomplete payload consumption")
                        original = message.SerializeToString()
                        known = message_factory.GetMessageClass(message.DESCRIPTOR)()
                        known.CopyFrom(message)
                        known.DiscardUnknownFields()
                        if original != known.SerializeToString():
                            result.update(status="unknown_fields", payload_hex=payload.hex())
                        else:
                            result["status"] = "decoded"
                        result["message"] = json_format.MessageToDict(message, preserving_proto_field_name=True)
                    except Exception as exc:
                        result.update(status="decode_failed", error=str(exc), payload_hex=payload.hex())
                if result["status"] == "decoded" and row["packet"] in ("PC2S_StartSkillReq", "PS2C_DamageNoti", "PS2C_UnitAddNoti", "PS2C_StatSyncNoti"):
                    examples.setdefault(row["packet"], {"opcode": opcode, "schema": result["schema"], "fields": list(result["message"]), "log_offset": start})
            line = json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n"
            all_stream.write(line)
            statuses[result["status"]] += 1
            counts[opcode] += 1
            if during:
                live_stream.write(line)
                new_frames += 1
                live_statuses[result["status"]] += 1
                live_counts[opcode] += 1
    with (args.output / "observed-opcodes.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["opcode", "hex", "packet", "family", "schema", "all_records", "records_after_initial_snapshot"])
        for opcode, count in sorted(counts.items()):
            row = opcodes.get(opcode, {})
            schema = resolve_schema(row, names) if row else None
            writer.writerow([opcode, hex(opcode), row.get("packet"), row.get("family"), schema[1] if schema else "", count, live_counts[opcode]])
    summary = {"source": str(args.log), "source_sha256": hashlib.sha256(data).hexdigest(), "source_bytes": len(data),
               "native_build_id": data[:40].decode(), "header_bytes": 57,
               "header_base_raw": struct.unpack_from("<Q", data, 41)[0], "header_offset_raw": struct.unpack_from("<q", data, 49)[0],
               "framing": "native record: elapsed_ms:uint32 + packet; S2C packet: length:uint16 + opcode:uint16 + protobuf; C2S adds sequence:uint32 before protobuf; little endian",
               "opcode_mappings": len(opcodes), "observed_opcode_count": len(counts), "total_records": sum(counts.values()),
               "decode_statuses": dict(statuses), "first_elapsed_ms": first_tick, "last_elapsed_ms": last_tick,
               "complete_records_end_offset": complete_end, "incomplete_tail_bytes": len(data)-complete_end,
               "live_start_offset": args.live_start_offset, "records_after_initial_snapshot": new_frames,
               "live_decode_statuses": dict(live_statuses), "live_observed_opcodes": len(live_counts),
               "examples_without_payload_values": examples,
               "limits": ["Application packets from the native logger, not a NIC PCAP; network transport encryption/framing was not captured.",
                          "Historical session records and newly appended records are counted separately.",
                          "Incomplete final record is retained in the raw snapshot and never decoded as a complete packet.",
                          "Only observed messages have live compatibility evidence; unobserved schemas remain static evidence."]}
    (args.output / "decode-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k:v for k,v in summary.items() if k not in ("source", "source_sha256", "limits", "examples_without_payload_values", "framing")}, indent=2))
    if any(status != "decoded" for status in statuses):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
