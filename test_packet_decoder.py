import struct
import tempfile
import unittest
from pathlib import Path
from google.protobuf import message_factory, descriptor_pb2
from google.protobuf.message import DecodeError
from decode_packets import frames, load_schemas, resolve_schema


class PacketDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Synthetic fixtures exercise the decoder without distributing game descriptors.
        cls.fixture_directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fixture_directory.cleanup)
        descriptor = descriptor_pb2.FileDescriptorProto(
            name="synthetic.proto", package="x5.pb", syntax="proto3")
        for name in ("StartSkillReq", "TimeSyncReq", "TimeSyncRes", "CommonErrorRes", "SystemMessageNoti"):
            message = descriptor.message_type.add(name=name)
            if name == "StartSkillReq":
                message.field.add(name="target_ids", number=1, type=4, label=3)
        descriptor_set = descriptor_pb2.FileDescriptorSet()
        descriptor_set.file.add().CopyFrom(descriptor)
        fixture = Path(cls.fixture_directory.name) / "synthetic.pb"
        fixture.write_bytes(descriptor_set.SerializeToString())
        cls.pool, cls.names = load_schemas(fixture)
        cls.header = b"0" * 40 + b"\0" + b"\0" * 16

    def test_complete_prefix_and_partial_final_record(self):
        packet = struct.pack("<IHH", 123, 4, 5)
        self.assertEqual(len(list(frames(self.header + packet + packet[:-1]))), 1)
        self.assertEqual(len(list(frames(self.header + packet + packet))), 2)

    def test_bad_header_and_bad_length_are_rejected(self):
        with self.assertRaises(ValueError):
            list(frames(b"x" * 100))
        with self.assertRaises(ValueError):
            list(frames(self.header + struct.pack("<IHH", 123, 3, 5)))

    def test_c2s_sequence_is_not_part_of_protobuf(self):
        cls = message_factory.GetMessageClass(self.pool.FindMessageTypeByName("x5.pb.StartSkillReq"))
        original = cls()
        original.target_ids.append(12345)
        body = original.SerializeToString()
        packet = struct.pack("<IHHI", 123, 8+len(body), 20010, 7) + body
        row = list(frames(self.header + packet))[0]
        self.assertEqual(struct.unpack_from("<I", row[4])[0], 7)
        self.assertEqual(cls.FromString(row[4][4:]), original)
        with self.assertRaises(DecodeError):
            cls.FromString(row[4])

    def test_shared_system_and_time_sync_schemas_resolve_exactly(self):
        for name in ("TimeSyncReq", "TimeSyncRes", "CommonErrorRes", "SystemMessageNoti"):
            row = {"family": "PC2S" if name.endswith("Req") else "PS2C", "message_basename": name}
            self.assertEqual(resolve_schema(row, self.names)[1], "x5.pb." + name)
        self.assertIsNone(resolve_schema({"family": "PS2C", "message_basename": "NotARealPacket"}, self.names))


if __name__ == "__main__":
    unittest.main()
