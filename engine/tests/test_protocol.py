import json
import unittest

from diskguardian import protocol
from diskguardian.protocol import EngineError


class DecodeLineTests(unittest.TestCase):
    def test_accepts_valid_request(self):
        request = protocol.decode_line(b'{"request_id":"req_1","operation":"scan_disk","params":{}}')
        self.assertEqual(request.request_id, "req_1")
        self.assertEqual(request.operation, "scan_disk")
        self.assertEqual(request.params, {})

    def test_defaults_missing_params_to_object(self):
        request = protocol.decode_line(b'{"request_id":"req_1","operation":"scan_disk"}')
        self.assertEqual(request.params, {})

    def test_rejects_invalid_json(self):
        with self.assertRaises(EngineError) as caught:
            protocol.decode_line(b"{not json")
        self.assertEqual(caught.exception.code, protocol.E_BAD_REQUEST)

    def test_rejects_non_object(self):
        with self.assertRaises(EngineError) as caught:
            protocol.decode_line(b"[1,2,3]")
        self.assertEqual(caught.exception.code, protocol.E_BAD_REQUEST)

    def test_rejects_missing_request_id(self):
        with self.assertRaises(EngineError) as caught:
            protocol.decode_line(b'{"operation":"scan_disk"}')
        self.assertEqual(caught.exception.code, protocol.E_BAD_REQUEST)

    def test_rejects_oversized_request(self):
        payload = b'{"request_id":"req_1","operation":"scan_disk","params":{"x":"' + b"a" * protocol.MAX_REQUEST_BYTES + b'"}}'
        with self.assertRaises(EngineError) as caught:
            protocol.decode_line(payload)
        self.assertEqual(caught.exception.code, protocol.E_TOO_LARGE)


class EnvelopeTests(unittest.TestCase):
    def test_success_shape(self):
        envelope = protocol.success("req_1", {"ok": True})
        self.assertEqual(envelope, {"request_id": "req_1", "success": True, "data": {"ok": True}, "error": None})

    def test_failure_shape(self):
        envelope = protocol.failure("req_1", protocol.E_ENGINE, "boom")
        self.assertFalse(envelope["success"])
        self.assertEqual(envelope["error"]["code"], protocol.E_ENGINE)
        self.assertIsNone(envelope["data"])

    def test_response_size_cap_replaces_payload(self):
        line = protocol.encode_response(protocol.success("req_1", {"blob": "x" * (protocol.MAX_RESPONSE_BYTES + 10)}))
        envelope = json.loads(line)
        self.assertFalse(envelope["success"])
        self.assertEqual(envelope["error"]["code"], protocol.E_TOO_LARGE)
        self.assertLess(len(line), protocol.MAX_RESPONSE_BYTES)

    def test_response_is_one_line(self):
        line = protocol.encode_response(protocol.success("req_1", {"text": "line\nbreak"}))
        self.assertEqual(line.count(b"\n"), 1)
        self.assertTrue(line.endswith(b"\n"))


class ParameterTests(unittest.TestCase):
    def test_optional_int_bounds(self):
        self.assertEqual(protocol.optional_int({}, "limit", 5, minimum=1, maximum=10), 5)
        with self.assertRaises(EngineError):
            protocol.optional_int({"limit": 99}, "limit", 5, minimum=1, maximum=10)
        with self.assertRaises(EngineError):
            protocol.optional_int({"limit": True}, "limit", 5, minimum=1, maximum=10)

    def test_optional_str_list(self):
        self.assertEqual(protocol.optional_str_list({"paths": ["C:\\Temp"]}, "paths"), ["C:\\Temp"])
        with self.assertRaises(EngineError):
            protocol.optional_str_list({"paths": "C:\\Temp"}, "paths")


if __name__ == "__main__":
    unittest.main()
