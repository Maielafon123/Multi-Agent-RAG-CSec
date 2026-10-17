import unittest

from csec.config import EXPLOIT_SPLITTER
from csec.ingest.common import chunk_rows, enrich_row_identifiers


class IngestIdentifiersTest(unittest.TestCase):
    def test_stable_identifiers_do_not_depend_on_call_order(self) -> None:
        item = {
            "code": "void f() { system(user_input); }",
            "filename": "CWE78_bad_1.c",
            "function_name": "f",
            "source_file": "testcases/CWE78/example_01a.c",
            "source_dataset": "juliet",
        }
        self.assertEqual(enrich_row_identifiers(item, "bad"), enrich_row_identifiers(item, "bad"))


    def test_chunk_payload_keeps_document_identity(self) -> None:
        identifiers = enrich_row_identifiers(
            {
                "code": "void f() { system(user_input); }",
                "filename": "CWE78_bad_1.c",
                "function_name": "f",
                "source_file": "testcases/CWE78/example_01a.c",
            },
            "bad",
        )
        row = {
            "code": "void f() { system(user_input); }",
            "cwe": "CWE78",
            "filename": "CWE78_bad_1.c",
            "function_name": "f",
            "label": "os_command_injection",
            "source": "dataset.jsonl",
            "kind": "bad",
            **identifiers,
        }
        chunks = chunk_rows([row], EXPLOIT_SPLITTER)
        self.assertTrue(chunks)
        self.assertTrue(all(chunk["document_id"] == identifiers["document_id"] for chunk in chunks))
        self.assertEqual(len({chunk["chunk_id"] for chunk in chunks}), len(chunks))


if __name__ == "__main__":
    unittest.main()
