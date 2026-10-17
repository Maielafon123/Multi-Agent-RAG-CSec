from types import SimpleNamespace
import unittest

from evals.eval_retrieval import ndcg_at_k, recall_at_k, reciprocal_rank_at_k, relevance_at_ranks


def hit(document_id: str, function_id: str = "function_x"):
    return SimpleNamespace(
        score=0.9,
        payload={"document_id": document_id, "function_id": function_id, "cwe": "CWE78"},
    )


class RetrievalMetricsTest(unittest.TestCase):
    def test_document_relevance_is_not_cwe_relevance(self) -> None:
        case = {
            "expected_cwe": "CWE-78",
            "relevant_document_ids": ["document_target"],
            "relevant_function_ids": [],
        }
        hits = [hit("document_wrong"), hit("document_target")]
        self.assertEqual(relevance_at_ranks(hits, case, 3), [0, 1, 0])
        self.assertEqual(recall_at_k(hits, case, 1), 0.0)
        self.assertEqual(recall_at_k(hits, case, 3), 1.0)
        self.assertEqual(reciprocal_rank_at_k(hits, case, 5), 0.5)
        self.assertAlmostEqual(ndcg_at_k(hits, case, 5), 1.0 / 1.5849625007)


    def test_duplicate_chunks_of_same_document_count_once(self) -> None:
        case = {
            "relevant_document_ids": ["document_a", "document_b"],
            "relevant_function_ids": [],
        }
        hits = [hit("document_a"), hit("document_a"), hit("document_b")]
        self.assertEqual(relevance_at_ranks(hits, case, 3), [1, 0, 1])
        self.assertEqual(recall_at_k(hits, case, 3), 1.0)


    def test_unannotated_case_is_not_reported_as_zero_recall(self) -> None:
        case = {"relevant_document_ids": [], "relevant_function_ids": []}
        self.assertIsNone(recall_at_k([hit("document_a")], case, 3))


if __name__ == "__main__":
    unittest.main()
