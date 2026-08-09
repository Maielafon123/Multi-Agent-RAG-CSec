"""Shared MVP config for Qdrant + embeddings + chunking."""

from langchain_text_splitters import RecursiveCharacterTextSplitter

QDRANT_HOST = "localhost"
QDRANT_PORT = 6333

COLLECTION_EXPLOITS = "exploits"
COLLECTION_FALSE_POSITIVES = "false_positives"

# BAAI/bge-small-en-v1.5
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
VECTOR_SIZE = 384

JULIET_DATASET = "LorenzH/juliet_test_suite_c_1_3"

# Empty set = all CWE classes. For a faster MVP smoke-test, set e.g. {78, 89, 134}.
MVP_CWES: set[int] = set()

# Cap rows per collection so first ingest finishes in minutes, not hours.
MVP_MAX_SAMPLES = 800

# Exploit chunks stay small so the vulnerable pattern is not diluted.
EXPLOIT_SPLITTER = RecursiveCharacterTextSplitter(
    chunk_size=512,
    chunk_overlap=128,
    separators=["\n\n", "\n", ";", "{", "}", " "],
)

# FP chunks are larger so the "why this is safe" context stays together.
FP_SPLITTER = RecursiveCharacterTextSplitter(
    chunk_size=1024,
    chunk_overlap=256,
    separators=["\n\n", "\n", "class ", "void ", "int ", "char ", " "],
)
