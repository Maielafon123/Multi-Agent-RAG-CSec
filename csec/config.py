"""Общие настройки MVP: Qdrant, эмбеддинги и стратегии чанкинга."""

from pathlib import Path

from langchain_text_splitters import RecursiveCharacterTextSplitter

# Подключение к локальному Qdrant (Docker).
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333

# Имена коллекций для Сканера и Критика.
COLLECTION_EXPLOITS = "exploits"
COLLECTION_FALSE_POSITIVES = "false_positives"

# Модель MVP. Для полной версии можно заменить на code-embedding (поменять VECTOR_SIZE).
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
VECTOR_SIZE = 384

# Сбалансированный датасет Насти (bad/good по 5 CWE).
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = PROJECT_ROOT / "data" / "dataset.jsonl"

# Пустой set = брать все CWE из jsonl. Пример: {"CWE78", "CWE134"}.
MVP_CWES: set[str] = set()

# None = загрузить все подходящие строки; число = ограничить размер ingest.
MVP_MAX_SAMPLES: int | None = None

# Exploits: мелкие чанки, чтобы не размыть уязвимый паттерн.
EXPLOIT_SPLITTER = RecursiveCharacterTextSplitter(
    chunk_size=512,
    chunk_overlap=128,
    separators=["\n\n", "\n", ";", "{", "}", " "],
)

# False positives: крупнее, чтобы сохранить контекст «почему код безопасен».
FP_SPLITTER = RecursiveCharacterTextSplitter(
    chunk_size=1024,
    chunk_overlap=256,
    separators=["\n\n", "\n", "class ", "void ", "int ", "char ", " "],
)
