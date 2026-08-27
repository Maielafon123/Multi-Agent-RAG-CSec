# Multi-Agent RAG — описание репозитория (MVP)

Кратко: dual-RAG для аудита кода — коллекция уязвимых примеров (`exploits`) и коллекция безопасных/похожих на FP (`false_positives`). Пайплайн MVP собран целиком (Router → Scanner/Critic → Decider → Synthesizer в LangGraph). Эмбеддинг-модель для MVP — лёгкая; для полной версии планируется замена (например code-embedding вроде Jina Code).

```mermaid
flowchart TD
    A[Код пользователя] --> B[Router: классификация CWE]
    B --> C[Параллельный запуск]
    C --> D[Сканер: поиск в exploits]
    C --> E[Критик: поиск в false_positives]
    D --> F[Decider: вердикт]
    E --> F
    F --> G[Синтезатор: отчёт]
    G --> H[Ответ пользователю]
```

Из схемы реализовано всё: загрузка двух коллекций в Qdrant, поиск Scanner/Critic, Router (Ollama), Decider, Синтезатор (Ollama), полный граф в LangGraph (`graph.py`) и eval на всех уровнях (retrieval, synthesizer, граф e2e с router_accuracy). Осталось: финальный интерфейс (FastAPI + Streamlit), опционально смена эмбеддера / подключение Big-Vul.

---

## Стек MVP (сейчас)

- Векторная БД: Qdrant
- Эмбеддинги: `BAAI/bge-small-en-v1.5` (dim **384**, cosine, `normalize_embeddings=True`)
- Префиксы BGE: документы `passage:`, запросы `query:`
- Router: `qwen2.5-coder:7b` через Ollama (`router.py`)
- Синтезатор: `qwen2.5-coder:7b` через Ollama (`synthesizer.py`) — генерирует отчёт из вердикта Decider'а + находок Scanner/Critic
- Датасет MVP: `data/dataset.jsonl` (Juliet C/C++, подготовка Насти)
  - `kind=bad` → `exploits`, `kind=good` → `false_positives`
  - 5 CWE: 78, 134, 190, 23, 476
  - после чистки: bad ≈ 1741, good = 2370 (убраны source-only и `POTENTIAL FLAW`)
  - CWE в payload: `CWE78` (Router отдаёт `CWE-78`, нормализуется)
- `MVP_MAX_SAMPLES = None` → грузим весь jsonl
- Eval: `evals/` (retrieval: recall@k, decision accuracy; synthesizer: fallback/grounding/faithfulness/resolved accuracy; граф e2e: router_accuracy, resolved accuracy, latency → `results.jsonl` / MLflow)

Для полной модели (не MVP) ожидается смена эмбеддера и/или источника `/exploits` (Big-Vul). После смены модели коллекции нужно пересоздать под новый `VECTOR_SIZE` и перезалить векторы.

---

## Файлы проекта

### `config.py`

Общие константы MVP.

- `QDRANT_HOST` / `QDRANT_PORT`
- имена коллекций: `exploits`, `false_positives`
- `EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"`
- `VECTOR_SIZE = 384`
- `DATASET_PATH = data/dataset.jsonl`
- `MVP_CWES` — опциональный фильтр CWE (пустой set = все)
- `MVP_MAX_SAMPLES = None` (весь датасет)
- два сплиттера:
  - **exploits:** `RecursiveCharacterTextSplitter(chunk_size=512, chunk_overlap=128)`
  - **false_positives:** `chunk_size=1024, chunk_overlap=256`  
    (другая стратегия специально: у FP крупнее контекст «почему безопасно»)

---

### `embeddings.py`

Обёртка над SentenceTransformer.

- `get_model()` — ленивая загрузка `BAAI/bge-small-en-v1.5`
- `embed_documents(texts)` — для upsert: префикс `passage:`, нормализация, список векторов `list[list[float]]`
- `embed_query(text)` — для поиска: префикс `query:`, один вектор

Токенизация отдельным этапом не делается: её выполняет tokenizer модели внутри `encode()` (BertTokenizer / WordPiece, max 512 токенов).

---

### `create_collections.py`

Создаёт в Qdrant две коллекции, если их ещё нет.

- vector size = `VECTOR_SIZE` (384)
- distance = cosine
- payload-index по полю `cwe` (keyword) — нужен фильтру Scanner’а

---

### `ingest_common.py`

Общая логика ingest (используется обоими load-скриптами).

- `normalize_cwe(...)` — `CWE-78` / `78` / `CWE78` → `CWE78`
- `load_dataset_rows("bad"|"good")` — читает `data/dataset.jsonl`
- `chunk_rows(rows, splitter)` — режет код выбранным сплиттером
- `upsert_chunks(collection_name, chunks)` — эмбеддинги + upsert
- payload: `code`, `cwe`, `filename`, `function_name`, `label`, `source`, `kind`, `chunk_index`

---

### `load_exploits.py`

Загрузка коллекции **Сканера** (`exploits`).

- вход: `dataset.jsonl`, `kind=bad`
- сплиттер: exploits 512 / 128
- эмбеддинг: BGE small (`passage:`)

---

### `load_false_positives.py`

Загрузка коллекции **Критика** (`false_positives`).

- вход: `dataset.jsonl`, `kind=good`
- сплиттер: FP 1024 / 256
- эмбеддинг: BGE small (`passage:`)

---

### `search_test.py`

Retrieval API + smoke-test (пример path traversal / CWE23).

**`search_exploits(code, cwe=None, limit=3)`** — Сканер

- коллекция: `exploits`
- query-эмбеддинг: BGE + `query:`
- опциональный filter по payload `cwe` (`"CWE23"` после normalize)
- возвращает hits с score и payload

**`search_false_positives(code, limit=3)`** — Критик

- коллекция: `false_positives`
- тот же query-эмбеддинг
- **без** фильтра по CWE (независимый поиск)
- возвращает hits с score и payload

Это готовые функции, на которые садятся узлы Scanner / Critic в графе.

---

### `synthesizer.py`

Синтезатор — превращает вердикт Decider'а и находки Scanner/Critic в текстовый отчёт.

**`synthesize(user_code, verdict, exploit_hits, fp_hits)`**

- LLM: `qwen2.5-coder:7b` через Ollama, `temperature=0.2` (нужна связная формулировка текста, не жёсткая детерминированная метка, как у Router'а)
- verdict не пересчитывается — принимается готовым от `decider.decide_from_hits`
- явно обрабатывает `inconclusive` (конфликт Scanner/Critic): промпт запрещает модели выбирать сторону произвольно, требует честно показать обе находки и порекомендовать ручную проверку
- fallback на шаблонный отчёт, если LLM недоступна или вернула невалидный JSON — узел не роняет граф целиком
- возвращает `SynthesizerResult` (verdict, summary, explanation, recommendation, cwe, scanner_score, critic_score, used_fallback)

---

### `graph.py`

Полный пайплайн в LangGraph: `START → router → (scanner ∥ critic) → decider → synthesizer → END`.

- `GraphState` (TypedDict) накапливает данные по мере прохождения: `user_code`, `router_result`, `cwe_filter`, `exploit_hits`, `fp_hits`, `verdict`, `synthesizer_result`, `report_text`
- каждый узел — тонкая обёртка над готовой функцией (`route`, `search_exploits`, `search_false_positives`, `decide_from_hits`, `synthesize`)
- `scanner` и `critic` — параллельные ветки после `router`; `decider` ждёт обе
- fallback Router'а (`no_match` / `low_confidence` → `cwe_filter=None`) не требует отдельной ветки: Scanner просто ищет без фильтра по всей базе, дальше единственный путь
- `analyze_code(user_code)` — точка входа для внешнего кода, возвращает финальный `GraphState`
- `test_graph.py` — прогон на одном примере + дамп схемы графа в `graph_structure.md` (Mermaid)

---

### `requirements.txt`

Зависимости MVP: `datasets`, `qdrant-client`, `sentence-transformers`, `langchain-text-splitters`, `langchain-core`, `tqdm`, `langchain-ollama`, `mlflow`, `langgraph`.


## Что лежит в Qdrant (контракт точки)

Каждая точка:

- `vector` — float[384]
- `payload.code` — текст чанка
- `payload.cwe` — `"CWE78"`
- `payload.filename`, `payload.function_name`, `payload.label`
- `payload.source` — `"dataset.jsonl"`
- `payload.kind` — `"bad"` или `"good"`
- `payload.chunk_index`

---

## Важные факты по текущей реализации

- Две коллекции, два чанкинга, один эмбеддер MVP.
- Critic не фильтрует по CWE Router’а.
- Scanner фильтрует по CWE; `normalize_cwe` принимает `CWE-78` / `CWE78` / `78`.
- Модель эмбеддингов для полной версии может смениться → recreate + re-ingest.
- Big-Vul пока не подключён; источник MVP — `data/dataset.jsonl`.

---

## Структура (корень репо)

```text
README.md
config.py
embeddings.py
create_collections.py
ingest_common.py
load_exploits.py
load_false_positives.py
search_test.py
router.py
test_router.py
decider.py
synthesizer.py
test_synthesizer.py
graph.py
test_graph.py
graph_structure.md
evals/
  build_cases.py
  eval_retrieval.py
  eval_synthesizer.py
  eval_graph.py
  cases.jsonl
data/dataset.jsonl
requirements.txt
```

### Eval / метрики

```bash
python evals/build_cases.py
python evals/eval_retrieval.py
python evals/eval_synthesizer.py
python evals/eval_graph.py
```

Пишет:
- `evals/results.jsonl` — история прогонов (поле `component`: `"retrieval"`, `"synthesizer"` или `"graph_e2e"`)
- `mlruns/` — если установлен MLflow (текущая версия MLflow требует `MLFLOW_ALLOW_FILE_STORE=true` для file-store backend, иначе логирование пропускается без падения скрипта)

**Retrieval-метрики** (Scanner/Critic recall@k, mean top-1 cosine, decision accuracy — proxy Decider): recall 100%/100%, decision accuracy 85% на 20 кейсах (после чистки датасета от source-only функций и комментариев-подсказок — до чистки было 95%, разница объяснима: часть точности держалась на текстовых подсказках в коде, а не на структуре).

**Synthesizer-метрики** (`evals/eval_synthesizer.py`, 20 кейсов, пишет `component: "synthesizer"` с вложенными `overall` и `by_cwe`):

- `fallback_rate` 0% — LLM всегда возвращает валидный JSON, шаблонный fallback не срабатывал
- `grounding_rate` ~80% — отчёт называет реальный найденный CWE (на выборке из 20 прогон-к-прогону гуляет 75–95%)
- `faithfulness_rate` ~60% — отчёт цитирует конкретный идентификатор/операцию из найденного кода, а не только категорию CWE (новая, более строгая метрика; на 20 кейсах шумит 40–80%)
- `resolved_accuracy` 100% — среди 17 не-inconclusive вердиктов
- `inconclusive_rate` 15% — 3 из 20, конфликт Scanner/Critic (оба нашли сильное сходство с противоположными примерами); почти весь вклад — CWE-134 (2 из 4)
- `avg_synth_only_latency_sec` ~38 (qwen2.5-coder:7b на CPU; ранние «холодные» прогоны давали ~80), `avg_cycle_latency_sec` — то же плюс retrieval

**Граф e2e** (`evals/eval_graph.py`, гоняет полный `graph.analyze_code` на тех же 20 кейсах, пишет `component: "graph_e2e"`):

- `router_accuracy` 70% — 14 из 20 (по CWE: 78 — 100%, 134 и 23 — 75%, 190 и 476 — 50%)
- `resolved_accuracy` 100% (17 не-inconclusive), `inconclusive_rate` 15% — совпадает с уровнем Synthesizer'а, граф ничего не ломает
- `avg_total_latency_sec` ~54 на кейс (Router + retrieval + Decider + Synthesizer)