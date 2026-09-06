
from pydantic import BaseModel, Field



#Вход (пост/анализ)
class AnalyzeRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Код пользователя на проверку")
    include_debug: bool = Field(False, description="Вернуть hits scanner/critic")

#Выход
class Report(BaseModel):
    summary: str
    explanation: str
    recommendation: str
class HitInfo(BaseModel):
    score: float
    cwe: str | None = None
    filename: str | None = None
    code_snippet: str | None = None

class RouterInfo(BaseModel):
    primary_cwe: str | None = None
    confidence: float | None = None
    action: str | None = None
    cwe_filter: str | None = None



class DebugInfo(BaseModel):
    scanner_hits: list[HitInfo] = []
    critic_hits: list[HitInfo] = []
    synthesizer_used_fallback: bool = False

class HealthResponse(BaseModel):
    status: str = "ok"


class AnalyzeResponse(BaseModel):
    verdict: str                         # vulnerable | false_positive | inconclusive
    report: Report
    router: RouterInfo
    latency_sec: float
    debug: DebugInfo | None = None

class ReadyResponse(BaseModel):
    status: str                        # ready | degraded
    qdrant: bool
    ollama: bool