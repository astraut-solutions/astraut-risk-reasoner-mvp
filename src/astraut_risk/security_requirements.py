"""PDF security-requirements ingestion, translation, mapping, and risk linkage."""

from __future__ import annotations

import hashlib
import json
import math
import re
import zlib
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from .models import FrameworkReference, RequirementControl, RequirementRisk

_PDF_EXTENSIONS = {".pdf"}

FOLDER_TAXONOMY: dict[str, tuple[str, str]] = {
    "01_": ("General Requirements", "Global policies"),
    "02_": ("Architecture", "System design"),
    "03_": ("Operating Systems", "OS layer"),
    "04_": ("Virtualization", "Containers / VM"),
    "05_": ("Databases", "Data layer"),
    "06_": ("Server Applications", "Application layer"),
    "07_": ("Application Servers", "Application layer"),
    "08_": ("Web Servers", "Web layer"),
    "09_": ("Endpoints", "Endpoint layer"),
    "10_": ("Network Components", "Network layer"),
    "11_": ("Third-party Access", "Third-party risk"),
    "12_": ("Mobile Apps", "Mobile apps"),
    "13_": ("Operational Security", "Operations"),
    "14_": ("Web Services", "APIs"),
    "15_": ("Cloud & SaaS", "Cloud"),
}

COMPONENT_TO_CATEGORY_PREFIX: dict[str, tuple[str, ...]] = {
    "cloud": ("15_",),
    "aws": ("15_",),
    "azure": ("15_",),
    "gcp": ("15_",),
    "database": ("05_",),
    "postgresql": ("05_",),
    "mysql": ("05_",),
    "web": ("06_", "08_"),
    "web_app": ("06_", "08_"),
    "iam": ("01_",),
    "api": ("14_", "06_", "08_"),
    "endpoint": ("09_",),
    "network": ("10_",),
    "third_party": ("11_",),
    "mobile": ("12_",),
    "operations": ("13_",),
}

GERMAN_TO_ENGLISH: dict[str, str] = {
    "anforderungen": "requirements",
    "allgemeine": "general",
    "architektur": "architecture",
    "betriebssysteme": "operating systems",
    "virtualisierung": "virtualization",
    "datenbanken": "databases",
    "server": "server",
    "applikationen": "applications",
    "applikationsserver": "application server",
    "webserver": "web server",
    "endgeraete": "endpoints",
    "netzwerkkomponenten": "network components",
    "fremdfirmenzugang": "third-party access",
    "betriebliche": "operational",
    "sicherheitsanforderungen": "security requirements",
    "kryptographische": "cryptographic",
    "algorithmen": "algorithms",
    "verschluesselung": "encryption",
    "zugriff": "access",
    "protokollierung": "logging",
    "ueberwachung": "monitoring",
    "sicherung": "backup",
    "wiederherstellung": "recovery",
    "muss": "must",
    "soll": "should",
}

KEYWORDS: dict[str, tuple[str, ...]] = {
    "encryption": ("encrypt", "encryption", "kryptograph", "verschluessel"),
    "iam": ("iam", "identity", "zugriff", "auth", "mfa", "least privilege"),
    "network_segmentation": ("segmentation", "netzwerk", "firewall", "zone"),
    "logging_monitoring": ("logging", "monitor", "protokoll", "alert"),
    "backup_recovery": ("backup", "restore", "recovery", "wiederher"),
    "vulnerability_management": ("patch", "vulnerability", "scan"),
    "api_security": ("api", "web service", "oauth", "token"),
    "cloud_security": ("cloud", "saas", "aws", "azure", "gcp"),
    "database_security": ("database", "sql", "postgres", "mysql"),
}

COMPLIANCE_PATTERNS: dict[str, tuple[str, ...]] = {
    "ISO 27001": ("iso 27001", "27001", "annex a"),
    "NIST": ("nist", "csf", "800-53"),
    "OWASP": ("owasp", "top 10", "asvs"),
}

FRAMEWORK_KEYWORD_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    "ISO 27001": {
        "A.5.15": ("supplier", "third-party", "vendor"),
        "A.5.17": ("auth", "access", "identity", "iam", "mfa"),
        "A.5.23": ("cloud", "external service", "outsourcing"),
        "A.8.16": ("monitor", "logging", "alert", "detection"),
        "A.8.13": ("backup", "restore", "recovery"),
    },
    "NIST": {
        "PR.AC-1": ("identity", "iam", "access", "mfa"),
        "PR.AC-4": ("least privilege", "privilege", "admin"),
        "PR.PS-5": ("third-party", "supplier", "vendor"),
        "DE.CM-1": ("logging", "monitor", "alert"),
        "PR.DS-11": ("backup", "restore", "recovery"),
        "PR.PT-4": ("network", "segmentation", "firewall"),
    },
    "OWASP": {
        "A01:2021": ("access control", "authorization", "privilege"),
        "A02:2021": ("crypto", "encrypt", "key management"),
        "A05:2021": ("security misconfiguration", "hardening"),
        "A07:2021": ("identity", "auth", "mfa", "session"),
        "A09:2021": ("logging", "monitor", "detection"),
    },
}

DEFAULT_REQUIREMENT_SCORING: dict[str, float] = {
    "control_risk_weight": 1.0,
    "data_sensitivity_weight": 1.0,
    "exposure_level_weight": 1.0,
    "compliance_gap_weight": 1.0,
    "normalization_multiplier": 3.5,
}


@dataclass
class SecurityDocument:
    """Parsed document metadata + full text."""

    id: str
    title: str
    version: str
    category: str
    mapped_layer: str
    source_path: str
    raw_text: str
    translated_text: str
    keywords: list[str] = field(default_factory=list)


@dataclass
class RequirementsRepository:
    """In-memory repository of parsed documents and controls."""

    generated_at: str
    source_root: str
    documents: list[SecurityDocument] = field(default_factory=list)
    controls: list[RequirementControl] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _security_document_from_dict(payload: dict[str, object]) -> SecurityDocument:
    return SecurityDocument(
        id=str(payload.get("id", "")),
        title=str(payload.get("title", "")),
        version=str(payload.get("version", "unknown")),
        category=str(payload.get("category", "Unmapped")),
        mapped_layer=str(payload.get("mapped_layer", "Unmapped")),
        source_path=str(payload.get("source_path", "")),
        raw_text=str(payload.get("raw_text", "")),
        translated_text=str(payload.get("translated_text", "")),
        keywords=[str(item) for item in payload.get("keywords", []) if isinstance(item, str)],
    )


def _requirement_control_from_dict(payload: dict[str, object]) -> RequirementControl:
    refs_raw = payload.get("framework_refs", [])
    refs: list[FrameworkReference] = []
    if isinstance(refs_raw, list):
        for item in refs_raw:
            if not isinstance(item, dict):
                continue
            framework = str(item.get("framework", "")).strip()
            control_id = str(item.get("control_id", "")).strip()
            if not framework or not control_id:
                continue
            refs.append(
                FrameworkReference(
                    framework=framework,
                    control_id=control_id,
                    title=str(item.get("title", "")).strip(),
                    description=str(item.get("description", "")).strip(),
                )
            )

    return RequirementControl(
        id=str(payload.get("id", "")),
        category=str(payload.get("category", "Unmapped")),
        mapped_layer=str(payload.get("mapped_layer", "Unmapped")),
        document_title=str(payload.get("document_title", "")),
        document_version=str(payload.get("document_version", "unknown")),
        document_path=str(payload.get("document_path", "")),
        control_text=str(payload.get("control_text", "")),
        control_text_en=str(payload.get("control_text_en", "")),
        keywords=[str(item) for item in payload.get("keywords", []) if isinstance(item, str)],
        compliance_tags=[
            str(item) for item in payload.get("compliance_tags", []) if isinstance(item, str)
        ],
        severity=str(payload.get("severity", "medium")),
        risk_weight=float(payload.get("risk_weight", 0.5)),
        retrieval_score=float(payload.get("retrieval_score", 0.0)),
        retrieval_rank=int(payload.get("retrieval_rank", 0)),
        retrieval_reason=str(payload.get("retrieval_reason", "")),
        retrieval_breakdown={
            str(k): float(v)
            for k, v in payload.get("retrieval_breakdown", {}).items()
            if isinstance(k, str) and isinstance(v, (int, float))
        },
        framework_refs=refs,
    )


def load_repository_index(index_path: str) -> RequirementsRepository:
    """Load an ingested requirements repository from JSON metadata store."""
    path = Path(index_path).expanduser().resolve()
    if not path.exists():
        return RequirementsRepository(
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_root="",
            documents=[],
            controls=[],
        )

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return RequirementsRepository(
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_root="",
            documents=[],
            controls=[],
        )

    if not isinstance(payload, dict):
        return RequirementsRepository(
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_root="",
            documents=[],
            controls=[],
        )

    docs_raw = payload.get("documents", [])
    controls_raw = payload.get("controls", [])
    documents = [
        _security_document_from_dict(item)
        for item in docs_raw
        if isinstance(item, dict)
    ]
    controls = [
        _requirement_control_from_dict(item)
        for item in controls_raw
        if isinstance(item, dict)
    ]
    return RequirementsRepository(
        generated_at=str(payload.get("generated_at", datetime.now(timezone.utc).isoformat())),
        source_root=str(payload.get("source_root", "")),
        documents=documents,
        controls=controls,
    )


def translate_german_terms(text: str) -> str:
    """Best-effort German keyword translation for retrieval normalization."""
    translated = text
    for german, english in sorted(
        GERMAN_TO_ENGLISH.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        translated = re.sub(
            rf"\b{re.escape(german)}\b",
            english,
            translated,
            flags=re.IGNORECASE,
        )
    return translated


def _document_hash(path: Path) -> str:
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:12]
    return f"doc_{digest}"


def _control_hash(document_id: str, line: str) -> str:
    digest = hashlib.sha1(f"{document_id}:{line}".encode("utf-8")).hexdigest()[:12]
    return f"ctrl_{digest}"


def _extract_text_with_fitz(path: Path) -> str:
    try:
        import fitz  # type: ignore[import-untyped]
    except Exception:
        return ""
    text_parts: list[str] = []
    try:
        with fitz.open(path) as doc:  # type: ignore[attr-defined]
            for page in doc:
                text_parts.append(page.get_text("text"))
    except Exception:
        return ""
    return "\n".join(part for part in text_parts if part).strip()


def _extract_text_with_pypdf(path: Path) -> str:
    try:
        from pypdf import PdfReader  # type: ignore[import-untyped]
    except Exception:
        return ""
    try:
        reader = PdfReader(str(path))
    except Exception:
        return ""
    text_parts: list[str] = []
    for page in reader.pages:
        extracted = page.extract_text() or ""
        if extracted:
            text_parts.append(extracted)
    return "\n".join(text_parts).strip()


def extract_pdf_text(path: Path) -> str:
    """Extract text from PDF using available parser backends."""
    text = _extract_text_with_fitz(path)
    if text:
        return text
    text = _extract_text_with_pypdf(path)
    if text:
        return text
    return _extract_text_with_builtin(path)


def _extract_text_with_builtin(path: Path) -> str:
    """Last-resort extractor for simple text PDFs without external dependencies."""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""

    stream_pattern = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
    text_tokens: list[str] = []

    def _extract_tokens(blob: bytes) -> None:
        for match in re.finditer(rb"\((.*?)\)\s*Tj", blob, flags=re.DOTALL):
            token = match.group(1)
            token = token.replace(rb"\(", b"(").replace(rb"\)", b")").replace(rb"\\n", b" ")
            decoded = token.decode("latin-1", errors="ignore").strip()
            if decoded:
                text_tokens.append(decoded)

        for match in re.finditer(rb"\[(.*?)\]\s*TJ", blob, flags=re.DOTALL):
            array_blob = match.group(1)
            for token_match in re.finditer(rb"\((.*?)\)", array_blob, flags=re.DOTALL):
                token = token_match.group(1)
                token = token.replace(rb"\(", b"(").replace(rb"\)", b")").replace(rb"\\n", b" ")
                decoded = token.decode("latin-1", errors="ignore").strip()
                if decoded:
                    text_tokens.append(decoded)

    for stream_match in stream_pattern.finditer(raw):
        stream_data = stream_match.group(1).strip(b"\r\n")
        _extract_tokens(stream_data)
        try:
            decompressed = zlib.decompress(stream_data)
        except Exception:
            continue
        _extract_tokens(decompressed)

    # Fallback: decode raw bytes and capture plain text-like lines.
    if not text_tokens:
        decoded = raw.decode("latin-1", errors="ignore")
        candidates = [
            re.sub(r"\s+", " ", line).strip()
            for line in decoded.splitlines()
            if len(line.strip()) > 25 and re.search(r"[A-Za-z]{4,}", line)
        ]
        text_tokens.extend(candidates[:1500])

    return "\n".join(text_tokens).strip()


def _infer_category_and_layer(path: Path, root: Path) -> tuple[str, str]:
    try:
        relative = path.relative_to(root)
        first = relative.parts[0] if relative.parts else ""
    except ValueError:
        first = path.parent.name

    for prefix, mapped in FOLDER_TAXONOMY.items():
        if first.startswith(prefix):
            return mapped
    return ("Unmapped", "Unmapped")


def _extract_version(text: str, filename: str) -> str:
    patterns = (
        r"\bversion\s*[:\-]?\s*(v?\d+(?:\.\d+)*)\b",
        r"\bstand\s*[:\-]?\s*(\d{1,2}[./]\d{4})\b",
        r"\bv(\d+(?:\.\d+)*)\b",
    )
    source = f"{filename}\n{text[:1200]}"
    for pattern in patterns:
        match = re.search(pattern, source, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return "unknown"


def _extract_title(text: str, path: Path) -> str:
    for line in text.splitlines():
        clean = re.sub(r"\s+", " ", line).strip(" -\t")
        if len(clean) >= 4:
            return clean[:160]
    return path.stem.replace("_", " ")


def _extract_keywords(text: str) -> list[str]:
    lowered = text.lower()
    matched: list[str] = []
    for keyword, patterns in KEYWORDS.items():
        if any(pattern in lowered for pattern in patterns):
            matched.append(keyword)
    return matched


def _extract_compliance_tags(text: str) -> list[str]:
    lowered = text.lower()
    tags: list[str] = []
    for tag, patterns in COMPLIANCE_PATTERNS.items():
        if any(pattern in lowered for pattern in patterns):
            tags.append(tag)
    return tags


def _framework_refs_for_text(text: str, keywords: list[str]) -> list[FrameworkReference]:
    lowered = text.lower()
    refs: list[FrameworkReference] = []
    seen: set[tuple[str, str]] = set()
    enriched_text = f"{lowered} {' '.join(keywords).lower()}"
    for framework, controls in FRAMEWORK_KEYWORD_MAP.items():
        for control_id, patterns in controls.items():
            if not any(pattern in enriched_text for pattern in patterns):
                continue
            key = (framework, control_id)
            if key in seen:
                continue
            seen.add(key)
            refs.append(
                FrameworkReference(
                    framework=framework,
                    control_id=control_id,
                    title=f"{framework} mapped control",
                    description="Deterministic mapping from control keywords and extracted text.",
                )
            )
    return refs


def _severity_for_control(control_text: str, keywords: list[str]) -> tuple[str, float]:
    lowered = control_text.lower()
    score = 0.4
    if "must" in lowered or "muss" in lowered:
        score += 0.2
    if any(term in lowered for term in ("critical", "hoch", "high", "mandatory")):
        score += 0.25
    if any(k in keywords for k in ("encryption", "iam", "network_segmentation")):
        score += 0.1
    score = max(0.1, min(1.0, score))
    if score >= 0.8:
        return ("high", score)
    if score >= 0.5:
        return ("medium", score)
    return ("low", score)


def _looks_like_control_line(line: str) -> bool:
    stripped = line.strip()
    if len(stripped) < 20:
        return False
    if re.match(r"^(\d+(\.\d+)*[.)]|\-|\u2022)\s+", stripped):
        return True
    return bool(
        re.search(
            r"\b(muss|soll|should|must|required|shall|ensure|implement|enforce)\b",
            stripped,
            flags=re.IGNORECASE,
        )
    )


def _extract_controls(
    document_id: str,
    category: str,
    layer: str,
    title: str,
    version: str,
    source_path: str,
    text: str,
) -> list[RequirementControl]:
    controls: list[RequirementControl] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        if not _looks_like_control_line(raw_line):
            continue
        line = re.sub(r"\s+", " ", raw_line).strip()
        if line in seen:
            continue
        seen.add(line)
        translated_line = translate_german_terms(line)
        keywords = _extract_keywords(f"{line}\n{translated_line}")
        framework_refs = _framework_refs_for_text(
            f"{line}\n{translated_line}",
            keywords=keywords,
        )
        compliance_tags = sorted(
            set(_extract_compliance_tags(line)).union({ref.framework for ref in framework_refs})
        )
        severity, weight = _severity_for_control(line, keywords)
        controls.append(
            RequirementControl(
                id=_control_hash(document_id, line),
                category=category,
                mapped_layer=layer,
                document_title=title,
                document_version=version,
                document_path=source_path,
                control_text=line,
                control_text_en=translated_line,
                keywords=keywords,
                compliance_tags=compliance_tags,
                severity=severity,
                risk_weight=round(weight, 4),
                framework_refs=framework_refs,
            )
        )
    return controls


def ingest_requirements_repository(root_path: str) -> RequirementsRepository:
    """Parse a requirements root into structured documents and controls."""
    root = Path(root_path).expanduser().resolve()
    documents: list[SecurityDocument] = []
    controls: list[RequirementControl] = []

    if not root.exists():
        return RequirementsRepository(
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_root=str(root),
            documents=[],
            controls=[],
        )

    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in _PDF_EXTENSIONS:
            continue
        raw_text = extract_pdf_text(path)
        if not raw_text.strip():
            continue
        translated = translate_german_terms(raw_text)
        category, layer = _infer_category_and_layer(path, root)
        doc_id = _document_hash(path)
        title = _extract_title(raw_text, path)
        version = _extract_version(raw_text, path.name)
        keywords = _extract_keywords(f"{raw_text}\n{translated}")
        document = SecurityDocument(
            id=doc_id,
            title=title,
            version=version,
            category=category,
            mapped_layer=layer,
            source_path=str(path),
            raw_text=raw_text,
            translated_text=translated,
            keywords=keywords,
        )
        documents.append(document)
        controls.extend(
            _extract_controls(
                document_id=doc_id,
                category=category,
                layer=layer,
                title=title,
                version=version,
                source_path=str(path),
                text=raw_text,
            )
        )

    return RequirementsRepository(
        generated_at=datetime.now(timezone.utc).isoformat(),
        source_root=str(root),
        documents=documents,
        controls=controls,
    )


def save_repository_index(repository: RequirementsRepository, output_path: str) -> str:
    """Persist ingested requirements repository into JSON index."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(repository.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)


def infer_stack_components(
    company_description: str,
    questionnaire: dict[str, dict[str, str]] | None = None,
) -> set[str]:
    """Infer high-level stack components to map controls quickly."""
    text = (company_description or "").lower()
    questionnaire = questionnaire or {}
    components: set[str] = set()
    patterns = {
        "aws": r"\baws\b",
        "azure": r"\bazure\b",
        "gcp": r"\bgcp\b",
        "database": r"\bdatabase\b|\bdb\b",
        "postgresql": r"\bpostgres(?:ql)?\b",
        "mysql": r"\bmysql\b",
        "web": r"\bweb\b|\bwebsite\b|\bweb app\b",
        "api": r"\bapi\b",
        "iam": r"\biam\b|\bidentity\b|\bmfa\b|\bsso\b",
        "mobile": r"\bmobile\b|\bandroid\b|\bios\b",
        "endpoint": r"\bendpoint\b|\blaptop\b|\bdevice\b",
        "network": r"\bnetwork\b|\bfirewall\b|\bsegment",
        "third_party": r"\bvendor\b|\bthird[\s-]*party\b",
        "operations": r"\bincident\b|\boperations\b|\blogging\b|\bmonitoring\b",
    }
    for component, pattern in patterns.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            components.add(component)

    if questionnaire.get("technical_architecture", {}).get("public_api") == "yes":
        components.update({"api", "web"})
    if questionnaire.get("technical_architecture", {}).get("internet_exposed") == "yes":
        components.add("cloud")
    if questionnaire.get("technical_architecture", {}).get("mfa_enforced") in {"yes", "no"}:
        components.add("iam")
    return components


def mapped_category_prefixes_for_components(components: set[str]) -> set[str]:
    prefixes: set[str] = set()
    for component in components:
        for prefix in COMPONENT_TO_CATEGORY_PREFIX.get(component, ()):
            prefixes.add(prefix)
    return prefixes


def match_controls_for_components(
    controls: list[RequirementControl],
    components: set[str],
) -> list[RequirementControl]:
    prefixes = mapped_category_prefixes_for_components(components)
    if not prefixes:
        return controls[:]
    matched: list[RequirementControl] = []
    for control in controls:
        path_name = Path(control.document_path).parent.name
        if any(path_name.startswith(prefix) for prefix in prefixes):
            matched.append(control)
    return matched


def _tokenize_for_retrieval(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9_]{3,}", text.lower())}


def _char_ngrams(text: str, n: int = 3) -> set[str]:
    normalized = re.sub(r"\s+", " ", text.lower()).strip()
    if len(normalized) < n:
        return set()
    return {normalized[i:i + n] for i in range(0, len(normalized) - n + 1)}


def _cosine_similarity(
    left_tokens: set[str],
    right_tokens: set[str],
    token_idf: dict[str, float],
) -> float:
    if not left_tokens or not right_tokens:
        return 0.0
    universe = left_tokens.union(right_tokens)
    dot = 0.0
    left_norm = 0.0
    right_norm = 0.0
    for token in universe:
        weight = token_idf.get(token, 1.0)
        l_val = weight if token in left_tokens else 0.0
        r_val = weight if token in right_tokens else 0.0
        dot += l_val * r_val
        left_norm += l_val * l_val
        right_norm += r_val * r_val
    if left_norm <= 0.0 or right_norm <= 0.0:
        return 0.0
    return dot / math.sqrt(left_norm * right_norm)


def _jaccard_similarity(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    union = left.union(right)
    if not union:
        return 0.0
    return len(left.intersection(right)) / len(union)


def _retrieval_reason(
    *,
    taxonomy_boost: float,
    keyword_overlap: int,
    vector_similarity: float,
    lexical_similarity: float,
) -> str:
    reasons: list[str] = []
    if taxonomy_boost > 0.8:
        reasons.append("matches inferred stack domain")
    if keyword_overlap > 0:
        reasons.append(f"keyword overlap ({keyword_overlap})")
    if vector_similarity >= 0.2:
        reasons.append("strong semantic token similarity")
    elif lexical_similarity >= 0.1:
        reasons.append("lexical overlap with query")
    if not reasons:
        return "baseline retrieval match"
    return "; ".join(reasons)


def retrieve_controls_baseline(
    controls: list[RequirementControl],
    *,
    query: str,
    components: set[str],
    limit: int = 60,
) -> list[RequirementControl]:
    """Deterministic retrieval: taxonomy + keyword + lexical + vector-style scoring."""
    if not controls:
        return []

    prefixes = mapped_category_prefixes_for_components(components)
    query_tokens = _tokenize_for_retrieval(query)
    query_ngrams = _char_ngrams(query)
    query_keyword_hits = _extract_keywords(query)

    token_df: dict[str, int] = {}
    control_tokens_by_id: dict[str, set[str]] = {}
    control_ngrams_by_id: dict[str, set[str]] = {}
    for control in controls:
        tokens = _tokenize_for_retrieval(
            f"{control.control_text_en} {control.control_text} {control.document_title} {control.mapped_layer}"
        )
        ngrams = _char_ngrams(
            f"{control.control_text_en} {control.control_text} {control.document_title}"
        )
        control_tokens_by_id[control.id] = tokens
        control_ngrams_by_id[control.id] = ngrams
        for token in tokens:
            token_df[token] = token_df.get(token, 0) + 1

    total_controls = max(1, len(controls))
    token_idf = {
        token: math.log((1 + total_controls) / (1 + freq)) + 1.0
        for token, freq in token_df.items()
    }

    ranked: list[tuple[float, RequirementControl]] = []
    for control in controls:
        parent = Path(control.document_path).parent.name
        taxonomy_boost = 0.0

        if prefixes and any(parent.startswith(prefix) for prefix in prefixes):
            taxonomy_boost = 1.0
        elif not prefixes:
            taxonomy_boost = 0.2

        keyword_overlap = len(set(control.keywords).intersection(query_keyword_hits))
        keyword_score = min(1.0, keyword_overlap / 3.0)
        vector_similarity = _cosine_similarity(
            control_tokens_by_id.get(control.id, set()),
            query_tokens,
            token_idf,
        )
        lexical_similarity = _jaccard_similarity(
            control_ngrams_by_id.get(control.id, set()),
            query_ngrams,
        )
        severity_bonus = 1.0 if control.severity.lower() == "high" else 0.0

        score = (
            0.30 * taxonomy_boost
            + 0.30 * vector_similarity
            + 0.20 * keyword_score
            + 0.15 * lexical_similarity
            + 0.05 * severity_bonus
        )

        if score <= 0.01:
            continue

        breakdown = {
            "taxonomy": round(0.30 * taxonomy_boost, 4),
            "vector": round(0.30 * vector_similarity, 4),
            "keyword": round(0.20 * keyword_score, 4),
            "lexical": round(0.15 * lexical_similarity, 4),
            "severity": round(0.05 * severity_bonus, 4),
        }
        enriched = replace(
            control,
            retrieval_score=round(score, 4),
            retrieval_reason=_retrieval_reason(
                taxonomy_boost=taxonomy_boost,
                keyword_overlap=keyword_overlap,
                vector_similarity=vector_similarity,
                lexical_similarity=lexical_similarity,
            ),
            retrieval_breakdown=breakdown,
        )
        ranked.append((score, enriched))

    ranked.sort(
        key=lambda item: (
            item[0],
            item[1].risk_weight,
            item[1].severity.lower() == "high",
            item[1].id,
        ),
        reverse=True,
    )
    selected = [item[1] for item in ranked[:max(1, limit)]]
    return [replace(control, retrieval_rank=idx) for idx, control in enumerate(selected, start=1)]


def _data_sensitivity_factor(questionnaire: dict[str, dict[str, str]] | None) -> float:
    value = (questionnaire or {}).get("business", {}).get("data_sensitivity", "medium")
    return {"low": 0.7, "medium": 1.0, "high": 1.35, "unknown": 1.35}.get(value, 1.35)


def _exposure_level_factor(questionnaire: dict[str, dict[str, str]] | None) -> float:
    technical = (questionnaire or {}).get("technical_architecture", {})
    exposure = 1.0
    internet_exposed = technical.get("internet_exposed", "unknown")
    public_api = technical.get("public_api", "unknown")
    if internet_exposed in {"yes", "unknown"}:
        exposure += 0.25
    if public_api in {"yes", "unknown"}:
        exposure += 0.25
    return exposure


def _compliance_gap_factor(questionnaire: dict[str, dict[str, str]] | None) -> float:
    technical = (questionnaire or {}).get("technical_architecture", {})
    maturity = (questionnaire or {}).get("maturity", {})
    known = 0
    total = 0
    for value in technical.values():
        total += 1
        if value != "unknown":
            known += 1
    for value in maturity.values():
        total += 1
        if value != "unknown":
            known += 1
    completeness = known / max(1, total)
    # Lower completeness and explicit "no"/unknown responses increase compliance gap.
    explicit_no = sum(1 for v in list(technical.values()) + list(maturity.values()) if v == "no")
    explicit_unknown = sum(
        1 for v in list(technical.values()) + list(maturity.values()) if v == "unknown"
    )
    return max(
        0.75,
        min(
            1.6,
            1.2 - (0.4 * completeness) + (0.05 * explicit_no) + (0.03 * explicit_unknown),
        ),
    )


def derive_requirement_risks(
    controls: list[RequirementControl],
    questionnaire: dict[str, dict[str, str]] | None = None,
    scoring_config: dict[str, float] | None = None,
    limit: int = 10,
) -> tuple[list[RequirementRisk], float]:
    """Calculate explainable risks using control-risk based formula."""
    config = DEFAULT_REQUIREMENT_SCORING.copy()
    if scoring_config:
        for key, value in scoring_config.items():
            if key in config and isinstance(value, (float, int)):
                config[key] = float(value)

    sensitivity = _data_sensitivity_factor(questionnaire)
    exposure = _exposure_level_factor(questionnaire)
    gap = _compliance_gap_factor(questionnaire)

    risks: list[RequirementRisk] = []
    total = 0.0
    for control in controls:
        control_risk_factor = control.risk_weight * config["control_risk_weight"]
        sensitivity_factor = sensitivity * config["data_sensitivity_weight"]
        exposure_factor = exposure * config["exposure_level_weight"]
        compliance_gap_factor = gap * config["compliance_gap_weight"]
        score = control_risk_factor * sensitivity_factor * exposure_factor * compliance_gap_factor
        total += score
        impact = "High" if score >= 1.2 else "Medium" if score >= 0.8 else "Low"
        risks.append(
            RequirementRisk(
                id=f"risk_{control.id}",
                risk=f"Control gap likely in {control.mapped_layer}: {control.control_text_en[:90]}",
                why=(
                    "This control is mapped to your detected stack components and carries "
                    "elevated risk due to control/sensitivity/exposure/gap multipliers. "
                    f"Retrieval confidence: {control.retrieval_score:.2f}."
                ),
                source_document=f"{control.document_title} (v{control.document_version})",
                reference_control=control.control_text_en,
                mapped_layer=control.mapped_layer,
                severity=control.severity.capitalize(),
                impact=impact,
                score=round(score, 4),
                compliance_tags=control.compliance_tags,
            )
        )

    risks.sort(key=lambda item: item.score, reverse=True)
    bounded_score = max(0.0, min(100.0, round(total * config["normalization_multiplier"], 2)))
    return risks[:limit], bounded_score


def repository_version_snapshot(repository: RequirementsRepository) -> dict[str, object]:
    """Build deterministic version snapshot for repository controls."""
    controls = sorted(
        repository.controls,
        key=lambda item: (item.document_path, item.document_version, item.id),
    )
    docs: dict[str, dict[str, object]] = {}
    control_signatures: list[str] = []
    for control in controls:
        path = control.document_path
        doc = docs.setdefault(
            path,
            {"version": control.document_version, "controls": 0},
        )
        doc["controls"] = int(doc["controls"]) + 1
        signature = re.sub(r"\s+", " ", control.control_text_en.lower()).strip()
        control_signatures.append(f"{path}|{control.document_version}|{signature}")

    fingerprint_source = "\n".join(control_signatures)
    fingerprint = hashlib.sha1(fingerprint_source.encode("utf-8")).hexdigest()
    return {
        "generated_at": repository.generated_at,
        "source_root": repository.source_root,
        "documents": docs,
        "document_count": len(repository.documents),
        "control_count": len(repository.controls),
        "control_fingerprint": fingerprint,
    }


def compare_control_versions(
    previous: RequirementsRepository,
    current: RequirementsRepository,
) -> dict[str, object]:
    """Compare two repository snapshots and return control-level deltas."""
    def key_for(control: RequirementControl) -> tuple[str, str]:
        normalized = re.sub(r"\s+", " ", control.control_text_en.lower()).strip()
        return (control.document_path, normalized)

    prev_by_key = {key_for(control): control for control in previous.controls}
    curr_by_key = {key_for(control): control for control in current.controls}

    previous_keys = set(prev_by_key.keys())
    current_keys = set(curr_by_key.keys())

    added_keys = sorted(current_keys - previous_keys)
    removed_keys = sorted(previous_keys - current_keys)
    common_keys = previous_keys.intersection(current_keys)

    version_changed: list[dict[str, str]] = []
    for key in sorted(common_keys):
        prev = prev_by_key[key]
        curr = curr_by_key[key]
        if prev.document_version == curr.document_version:
            continue
        version_changed.append(
            {
                "document_path": key[0],
                "control_text_en": curr.control_text_en[:220],
                "from_version": prev.document_version,
                "to_version": curr.document_version,
            }
        )

    added = [
        {
            "document_path": item[0],
            "document_version": curr_by_key[item].document_version,
            "control_text_en": curr_by_key[item].control_text_en[:220],
        }
        for item in added_keys
    ]
    removed = [
        {
            "document_path": item[0],
            "document_version": prev_by_key[item].document_version,
            "control_text_en": prev_by_key[item].control_text_en[:220],
        }
        for item in removed_keys
    ]

    previous_snapshot = repository_version_snapshot(previous)
    current_snapshot = repository_version_snapshot(current)
    return {
        "previous": previous_snapshot,
        "current": current_snapshot,
        "summary": {
            "added_controls": len(added),
            "removed_controls": len(removed),
            "version_changed_controls": len(version_changed),
        },
        "added": added,
        "removed": removed,
        "version_changed": version_changed,
    }
