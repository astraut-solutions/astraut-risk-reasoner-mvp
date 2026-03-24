# AI Risk Intelligence Plan

## 1. Goal
Build a deterministic, explainable risk intelligence system that follows real-world security-industry calculation patterns and produces traceable reports for customer environments.

## 2. Source Scope
Repository root:
- `D:\workspace\open-source\risk-reasoner-post\Sicherheitsanforderungen 12_2025_de`

Important:
- The PDF set is a **reference sample corpus** used to study and calibrate scoring/mapping logic.
- It is **not** a required end-user product feature in CLI/Web flows.
- Product behavior should remain stable even when these PDFs are absent.

Categories:
- `01_Allgemeine_Anforderungen` -> Global policies
- `02_Architektur` -> System design
- `03_Betriebssysteme` -> OS layer
- `04_Virtualisierung` -> Containers/VM
- `05_Datenbanken` -> Data layer
- `06_Server_Applikationen` -> App layer
- `07_Applikationsserver` -> App runtime layer
- `08_Webserver` -> Web layer
- `09_Endgeraete` -> Endpoints
- `10_Netzwerkkomponenten` -> Network
- `11_Fremdfirmenzugang` -> Third-party risk
- `12_Mobile_Applikationen` -> Mobile apps
- `13_Betriebliche_Sicherheitsanforderungen` -> Operations
- `14_Web_Services` -> APIs
- `15_Cloud` -> Cloud/SaaS

## 3. Functional Outputs
- Deterministic risk scoring from company profile + structured questionnaire context.
- Control-domain mapping aligned to industry security practices.
- Compute explainable risk scores.
- Generate report sections:
  - Applicable Standards
  - Identified Risks
  - Recommendations
- Provide 3 assessment input modes:
  - General
  - Medium
  - Full Detailed

## 4. Target Architecture
- `Ingestion Service`
  - (Internal/reference only; not user-facing)
  - PDF parser (PyMuPDF/PDFMiner)
  - OCR fallback for scanned pages
  - chunking + metadata extraction
- `Normalization Service`
  - DE->EN translation layer (store original + translated text)
  - requirement sentence detection
  - keyword tagging and deduplication
- `Knowledge Layer`
  - structured store (optional/internal)
  - vector index (future/optional)
  - metadata index (optional/internal)
- `Risk Engine`
  - profile-to-domain mapper
  - control matcher
  - gap evaluator
  - weighted scorer
- `Explainability Engine`
  - risk -> source document/control trace
  - reason + impact + recommendation synthesis
- `Reporting/UI Layer`
  - domains panel
  - mapped requirements viewer
  - control coverage metrics

## 5. Core Data Model
```json
{
  "id": "ctrl_05_3_60_001",
  "doc_id": "3_60_PostgreSQL_Datenbanken_v10.0",
  "doc_title": "PostgreSQL Databases",
  "version": "10.0",
  "category": "05_Datenbanken",
  "mapped_layer": "Data Layer",
  "control_text_de": "...",
  "control_text_en": "...",
  "keywords": ["patching", "postgresql", "vulnerability"],
  "compliance_tags": ["ISO27001", "NIST", "OWASP"],
  "severity": "High",
  "risk_weight": 0.82,
  "source_ref": {"file": "05_Datenbanken/...pdf", "page": 12}
}
```

## 6. Ingestion Pipeline
Note: Internal/reference pipeline only (calibration and benchmarking), not mandatory for user-facing runtime.

1. Discover PDFs recursively by category.
2. Parse text and metadata.
3. OCR fallback where text extraction fails.
4. Detect sections and control statements (`must/should`, `muss/soll`).
5. Extract title/version/date/status.
6. Map categories to system layers.
7. Tag keywords and preliminary severity.
8. Translate DE->EN and store dual-language fields.
9. Generate embeddings for control chunks.
10. Persist raw + normalized + indexed records.

## 7. Risk Mapping and Scoring
### 7.1 Mapping
Input profile examples:
- Cloud provider/use -> `15_Cloud`
- PostgreSQL/DB -> `05_Datenbanken`
- Web app/web server -> `06/08`
- IAM/auth -> `01_Allgemeine_Anforderungen`

### 7.2 Scoring Formula
`Risk Score = Σ(Control Risk x Data Sensitivity x Exposure Level x Compliance Gap)`

Definitions:
- `Control Risk`: base criticality from control/severity mapping.
- `Data Sensitivity`: Low/Medium/High/Critical data factor.
- `Exposure Level`: internal/partner/public attack surface factor.
- `Compliance Gap`: implemented=0, partial=0.5, missing=1.0 (configurable).

### 7.3 Explainability Contract
For each risk, always show:
- Why this risk exists
- Trigger document + version + page
- Reference control text
- Impact level
- Recommended remediation

## 8. Report Structure
1. **Applicable Standards**
- matched documents
- matched compliance frameworks (ISO/NIST/OWASP)

2. **Identified Risks**
- risk title
- score/severity
- linked controls + source refs

3. **Recommendations**
- direct, control-derived actions
- priority and expected risk reduction

4. **Coverage Metrics**
- domain-level Control Coverage %
- implemented vs missing vs partial controls

## 9. UI Plan
- Add `Detected Security Domains` panel.
- Add `Mapped Requirements` table with filter/sort.
- Add `Control Coverage %` chart by domain/severity.
- Add risk drill-down with source references and rationale.

## 10. Input Options (Three Modes)
### 10.1 Option 1: General (minimal)
Collect only high-level architecture facts:
- hosting model, internet exposure, data sensitivity, third-party access.
Output:
- top domains, top risks, high-level recommendations.

### 10.2 Option 2: Medium
Collect balanced detail:
- cloud/platform, DBs, IAM/MFA, network segmentation, logging, patch cadence.
Output:
- mapped controls, risk list with source links, coverage by domain.

### 10.3 Option 3: Full Detailed
Collect full implementation evidence:
- asset inventory, trust boundaries, data classes, control implementation status, compliance objectives.
Output:
- full traceable assessment, weighted scoring, audit-ready report.

## 11. MVP to Enterprise Roadmap
### Phase 1 (MVP)
- [x] Deterministic risk scoring + explainable report
- [x] Taxonomy-aligned domain mapping and questionnaire-based risk factors

### Phase 2
- [x] Vector retrieval + explainability enrichment
- [x] UI domains/coverage/mapped controls

### Phase 3
- [ ] DE->EN translation hardening
- [x] Version tracking and control delta analysis

### Phase 4 (Enterprise)
- [x] ISO/NIST/OWASP mapping at scale
- [x] Policy-as-code checks and integration hooks
- [x] Governance workflows and approval trails

## 12. Implementation Backlog (Initial)
- [x] Implement category->layer mapper for runtime scoring.
- [x] Implement scoring engine with configurable factors.
- [x] Implement explainability payload generator.
- [x] Implement report generator (3 required sections).
- [x] Implement UI panels: domains, mapped requirements, coverage.
- [x] Keep PDF ingestion/retrieval as optional internal calibration tooling.

## 13. Acceptance Criteria
- Risk computation follows deterministic formula and is test-covered.
- Explainability includes why/impact/recommendation with transparent factors.
- Risk score formula is applied consistently and test-covered.
- Reports contain Applicable Standards, Identified Risks, Recommendations.
- UI exposes domains, mapped requirements, and coverage percent.
- System supports General/Medium/Full input modes.

## 14. Future Suggestions
- [ ] Questionnaire UX transparency:
  - add a small "selected mode summary" panel in the UI showing exactly which questionnaire fields were derived from mode answers before assessment runs.
- [ ] Governance workflow guardrails:
  - enforce immutable terminal states unless an explicit admin override action is used.
  - add role-aware authorization hooks for approver identities.
- [ ] Governance operations UX:
  - add `governance-list` filters for requester, assessment ref, and created-at windows.
  - add trail detail command showing full decision history and comments.
- [ ] Policy pack lifecycle:
  - support policy pack versioning and signed policy-pack checksum verification.
  - add reusable policy-pack templates for regulated profiles (ISO/NIST/OWASP baseline packs).
- [ ] Policy/Web parity:
  - expose policy-check and governance workflows in Streamlit UI with hook export download.
