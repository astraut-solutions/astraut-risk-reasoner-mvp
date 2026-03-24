# Enterprise Security Intelligence Layer

## Updated Architecture

1. Ingestion Layer
- Scans categorized folders (`01_`..`15_`) for PDFs.
- Extracts raw text with parser backends (`PyMuPDF` first, `pypdf` fallback).
- Applies German-to-English term normalization for retrieval.
- Extracts metadata: title, version, category, mapped system layer, keywords.
- Extracts requirement controls and assigns severity + risk weight.

2. Taxonomy and Mapping Layer
- Maps folder prefixes to architecture layers:
  - `01_` Global policies
  - `02_` System design
  - `03_` OS layer
  - `04_` Containers / VM
  - `05_` Data layer
  - `06_` + `07_` + `08_` App/Web layers
  - `09_` Endpoints
  - `10_` Network
  - `11_` Third-party risk
  - `12_` Mobile apps
  - `13_` Operations
  - `14_` APIs
  - `15_` Cloud

3. Knowledge/Index Layer
- Produces JSON repository index with:
  - `documents[]` (raw + translated text, metadata, keywords)
  - `controls[]` (control text, mapped layer, compliance tags, severity, weight)
- This index can feed vector indexing (FAISS/Pinecone) externally.

4. Risk Mapping Layer
- Detects stack components from user input (`AWS`, `PostgreSQL`, `Web/API`, `IAM`).
- Maps components to category prefixes and pulls relevant controls.
- Builds traceable requirement matches in the assessment output.

5. Scoring + Explainability Layer
- Uses formula:
  - `Risk Score = Σ(Control Risk × Data Sensitivity × Exposure Level × Compliance Gap)`
- Generates explainable risk objects with:
  - why this risk exists
  - source document
  - reference control
  - severity and impact

6. Output Layer
- Adds report sections:
  - Applicable Standards
  - Identified Risks (linked to controls)
  - Recommendations (derived from mapped controls)
  - Detected Security Domains
  - Control Coverage %

## Data Model

### RequirementControl
- `id`
- `category`
- `mapped_layer`
- `document_title`
- `document_version`
- `document_path`
- `control_text`
- `control_text_en`
- `keywords[]`
- `compliance_tags[]`
- `severity`
- `risk_weight`

### RequirementRisk
- `id`
- `risk`
- `why`
- `source_document`
- `reference_control`
- `mapped_layer`
- `severity`
- `impact`
- `score`
- `compliance_tags[]`

## Ingestion Pipeline Design

1. Discover PDFs recursively from requirements root.
2. Parse text using parser fallback chain.
3. Normalize German terms to English for retrieval consistency.
4. Extract title/version/keywords/compliance tags.
5. Extract requirement control statements.
6. Assign severity and risk weight per control.
7. Save JSON index.

CLI:
- `astraut-risk ingest-requirements <root> --output assessments/security_requirements_index.json`

## Questionnaire Depth Options

1. General
- Minimal headings and broad options for quick intake.

2. Medium
- Domain-specific operational questions (architecture, IAM, network, detection).

3. Detailed
- Full controls-level intake (IAM, data protection, infra, appsec, ops, compliance).

CLI:
- `astraut-risk questionnaire-options`

## Sample Enriched Report Fragment

```markdown
## Applicable Standards
- ISO 27001
- NIST
- OWASP

## Identified Risks
1. Control gap likely in Cloud: encryption at rest must be enforced (High, impact: High)
   - Why this risk exists: Mapped to internet-facing cloud stack with high sensitivity and control gaps.
   - Source document: 3_50_Kryptographische_Algorithmen (v8.0)
   - Reference control: Use approved cryptographic algorithms for sensitive data.

## Recommendations
- [Cloud] Enforce approved cryptographic algorithms and key management (source: 3_50... v8.0)

## Detected Security Domains
- aws
- postgresql
- web
- iam

## Control Coverage
- Control Coverage %: 63.50
```

