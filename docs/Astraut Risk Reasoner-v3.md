Understood. The earlier version was a strong outline, but not a full architecture package.

Below is a **complete, implementation-ready system design document** for the **Astraut Risk Reasoner**, expanded into a level a platform team, security architects, data engineers, and product stakeholders can work from directly. It is grounded in the core requirements from your rough design: risk must be **context-aware, scenario-based, compliance-driven, explainable, and not reduced to a static formula**. It must incorporate questionnaires, asset context, threat intelligence, control effectiveness, inherent and residual risk, and modular extensibility.  

---

# Astraut Risk Reasoner

## Production-Grade System Design Document

---

## 1. Executive Summary

Astraut Risk Reasoner is a **cyber risk reasoning platform** that evaluates enterprise risk using a combination of:

* organizational context
* technical architecture and exposure
* threat and vulnerability intelligence
* control implementation and effectiveness
* compliance and regulatory requirements
* scenario-based attack modeling
* explainable scoring and confidence output

The platform exists because direct or static risk scoring is structurally wrong for real cybersecurity programs. Risk is not a single arithmetic constant. It changes with architecture, internet exposure, control maturity, asset criticality, trust relationships, adversary capability, exploit activity, and regulatory obligations. The design goal is to compute both **inherent risk** and **residual risk** from real evidence, not from hardcoded severity tables.  

This document defines:

* target platform architecture
* domain model
* service boundaries
* data model and storage choices
* ingestion and reasoning pipelines
* security architecture
* API contracts
* operational model
* phased implementation roadmap

The target system is a **multi-tenant, event-driven, microservice-based platform** deployed on Kubernetes, using a mix of relational, analytical, search, and graph data stores. The risk engine uses a hybrid reasoning approach combining rules, graph traversal, statistical scoring, and optional LLM-assisted explanation.

---

# 2. Problem Definition

## 2.1 Why the current approach is insufficient

The rough system direction already identifies the core flaw: cyber risk cannot be modeled correctly through simplified direct formulas or hardcoded scoring alone. A system that computes risk from isolated attributes without context will produce misleading output because it ignores:

* asset role and business criticality
* internal versus internet-facing exposure
* dependencies between components
* control evidence and effectiveness
* current exploit activity
* differences between environments such as prod, dev, SaaS, cloud, or on-prem
* compliance obligations that change required controls
* confidence and evidence quality

That concern is explicitly present in the source material, which states that risk must be derived from contextual assessment rather than static logic, and that questionnaires are required before scoring begins. 

## 2.2 Problem the platform solves

Security teams need a system that answers:

* what assets matter
* where those assets are exposed
* what attack scenarios are realistic
* which threats and vulnerabilities apply
* what controls should exist
* which controls actually exist
* how effective those controls are
* what the risk is before controls
* what the risk remains after controls
* why the system reached that conclusion

The source material frames Astraut Risk Reasoner as exactly this type of engine: a context-aware platform that ties architecture, threat intelligence, controls, and compliance into a single explainable model.  

---

# 3. Scope

## 3.1 In Scope

* questionnaire-driven organizational discovery
* automated technical discovery
* asset inventory and dependency modeling
* threat and vulnerability intelligence ingestion
* compliance control mapping
* control validation and evidence handling
* scenario generation
* inherent and residual risk scoring
* explainable reasoning output
* dashboards, APIs, reports, and integrations
* multi-tenant enterprise SaaS deployment

## 3.2 Out of Scope for initial release

* full SOAR-style automated remediation
* endpoint protection or EDR
* packet capture and deep network telemetry
* malware sandboxing
* long-horizon predictive risk simulation at industrial scale
* fully autonomous control verification through agents

These can be phased in later.

---

# 4. Design Principles

The system must follow these design principles.

## 4.1 Context before scoring

No score is generated until tenant context exists. The source requirements clearly state that questionnaires and organizational understanding are needed before scoring. 

## 4.2 Scenario-based reasoning

Risk is evaluated per attack scenario, not just per asset or per CVE. This is one of the core features in the original brief. 

## 4.3 Inherent and residual separation

The platform computes risk both before and after control influence. 

## 4.4 Explainability by default

Every score must include factors, evidence, missing controls, and confidence. 

## 4.5 Evidence over assumptions

Control presence is not enough. The platform must support evidence-backed control effectiveness.

## 4.6 Modular extensibility

The architecture must support new frameworks, new threat feeds, custom scoring policies, and tenant-specific risk models without core rewrites.

## 4.7 Secure multi-tenancy

Tenant isolation is a first-class requirement, not an afterthought.

---

# 5. Current State vs Target State

## 5.1 Current State

The rough design indicates a concept-stage platform with the correct strategic direction but missing the deeper architecture required for enterprise use. The documented concerns highlight missing context modeling, lack of control validation, weak compliance-driven scoring, and over-simplified risk logic. 

## 5.2 Target State

The target state is a production platform that provides:

* tenant onboarding through questionnaires and discovery
* normalized asset and service inventory
* architecture-aware exposure mapping
* dependency graph and scenario modeling
* intelligence enrichment from CVE/NVD and threat sources
* framework-aware control requirements
* control effectiveness scoring from evidence
* explainable inherent and residual risk output
* APIs and integrations for SIEM, GRC, scanners, cloud providers
* strong observability, reliability, and security controls

---

# 6. Assumptions and Constraints

## 6.1 Assumptions

* customers are SMEs to mid-market enterprises first, with a path to larger enterprises
* environments are hybrid across SaaS, cloud, and on-prem
* source data will be incomplete and inconsistent
* control evidence may be manual, automated, or absent
* initial regulatory focus includes ISO 27001, NIST CSF, CIS Controls, GDPR-related obligations, with more frameworks later
* multi-tenancy is required from the start

These assumptions align with the design brief and its emphasis on compliance controls, tech stack diversity, deployment model differences, and contextual questionnaires. 

## 6.2 Constraints

* some tenants will have minimal telemetry
* vulnerability feeds are high volume and noisy
* attack scenarios must remain explainable to non-research users
* control validation will often be probabilistic rather than absolute
* many organizations will not have perfect CMDB data
* scoring must stay stable enough for governance use, but dynamic enough to reflect change

---

# 7. High-Level Architecture

## 7.1 Logical Architecture

The platform is divided into eight logical layers:

1. **Experience Layer**

   * web console
   * admin UI
   * analyst UI
   * API consumers
   * report exporters

2. **Access Layer**

   * API gateway
   * auth and tenant routing
   * rate limiting
   * WAF

3. **Core Platform Services**

   * onboarding and questionnaire service
   * asset service
   * topology service
   * vulnerability intelligence service
   * threat intelligence service
   * compliance service
   * control intelligence service
   * scenario modeling service
   * risk engine service
   * explainability service
   * reporting service
   * notification service

4. **Processing and Orchestration Layer**

   * workflow engine
   * rules engine
   * stream processors
   * job scheduler
   * event bus

5. **AI and Reasoning Layer**

   * feature service
   * model inference service
   * LLM explanation service
   * graph reasoning engine

6. **Data Layer**

   * transactional database
   * graph database
   * search index
   * object storage
   * analytics warehouse
   * cache

7. **Integration Layer**

   * cloud connectors
   * scanner connectors
   * SIEM connectors
   * GRC connectors
   * ticketing connectors
   * webhook handlers

8. **Security and Operations Layer**

   * IAM
   * secrets and KMS
   * observability
   * policy enforcement
   * audit logging

## 7.2 Deployment Style

Use a **microservice architecture**, not a monolith.

### Why microservices are the right choice

This platform has very different workloads:

* questionnaire and UI traffic
* high-volume vulnerability ingestion
* graph computation
* scheduled risk recomputation
* API requests
* AI inference
* report generation

These workloads need independent scaling, isolated failure domains, and separate release cycles. A monolith would slow delivery and create risk concentration around the ingestion and reasoning pipeline.

### Service granularity guidance

Do not create dozens of tiny services on day one. Start with a **modular microservice architecture**, around 8 to 12 deployable services, each with clear bounded contexts.

---

# 8. Service Architecture

## 8.1 API Gateway Service

### Responsibilities

* external entry point
* JWT validation and auth handoff
* tenant resolution
* request routing
* API throttling
* WAF integration
* schema validation for public APIs

### Recommended stack

* Kong, Envoy Gateway, or AWS API Gateway

---

## 8.2 Identity and Tenant Service

### Responsibilities

* user auth via OIDC/SAML
* tenant creation and isolation metadata
* RBAC and ABAC policies
* service-to-service auth
* API token issuance
* audit of privileged actions

### Key objects

* Tenant
* User
* Group
* Role
* Permission
* Policy
* ServicePrincipal

---

## 8.3 Onboarding and Questionnaire Service

The source requirements explicitly state that questionnaire-based surveys are needed to understand an organization before scoring. 

### Responsibilities

* business questionnaire
* technical architecture questionnaire
* compliance questionnaire
* maturity questionnaire
* evidence uploads
* answer versioning
* derived metadata generation

### Example questionnaire domains

* industry and regulatory obligations
* data types handled
* deployment model
* internet exposure
* supplier dependencies
* IAM practices
* incident response maturity
* cloud usage
* encryption practices
* backup and recovery
* privileged access model

### Outputs

* tenant context profile
* required framework scope
* confidence baseline
* discovery coverage requirements
* initial risk hypotheses

---

## 8.4 Asset and Topology Service

### Responsibilities

* asset inventory management
* service inventory
* interfaces and dependencies
* ownership and environment tagging
* exposure classification
* criticality classification
* trust boundary mapping

### Asset categories

* applications
* APIs
* services
* hosts
* cloud resources
* containers
* data stores
* identities
* endpoints
* integrations
* third-party dependencies

### Example fields

* asset_id
* tenant_id
* asset_type
* environment
* business_owner
* technical_owner
* internet_exposed
* authentication_type
* data_classification
* criticality
* dependency_list

---

## 8.5 Discovery and Connector Service

### Responsibilities

* cloud inventory sync
* vulnerability scanner sync
* CMDB sync
* SaaS connector sync
* IAM inventory ingestion
* log source registration

### Initial connectors

* AWS Security Hub / Config / Inspector
* Azure Defender / Resource Graph / Security Center
* GCP Security Command Center / Asset Inventory
* Microsoft 365
* GitHub / GitLab
* Jira / ServiceNow
* Qualys / Tenable / Nessus
* CrowdStrike or EDR metadata
* SIEM source adapters

### Design note

Connectors should be implemented as pluggable adapters behind a common ingestion interface.

---

## 8.6 Vulnerability Intelligence Service

The source brief requires integration of CVE/NVD and exploit data.  

### Responsibilities

* ingest CVE and NVD feeds
* ingest vendor advisories
* map CVEs to products and versions
* enrich vulnerabilities with exploitability and severity signals
* maintain normalized vulnerability catalog
* correlate scanner findings with asset context

### Core enrichment dimensions

* CVSS base and temporal data
* exploit maturity
* exploit availability
* product exposure
* asset exploit preconditions
* patch availability
* known active exploitation
* age of vulnerability

### Output

* normalized vulnerability record
* affected asset mapping
* exploitability score
* intelligence freshness score

---

## 8.7 Threat Intelligence Service

### Responsibilities

* threat actor catalog
* campaign and tactic mapping
* sector-specific threat relevance
* TTP mapping to MITRE ATT&CK
* active signal ingestion
* region and industry threat weighting

### Output

* threat relevance profile per tenant
* threat scenario seeds
* actor-capability vectors
* campaign-to-exposure correlations

---

## 8.8 Compliance Service

The source material emphasizes ISO 27001, NIST CSF, CIS Controls, and regulatory requirements such as GDPR. 

### Responsibilities

* maintain framework catalogs
* map requirements to control families
* map controls to asset and service types
* determine which controls are required by tenant context
* provide compliance gap outputs

### Supported standards, phase 1

* ISO 27001 Annex A mapping
* NIST CSF 2.0 structure
* CIS Controls
* GDPR control relevance tagging

### Output

* required controls per tenant
* required controls per asset class
* framework coverage score
* control obligation graph

---

## 8.9 Control Intelligence Service

### Responsibilities

* register implemented controls
* ingest evidence
* validate control applicability
* score control design effectiveness
* score control operating effectiveness
* identify gaps and weak coverage

### Control object dimensions

* control_id
* control_family
* applicable_scope
* implementation_status
* evidence_status
* validation_date
* owner
* design_effectiveness
* operating_effectiveness
* coverage
* freshness
* confidence

### Effectiveness scoring model

Use a weighted approach:

**Control effectiveness =**

* design effectiveness 30%
* operating evidence 35%
* coverage breadth 20%
* evidence freshness 10%
* exception rate 5%

This is adjustable per control family.

---

## 8.10 Scenario Modeling Service

The original vision states that risk must be calculated per attack scenario. 

### Responsibilities

* generate attack scenarios from context
* construct attack graphs
* identify entry points, pivots, targets, and required conditions
* link vulnerabilities, exposures, identities, and controls
* score path plausibility

### Scenario examples

* internet-facing app with exploitable vulnerability leads to DB access
* exposed admin interface with weak MFA leads to privileged compromise
* supplier identity integration leads to lateral access
* cloud storage misconfiguration exposes sensitive data
* phishing leads to SaaS takeover due to missing conditional access

### Scenario structure

* scenario_id
* attack_goal
* entry_vector
* intermediate_steps
* target_assets
* required_controls
* observed_controls
* threat actors likely to use path
* likelihood drivers
* impact drivers

---

## 8.11 Risk Engine Service

### Responsibilities

* compute inherent risk
* compute residual risk
* evaluate confidence
* produce normalized risk records
* version scoring logic
* support model explainability

### Risk equation design

Do not expose a simplistic one-line formula in the product as though risk were fixed. Internally, use a weighted reasoning framework.

#### Inherent Risk dimensions

* threat relevance
* exploitability
* exposure
* asset criticality
* data sensitivity
* lateral movement opportunity
* scenario plausibility
* business process dependency

#### Residual Risk dimensions

Residual risk is inherent risk reduced by validated control effectiveness and bounded by uncertainty.

### Proposed scoring model

For each scenario:

1. compute **Scenario Likelihood**
2. compute **Scenario Impact**
3. compute **Inherent Risk**
4. compute **Control Reduction**
5. compute **Residual Risk**
6. compute **Confidence**

#### Likelihood factors

* attack surface exposure
* exploit availability
* vulnerability severity in context
* threat activity relevance
* identity exposure
* precondition complexity
* discovery confidence

#### Impact factors

* business criticality
* data sensitivity
* privilege level
* blast radius
* regulatory consequence
* recovery complexity
* customer impact

#### Inherent Risk

`InherentRisk = normalize(Likelihood * Impact)`

#### Control Reduction

Controls do not erase risk equally. Each control contributes reduction only if:

* applicable to the scenario
* implemented in scope
* evidenced
* effective
* fresh

`ControlReduction = aggregate(applicable_control_effectiveness with diminishing returns)`

#### Residual Risk

`ResidualRisk = InherentRisk * (1 - ControlReductionAdjusted)`

#### Confidence

Confidence is based on:

* data completeness
* recency
* control evidence quality
* asset coverage
* scanner coverage
* questionnaire completeness

This is essential because explainable output with confidence is a core requirement in the source material. 

---

## 8.12 Explainability Service

### Responsibilities

* generate factor breakdowns
* show score contribution paths
* list missing and weak controls
* explain why scenario exists
* summarize evidence sources
* support analyst-facing natural-language narratives

### Output example

“Residual risk remains High because the application is internet-facing, hosts a known exploitable dependency, processes sensitive customer data, and lacks proven network segmentation. MFA exists for admins, reducing takeover paths, but no evidence confirms WAF tuning or runtime exploit detection. Confidence is Medium due to incomplete scanner coverage.”

---

## 8.13 Reporting and Notification Service

### Responsibilities

* scheduled reports
* executive summary generation
* control gap reports
* framework coverage exports
* webhook and email alerts
* integration with ticketing systems

---

# 9. Data Architecture

## 9.1 Storage Strategy

Use polyglot persistence.

### PostgreSQL

Use for:

* tenants
* users
* questionnaires
* assets metadata
* controls
* risk records
* workflow state
* API state

### Graph Database: Neo4j or Amazon Neptune

Use for:

* asset dependency graph
* trust relationships
* identity-to-resource relationships
* attack paths
* scenario traversal

### Search Engine: OpenSearch or Elasticsearch

Use for:

* vulnerability search
* evidence search
* report search
* logs and event exploration

### Object Storage: S3 or equivalent

Use for:

* uploaded evidence
* report exports
* raw feed archives
* large JSON snapshots

### Analytics Warehouse: Snowflake, BigQuery, or ClickHouse

Use for:

* historical trends
* tenant benchmarking
* reporting and BI
* model features
* aggregate risk analysis

### Cache: Redis

Use for:

* session data
* feature caching
* repeated lookups
* workflow locks
* short-term scoring cache

---

## 9.2 Canonical Data Domains

### Tenant Domain

* tenant
* subscription
* org_profile
* regulatory_profile

### Discovery Domain

* asset
* service
* interface
* dependency
* identity
* environment

### Intelligence Domain

* cve
* vendor_advisory
* threat_actor
* campaign
* technique
* exploit_signal

### Compliance Domain

* framework
* requirement
* control
* control_mapping
* evidence

### Risk Domain

* scenario
* likelihood_factor
* impact_factor
* inherent_risk
* residual_risk
* confidence
* recommendation

---

## 9.3 Core Relational Schema

### tenants

* id
* name
* region
* sector
* status
* created_at

### org_profiles

* tenant_id
* employee_count
* revenue_band
* operating_regions
* regulatory_flags
* business_model
* risk_appetite

### questionnaire_templates

* id
* name
* version
* domain
* status

### questionnaire_responses

* id
* tenant_id
* template_id
* submitted_by
* submitted_at
* response_json
* derived_context_json

### assets

* id
* tenant_id
* asset_type
* name
* environment
* criticality
* data_classification
* internet_exposed
* owner_user_id
* source_system
* status

### services

* id
* tenant_id
* asset_id
* protocol
* auth_model
* public_endpoint
* dependency_count

### vulnerabilities

* id
* cve_id
* source
* cvss_base
* exploitability_index
* vendor_fix_available
* published_at
* updated_at

### asset_vulnerabilities

* id
* tenant_id
* asset_id
* vulnerability_id
* detection_source
* first_seen_at
* last_seen_at
* status
* evidence_json

### frameworks

* id
* name
* version

### controls

* id
* framework_id
* control_code
* title
* description
* control_family

### tenant_controls

* id
* tenant_id
* control_id
* applicability_status
* implementation_status
* design_effectiveness
* operating_effectiveness
* confidence
* owner_id
* last_validated_at

### control_evidence

* id
* tenant_control_id
* evidence_type
* storage_uri
* uploaded_by
* observed_at
* validation_status
* metadata_json

### scenarios

* id
* tenant_id
* scenario_type
* name
* entry_vector
* target_asset_id
* graph_path_json
* status
* generated_at

### risks

* id
* tenant_id
* scenario_id
* inherent_risk_score
* residual_risk_score
* confidence_score
* severity_band
* reasoning_snapshot_json
* computed_at
* model_version

### recommendations

* id
* tenant_id
* risk_id
* control_id
* action_text
* priority
* expected_risk_reduction
* status

---

## 9.4 Graph Model

### Node Types

* Tenant
* Asset
* Service
* Interface
* Identity
* DataStore
* Vulnerability
* Control
* ThreatActor
* Technique
* Scenario

### Edge Types

* DEPENDS_ON
* EXPOSES
* AUTHENTICATES_TO
* STORES
* COMMUNICATES_WITH
* AFFECTED_BY
* MITIGATED_BY
* USED_BY
* TARGETS
* ENABLES
* TRUSTS

The graph is a core design choice because attack scenario reasoning is hard to do cleanly in pure relational joins at scale.

---

# 10. Data Ingestion and Processing

## 10.1 Ingestion Modes

### Batch

Used for:

* nightly CMDB sync
* framework catalog updates
* scheduled scanner imports
* risk recomputation
* report generation

### Event-driven / near real time

Used for:

* newly published CVEs
* new findings from scanners
* IAM changes
* cloud misconfiguration updates
* evidence uploads
* policy changes
* manual asset updates

## 10.2 Event Backbone

Use Kafka, Redpanda, or managed equivalent.

### Initial topics

* tenant.onboarded
* questionnaire.completed
* asset.discovered
* asset.updated
* vulnerability.catalog.updated
* vulnerability.detected
* control.evidence.uploaded
* control.validated
* scenario.generated
* risk.computed
* alert.triggered

## 10.3 Processing Pipeline

### Stage 1: Raw ingestion

Source-specific connector emits raw JSON to object storage and event bus.

### Stage 2: Normalization

Convert raw payloads to canonical internal schemas.

### Stage 3: Deduplication and identity resolution

Resolve duplicate assets, services, identities, and vulnerability records.

### Stage 4: Enrichment

Add:

* tenant context
* business criticality
* framework obligations
* exploitability enrichment
* exposure context

### Stage 5: Graph update

Persist nodes and edges.

### Stage 6: Scenario generation

Rebuild affected scenarios incrementally.

### Stage 7: Risk scoring

Recompute only impacted scenarios where possible.

### Stage 8: Explainability and notification

Update UI, APIs, dashboards, and reports.

---

# 11. Risk Reasoning Logic

## 11.1 Why static formulas are incorrect

The source requirements directly state that risk is not a direct calculation or fixed formula. 

A static formula fails because:

* the same CVE has different risk depending on exposure and asset role
* a severe vuln on an isolated dev instance is not equal to the same vuln on a public payment API
* missing controls matter differently by scenario
* business impact changes by tenant context
* scanner presence is not proof of exploitability
* compliance obligations change the required baseline

## 11.2 Correct reasoning approach

Use a layered reasoning stack.

### Layer 1: Context qualification

Determine what the tenant actually has:

* asset inventory
* business model
* regulated data
* deployment model
* trust boundaries

### Layer 2: Scenario generation

Generate plausible attack scenarios from context.

### Layer 3: Likelihood modeling

Estimate plausibility using:

* exposure
* exploit availability
* threat relevance
* preconditions
* attacker capability
* path length

### Layer 4: Impact modeling

Estimate damage using:

* data class
* business process value
* customer and legal consequence
* privilege attained
* lateral movement potential
* recovery complexity

### Layer 5: Control modification

Reduce risk based on applicable and evidenced controls.

### Layer 6: Confidence modeling

Express uncertainty when data quality is weak.

---

# 12. AI and Reasoning Layer

## 12.1 Hybrid Model Choice

Use a hybrid approach, not pure ML and not pure LLM.

### Rules engine

Best for:

* control applicability logic
* framework mapping
* deterministic thresholds
* policy evaluation

### Graph reasoning

Best for:

* attack path discovery
* dependency traversal
* blast radius estimation
* privilege chain analysis

### Statistical / ML scoring

Best for:

* likelihood calibration
* prioritization
* anomaly scoring
* recommendation ranking

### LLMs

Best for:

* explanation generation
* report drafting
* evidence summarization
* analyst assistance

LLMs should not be the source of truth for final risk scores.

## 12.2 Feature Engineering

Feature sets should include:

### Asset features

* criticality
* data sensitivity
* exposure class
* environment
* dependency centrality
* auth type

### Vulnerability features

* CVSS
* exploit maturity
* active exploitation signal
* patch age
* asset-product fit confidence

### Threat features

* actor relevance by industry
* technique frequency
* campaign recency
* geographic targeting

### Control features

* implementation status
* evidence freshness
* design effectiveness
* operating effectiveness
* exception rate

### Tenant features

* sector
* regulatory obligations
* maturity level
* questionnaire completeness

## 12.3 Model Lifecycle

### Training

* use historical internal labeled outcomes where available
* start with heuristic calibration, then add ML gradually
* maintain feature lineage

### Validation

* offline validation against expert-reviewed scenarios
* drift detection by tenant cohort and by industry
* compare recommendation precision

### Deployment

* model registry with version control
* canary rollout
* rollback on degradation
* explicit model version in every risk record

---

# 13. Security Architecture

## 13.1 Threat Model

Key threats to the platform:

* tenant data leakage
* broken access control
* insecure evidence uploads
* API abuse
* connector credential compromise
* prompt injection into LLM explanation flows
* poisoned intelligence feeds
* insecure graph traversal exposure
* report export data leakage
* secrets exposure in CI/CD
* unauthorized model changes
* control evidence tampering

## 13.2 Secure Design Principles

* least privilege
* zero trust
* deny by default
* strong tenant isolation
* cryptographic data protection
* immutable auditability
* supply chain verification
* secretless workloads where possible

## 13.3 Identity and Access Control

### Human auth

* enterprise SSO via OIDC/SAML
* MFA mandatory for privileged users
* step-up auth for exports, policy changes, framework changes

### Authorization

Use RBAC plus ABAC.

#### Roles

* Tenant Admin
* Security Analyst
* Compliance Lead
* Executive Viewer
* Integration Operator
* Platform Support
* Internal Super Admin with break-glass controls

#### ABAC examples

* tenant_id match required
* export permission requires region policy
* evidence reviewer role required for control validation
* internal support cannot see raw customer evidence by default

## 13.4 Data Protection

* TLS 1.3 in transit
* AES-256 encryption at rest
* KMS-managed keys
* optional customer-managed keys later
* signed URLs for evidence access
* malware scanning for uploads
* sensitive fields tokenized or encrypted
* no secrets in application config

## 13.5 Network Security

* private subnets for databases
* service mesh mTLS for internal traffic
* WAF on public endpoints
* egress control for connectors and AI services
* administrative access through bastionless identity-aware access

## 13.6 Audit and Forensics

Audit all:

* logins
* failed auth
* role changes
* connector creation
* evidence uploads
* control validation changes
* risk model version changes
* report exports
* tenant config changes

Audit trails must be immutable or tamper-evident.

---

# 14. Infrastructure and DevOps

## 14.1 Cloud Strategy

Recommended primary cloud: **AWS**

### Core services

* EKS for Kubernetes
* RDS PostgreSQL
* MSK or Redpanda Cloud for streaming
* S3 for object storage
* OpenSearch
* Neptune or self-managed Neo4j depending maturity
* ElastiCache Redis
* IAM, KMS, Secrets Manager
* CloudWatch plus OpenTelemetry pipeline

This choice is based on maturity, strong security primitives, and broad integration support.

## 14.2 Environment Model

* local
* dev
* test
* staging
* production
* isolated customer validation environments if required

## 14.3 CI/CD Pipeline

### Stages

1. lint and static analysis
2. unit tests
3. container build
4. dependency and image scanning
5. integration tests
6. contract tests
7. IaC validation
8. deploy to staging
9. smoke tests
10. policy checks
11. progressive deploy to production

### Tooling

* GitHub Actions or GitLab CI
* ArgoCD or Flux for GitOps
* Terraform for IaC
* Helm for K8s deployment
* Trivy, Snyk, Semgrep, CodeQL for security checks

## 14.4 Scalability Strategy

### Horizontally scalable stateless services

* API service
* questionnaire service
* reporting service
* explainability service

### Independently scaled heavy services

* ingestion consumers
* graph processing workers
* risk computation workers
* LLM summarization workers

### Data scaling

* PostgreSQL partitioning by tenant/time for high-volume tables
* Kafka partitioning
* warehouse scale-out
* graph shard strategy later if needed

## 14.5 Fault Tolerance

* idempotent consumers
* dead-letter queues
* outbox pattern for reliable event publishing
* retries with backoff
* circuit breakers
* graceful degradation if one intelligence source fails
* fall back to prior model state if current enrichment unavailable

---

# 15. Observability and Reliability

## 15.1 Logging

Structured JSON logging for every service.

Required fields:

* timestamp
* service
* tenant_id if permitted
* request_id
* user_id or service_principal
* action
* outcome
* severity
* correlation_id

## 15.2 Metrics

Track:

### Platform metrics

* API latency
* error rates
* queue lag
* job failure rates
* ingestion throughput
* DB query latency
* cache hit rate
* report generation time

### Domain metrics

* assets discovered per tenant
* vulnerability enrichment success rate
* control evidence freshness
* scenario recomputation volume
* scoring confidence distribution

## 15.3 Tracing

Use OpenTelemetry.

Trace examples:

* connector import to risk recomputation
* evidence upload to control revalidation
* questionnaire completion to initial risk baseline

## 15.4 SLOs

### MVP

* API availability: 99.5%
* median API latency: <300 ms
* vulnerability ingestion lag: <15 minutes
* risk recomputation for changed scenario: <5 minutes
* report generation: <60 seconds for standard reports

### Mature target

* API availability: 99.9%
* ingestion lag: <5 minutes
* critical risk change propagation: <2 minutes

## 15.5 Incident Response

* on-call rotation
* severity matrix
* automated paging
* runbooks per service
* post-incident reviews
* game days for ingestion failure, graph corruption, and auth outage

---

# 16. API and Integration Design

## 16.1 API Style

Use REST for broad platform interoperability.
Use GraphQL only for selected UI aggregation needs.

## 16.2 Public API Domains

### Tenant and onboarding

* `POST /v1/tenants`
* `GET /v1/tenants/{id}`
* `POST /v1/questionnaires/{templateId}/responses`

### Asset inventory

* `GET /v1/assets`
* `POST /v1/assets`
* `GET /v1/assets/{id}`
* `GET /v1/assets/{id}/dependencies`

### Vulnerabilities

* `GET /v1/vulnerabilities`
* `GET /v1/assets/{id}/vulnerabilities`

### Controls and compliance

* `GET /v1/controls`
* `GET /v1/frameworks`
* `GET /v1/tenants/{id}/control-gaps`
* `POST /v1/control-evidence`

### Scenarios and risks

* `GET /v1/scenarios`
* `GET /v1/scenarios/{id}`
* `GET /v1/risks`
* `GET /v1/risks/{id}`
* `POST /v1/risks/recompute`

### Reports

* `POST /v1/reports`
* `GET /v1/reports/{id}`

## 16.3 Webhooks

Support webhooks for:

* risk.severity.changed
* scenario.created
* control.validation.failed
* evidence.expired
* vulnerability.detected.on_critical_asset

## 16.4 External Integrations

### Inbound

* scanners
* cloud APIs
* SIEM findings
* IAM exports
* CMDB
* ticketing data

### Outbound

* ServiceNow
* Jira
* Slack / Teams
* SIEM
* GRC platforms
* email alerts

---

# 17. UX and Dashboard Requirements

## 17.1 User Personas

* Tenant Admin
* Security Analyst
* Compliance Manager
* Executive Viewer
* Platform Support

## 17.2 Key Screens

### Executive dashboard

* top risks
* residual vs inherent risk trend
* framework gap summary
* confidence distribution
* critical asset exposure count

### Analyst workbench

* scenario graph
* score breakdown
* evidence and controls
* affected assets
* recommendations
* raw factors and history

### Compliance dashboard

* controls by framework
* missing evidence
* overdue validations
* gap heatmap by control family

### Asset explorer

* service map
* exposure paths
* dependency graph
* ownership
* vuln and control overlay

---

# 18. Textual Diagrams

## 18.1 System Architecture Diagram

```text
[Users / APIs / Integrations]
          |
          v
 [API Gateway + WAF + Auth]
          |
          v
 ------------------------------------------------------
| Core Services                                         |
| Onboarding | Asset | Discovery | Vuln Intel | Threat |
| Compliance | Control | Scenario | Risk | Explain     |
| Reporting  | Notifications                         |
 ------------------------------------------------------
          |
          v
 ------------------------------------------------------
| Processing Layer                                      |
| Kafka | Workflow Engine | Rules Engine | Workers     |
 ------------------------------------------------------
          |
          v
 ------------------------------------------------------
| Data Layer                                            |
| PostgreSQL | Graph DB | Search | Object Store        |
| Warehouse  | Redis                                   |
 ------------------------------------------------------
          |
          v
 ------------------------------------------------------
| Security / Ops                                        |
| IAM | KMS | Secrets | OTel | Logging | Monitoring    |
 ------------------------------------------------------
```

## 18.2 Risk Computation Flow Diagram

```text
Questionnaire + Discovery + Intel + Evidence
                  |
                  v
          Context Normalization
                  |
                  v
         Asset / Dependency Graph Build
                  |
                  v
          Scenario Generation Engine
                  |
                  v
 Likelihood Model + Impact Model + Control Modifier
                  |
                  v
   Inherent Risk -> Residual Risk -> Confidence
                  |
                  v
 Explainability -> API/UI -> Reports/Webhooks
```

## 18.3 Deployment Diagram

```text
Internet / Customer Networks
          |
          v
   CDN / WAF / API Gateway
          |
          v
   Kubernetes Cluster (EKS)
   ------------------------------------------
   | web ui | api | auth | asset | control  |
   | vuln   | threat | scenario | risk      |
   | explain| report | workers | connectors |
   ------------------------------------------
          |
          v
Private Data Services
-----------------------------------------------
| RDS PostgreSQL | Redis | OpenSearch | Graph |
| S3 | Kafka/MSK | Warehouse Loader           |
-----------------------------------------------
          |
          v
Cloud IAM / KMS / Secrets / Monitoring
```

---

# 19. Governance and Data Lifecycle

## 19.1 Data Classification

Classify internal platform data as:

* public metadata
* internal operational
* customer confidential
* regulated/sensitive
* cryptographically protected evidence

## 19.2 Retention

### Suggested defaults

* raw feed snapshots: 90 days
* scanner imports: 180 days
* control evidence: 1 to 3 years depending contract
* audit logs: minimum 1 year
* risk snapshots: indefinite or long-term for trending
* report artifacts: customer-configurable

## 19.3 Governance Controls

* schema registry for event contracts
* data lineage tracking
* versioned scoring snapshots
* framework version history
* evidence validation workflow
* tenant deletion and export process

---

# 20. Recommended Tech Stack

## 20.1 Frontend

* React + TypeScript
* Next.js for admin and app shell
* TanStack Query
* Cytoscape.js or React Flow for graph views
* ECharts or Apache Superset embed for analytics visuals

## 20.2 Backend

* TypeScript with NestJS for platform APIs and orchestration
* Python services for data science, graph processing, ML, and enrichment jobs
* gRPC internally where low-latency service communication matters
* REST externally

## 20.3 Data

* PostgreSQL
* Neo4j or Neptune
* OpenSearch
* Redis
* S3
* ClickHouse or Snowflake for analytics

## 20.4 Streaming and Workflows

* Kafka or Redpanda
* Temporal for workflow orchestration

## 20.5 AI/ML

* Python
* MLflow
* Feast optional for feature serving later
* LLM gateway abstraction so provider can be swapped

## 20.6 DevOps and Security

* Kubernetes
* Terraform
* ArgoCD
* GitHub Actions
* Trivy, Semgrep, CodeQL
* OpenTelemetry
* Prometheus and Grafana

---

# 21. Implementation Roadmap

## Phase 1: Foundation MVP

### Goals

* prove core architecture
* onboard tenants
* collect baseline context
* compute first explainable risks

### Deliverables

* tenant/auth service
* questionnaire service
* asset service
* basic CVE ingestion
* compliance framework catalogs
* control registry
* initial risk engine
* executive dashboard
* report export

### Risks

* weak initial data coverage
* over-engineering graph too early

### Success criteria

* produce explainable inherent and residual risks for at least 3 scenario types
* support manual evidence and manual asset entry

---

## Phase 2: Context and Intelligence Expansion

### Deliverables

* cloud connectors
* scanner connectors
* graph DB integration
* scenario modeling service
* automated control mapping
* confidence scoring
* analyst workbench

### Success criteria

* automated scenario generation for internet-exposed assets
* incremental recomputation on vulnerability changes
* first control gap recommendations

---

## Phase 3: Enterprise Hardening

### Deliverables

* SSO and enterprise RBAC
* stronger audit and reporting
* multi-region deployment
* advanced observability
* ticketing and SIEM integrations
* model registry and scoring version governance

### Success criteria

* 99.9% availability target readiness
* audit-complete trail for all privileged actions
* scalable ingestion for large tenants

---

## Phase 4: Advanced AI and Optimization

### Deliverables

* recommendation ranking model
* LLM explanation refinement
* evidence summarization
* sector-specific threat relevance models
* predictive scenario simulation

### Success criteria

* measurable analyst time reduction
* improved prioritization precision
* no loss of explainability or governance

---

# 22. Technical Risks and Mitigations

## Risk 1: Data quality is poor

### Mitigation

* confidence scoring
* explicit completeness indicators
* manual override workflows
* source-level quality metrics

## Risk 2: Graph complexity grows too fast

### Mitigation

* constrain graph scope
* incremental path recomputation
* archived graph partitions
* predefined scenario templates

## Risk 3: Controls are marked implemented without proof

### Mitigation

* evidence validation workflow
* evidence freshness rules
* operating effectiveness separate from design effectiveness

## Risk 4: LLM explanations hallucinate

### Mitigation

* retrieval-only context
* source-bound prompting
* no LLM authority over final score
* explanation review flagging

## Risk 5: Tenant isolation failure

### Mitigation

* row-level security
* service-level tenant enforcement
* tenancy-aware integration tests
* separate encryption scopes

## Risk 6: Overly complex scoring reduces trust

### Mitigation

* publish factor model
* stable severity bands
* version scores
* expose breakdowns in UI

---

# 23. Recommended Initial Scenario Library

Start with a small but high-value scenario set.

1. Internet-facing web application compromise
2. SaaS account takeover due to weak identity controls
3. Cloud storage exposure and data leakage
4. Vulnerability exploitation on critical server
5. Privileged access abuse
6. Supplier or integration trust-chain compromise
7. Missing segmentation leading to lateral movement
8. Public admin interface exposure
9. Backup compromise reducing recoverability
10. Unsupported software on critical asset

These align closely with the kind of contextual and control-driven reasoning described in the source brief. 

---

# 24. Concrete Refactor Plan for the Existing Repository

The source material asks for actionable redesign steps, not theory. 

## Step 1: Remove direct risk formula assumptions

* isolate current scoring logic behind a scoring interface
* stop treating risk as direct severity aggregation
* introduce separate likelihood, impact, and control dimensions

## Step 2: Add questionnaire and tenant context module

* create tenant profile schema
* capture business, technical, and compliance context
* block final scoring until context minimum is met

## Step 3: Build canonical asset model

* add asset, service, interface, dependency, and data classification entities
* support both manual entry and connector ingestion

## Step 4: Introduce control catalog and tenant control state

* load ISO, NIST, CIS mappings
* represent applicability, implementation, and effectiveness separately

## Step 5: Add vulnerability normalization layer

* ingest CVE/NVD
* map to products and assets
* enrich with exploit and activity signals

## Step 6: Implement scenario objects

* represent entry vector, target, path, and required conditions
* score scenarios instead of raw vulnerabilities alone

## Step 7: Separate inherent and residual scoring

* inherent from threat, exposure, impact
* residual from applicable control reduction

## Step 8: Add explainability snapshots

* persist factor contributions
* store model version and evidence references

## Step 9: Introduce confidence scoring

* start simple with coverage and freshness
* expose confidence in every result

## Step 10: Make architecture modular

* split into onboarding, asset, control, intel, scenario, and risk modules
* use domain events for recomputation triggers

---

# 25. Final Architecture Positioning

Astraut Risk Reasoner should not be positioned as a scoring calculator.

It should be positioned as a **cyber risk reasoning platform** that:

* understands organizational and technical context
* models realistic attack scenarios
* applies compliance and control logic
* fuses vulnerability and threat intelligence
* computes inherent and residual risk
* explains every output with confidence and evidence

That positioning matches the original vision in your source document: the platform is not just a scoring tool, but a reasoning engine that connects context, threats, controls, and compliance into one explainable model.  

---

# 26. What I recommend doing next

The strongest next step is to turn this into three concrete artifacts:

1. a **software architecture specification**
2. a **database schema and domain model package**
3. a **set of visual diagrams and an MVP implementation plan**

I can turn this into a **proper formatted DOCX or PDF package** with diagrams, tables, and polished architecture sections.
