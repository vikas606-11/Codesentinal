# CodeSentinal.

**An AWS SecOps agent you deploy into a client's own AWS account.**

CodeSentinal. runs inside the client's Amazon EKS cluster, discovers every AWS resource
in the account (grouped by service), runs read-only security checks plus the
open-source **Prowler** scanner, ranks findings by real risk, and presents a
security posture dashboard with AI-generated explanations (via Amazon Bedrock).

It is **read-only and recommend-only** — it never changes, deletes, or remediates
anything in the account. Each client gets their own private deployment; this is a
per-client product, not a shared SaaS.

## Why Go
A single small static binary, k8s-native, no interpreter or dependency sprawl inside
the client's account. The AI layer is Amazon Bedrock (a hosted API), so no local ML
runtime is needed.

## Architecture (microservices)
When installed, the Helm chart deploys **three separate workloads** into the
client's cluster, plus a shared volume and a public load balancer:

- **backend** (`CodeSentinal.-backend`, Deployment+Service) — the Go agent/API.
  Read-only, runs under the IRSA role. Serves `/api/v1/*`.
- **frontend** (`CodeSentinal.-frontend`, Deployment+Service) — the React dashboard
  served by Nginx, which proxies `/api` to the backend.
- **prowler** (`CodeSentinal.-prowler`, CronJob) — the open-source **Prowler**
  scanner. Runs read-only under the same IRSA role on a schedule and writes
  OCSF JSON to a shared PVC that the backend ingests.
- **ingress** (ALB) — one public URL: `/` → frontend, `/api` + `/health` → backend.

### Source layout
- `cmd/CodeSentinal.` — the agent / API server (Go)
- `internal/discovery` — read-only AWS resource inventory, grouped by service
- `internal/collectors` — read-only security checks: own-checks + **Prowler** (OCSF ingest)
- `internal/ranking` — deterministic risk rubric (severity/exposure/reachability/criticality)
- `internal/bedrock` — Bedrock explanations with offline fallback
- `internal/api` — HTTP API for the dashboard
- `dashboard/` — React dashboard (Vite + Nginx)
- `deploy/helm/CodeSentinal.` — Helm chart (backend, frontend, prowler, PVC, ALB ingress)

## Docs
- `docs/PRODUCT.md` — the product vision and how it works
- `docs/SOW.md` — scope of work
- `docs/DEPLOYMENT.md` — how it is deployed into a client account
- `docs/PREREQUISITES.md` — what access/resources the client must provide

## Status
Early build. Core engine (discovery, checks, ranking, Bedrock, API) works live
against a real AWS account, read-only.
