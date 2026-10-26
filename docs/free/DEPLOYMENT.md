# CodeSentinal. — Deployment & Architecture (Free Build)

How the free build is put together and how it runs inside our own AWS account
(`eks-lab`, us-east-1). This is the env we build and test on before the paid build
goes to a client account.

> This document explains **how it works** — the architecture, the microservices, how
> they connect, and how it is built. The actual setup/install/deploy commands live in
> **RUNBOOK.md**.

> Read-only product. It reads the account and reports; it changes nothing on AWS.
> No static AWS keys run in the cluster — access is via IRSA.

---

## 1. Microservice architecture (in-cluster)

```
                         Internet
                            │                 (HTTPS when an ACM cert + domain are set;
                   ┌────────▼─────────┐        optional source-IP allow-list)
                   │   ALB Ingress    │
                   │  / → frontend    │
                   │  /api → backend  │
                   └────────┬─────────┘
                            │
   ┌────────────────────────┼──────────── EKS: eks-lab (namespace CodeSentinal.) ────────┐
   │                        │                                                       │
   │   ┌──────────────┐     │     ┌────────────────────────────────┐                │
   │   │  frontend    │◄────┴────►│   backend (Go API/agent)       │                │
   │   │ (React/Nginx)│   HTTP    │  discovery · own checks ·      │                │
   │   │  risk-first  │           │  lifecycle · dedupe · rank ·   │                │
   │   │  portal      │           │  attack paths · reports ·      │                │
   │   └──────────────┘           │  alerts · signed sessions      │                │
   │                              └────┬─────────────┬──────┬──────┘                │
   │     reads results (shared PVC) ───┘             │      │ creates Jobs (RBAC)   │
   │   ┌───────────── scanners ─────────────────┐    │      ▼                       │
   │   │ prowler CronJob + on-demand Jobs       │    │   batch/Jobs (deep scan)     │
   │   │ (scoutsuite, cloudsplaining optional)  │    │                              │
   │   │ co-located with backend via podAffinity│    │ IRSA (read-only role)        │
   │   └──────────────────┬─────────────────────┘    │                              │
   └──────────────────────┼──────────────────────────┼────────────────┬────────────┘
                          │ results volume (EBS PVC) │                │
       ┌──────────────────┴───────────┐         ┌────┴───────┐   ┌────▼──────────────┐
       ▼        ▼      ▼     ▼     ▼   ▼        ▼            ▼   │  DynamoDB         │
     EC2       S3     IAM   RDS  Lambda EKS  CloudTrail  Bedrock │  reviews/history  │
   (Describe/Get/List — READ ONLY, ALL REGIONS)        (wording) │  risks/plans/...  │
                                                                 └───────────────────┘
```

A deploy creates these objects in the `CodeSentinal.` namespace:

| Object | Kind | Role |
|---|---|---|
| `CodeSentinal.-backend` | Deployment + Service | the Go agent/API |
| `CodeSentinal.-frontend` | Deployment + Service | the React portal (Nginx) |
| `CodeSentinal.-prowler` | CronJob (+ on-demand Jobs) | the Prowler scanner |
| `CodeSentinal.-prowler-results` | PVC (EBS) | shared scanner output |
| `CodeSentinal.` | Ingress (ALB) | public entry: `/` → frontend, `/api`+`/health` → backend |
| `CodeSentinal.-auth` | Secret | superadmin password + session secret (+ optional Slack webhook) |
| `CodeSentinal.-sa` | ServiceAccount (IRSA) | the read-only AWS role |
| `CodeSentinal.-deepscan` | Role + RoleBinding | lets the backend run on-demand Prowler Jobs |

ScoutSuite and cloudsplaining CronJobs are shipped but disabled by default.

---

## 2. The three microservices and how they connect

### Backend (`CodeSentinal.-backend`) — pure Go
The agent and the HTTP API. It:
- **discovers** every resource across all enabled regions (read-only AWS SDK),
- runs its **own read-only checks** and **ingests** the scanners' results,
- gives each finding a **stable fingerprint** and a **lifecycle** (open / fixed /
  regressed / accepted), **deduplicates** across sources, and **ranks** by a
  weighted rubric,
- computes **attack paths**, builds **reports**, evaluates **Slack alerts**,
- persists everything to **DynamoDB**,
- serves the API behind a **signed-session auth gate** with security headers.

It assumes the read-only IAM role via **IRSA** — no static keys. The only thing it
writes is its own DynamoDB table.

### Frontend (`CodeSentinal.-frontend`) — React + Nginx
The risk-first portal (Overview, Findings, Attack paths, Inventory, Risks, Reports,
Activity, Settings). Nginx serves the built SPA and **proxies** `/api` and `/health`
to the backend Service, and sets security headers (CSP, nosniff, frame-deny). The
browser talks only to the frontend origin; the frontend reaches the backend over the
in-cluster Service DNS (`CodeSentinal.-backend:8080`).

### Scanners (`CodeSentinal.-prowler`, optional ScoutSuite/cloudsplaining)
Open-source scanners run as **Kubernetes Jobs/CronJobs** under the same read-only
IRSA role. They write results to the **shared EBS PVC**; the backend reads that
volume and normalises everything into one `Finding` model. On-demand **deep scans**
are started by the backend creating a Job from the CronJob (the namespace-scoped
RBAC Role grants exactly that — nothing on AWS, nothing outside the namespace).

### Data store (DynamoDB)
One on-demand table (`CodeSentinal.-reviews`) holds reviews, history/trend, the
accepted-risk register, remediation plans, report snapshots, the audit log,
settings, and the scheduler lease. Large reviews are chunked to stay under the
item-size limit. Review history is what lets the product show "what's new, what was
fixed, how long it's been open".

### Bedrock (optional)
Amazon Bedrock only turns already-detected findings into plain-English wording and
report narrative. It never detects anything and never changes a number. If it is
unavailable, built-in templates are used and nothing breaks.

---

## 3. How it's built

- **Backend image** — multi-stage: compile the pure-Go static binary, then ship it
  on a distroless nonroot base. Tiny, no shell, no interpreter.
- **Frontend image** — multi-stage: Vite builds the React SPA, then it is served by
  `nginxinc/nginx-unprivileged` (runs as uid 101) with writable `emptyDir` mounts
  for the Nginx cache/pid/conf dirs. Config is templated with `envsubst` at start so
  the backend Service name is injected.
- Both images are pushed to **private ECR** repos (`CodeSentinal.`, `CodeSentinal.-frontend`),
  one per image, and tagged `latest` with `imagePullPolicy: Always` so a redeploy
  always pulls the new image.
- The **Helm chart** (`deploy/helm/CodeSentinal.`) renders every object above from
  `values.yaml`. The session secret is generated by the chart and **reused on
  upgrade** (via `helm lookup`) so sessions survive restarts and multiple replicas.

---

## 4. Access & safety model

- **IRSA, read-only.** The `CodeSentinal.ReadOnly` IAM policy allows only
  `Describe*/Get*/List*` across the audited services (EC2, S3, IAM, Lambda, RDS,
  DynamoDB, EKS, CloudTrail, KMS, CloudWatch, Logs, SNS, Access Analyzer) plus
  optional `bedrock:InvokeModel`. The one read/write grant is scoped to the single
  `CodeSentinal.-reviews` DynamoDB table — never client resources.
- **No static keys** anywhere in the cluster.
- **Portal auth.** Every data endpoint requires a signed superadmin session token
  (no `?token=` in URLs); logins are throttled; security headers + CSP are set.
- **Multi-replica safe.** Sessions are stateless (HMAC-signed); a DynamoDB lease
  ensures only one replica runs scheduled scans.
- **HTTPS.** With an ACM certificate + domain, the ALB serves HTTPS and redirects
  HTTP → 443. Without them it runs HTTP (the portal shows a warning); an IP
  allow-list can restrict access in the meantime.

---

## 5. Environments

- **This free build runs in our own AWS account** (`eks-lab`). For now, our account
  *is* the test/local environment — we build and verify the whole product here.
- The **paid build** (native AWS security-service readers) and **client-account**
  deployment come later and are out of scope for this build.

See **RUNBOOK.md** for the exact commands to deploy, verify, operate, and tear down,
and **VERIFY.md** for the test cases that prove the platform works.
