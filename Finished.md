# CodeSentinal. — Finished (Free Build)

Everything in the free build is **built, tested, and deployed live** to our account
(`eks-lab`, us-east-1). Read-only, pure-Go backend + React portal, no paid AWS
services. Detection is done by the scanners/own-checks; Bedrock only writes wording.

## Foundation — findings that remember
- **F1 Stable finding identity & lifecycle** — every finding has a deterministic
  fingerprint; status moves open → fixed → regressed → accepted; first-seen/last-seen/
  age tracked; a finding is marked fixed only when every source that reported it ran.
- **F2 Cross-source deduplication** — one finding per problem, all reporting sources
  listed, highest severity kept, "N duplicates merged" surfaced.
- **F3 History & trend** — a history point saved after each full scan; the portal
  shows the score trend and "what changed since last scan".
- **F4 Accepted-risk register** — accept a risk with reason/owner/expiry; excluded
  from the score; returns to open at expiry.
- **F5 Remediation plan** — owner + effort (S/M/L) + due date per finding; persisted.
- **F8 Editable scoring rubric** — weights/penalties/bands editable with validation;
  per-severity cap so large accounts don't always floor at 0.

## Intelligence
- **F6 Attack paths** — six conservative chains (AP-1..AP-6) computed from facts,
  each with evidence and the cheapest step that breaks the chain; on-path findings
  rank higher.
- **F7 Fix-as-code** — Terraform + AWS CLI snippets for 15 common finding types, each
  with "what could break", effort, and a "Review before applying" label. Works with
  no AI; Bedrock may improve the wording.

## Reports & workflow
- **F9 Reports** — account / service / resource scope, rendered to **Word (.docx),
  Markdown and print-ready HTML**; numbers come from data, never from a model.
- **F10 Review & approval** — draft → in_review → approved/rejected with reviewer +
  note; approved reports are immutable; illegal transitions blocked.
- **F11 Audit log** — every action recorded; filter + CSV/JSON export (formula-safe).
- **F12 Slack alerts** — new critical/high, regressions, new attack paths, expiring
  risks, failed scans; immediate or digest; duplicate suppression; strict webhook
  validation.
- **F13 Branding & settings** — MSP/client name + logo, source toggles, schedule,
  rubric, reviewer, alert rules; stored in DynamoDB.

## Platform
- **F14 Access hardening** — stateless HMAC-signed sessions (survive restarts &
  multi-replica), no token in URLs, login throttling, security headers + CSP, ALB
  HTTPS + HTTP→HTTPS redirect when an ACM cert/domain is set, optional IP allow-list.
- **F15 Real on-demand scans** — quick audit (own checks, one service/resource, no
  full re-discovery) and deep scan (on-demand Prowler Job via namespace RBAC, with
  live status), single-flight; scan pods co-located with the backend for the volume.
- **F16 Discovery completeness** — CloudTrail trails listed; security groups &
  volumes discovered; resource-type filter on the service page; multi-region.
- **F6-supporting own checks** — added IAM old-access-key and EC2 IMDSv2, alongside
  IAM MFA/admin, S3 public/encryption, EC2 SG open-world, EBS, EKS public endpoint,
  RDS public/unencrypted, Lambda public URL, DynamoDB encryption, CloudTrail.

## Portal & modes
- **F17 Risk-first portal** — 8 sections (Overview, Findings, Attack paths,
  Inventory, Risks, Reports, Activity, Settings), light/dark theme, inline SVG icons,
  score ring, trend chart, attack-path diagram, finding drawer with fix tabs;
  keyboard-accessible.
- **F19 Demo mode** — `DEMO_MODE=true` serves deterministic synthetic data with no
  AWS calls and a "Demo data" banner (used for safe UI testing).

## Persistence & scheduling
- **DynamoDB store** — reviews (chunked for large accounts), history, risks, plans,
  reports, activity, settings, scheduler lease; in-memory fallback.
- **Scheduled scans** — in-process interval scheduler (one replica via a DynamoDB
  lease) plus the Prowler CronJob.

## Detection model (locked in)
- Tools detect; code ranks; templates/Bedrock only write wording. Bedrock is never a
  finding source and never changes a number; everything works with Bedrock off.

## Open-source scanners (behind one Finding model)
- **Prowler** — default, OCSF ingested (robust parser).
- **ScoutSuite, cloudsplaining** — collectors + CronJob templates shipped, disabled
  by default, enable per deployment.

## Delivery
- Microservice Helm chart (backend, frontend, Prowler CronJob, PVC, ALB ingress,
  auth secret, deep-scan RBAC); `start.sh` / `stop.sh`; IRSA read-only policy.
- **Deployed and verified live on eks-lab**: auth gate, 17-region scan, dedup,
  stable-fingerprint lifecycle, trend, report create→approve→download DOCX, activity
  log, disabled native toggles, scoped-audit "no stale data", SPA + CSP.
- 16 Go packages, all table-driven tested; `go build` / `go vet` / `gofmt` /
  `go test -race` / `helm lint` all clean. Merged to `main`.

## Docs
- `docs/free/DEPLOYMENT.md` (architecture & how it works), `RUNBOOK.md` (setup,
  start/stop, debug), `VERIFY.md` (test cases), `Sow-free-build.md` (the SOW),
  `CodeSentinal.-Build-Spec.md` (engineering spec).
