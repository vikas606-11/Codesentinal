# CodeSentinal. — Test Cases (Free Build)

How to check the platform is working. Each test has steps and the expected result.
Run against the live deployment on `eks-lab`. Deploy/operate commands are in
RUNBOOK.md; this file is only "does it work?".

Set up once per session:
```bash
URL=$(kubectl -n CodeSentinal. get ingress CodeSentinal. -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
TOKEN=$(curl -s -XPOST http://$URL/api/v1/auth/login -d '{"password":"'"$SUPERADMIN_PASSWORD"'"}' | jq -r .token)
H="Authorization: Bearer $TOKEN"
```

---

## Platform / health

**T1 — Service is up**
```bash
curl -s http://$URL/health
```
Expect: `{"status":"ok","service":"CodeSentinal.","store":"dynamodb:CodeSentinal.-reviews"}`.

**T2 — Meta reports the right mode**
```bash
curl -s http://$URL/api/v1/meta
```
Expect: `version` 2.0.0, `auth_required: true`, `kube_available: true`, store dynamodb.

---

## Authentication (the portal is not public)

**T3 — No token is rejected**
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://$URL/api/v1/overview
```
Expect: `401`.

**T4 — Wrong password is rejected**
```bash
curl -s -o /dev/null -w "%{http_code}\n" -XPOST http://$URL/api/v1/auth/login -d '{"password":"wrong"}'
```
Expect: `401`.

**T5 — Valid password returns a token; token works**
```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "$H" http://$URL/api/v1/services
```
Expect: `200`.

**T6 — Token in the URL is refused (no ?token= fallback)**
```bash
curl -s -o /dev/null -w "%{http_code}\n" "http://$URL/api/v1/services?token=$TOKEN"
```
Expect: `401`.

**T7 — Repeated bad logins are throttled**
Fire 6+ wrong-password logins quickly.
Expect: eventually `429` with a `Retry-After` header.

---

## Discovery & scanning

**T8 — Full multi-region scan**
```bash
curl -s -XPOST -H "$H" http://$URL/api/v1/review \
 | jq '{regions:(.regions|length), findings:.summary.total, sources:.summary.by_source, dupes:.duplicates_merged, paths:(.paths|length)}'
```
Expect: `regions` = number of enabled regions (e.g. 17), `findings` > 0, sources
include `own-check` (and `prowler` once a Prowler scan has run), `dupes` >= 0.

**T9 — Services landing has counts**
```bash
curl -s -H "$H" http://$URL/api/v1/services | jq '.services[] | {key, resource_count, finding_count}'
```
Expect: EC2, S3, IAM, Lambda, RDS, DynamoDB, EKS, CloudTrail with counts.

**T10 — Region filter narrows resources**
```bash
curl -s -H "$H" "http://$URL/api/v1/resources?service=ec2&region=us-east-1" | jq '.resources | length'
```
Expect: only us-east-1 EC2 resources (<= the all-regions count).

**T11 — CloudTrail card is not empty (discovery completeness)**
```bash
curl -s -H "$H" "http://$URL/api/v1/resources?service=cloudtrail" | jq '.resources | length'
```
Expect: the real number of trails (not always 0).

---

## Lifecycle, dedup, no-stale-data (the core MSP value)

**T12 — Stable IDs: rescan an unchanged account**
Run the full scan (T8) twice.
```bash
curl -s -XPOST -H "$H" http://$URL/api/v1/review | jq '.changes'
```
Expect on the **second** run: `new_count: 0, fixed_count: 0, regressed_count: 0`
(findings keep their identity across scans).

**T13 — Cross-source dedup**
With Prowler results present, check a finding reported by both sources:
```bash
curl -s -H "$H" "http://$URL/api/v1/findings?q=security%20group" | jq '.items[0].sources'
```
Expect: one finding listing multiple sources (e.g. own-check + prowler), not two rows.

**T14 — No stale data: scoped audit preserves other scopes**
```bash
BEFORE=$(curl -s -H "$H" http://$URL/api/v1/review/latest | jq '.summary.by_service.iam')
curl -s -XPOST -H "$H" "http://$URL/api/v1/audit?service=ec2" >/dev/null
AFTER=$(curl -s -H "$H" http://$URL/api/v1/review/latest | jq '.summary.by_service.iam')
echo "iam before=$BEFORE after=$AFTER"
```
Expect: `before == after` — an EC2-scoped audit does not wipe IAM findings.

**T15 — Fixed / regressed (needs a real change in the account)**
Fix one finding's cause in AWS, rescan → that finding's `status` becomes `fixed`.
Revert the change, rescan → it becomes `regressed` and keeps its original `first_seen`.

---

## Intelligence

**T16 — Attack paths**
```bash
curl -s -H "$H" http://$URL/api/v1/paths | jq '.paths[] | {kind, title, break_hint}'
```
Expect: zero or more of AP-1..AP-6, each with evidence and a "break the chain" hint.

**T17 — Fix-as-code on a finding**
```bash
FID=$(curl -s -H "$H" "http://$URL/api/v1/findings?status=open" | jq -r '.items[0].id')
curl -s -H "$H" "http://$URL/api/v1/finding?id=$FID" | jq '{fix:.fix.title, tf:(.fix.terraform!=null), cli:(.fix.cli!=null), label:.fix.label}'
```
Expect: a fix with Terraform + CLI and the label "Review before applying" (for
mapped finding types; unmapped ones fall back to the recommendation).

**T18 — Explanation works with or without Bedrock**
The same `GET /api/v1/finding?id=` response includes `explanation`. Expect a
`problem` / `how_to_fix`; `provider` is `bedrock` when available, else `offline`.

---

## Risk register & plan

**T19 — Accept a risk removes it from the score**
```bash
FP=$(curl -s -H "$H" "http://$URL/api/v1/findings?status=open" | jq -r '.items[0].fingerprint')
curl -s -XPOST -H "$H" http://$URL/api/v1/risks \
  -d '{"fingerprint":"'"$FP"'","reason":"accepted for testing purposes","owner":"sre","expires_at":"'"$(date -u -v+2d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+2 days' +%Y-%m-%dT%H:%M:%SZ)"'"}'
curl -s -H "$H" http://$URL/api/v1/risks | jq '.risks | length'
```
Expect: the risk appears in the register; after the next scan that finding's status
is `accepted` and it no longer counts toward the posture score.

**T20 — Remediation plan persists**
```bash
curl -s -XPUT -H "$H" http://$URL/api/v1/finding/plan -d '{"id":"'"$FID"'","owner":"alice","effort":"M","due_date":"2026-12-01"}'
```
Expect: `{"ok":true,...}`; the owner/effort/date survive a backend restart.

---

## History, reports, workflow

**T21 — Trend grows with each scan**
```bash
curl -s -H "$H" http://$URL/api/v1/history | jq '.history | length'
```
Expect: increases by one after each full scan.

**T22 — Report: create → submit → approve → download**
```bash
RID=$(curl -s -XPOST -H "$H" http://$URL/api/v1/reports -d '{"scope":"account"}' | jq -r .id)
curl -s -XPOST -H "$H" "http://$URL/api/v1/reports/$RID/submit" -d '{"reviewer":"SRE Team"}' | jq .status   # in_review
curl -s -XPOST -H "$H" "http://$URL/api/v1/reports/$RID/approve" | jq .status                               # approved
curl -s -H "$H" "http://$URL/api/v1/reports/$RID/download?format=docx" -o report.docx
head -c2 report.docx | xxd | grep 'PK'   # valid .docx (zip) magic bytes
```
Expect: status moves draft → in_review → approved; the `.docx` is a valid file (and
opens in Word/LibreOffice without a repair prompt). `format=md` and `format=html`
also work and carry the same numbers.

**T23 — Illegal report transition is blocked**
Try to `approve` a draft (skip submit).
Expect: `409`.

---

## Activity, settings, integrations

**T24 — Audit log records actions**
```bash
curl -s -H "$H" http://$URL/api/v1/activity | jq '.entries[0:5] | .[].action'
curl -s -H "$H" "http://$URL/api/v1/activity?format=csv" | head -3
```
Expect: entries like `login.success`, `scan.full`, `report.create/approve/download`;
CSV export works and escapes formula-injection.

**T25 — Settings validation**
Try to save a rubric whose weights don't sum to 1.
Expect: `400` with a clear error; valid weights change the next scan's scores.

**T26 — Native-service toggles are shown but disabled (free build)**
```bash
curl -s -H "$H" http://$URL/api/v1/integrations | jq '.integrations[] | {key, enabled, available}'
```
Expect: guardduty / securityhub / inspector all `enabled:false, available:false`.

---

## Frontend

**T27 — Portal loads**
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://$URL/
curl -s http://$URL/ | grep -o '<title>.*</title>'
```
Expect: `200` and the CodeSentinal. title; assets under `/assets/*.js` return `200`.

**T28 — Security headers present**
```bash
curl -s -D - -o /dev/null http://$URL/ | grep -iE 'content-security-policy|x-frame-options|x-content-type-options'
```
Expect: CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.

**T29 — Manual UI walk** (browser)
Sign in → Overview shows the score ring, trend and top fixes → open a finding, see
the fix tabs and accept-risk → Attack paths render → Inventory → service → resource
→ quick audit → Reports create/approve/download → Settings toggles. Check it works
by keyboard and in both light/dark themes.

---

## Safety (must always hold)

**T30 — Read-only**: no API makes a write/modify/delete call on a client resource;
the IAM policy has no write action except on the `CodeSentinal.-reviews` table.

**T31 — No static keys**: the backend pod has `AWS_ROLE_ARN` + a web-identity token
(IRSA), not static credentials (see the debug command in RUNBOOK §4).

**T32 — Bedrock is never a source**: no finding's `sources[].source` is "bedrock".
