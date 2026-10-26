# CodeSentinal. — Statement of Work

**Paid Build (v2): everything in the Free Build plus Security Hub, GuardDuty, Inspector and IAM Access Analyzer**

| | |
|---|---|
| **Product** | CodeSentinal., an AWS SecOps agent for managed service providers (MSPs) |
| **Edition** | **Paid build.** The full Free Build **plus** read-only readers for Security Hub, GuardDuty, Inspector and IAM Access Analyzer |
| **Supplier** | [Supplier name] |
| **Customer** | [MSP name] |
| **Delivery model** | One private deployment per managed client, inside that client's own AWS account. Not a shared SaaS |
| **Account scope** | One AWS account per deployment. AWS Organizations and multi-account views are out of scope and planned for a later release |
| **Document status** | Draft v2.0 for review, 24-Oct-2026 |
| **Companion documents** | `Sow-free-build.md` (the base build; this document includes all of it), `CodeSentinal.-Build-Spec.md` (engineering instructions, Part A free and Part B paid) |

## 1. Summary

CodeSentinal. is installed into a managed client's AWS account. It discovers every resource across all enabled regions, audits it with its own read-only checks and the open-source Prowler scanner, ranks findings by real risk, and keeps a history so it can say what is new, what was fixed, and what has been open for how long. It then produces what an MSP hands to a client: a ranked fix list, a risk register, a branded posture report, and alerts.

This **paid build** adds the AWS-native security services as extra, optional detection sources. When the client already runs Security Hub, GuardDuty, Inspector or IAM Access Analyzer, CodeSentinal. reads their findings, merges them with its own into one queue, and shows what none of the free sources can: **active threats** and **known vulnerabilities (CVEs) on workloads**.

CodeSentinal. stays **read-only and recommend-only**. It reads findings from these services; it never enables them, changes them, suppresses a finding in them, or remediates anything. The client switches those AWS services on (and pays AWS for them); CodeSentinal. only reads.

CodeSentinal. does not depend on those services. If a client has none of them, the paid build behaves exactly like the free build for that account.

### 1.1 What this build adds to the current product

All of the Free Build (stable finding lifecycle, deduplication, accepted-risk register, attack paths, fix-as-code, branded reports with review and approval, audit log, alerts, risk-first portal, local and demo modes), plus:

| # | Addition | Why an MSP cares |
|-----|----------------------------------------|-------------------------------------------------------|
| P1 | Security Hub reader | Pulls in whatever the client already aggregates, including partner products |
| P2 | GuardDuty reader and active-threat panel | Answers "is something happening right now?", which configuration scanning cannot |
| P3 | Inspector reader | CVEs on EC2, container images and Lambda, with fix versions and exploit flags |
| P4 | IAM Access Analyzer reader | Resources shared outside the account |
| P5 | Cross-source deduplication including native control IDs | One finding even when Prowler, Security Hub and CodeSentinal. all report it |
| P6 | Attack paths enriched with native signals | A path that also has an exploitable CVE or an active threat is ranked higher |
| P7 | Live integration page | Shows whether each service is enabled, whether CodeSentinal. can read it, and what it costs |

### 1.2 How this edition differs from the free build

| | Free build | **Paid build (this document)** |
|---|---|---|
| Detection sources | Own checks + Prowler (+ optional ScoutSuite, cloudsplaining) | The same, plus Security Hub, GuardDuty, Inspector and Access Analyzer readers |
| Works on a free-tier account | Yes | The free sources do; the native readers need those AWS services enabled |
| Active threat view | Not available | Yes (GuardDuty) |
| Vulnerability (CVE) view | Not available | Yes (Inspector) |
| Native service toggles | Shown, disabled | Live; read-only; off by default |
| AWS cost to the client | Compute and storage for CodeSentinal. only | The same, plus the client's own charges for each native service they enable |

## 2. Who it is for and when it is used

### 2.1 Users

| Who | What they do with CodeSentinal. |
|----------------------------|------------------------------------------------------------------------|
| **MSP security or cloud lead** (the `superadmin` in this release) | Runs scans, reviews findings, accepts risks, approves reports, sets alerts |
| **MSP engineer** | Works through the fix list, applies the Terraform or CLI change through the MSP's normal change process |
| **Client stakeholder** | Receives the approved report. Does not sign in to the portal in this release |

This release keeps a single sign-in role (`superadmin`). Reviewer and owner names are recorded as text. Named users and roles are planned for a later release.

### 2.2 When it is used

| Moment | What happens | What the MSP gets |
|--------------------|--------------------------------------|------------------------------------------|
| **Client onboarding** | Deploy, run the first full scan and a Prowler deep scan | A baseline: score, ranked fixes, attack paths |
| **Weekly review** | Open the Overview: what changed since last scan | New, fixed and regressed findings; the next five things to fix |
| **Monthly client report** | Generate, review, approve, download | A branded Word report showing the score trend and what was closed |
| **Change window** | Audit a service or resource before and after | Proof a change worked, or an alert if it regressed |
| **Audit or questionnaire prep** | Use the report and the risk register | Evidence of controls mapped to CIS, and a register of accepted risks |
| **Between reviews** | Scheduled scans and Slack alerts | Notice of a new critical finding without anyone looking |

### 2.3 What the first week looks like

1. Day 1: deploy into the client account and run the full scan and deep scan.
2. Day 2: the MSP reviews the baseline, marks genuine exceptions as accepted risks, and assigns owners and effort to the top findings.
3. Days 3 to 7: engineers apply fixes. Each scheduled scan marks fixed items as fixed and flags anything that comes back.
4. End of week: the MSP generates the report, reviews it, approves it and sends it. The score trend now shows movement.

## 3. Starting point and detection model

### 3.1 Where the product stands today (v1)

v1 is deployed and working: multi-region discovery, own checks, Prowler ingestion, risk ranking, Bedrock explanations with offline fallback, a service-then-resource portal, DynamoDB persistence, a password gate, and Helm deployment. A review of the v1 code found these gaps, which this build closes:

| # | Gap in v1 | Effect | Closed by |
|-----|--------------------------------------|------------------------------------------|---------------|
| G1 | Finding IDs and first-seen times are regenerated on every scan | Cannot tell new from old, fixed from open, or show history | F1 |
| G2 | The same problem reported by two sources appears twice | Inflated counts and noise | F2 |
| G3 | Review history is stored but never shown | No trend, no proof of improvement | F3 |
| G4 | Reports (Markdown and PDF) are promised in the v1 SOW but not built | The main MSP deliverable does not exist | F9 |
| G5 | The **Audit** button re-runs own checks and re-reads the last Prowler file; it does not run Prowler | The button overstates what it does; a single-resource audit also re-discovers the whole account | F15 |
| G6 | CloudTrail appears as a service card but discovery never lists CloudTrail resources, so the card is always empty | Looks broken | F16 |
| G7 | Login sessions are held in memory | Signing in fails or is lost when there is more than one replica or after a restart | F14 |
| G8 | The portal is served over plain HTTP; CORS allows any origin; a token is accepted in the URL | Weak for a security product | F14 |
| G9 | The landing page hides the posture score and offers no priority view | The first screen does not answer "what is wrong and what do I do first" | F17 |
| G10 | The shared results volume is a single-node disk, so a scan pod on another node cannot mount it | Deep scans fail on a multi-node cluster | F15 |

### 3.2 Detection model (unchanged principle)

- **Tools detect.** Own checks, Prowler and, where enabled, ScoutSuite and cloudsplaining find the problems. Detection is deterministic.
- **Code ranks.** A weighted rubric (severity, exposure, reachability, resource criticality) produces a 0 to 100 score for each finding. Weights are editable in Settings (F8).
- **Text is written separately.** Explanations, fix guidance and report narrative come from built-in templates. Amazon Bedrock may improve the wording when it is available. Bedrock is never a source of a finding and never changes a number.
- **Nothing depends on Bedrock.** Every feature, including reports, works with the offline templates.
- **Paid build: native sources.** Where the client has enabled them, Security Hub, GuardDuty, Inspector and IAM Access Analyzer are additional detection sources, read-only. Their findings go through the same fingerprint, deduplication, lifecycle and ranking as every other source. CodeSentinal. adds the ranking, the merging, the history, the register, the attack paths and the reports on top; it does not depend on any of them.

## 4. Scope of work: features

Every feature below is in scope for this build. Each has a "done when" line that the acceptance criteria in section 10 test.

### 4.1 Foundation: findings that remember

| ID | Feature | What the MSP gets | Done when |
|------|-----------------|-----------------------------------------------|------------------------------|
| **F1** | **Stable finding identity and lifecycle** | Each finding has a fingerprint built from account, service, region, resource and a canonical check key. Status moves through **open, fixed, regressed, accepted**. Each finding shows first seen, last seen, age in days, fixed date. A scan only marks a finding fixed when every source that reported it actually ran | Re-scanning an unchanged account produces the same finding IDs and keeps first-seen; fixing the cause and re-scanning marks it fixed; breaking it again marks it regressed |
| **F2** | **Cross-source deduplication** | One finding per problem. It lists every source that reported it, uses the highest severity, and the portal shows "N duplicates merged" | An open security group reported by an own check and by Prowler appears once, with both sources listed |
| **F3** | **History and trend** | A history point is saved after every full scan: score, counts by severity, new, fixed, regressed. The portal shows a trend and "what changed since last scan" | After three scans the trend shows three points and the change list matches the real differences |
| **F4** | **Accepted-risk register** | Mark a finding as an accepted risk with a reason, an owner and an expiry date. Accepted findings leave the score but stay visible. At expiry the finding returns to open and an alert is raised | An accepted finding is excluded from the score; after expiry it is open again |
| **F5** | **Remediation plan** | Each finding can carry an owner (text), an effort size (S, M, L) and a target date. A plan view lists the top priority findings with these fields | The plan view shows owner, effort and date and survives a restart |
| **F8** | **Scoring rubric and settings** | The four rubric weights, the score penalties and the rating bands are editable, with validation that weights sum to 1. Defaults match v1 | Changing a weight changes the scores on the next scan; invalid weights are rejected |

### 4.2 Intelligence: what matters and how to fix it

| ID | Feature | What the MSP gets | Done when |
|------|-----------------|-----------------------------------------------|------------------------------|
| **F6** | **Attack paths** | Six hand-built chains computed from discovered facts, for example an instance reachable from the internet whose role is an administrator. Each path shows its steps, the evidence, the severity, and the **cheapest step that breaks the chain**. Findings on a path rank higher | Given a fixture account, each of the six paths is detected when its conditions hold and not detected when one condition is removed (Appendix B) |
| **F7** | **Fix-as-code** | For about 15 common finding types: a Terraform snippet, an AWS CLI command, what could break, and the effort. Works with no AI. Bedrock may tailor the wording. Every snippet is labelled "review before applying" | Each of the 15 templates renders with sample data and leaves no unresolved placeholder; unknown findings show the generic recommendation |

### 4.3 Reports and workflow

| ID | Feature | What the MSP gets | Done when |
|------|-----------------|-----------------------------------------------|------------------------------|
| **F9** | **Reports** | A report for the whole account, one service or one resource, as **Word (.docx), Markdown and print-ready HTML**. Contents: cover with MSP and client names and logo, executive summary, score and trend, what changed, ranked findings, attack paths, accepted risks, remediation plan, CIS-mapped section (Appendix C). Numbers come from data, never from a model | The .docx opens in Word without repair prompts; the Markdown and HTML contain the same numbers |
| **F10** | **Review and approval** | A report goes draft, in review, approved or rejected, with reviewer name, note and time. Rejecting with feedback and regenerating creates a new version linked to the old one. An approved report cannot change | The status can only move along allowed transitions; an approved report downloads identically every time |
| **F11** | **Audit log** | Every action is recorded: scans, accepted risks, plan edits, setting changes, report transitions, sign-ins. Viewable, filterable, exportable as CSV and JSON | Each listed action creates one log entry with time, actor, action and target |
| **F12** | **Slack alerts** | A Slack webhook message for a new critical or high finding, a regressed finding, a new attack path, an expiring accepted risk, or a failed scan. A digest option groups messages. Duplicate alerts are suppressed | A new critical finding sends one message; the next scan does not repeat it |
| **F13** | **Branding and settings page** | MSP name, client name and logo; sources on or off; scan schedule; rubric; reviewer name; Slack webhook; alert rules. Stored in the database | Branding appears on the portal header and on every report |

### 4.4 Platform

| ID | Feature | What the MSP gets | Done when |
|------|-----------------|-----------------------------------------------|------------------------------|
| **F14** | **Access hardening** | Stateless signed sessions that work across replicas and restarts; no token in URLs; same-origin by default; login throttling; security headers; HTTPS on the load balancer with a certificate, plus an optional allow-list of source IP ranges | Two backend replicas accept the same session; repeated bad logins are throttled; the load balancer redirects HTTP to HTTPS when a certificate is configured |
| **F15** | **Real on-demand scans** | **Quick audit** re-runs own checks for one service or resource in seconds, without re-discovering the whole account. **Deep scan** starts a Prowler job on demand, shows its progress, and ingests the result. Scans are single-flight and survive page reloads. Scan pods are placed on the same node as the results volume | Quick audit of one resource completes without a full discovery; deep scan shows queued, running, completed or failed and ingests findings |
| **F16** | **Discovery completeness** | CloudTrail trails are listed as resources; security groups, volumes and access keys are discovered as facts for attack paths; the service page can filter by resource type as well as region | The CloudTrail card shows real counts; the EC2 page can show instances only |

### 4.5 Portal and modes

| ID | Feature | What the MSP gets | Done when |
|------|-----------------|-----------------------------------------------|------------------------------|
| **F17** | **Risk-first portal** | New navigation: **Overview, Findings, Attack paths, Inventory, Risks, Reports, Activity, Settings**. The Overview shows the score ring, trend, what changed, the top five fixes and the last scan time per source. The service and resource browser remains, under Inventory. Light theme by default with a dark option; no emoji icons; accessible by keyboard | Every screen is reachable by keyboard; contrast meets WCAG AA; the layout works at tablet width |
| **F18** | **Local mode** | `docker compose up` runs the backend and portal on a laptop against the MSP's own AWS profile, read-only, with no cluster | A fresh checkout starts with one command and shows the portal |
| **F19** | **Demo mode** | `DEMO_MODE=true` loads clearly fake sample data (a fictional account, eight weeks of history, attack paths, a risk register) and shows a "Demo data" banner on every page. No AWS call is made | The banner is always visible; no AWS credential is needed; a sales demo runs end to end |
| **F20** | **Documentation and handover** | Updated product, deployment and prerequisites documents, an MSP onboarding checklist, a runbook and a verification checklist | A new engineer can deploy from the documents alone |

### 4.6 Paid build additions: native AWS security sources

These are additional **read-only readers**. Each can be switched on or off in Settings and is **off by default**. None of them enables, changes or suppresses anything in AWS.

| ID | Feature | What the MSP gets | Done when |
|------|-----------------|-----------------------------------------------|------------------------------|
| **P1** | **Security Hub reader** | Reads active findings from Security Hub, including the findings that GuardDuty, Inspector and Access Analyzer send to it and findings from partner products. Findings are normalised into the same model, keep their native control ID (for example `S3.1`) and show the product that raised them. Uses the aggregation region when a finding aggregator exists, otherwise each region where Security Hub is enabled | Given recorded sample findings, each maps to the right service, severity and control; suppressed and resolved findings are skipped |
| **P2** | **GuardDuty reader and Active threats panel** | Reads findings directly when Security Hub is not in use. The Overview shows an **Active threats** panel: type, affected resource, severity, first and last seen. Archived findings are skipped | The panel lists sample threats and links each to its resource page |
| **P3** | **Inspector reader** | Reads vulnerability findings for EC2 instances, container images and Lambda functions: CVE ID, package, fixed-in version, whether an exploit is known. The resource page shows a **Vulnerabilities** tab | A sample CVE appears on the right resource with its fix version; a known-exploit flag raises reachability in the rubric |
| **P4** | **IAM Access Analyzer reader** | Reads active external-access findings (for example a bucket or role shared outside the account) | A public-access finding maps to exposure 1.0 and appears under the right service |
| **P5** | **Cross-source deduplication with native controls** | A data file maps native control IDs to the same canonical keys used by own checks and Prowler, so one problem is one finding even when three tools report it. The file can be edited without a code change | A sample open-port problem reported by own check, Prowler and Security Hub appears once with three sources |
| **P6** | **Enriched attack paths** | A path whose instance has a critical CVE with a known exploit, or an active GuardDuty finding, is raised in severity and labelled with the signal | A sample path gains the label and a higher rank when the signal is present |
| **P7** | **Live integration page** | For each native service: **not enabled in this account**, **enabled and reading**, **enabled but switched off here**, or **permission missing**. Shows a plain cost note and a read-only enablement guide for the client's administrator. The toggle controls only whether CodeSentinal. reads the service | The page reports the correct state for each service in a test account; no toggle ever calls an AWS write action |

### 4.7 Paid build: cost and consent

The client, not the supplier, enables each native service and pays AWS for it. CodeSentinal. shows a cost notice next to each toggle and recommends a billing alarm. Any free trial period for these services is set by AWS and may change. CodeSentinal. never enables a service on the client's behalf, because enabling is a write action.

## 5. Out of scope

- Any change, deletion, restart or remediation of client AWS resources. CodeSentinal. is read-only and recommend-only. Fix-as-code produces text for a human to review.
- **Enabling, configuring, suppressing or archiving anything in Security Hub, GuardDuty, Inspector or Access Analyzer.** CodeSentinal. only reads them. The client enables them.
- Reading findings from other native services not named in section 4.6 (for example Macie, Detective, Config rules).
- AWS Organizations, multi-account and delegated-administrator views, including organization-wide Security Hub or GuardDuty aggregation across accounts. Planned for a later release.
- Named users, roles and single sign-on. This release has one `superadmin` role. Cognito or OIDC is planned.
- Ticketing integrations (Jira, ServiceNow). Reports and the plan view can be exported; no ticket is created.
- Penetration testing, application code review, 24x7 security operations, incident response, compliance certification.
- Any machine-learning model or Python component in the agent. The agent stays pure Go.
- Kubernetes workload and cluster posture (Trivy, kube-bench, Kyverno, Falco). Planned as a later module.
- Natural-language questions over the account ("ask your account"). Planned for a later release.

## 6. Architecture

### 6.1 Workloads in the client's cluster

| Workload | Kind | Role |
|--------------------|--------------------|------------------------------------------------------------|
| `CodeSentinal.-backend` | Deployment + Service | Go agent and API: discovery, own checks, scan ingestion, lifecycle, ranking, attack paths, reports, alerts. Runs under a read-only IAM role (IRSA) |
| `CodeSentinal.-frontend` | Deployment + Service | React portal served by unprivileged Nginx, which proxies `/api` to the backend and sets security headers |
| `CodeSentinal.-prowler` | CronJob (plus on-demand Jobs) | Prowler scanner. Writes results to the shared volume. On-demand Jobs are created by the backend from this CronJob |
| Results volume | PVC | Shared scan output. Scan pods are scheduled on the same node as the backend |
| Ingress | AWS ALB | `/` to frontend, `/api` and `/health` to backend. HTTPS with an ACM certificate when configured; optional source IP allow-list |
| Optional scanners | CronJobs | ScoutSuite and cloudsplaining, off by default |

New in this build: a namespace-scoped Kubernetes role that lets the backend read the Prowler CronJob and create, get and list Jobs. It grants nothing on AWS and nothing outside the `CodeSentinal.` namespace.

### 6.2 Data

All state is in one DynamoDB table (on-demand billing), keyed by partition and sort key. Large reviews are split into chunks to stay below the item size limit.

| Partition | Holds |
|------------------|----------------------------------------------------------------------------------|
| `review` | Latest and past reviews (summary plus chunked findings and resources) |
| `history` | One point per full scan: score, counts, new, fixed, regressed |
| `risk` | Accepted-risk register entries |
| `plan` | Owner, effort and target date per finding |
| `report` | Report snapshots with status, reviewer and version links |
| `activity` | Audit log entries |
| `settings` | Branding, rubric, schedule, source toggles, alert rules |
| `lease` | Scheduler lease so only one replica runs scheduled scans |

Without a table the backend falls back to memory, for demos and local mode only.

### 6.3 Interfaces

The API is versioned under `/api/v1`. Existing endpoints keep their shape; new endpoints are additive. The summary list is in `CodeSentinal.-Build-Spec.md`. All endpoints except health, login and auth status require a signed session.

### 6.4 Modes

| Mode | How it runs | Used for |
|--------------|----------------------------------------------|----------------------------------------|
| **Cluster** | Helm chart into the client's EKS | Production |
| **Local** | `docker compose up` with the engineer's AWS profile mounted read-only | Development, onboarding rehearsal, a client with no cluster yet |
| **Demo** | `DEMO_MODE=true`, synthetic data, no AWS calls | Sales demonstrations and portal testing |

### 6.5 Paid build: native source readers

```
          Security Hub ──┐                         (GuardDuty, Inspector and
          GuardDuty ─────┤                          Access Analyzer can also
          Inspector ─────┼──► readers ──► one      be read directly when Security
          Access Analyzer┘     (read-only) Finding   Hub is not in use)
                                            model
  Own checks ───────────────────────────────►  │
  Prowler / ScoutSuite / cloudsplaining ────►  ▼
                                      fingerprint → dedupe → lifecycle → rank
```

- Every reader implements the same small interface and returns findings in the one model, so the portal, ranking, reports and alerts need no source-specific code.
- Readers run on the scan schedule and on a deep scan. A reader that fails is reported as a source error and **never marks its findings as fixed** (see F1).
- The service-to-resource mapping covers EC2, S3, IAM, Lambda, RDS, DynamoDB, EKS and CloudTrail. Findings on other resource types are kept and shown under an **Other services** card, so nothing is dropped.
- The data file that maps native control IDs to canonical keys ships with the product and can be extended per client.

## 7. Security and safety principles

- **Read-only on the client account.** The IAM role allows `Describe`, `Get` and `List` actions only. The single exception is read and write on CodeSentinal.'s own DynamoDB table.
- **No static AWS keys in the cluster.** Access is by IAM Roles for Service Accounts (IRSA). In local mode the engineer's own profile is mounted read-only and is not copied into any image.
- **Portal not publicly readable.** Sign-in is required for every data endpoint. Sessions are signed, short-lived and never accepted in a URL. Logins are throttled. HTTPS is used when a certificate is configured, and an IP allow-list is available.
- **Recommend-only.** Fix-as-code is text. It is labelled "review before applying" and includes what could break. CodeSentinal. never runs it.
- **Secrets.** The superadmin password, the session secret and the Slack webhook are held in Kubernetes Secrets, never in the repository, and never returned by the API after they are saved.
- **Outbound calls are limited.** The only outbound destinations are AWS APIs, Amazon Bedrock (optional) and the configured Slack webhook, which must be an HTTPS Slack address.
- **Reports contain account findings.** They are generated on demand, stored only in the client's DynamoDB table, and downloaded only by an authenticated user. Bedrock, when used, receives aggregated counts and finding titles, not account IDs or resource names.
- **Handover.** The client keeps full administrator rights. The supplier retains no standing access. `stop.sh --purge` removes everything CodeSentinal. created.
- **Native readers are read-only.** The extra IAM statement for the paid build lists read and list actions for Security Hub, GuardDuty, Inspector and Access Analyzer only. It is a separate policy so a client can review it on its own, and it is attached only when the client turns these sources on.
- **CodeSentinal. never changes the state of a native finding.** It does not archive, suppress, resolve or update workflow status in any of those services.

## 8. Deliverables

1. CodeSentinal. v2 source: Go backend, React portal, Helm chart, scripts, on a `v2-msp` branch.
2. Features F1 to F20 (sections 4.1 to 4.5) and P1 to P7 (section 4.6).
3. Unit tests for all pure logic (lifecycle, deduplication, attack paths, fix templates, report rendering, auth tokens, alert suppression, and the normalisation of every native finding type from recorded samples) and a documented verification checklist for the parts that call AWS.
4. Updated Helm chart: HTTPS and IP allow-list values, session secret, Kubernetes role for deep scans, node co-location for scan pods, and the optional native-reader IAM policy.
5. A separate read-only IAM policy file for the native readers, with the exact actions listed.
6. `docker-compose.yml`, a local-mode guide, and a demo-mode data set that includes sample threats and vulnerabilities.
7. Documents: `PRODUCT.md`, `SOW.md`, `DEPLOYMENT.md`, `PREREQUISITES.md`, an MSP onboarding checklist, a runbook, and a short guide for the client's administrator on enabling each native service and what it costs.
8. A sample report in Word, Markdown and HTML generated from the demo data set.

## 9. Delivery plan

Effort is indicative, in working days for one engineer, and is a planning estimate, not a commitment.

| Phase | Content | Features | Days |
|--------|----------------------------------------------------------|--------------------|--------------|
| 0 | Branch, baseline tests, fixtures from a real scan | | 1 |
| 1 | Foundation: fingerprints, lifecycle, deduplication, history, risk register, plan, settings store, CloudTrail fix | F1 to F5, F8, F16 | 7 to 9 |
| 2 | Intelligence: attack paths, fix templates | F6, F7 | 6 to 8 |
| 3 | Workflow: report engine and Word writer, approval, audit log, alerts, branding | F9 to F13 | 7 to 9 |
| 4 | Platform: access hardening, HTTPS, quick audit, deep scan job | F14, F15 | 4 to 5 |
| 5 | Portal redesign | F17 | 7 to 9 |
| 6 | Local mode, demo mode, documents | F18 to F20 | 3 to 4 |
| 7 | Verification on a real account of the free sources, fixes | | 3 to 4 |
| 8 | Native readers: Security Hub, then GuardDuty, Inspector, Access Analyzer; native dedupe mapping | P1 to P5 | 7 to 9 |
| 9 | Enriched paths, threat panel, vulnerabilities tab, live integration page | P6, P7 | 3 to 4 |
| 10 | Verification of native readers in an account with the services enabled, fixes, handover | | 3 to 4 |
| | **Total** | | **51 to 66** |

Phases 1 to 3 and 8 to 9 can be demonstrated on sample data. Phase 10 needs an AWS account where the native services are enabled; see section 11.

## 10. Acceptance criteria

The build is accepted when every criterion below passes. "Fixture" means a recorded, anonymised scan or a sample data set that tests can run without AWS. Criteria AC-01 to AC-29 apply to the free sources and the base product; AC-P1 onward apply to the native readers.

| # | Criterion | Feature | How it is checked |
|--------|------------------------------------------------------|----------|----------------------------|
| AC-01 | Re-scanning an unchanged fixture gives identical finding IDs and unchanged first-seen times | F1 | Automated test |
| AC-02 | A finding absent from a later scan becomes **fixed** only if every source that reported it ran in that scan | F1 | Automated test with one source skipped |
| AC-03 | A fixed finding that reappears becomes **regressed**, keeping its original first-seen | F1 | Automated test |
| AC-04 | A scoped audit changes only findings inside its scope | F1 | Automated test |
| AC-05 | Two sources reporting the same problem produce one finding listing both sources and the highest severity | F2 | Automated test |
| AC-06 | After three full scans the history returns three points; the change counts equal the true differences | F3 | Automated test |
| AC-07 | An accepted finding is excluded from the score and shown as accepted; after expiry it is open and an alert is queued | F4 | Automated test |
| AC-08 | Owner, effort and target date persist across a backend restart | F5 | Test against the store |
| AC-09 | Weights that do not sum to 1 are rejected; a valid change alters the next scores | F8 | Automated test |
| AC-10 | Each of the six attack paths is detected when its conditions hold and absent when any one condition is removed | F6 | Automated test per path |
| AC-11 | Each fix template renders with no unresolved placeholder and carries the "review before applying" label | F7 | Automated test over all templates |
| AC-12 | The Word report opens in Word and in LibreOffice without a repair prompt, and has the same figures as the Markdown and HTML versions | F9 | Automated structure test plus manual open |
| AC-13 | Report status moves only along draft, in review, approved or rejected; an approved report cannot be edited and downloads identically | F10 | Automated test |
| AC-14 | Each listed action writes one audit entry; export to CSV and JSON works | F11 | Automated test |
| AC-15 | A new critical finding sends one Slack message; a repeat scan sends none; a non-Slack or non-HTTPS URL is rejected | F12 | Automated test with a stub server |
| AC-16 | Branding set in Settings appears in the portal header and on every report | F13 | Manual check |
| AC-17 | A session issued by one backend replica is accepted by another; a token in a URL is refused; repeated bad logins are throttled | F14 | Automated test |
| AC-18 | With a certificate configured the load balancer redirects HTTP to HTTPS; with an allow-list, other source addresses are refused | F14 | Deployment check |
| AC-19 | Quick audit of one resource completes without full discovery and returns only that resource's findings | F15 | Automated test with a stub AWS layer; timing check on a live account |
| AC-20 | Deep scan reports queued, running, completed or failed, rejects a second concurrent request, and ingests the result | F15 | Stub Kubernetes API test; one live run on the cluster |
| AC-21 | The CloudTrail card shows the real trail count; the EC2 page can filter to instances only | F16 | Live check |
| AC-22 | The portal has the eight navigation sections; every screen works by keyboard; text contrast meets WCAG AA | F17 | Automated accessibility scan plus manual check |
| AC-23 | `docker compose up` starts the portal from a fresh checkout | F18 | Manual check |
| AC-24 | In demo mode every page shows the demo banner, no AWS call is made, and no credential is needed | F19 | Automated test plus manual check |
| AC-25 | A new engineer deploys from the documents alone | F20 | Walkthrough |
| AC-26 | No API write or modify call is made to any client resource; the IAM policy has no write action except on the CodeSentinal. table | Safety | Policy review and a search of the code |
| AC-27 | The word "Bedrock" never appears as a source on any finding; every report number matches the underlying data | Detection model | Automated test |
| AC-28 | All features work with Bedrock unavailable | Detection model | Run the test suite and a manual walkthrough with Bedrock off |
| AC-29 | The build compiles, passes `go vet` and all tests, and the portal builds without warnings | All | CI run |
| AC-P1 | Recorded Security Hub findings normalise to the correct service, severity, control ID and product; suppressed and resolved findings are skipped | P1 | Automated test on samples |
| AC-P2 | Recorded GuardDuty findings map to severity bands and fill the Active threats panel; archived findings are skipped | P2 | Automated test on samples |
| AC-P3 | Recorded Inspector findings show CVE ID, package and fix version on the right resource; a known exploit raises reachability | P3 | Automated test on samples |
| AC-P4 | Recorded Access Analyzer findings map to the right service and a public finding gets exposure 1.0 | P4 | Automated test on samples |
| AC-P5 | The same problem reported by own check, Prowler and Security Hub is one finding with three sources | P5 | Automated test |
| AC-P6 | A path with a known-exploit CVE or an active threat is labelled and ranked higher than the same path without it | P6 | Automated test |
| AC-P7 | The integration page shows the correct state for each service in a test account, and no toggle calls an AWS write action | P7 | Live check; code search |
| AC-P8 | A native reader that errors reports a source error and does not mark any of its findings fixed | P1 to P4 | Automated test |
| AC-P9 | With every native reader switched off, results are identical to the free build | P1 to P7 | Automated test |
| AC-P10 | Live: in an account with the native services enabled, the number of findings CodeSentinal. shows for each service equals the number the service reports as active, within the recorded read time | P1 to P4 | Live check |

## 11. Assumptions, dependencies and risks

### 11.1 Assumptions

- One AWS account per deployment, with an existing EKS cluster, an OIDC provider, the EBS CSI driver and the AWS Load Balancer Controller (see `PREREQUISITES.md`).
- The client provides temporary deploy access (an assumable role or short-lived credentials) and removes it after handover.
- A domain name and an ACM certificate are needed for HTTPS. Without them the portal runs over HTTP and shows a warning, and the IP allow-list is strongly advised.
- Amazon Bedrock is optional. It needs model access and a valid payment method on the account. Without it every feature still works with built-in text.
- A Slack incoming webhook is supplied by the MSP if alerts are wanted.
- Engineering estimates assume one engineer and access to a test AWS account with real resources.
- **For the native readers:** the client enables each service they want read. Security Hub, GuardDuty and Inspector are paid AWS services; any free trial is set by AWS and may change, so the client confirms current pricing before enabling. CodeSentinal. never enables them.
- **Acceptance of the native readers needs an AWS account where those services are enabled.** A free-tier account that cannot enable them can accept AC-01 to AC-29 and AC-P1 to AC-P9, but not AC-P10 (live) or the live part of AC-P7.

### 11.2 Dependencies

| Dependency | Needed for |
|----------------------------------------|------------------------------------------------------------|
| Prowler container image | Deep scans and the broad CIS and AWS best-practice coverage |
| Kubernetes API in the cluster | On-demand deep scans |
| DynamoDB | History, register, reports, audit log, settings |
| ACM certificate and a domain | HTTPS on the portal |
| Security Hub, GuardDuty, Inspector, Access Analyzer enabled by the client | The matching native reader |
| Current AWS documentation for each service's findings API | Confirming field names; the newer Security Hub format may differ from the classic one |

### 11.3 Risks

| Risk | Impact | Mitigation |
|----------------------------------|------------------------|------------------------------------------|
| EKS and the load balancer bill hourly even when idle | Cost on a free-tier account | Local mode and demo mode for development and sales; scale down with `stop.sh` |
| Prowler output format changes between versions | Ingestion breaks | Pin the Prowler version; keep recorded sample files in the tests |
| Equivalence mapping between check sources is incomplete | Some duplicates remain | Mapping lives in an editable data file; unmapped checks are shown as separate findings, never dropped |
| Large accounts exceed the DynamoDB item size | Writes fail | Chunk reviews across items; a test with a large fixture |
| AWS SDK code cannot be exercised without an account | Defects found late | Keep AWS calls in thin, interface-based code; keep logic in pure packages with tests; run the verification checklist on a real account in phases 7 and 10 |
| Attack-path rules produce false positives | Loss of trust | Six conservative rules, each showing its evidence; each can be switched off in Settings |
| Fix snippets applied without review | Outage | Every snippet states what could break and is labelled for review |
| Several backend replicas run scheduled scans at once | Duplicate scans and alerts | Scheduler lease in DynamoDB |
| **Native finding formats change** (Security Hub now has more than one finding format) | A reader returns wrong or empty data | Put each reader behind an interface; keep recorded samples; confirm against current AWS documentation in phase 8; add a second reader if needed |
| **Client enables a paid service and is surprised by the bill** | Client dissatisfaction | Cost notice beside every toggle; recommend a billing alarm; CodeSentinal. never enables a service |
| **Large numbers of native findings** | Slow scans, large reviews | Page through results with a cap and a warning; chunked storage |
| **Native readers cannot be tested on a free-tier account** | Defects found late | Recorded samples for every finding type; AC-P10 run in an account with the services enabled |

## 12. Responsibilities

| Party | Responsibilities |
|--------------------|--------------------------------------------------------------------------------|
| **Supplier** | Build and test the features in section 4; provide the documents and sample data; deploy and verify in the agreed account; hand over and remove its access |
| **MSP (Customer)** | Provide a test account and, for deployment, temporary access; supply branding, report template wording and the Slack webhook; review and approve the sample report; designate the reviewer |
| **Client of the MSP** | Provide the prerequisites in `PREREQUISITES.md`; keep full administrator control of their account; confirm cost awareness for any paid AWS service they choose to enable |

## 13. Change control and sign-off

- A change to scope, a feature or an acceptance criterion is agreed in writing before work on it starts, with its effect on effort.
- Items listed as out of scope in section 5 are handled as separate change requests.
- Commercial terms (fees, payment schedule, warranty period, liability) are set out in a separate commercial schedule: **[to be completed by the parties]**.

| | Supplier | Customer |
|---|---|---|
| Name | [Name] | [Name] |
| Title | [Title] | [Title] |
| Signature | | |
| Date | | |

## Appendix A. Finding lifecycle

| Status | Meaning | How a finding gets there | Counts in score |
|------------|------------------------------|----------------------------------------|------------------|
| **open** | Present in the latest scan | First seen, or seen again | Yes |
| **fixed** | Not present in a scan where all its sources ran | Disappears from a complete scan | No |
| **regressed** | Was fixed, is present again | Reappears after being fixed | Yes |
| **accepted** | Knowingly accepted by the MSP until an expiry date | Accepted-risk entry created | No |

Rules: a scan outside a finding's scope never changes it; a finding whose source did not run keeps its status; fixed findings stay visible for 90 days and remain in history; an accepted finding that expires returns to open.

## Appendix B. Attack path catalogue

| ID | Path | Conditions (all must hold) | Break the chain by |
|--------|--------------------|----------------------------------------------------|--------------------|
| AP-1 | **Internet to administrator** | Instance has a public address; a security group allows 0.0.0.0/0 on a remote-access or database port, or on all ports; the instance role is an administrator or has wildcard actions on all resources | Restricting the security group |
| AP-2 | **Internet to data** | Same exposure as AP-1; the role can read or write S3 broadly | Restricting the group, then narrowing the role |
| AP-3 | **Public, unprotected bucket** | Bucket public through policy or ACL or lacking a full public-access block; no default encryption | Enabling the public-access block |
| AP-4 | **Public database** | Database publicly accessible; its security group allows 0.0.0.0/0 on the database port; storage not encrypted | Turning off public access |
| AP-5 | **Public function with power** | Lambda function URL with no authentication; the function role is an administrator or has wildcard actions | Requiring IAM authentication on the URL |
| AP-6 | **Identity takeover** | Console user with no MFA; user has administrator access; an access key older than 90 days | Enforcing MFA |

## Appendix C. Report outline

1. Cover: MSP and client names, logo, report date, scope, status and version.
2. Executive summary: score, rating, change since the last report, three sentences on what matters.
3. Score trend and what changed: new, fixed, regressed.
4. Top fixes: the ranked list with owner, effort and target date.
5. Attack paths: each path, its evidence and where to break it.
6. Findings by service and severity, with the fix guidance.
7. Accepted risks: reason, owner, expiry.
8. CIS-mapped controls: pass, fail and accepted counts.
9. Scope and method: sources run, regions covered, scan times, limits (read-only; point-in-time).
10. Review record: reviewer name, decision and time.


## Appendix D. Native source mapping (paid build)

| Source | What is read | Key fields used | Severity mapping |
|--------------|--------------------------|----------------------------------|--------------------------|
| **Security Hub** | Active findings with a new or notified workflow status | Severity label, title, description, remediation text, resource ID, type and Region, account, product name, security control ID | Informational, low, medium, high, critical map directly |
| **GuardDuty** | Findings that are not archived, per detector and Region | Type, severity number, resource, first and last seen, count | Number 9.0 or above critical; 7.0 to 8.9 high; 4.0 to 6.9 medium; below 4.0 low. Confirm bands against current AWS documentation |
| **Inspector** | Active findings for instances, container images and Lambda | CVE ID, package, fixed-in version, exploit available, severity | Informational, low, medium, high, critical map directly; untriaged is shown as medium |
| **Access Analyzer** | Active external-access findings from account-level analyzers | Resource, resource type, whether public, principals | Public is high; other external access is medium |

Resource types outside the eight supported services are shown under **Other services**.

## Appendix E. Read-only permissions added by the paid build

Attached only when the client turns the native readers on, as a separate policy:

- Security Hub: `securityhub:GetFindings`, `securityhub:DescribeHub`, `securityhub:ListFindingAggregators`
- GuardDuty: `guardduty:ListDetectors`, `guardduty:ListFindings`, `guardduty:GetFindings`, `guardduty:GetDetector`
- Inspector: `inspector2:ListFindings`, `inspector2:BatchGetAccountStatus`, `inspector2:ListCoverage`
- IAM Access Analyzer: `access-analyzer:ListAnalyzers`, `access-analyzer:ListFindingsV2`, `access-analyzer:GetFindingV2`

No write, update, archive or enable action is requested.
