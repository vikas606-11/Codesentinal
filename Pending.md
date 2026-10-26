# CodeSentinal. — Pending

The **free build is finished and deployed** to our account (`eks-lab`). Everything
below is **not** part of the free build. Nothing here is started yet — do not touch
the paid build until we explicitly move to it.

---

## 1. Paid build (next phase — client-account edition)
Adds the AWS-native security services as optional **read-only** sources, behind the
same `Finding` model, off by default. Full spec: `docs/paid/Sow-paid-build.md` and
Part B of `docs/free/CodeSentinal.-Build-Spec.md`.

- **P1 — Security Hub reader**: pull aggregated findings (ASFF), map controls to our
  canonical keys, service classification from resource type.
- **P2 — GuardDuty reader + Active-threats panel**: "is something happening now?"
  (configuration scanning can't answer this).
- **P3 — Inspector reader**: CVEs on EC2 / ECR images / Lambda, with fixed-in
  versions and exploit flags; a Vulnerabilities tab on the resource page.
- **P4 — IAM Access Analyzer reader**: resources shared outside the account.
- **P5 — Dedup including native control IDs**: one finding when Prowler + Security
  Hub + own-check all report the same thing.
- **P6 — Attack paths enriched with native signals**: a path that also has an
  exploitable CVE or an active threat ranks higher.
- **P7 — Live integration page**: show each service's real state (enabled / readable
  / permission-missing) with a cost note. Toggles write only to CodeSentinal. settings;
  **no** enable/create/update call to those AWS services, ever.
- New read-only IAM policy `deploy/iam/CodeSentinal.-native-readers-policy.json`, attached
  only when `nativeReaders.enabled=true`.

> In the free build these three appear in Settings as **disabled toggles** with a
> cost note — the UI is ready, the wiring is the paid build.

## 2. Client-account deployment
- Deploy the product into a **client's own AWS account** (not just our `eks-lab`),
  with temporary scoped deploy access and handover. Our account is the test env; the
  client account is the real delivery target for the paid build.

## 3. Explicitly deferred (later releases, not scheduled)
- **AWS Organizations / multi-account** and delegated-admin views (one account per
  deployment today).
- **Named users / roles / SSO** (Cognito or OIDC). Today a single `superadmin` role.
- **Ticketing integrations** (Jira / ServiceNow). Reports/plan export only for now.
- **Kubernetes workload & cluster posture** (Trivy, kube-bench, kube-hunter, Kyverno,
  Falco) as a later module.
- **"Ask your account"** natural-language queries over the inventory/findings.
- **Live Word/LibreOffice open check** of the generated .docx — validated
  structurally in tests (valid zip + well-formed XML parts + matching figures); the
  one-time manual open in Word is a handover check.

## 4. Known limitations / caveats (free build, by design)
- **Bedrock** currently falls back to built-in templates because the account has no
  valid payment instrument (`INVALID_PAYMENT_INSTRUMENT`). This is an account-billing
  action, not a code issue; nothing depends on Bedrock being up.
- **HTTP (not HTTPS)** until a domain + ACM certificate are added — then the chart's
  `ingress.certificateArn` turns on HTTPS and the HTTP→HTTPS redirect automatically.
  Use `ingress.inboundCidrs` to restrict access in the meantime.
- **Shared PVC is ReadWriteOnce** — scan pods are co-located with the backend via
  pod affinity. For multi-node flexibility, move the results volume to EFS
  (ReadWriteMany) and drop the affinity.
