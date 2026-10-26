# CodeSentinal. — Runbook (Free Build)

Everything operational: one-time setup, the start/stop scripts, manual deploy
commands, and debugging. Architecture and "how it works" live in **DEPLOYMENT.md**;
test cases live in **VERIFY.md**.

Target: our own account, cluster `eks-lab`, region `us-east-1`, namespace `CodeSentinal.`.
Everything is read-only on AWS; the only write is to the `CodeSentinal.-reviews` table.

---

## 1. One-time cluster setup

Two add-ons are needed once per cluster (full commands in `deploy/CLUSTER_PREREQS.md`):

```bash
# EBS CSI driver (for the shared PVC) and the AWS Load Balancer Controller (for the ALB)
kubectl get csidriver ebs.csi.aws.com      # should exist
kubectl get ingressclass alb               # should exist
```

If either is missing, follow `deploy/CLUSTER_PREREQS.md`, or deploy with
`--set prowler.enabled=false` and/or `--set ingress.enabled=false`.

---

## 2. Easiest path — the start script

`start.sh` does the whole spin-up: ensures both ECR repos, builds + pushes both
images, ensures the read-only IAM policy + IRSA service account, the DynamoDB table
and the deep-scan RBAC, scales the node group up, and `helm install`s everything.

```bash
export SUPERADMIN_PASSWORD='choose-a-strong-password'   # never commit this
./start.sh

# optional overrides (defaults shown):
# REGION=us-east-1 CLUSTER=eks-lab NAMESPACE=CodeSentinal. DESIRED_NODES=2 ./start.sh
```

When it finishes it prints the public URL and how to trigger the first Prowler scan.

Tear down (stop billing, keep the cluster):

```bash
./stop.sh            # helm uninstall + scale the node group to 0
./stop.sh --purge    # also delete IAM policy/role, both ECR repos, the DynamoDB
                     # table, the RBAC, and the CodeSentinal. namespace
```

---

## 3. Manual deploy (what start.sh does, step by step)

Use this when you want to run a single step yourself.

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=us-east-1
ECR=$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com
CLUSTER=eks-lab
```

### 3.1 ECR repos + build/push both images
```bash
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR
for repo in CodeSentinal. CodeSentinal.-frontend; do
  aws ecr describe-repositories --repository-names $repo --region $REGION >/dev/null 2>&1 \
    || aws ecr create-repository --repository-name $repo --region $REGION
done
docker build --platform linux/amd64 -t $ECR/CodeSentinal.:latest .
docker push $ECR/CodeSentinal.:latest
docker build --platform linux/amd64 -t $ECR/CodeSentinal.-frontend:latest ./dashboard
docker push $ECR/CodeSentinal.-frontend:latest
```

### 3.2 Read-only IAM policy + IRSA service account
```bash
aws iam create-policy --policy-name CodeSentinal.ReadOnly \
  --policy-document file://deploy/iam/CodeSentinal.-readonly-policy.json || true
# update an existing policy to the latest document:
# aws iam create-policy-version --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/CodeSentinal.ReadOnly \
#   --policy-document file://deploy/iam/CodeSentinal.-readonly-policy.json --set-as-default

eksctl utils associate-iam-oidc-provider --cluster $CLUSTER --region $REGION --approve
eksctl create iamserviceaccount \
  --cluster $CLUSTER --region $REGION \
  --namespace CodeSentinal. --name CodeSentinal.-sa \
  --role-name CodeSentinal.ReadOnly \
  --attach-policy-arn arn:aws:iam::$ACCOUNT_ID:policy/CodeSentinal.ReadOnly \
  --approve --override-existing-serviceaccounts
```

### 3.3 DynamoDB table (persistence)
```bash
aws dynamodb create-table --table-name CodeSentinal.-reviews --region $REGION \
  --billing-mode PAY_PER_REQUEST \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE
```

### 3.4 Helm install / upgrade
```bash
ROLE_ARN=$(aws iam get-role --role-name CodeSentinal.ReadOnly --query 'Role.Arn' --output text)
helm upgrade --install CodeSentinal. deploy/helm/CodeSentinal. \
  --namespace CodeSentinal. --create-namespace \
  --set backend.image.repository=$ECR/CodeSentinal.         --set backend.image.tag=latest \
  --set frontend.image.repository=$ECR/CodeSentinal.-frontend --set frontend.image.tag=latest \
  --set serviceAccount.create=false --set serviceAccount.name=CodeSentinal.-sa \
  --set serviceAccount.roleArn=$ROLE_ARN --set region=$REGION \
  --set persistence.reviewsTable=CodeSentinal.-reviews \
  --set-string auth.password="$SUPERADMIN_PASSWORD" \
  --wait --timeout 6m
```

Optional values:
- `ingress.certificateArn` + `ingress.host` — enable HTTPS once you have an ACM cert
  and a domain (then the ALB redirects HTTP → HTTPS automatically).
- `ingress.inboundCidrs="203.0.113.0/24"` — restrict who can reach the ALB.
- `scanInterval` (default `6h`), `prowler.schedule`, `scoutsuite.enabled`,
  `cloudsplaining.enabled`, `backend.replicaCount`.

### 3.5 Pull the new image after a rebuild
`latest` + `pullPolicy: Always` means a restart re-pulls:
```bash
kubectl -n CodeSentinal. rollout restart deploy/CodeSentinal.-backend deploy/CodeSentinal.-frontend
kubectl -n CodeSentinal. rollout status  deploy/CodeSentinal.-backend
```

### 3.6 Get the public URL
```bash
kubectl -n CodeSentinal. get ingress CodeSentinal. \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

---

## 4. Debugging commands

```bash
# What's deployed
kubectl -n CodeSentinal. get deploy,svc,cronjob,ingress,role,rolebinding,pods,pvc

# Logs
kubectl -n CodeSentinal. logs deploy/CodeSentinal.-backend --tail=100
kubectl -n CodeSentinal. logs deploy/CodeSentinal.-frontend --tail=50

# Describe a stuck pod (events at the bottom)
kubectl -n CodeSentinal. describe pod -l app.kubernetes.io/component=backend

# Confirm the running image digest matches the one you pushed
kubectl -n CodeSentinal. get pod -l app.kubernetes.io/component=backend \
  -o jsonpath='{.items[0].status.containerStatuses[0].imageID}'; echo
aws ecr describe-images --repository-name CodeSentinal. --region us-east-1 \
  --image-ids imageTag=latest --query 'imageDetails[0].imageDigest' --output text

# Confirm IRSA is wired (no static keys)
POD=$(kubectl -n CodeSentinal. get pod -l app.kubernetes.io/component=backend -o jsonpath='{.items[0].metadata.name}')
kubectl -n CodeSentinal. describe pod $POD | grep -A2 AWS_ROLE_ARN

# Prowler CronJob + on-demand deep-scan Jobs
kubectl -n CodeSentinal. get cronjob CodeSentinal.-prowler
kubectl -n CodeSentinal. get jobs -l CodeSentinal./deep-scan=true
kubectl -n CodeSentinal. logs -l job-name=<job-name> --tail=40

# Health + API through the ALB
URL=$(kubectl -n CodeSentinal. get ingress CodeSentinal. -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl -s http://$URL/health
curl -s http://$URL/api/v1/meta

# Port-forward the backend directly (bypass the ALB)
kubectl -n CodeSentinal. port-forward svc/CodeSentinal.-backend 8080:8080
```

### Common issues
- **Stuck scan** — `POST /api/v1/review` is single-flight (a second returns 409). A
  full multi-region scan takes up to a minute. Check backend logs.
- **Deep scan failed / 501** — 501 means the in-cluster API wasn't reachable; use the
  scheduled Prowler CronJob. Prowler exits non-zero when it finds failing controls —
  that is normal and the results are still written and ingested.
- **Prowler results missing** — until the first Prowler run completes, the backend
  uses only its own checks and shows a warning (expected, not an error).
- **Stale image after rebuild** — do a `rollout restart`; confirm the digest (above).
- **DynamoDB throttling** — confirm the table is `PAY_PER_REQUEST`; large reviews are
  chunked automatically.
- **Bedrock unavailable** — explanations fall back to built-in templates; nothing
  breaks. Live wording needs model access + a valid payment method on the account.

---

## 5. Rotating secrets

```bash
# Superadmin password
helm upgrade CodeSentinal. deploy/helm/CodeSentinal. --namespace CodeSentinal. --reuse-values \
  --set-string auth.password="NEW-PASSWORD"
kubectl -n CodeSentinal. rollout restart deploy/CodeSentinal.-backend

# Session secret — delete the key (or the whole Secret) and upgrade; the chart makes
# a fresh one and all existing sessions are invalidated.
kubectl -n CodeSentinal. delete secret CodeSentinal.-auth
helm upgrade CodeSentinal. deploy/helm/CodeSentinal. --namespace CodeSentinal. --reuse-values \
  --set-string auth.password="$SUPERADMIN_PASSWORD"
```
