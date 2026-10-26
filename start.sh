#!/usr/bin/env bash
# CodeSentinal. — full spin-up (microservice architecture).
#
# Deploys THREE workloads into the client's EKS:
#   - CodeSentinal.-backend   (Go agent/API, read-only, IRSA)
#   - CodeSentinal.-frontend  (React dashboard served by Nginx)
#   - CodeSentinal.-prowler   (open-source Prowler scanner, CronJob, read-only, IRSA)
# plus a shared PVC (Prowler OCSF results) and an ALB Ingress (public URL).
#
# READ-ONLY product: it only reads the account and reports. No static AWS keys
# in-cluster — both backend and prowler use the read-only IRSA role.
#
# Requires local AWS credentials (aws configure / assumed role), docker,
# kubectl, helm, eksctl. Never paste AWS keys into this script.
set -euo pipefail

# ---- config (override via env) ----
REGION="${REGION:-us-east-1}"
CLUSTER="${CLUSTER:-eks-lab}"
NODEGROUP="${NODEGROUP:-core}"
NAMESPACE="${NAMESPACE:-CodeSentinal.}"
BACKEND_REPO="${BACKEND_REPO:-CodeSentinal.}"
FRONTEND_REPO="${FRONTEND_REPO:-CodeSentinal.-frontend}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
POLICY_NAME="${POLICY_NAME:-CodeSentinal.ReadOnly}"
SA_NAME="${SA_NAME:-CodeSentinal.-sa}"
ROLE_NAME="${ROLE_NAME:-CodeSentinal.ReadOnly}"
DESIRED_NODES="${DESIRED_NODES:-2}"

cd "$(dirname "$0")"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ECR="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
BACKEND_IMAGE="${ECR}/${BACKEND_REPO}"
FRONTEND_IMAGE="${ECR}/${FRONTEND_REPO}"
echo ">> Account ${ACCOUNT_ID} | region ${REGION} | cluster ${CLUSTER}"

ecr_login() { aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ECR}"; }
push_retry() { # $1 = image:tag
  for i in 1 2 3 4 5; do
    if docker push "$1" 2>&1 | tee /dev/stderr | grep -q "digest:"; then return 0; fi
    echo ">> push retry $i for $1"; ecr_login >/dev/null 2>&1; sleep 3
  done
  echo "!! push failed: $1"; return 1
}

# ---- 1. ECR repos (one per image, private) ----
echo ">> Ensuring private ECR repos"
for r in "${BACKEND_REPO}" "${FRONTEND_REPO}"; do
  aws ecr describe-repositories --repository-names "$r" --region "${REGION}" >/dev/null 2>&1 \
    || aws ecr create-repository --repository-name "$r" --region "${REGION}" >/dev/null
done
ecr_login

# ---- 2. Build + push both images (amd64) ----
echo ">> Building + pushing backend ${BACKEND_IMAGE}:${IMAGE_TAG}"
docker build --platform linux/amd64 -t "${BACKEND_IMAGE}:${IMAGE_TAG}" .
push_retry "${BACKEND_IMAGE}:${IMAGE_TAG}"

echo ">> Building + pushing frontend ${FRONTEND_IMAGE}:${IMAGE_TAG}"
docker build --platform linux/amd64 -t "${FRONTEND_IMAGE}:${IMAGE_TAG}" ./dashboard
push_retry "${FRONTEND_IMAGE}:${IMAGE_TAG}"

# ---- 3. Read-only IAM policy ----
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"
if aws iam get-policy --policy-arn "${POLICY_ARN}" >/dev/null 2>&1; then
  echo ">> IAM policy ${POLICY_NAME} exists"
else
  echo ">> Creating IAM policy ${POLICY_NAME}"
  aws iam create-policy --policy-name "${POLICY_NAME}" \
    --policy-document file://deploy/iam/CodeSentinal.-readonly-policy.json >/dev/null
fi

# ---- 4. OIDC + IRSA service account (read-only role for backend + prowler) ----
echo ">> Associating OIDC provider (idempotent)"
eksctl utils associate-iam-oidc-provider --cluster "${CLUSTER}" --region "${REGION}" --approve

echo ">> Ensuring IRSA service account ${SA_NAME}"
eksctl create iamserviceaccount \
  --cluster "${CLUSTER}" --region "${REGION}" \
  --namespace "${NAMESPACE}" --name "${SA_NAME}" \
  --role-name "${ROLE_NAME}" \
  --attach-policy-arn "${POLICY_ARN}" \
  --approve --override-existing-serviceaccounts
ROLE_ARN="$(aws iam get-role --role-name "${ROLE_NAME}" --query 'Role.Arn' --output text)"
echo ">> IRSA role: ${ROLE_ARN}"

# ---- 4b. DynamoDB reviews table (persistence) ----
REVIEWS_TABLE="${REVIEWS_TABLE:-CodeSentinal.-reviews}"
if [ -n "${REVIEWS_TABLE}" ]; then
  if aws dynamodb describe-table --table-name "${REVIEWS_TABLE}" --region "${REGION}" >/dev/null 2>&1; then
    echo ">> DynamoDB table ${REVIEWS_TABLE} exists"
  else
    echo ">> Creating DynamoDB table ${REVIEWS_TABLE} (PK pk, SK sk)"
    aws dynamodb create-table --table-name "${REVIEWS_TABLE}" --region "${REGION}" \
      --billing-mode PAY_PER_REQUEST \
      --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
      --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE >/dev/null
    aws dynamodb wait table-exists --table-name "${REVIEWS_TABLE}" --region "${REGION}"
  fi
fi

# ---- 4c. Superadmin password (v1 auth gate) ----
# Provide SUPERADMIN_PASSWORD in the environment; never paste it in a commit.
if [ -z "${SUPERADMIN_PASSWORD:-}" ]; then
  echo "!! SUPERADMIN_PASSWORD not set — the portal auth gate will be OPEN."
  echo "   Export SUPERADMIN_PASSWORD before running start.sh to protect the portal."
fi

# ---- 5. Cluster prerequisites: EBS CSI driver (PVC) + ALB controller (Ingress) ----
# These are required for the shared Prowler PVC and the public ALB URL.
# See deploy/CLUSTER_PREREQS.md to install them once per cluster.
if ! kubectl get csidriver ebs.csi.aws.com >/dev/null 2>&1; then
  echo "!! EBS CSI driver not found — the Prowler PVC won't bind."
  echo "   Install it (see deploy/CLUSTER_PREREQS.md) or run with --set prowler.enabled=false."
fi
if ! kubectl get ingressclass alb >/dev/null 2>&1; then
  echo "!! AWS Load Balancer Controller (ingressclass 'alb') not found — no public URL."
  echo "   Install it (see deploy/CLUSTER_PREREQS.md) or run with --set ingress.enabled=false."
fi

# ---- 6. Scale node group up ----
echo ">> Scaling node group ${NODEGROUP} to desired ${DESIRED_NODES}"
aws eks update-nodegroup-config --cluster-name "${CLUSTER}" --nodegroup-name "${NODEGROUP}" \
  --region "${REGION}" \
  --scaling-config "minSize=1,maxSize=4,desiredSize=${DESIRED_NODES}" >/dev/null 2>&1 || true

# ---- 7. Helm install (microservices) ----
echo ">> helm upgrade --install CodeSentinal."
helm upgrade --install CodeSentinal. deploy/helm/CodeSentinal. \
  --namespace "${NAMESPACE}" --create-namespace \
  --set backend.image.repository="${BACKEND_IMAGE}" \
  --set backend.image.tag="${IMAGE_TAG}" \
  --set frontend.image.repository="${FRONTEND_IMAGE}" \
  --set frontend.image.tag="${IMAGE_TAG}" \
  --set serviceAccount.roleArn="${ROLE_ARN}" \
  --set region="${REGION}" \
  --set persistence.reviewsTable="${REVIEWS_TABLE}" \
  --set-string auth.password="${SUPERADMIN_PASSWORD:-}" \
  --wait --timeout 6m

echo ">> Done. Workloads:"
kubectl -n "${NAMESPACE}" get deploy,svc,cronjob,ingress,pods

URL="$(kubectl -n "${NAMESPACE}" get ingress CodeSentinal. -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)"
echo
if [ -n "${URL}" ]; then
  echo ">> Public URL (ALB may take ~2-3 min): http://${URL}"
else
  echo ">> Ingress ALB still provisioning. Re-check with:"
  echo "   kubectl -n ${NAMESPACE} get ingress CodeSentinal. -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'"
fi
echo ">> Trigger an immediate Prowler scan (otherwise it runs on schedule):"
echo "   kubectl -n ${NAMESPACE} create job --from=cronjob/CodeSentinal.-prowler prowler-now"
