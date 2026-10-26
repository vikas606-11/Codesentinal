# Cluster prerequisites (one-time per EKS cluster)

CodeSentinal.'s microservice chart needs two cluster add-ons:

1. **Amazon EBS CSI driver** — provisions the shared PVC where Prowler writes
   its OCSF results and the backend reads them.
2. **AWS Load Balancer Controller** — turns the `alb` Ingress into a public ALB.

Both use IRSA (no static keys). Run these once per cluster. If you skip them,
deploy with `--set prowler.enabled=false` and/or `--set ingress.enabled=false`.

```bash
CLUSTER=eks-lab
REGION=us-east-1
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

eksctl utils associate-iam-oidc-provider --cluster $CLUSTER --region $REGION --approve

# ---- EBS CSI driver ----
eksctl create iamserviceaccount \
  --cluster $CLUSTER --region $REGION \
  --namespace kube-system --name ebs-csi-controller-sa \
  --role-name AmazonEKS_EBS_CSI_DriverRole \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
  --approve --override-existing-serviceaccounts

aws eks create-addon --cluster-name $CLUSTER --region $REGION \
  --addon-name aws-ebs-csi-driver \
  --service-account-role-arn arn:aws:iam::${ACCOUNT_ID}:role/AmazonEKS_EBS_CSI_DriverRole \
  --resolve-conflicts OVERWRITE
aws eks wait addon-active --cluster-name $CLUSTER --region $REGION --addon-name aws-ebs-csi-driver

# ---- AWS Load Balancer Controller ----
curl -s -o /tmp/alb-iam-policy.json \
  https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.9.2/docs/install/iam_policy.json
aws iam create-policy --policy-name AWSLoadBalancerControllerIAMPolicy \
  --policy-document file:///tmp/alb-iam-policy.json 2>/dev/null || true

eksctl create iamserviceaccount \
  --cluster $CLUSTER --region $REGION \
  --namespace kube-system --name aws-load-balancer-controller \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --attach-policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWSLoadBalancerControllerIAMPolicy \
  --approve --override-existing-serviceaccounts

VPC_ID=$(aws eks describe-cluster --name $CLUSTER --region $REGION \
  --query 'cluster.resourcesVpcConfig.vpcId' --output text)
helm repo add eks https://aws.github.io/eks-charts && helm repo update eks
helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
  --namespace kube-system \
  --set clusterName=$CLUSTER \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller \
  --set region=$REGION --set vpcId=$VPC_ID --wait
```

Verify:
```bash
kubectl get csidriver ebs.csi.aws.com
kubectl get ingressclass alb
```
