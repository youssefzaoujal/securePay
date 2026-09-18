# Alias Terraform (GuardianPay / SentinelPay)

Le code IaC vit dans `../infra/terraform/` (VPC, EKS, RDS). Stub Azure : `infra/terraform/azure/`. Pulumi : `infra/pulumi/`. CloudFormation : `infra/cloudformation/securepay-lab.yaml`.

```bash
cd infra/terraform
terraform init
terraform plan
```

Scan shift-left :

```bash
python -m cspm --mode terraform --terraform infra/terraform
checkov -d infra/terraform
```
