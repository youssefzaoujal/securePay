# CSPM — CIS AWS Foundations (subset)

```bash
python -m cspm --mode fixture                 # inventaire synthétique (démo)
python -m cspm --mode terraform --terraform infra/terraform
python -m cspm --mode aws --region eu-west-1  # boto3, compte réel
```

Rapports : `cspm/reports/cspm-latest.html` + `.json`  
Mapping : `cspm/cis_mapping.json`

Contrôles : 1.4 root keys, 1.16 admin users / *:* , 2.1.1 S3 public, 2.1.4 encryption, 2.2.1 EBS, 3.1 CloudTrail, 5.2 SG world-open.
