"""Pulumi — alternative multi-cloud (lab, non appliqué).

  pip install pulumi pulumi-aws
  pulumi up   # seulement après `pulumi login` et revue
"""

import pulumi
from pulumi_aws import s3

bucket = s3.Bucket(
    "securepay-lab-logs",
    acl="private",
    server_side_encryption_configuration=s3.BucketServerSideEncryptionConfigurationArgs(
        rule=s3.BucketServerSideEncryptionConfigurationRuleArgs(
            apply_server_side_encryption_by_default=s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="aws:kms",
            )
        )
    ),
    versioning=s3.BucketVersioningArgs(enabled=True),
)

public_block = s3.BucketPublicAccessBlock(
    "securepay-lab-logs-pab",
    bucket=bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

pulumi.export("bucket_name", bucket.id)
