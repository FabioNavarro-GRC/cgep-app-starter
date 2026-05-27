package soc2.security_test

import data.soc2.security.allow
import data.soc2.security.deny

# --- TEST 1: Verificar paso exitoso si todo está bien configurado ---
test_allow_valid_plan {
    mock_input := {"resource_changes": [
        {
            "address": "aws_s3_bucket_server_side_encryption_configuration.uploads_encryption",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}}
        },
        {
            "address": "aws_dynamodb_table.intake",
            "type": "aws_dynamodb_table",
            "change": {"after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:valid-key"}]}}
        },
        {
            "address": "aws_s3_bucket_versioning.uploads_versioning",
            "type": "aws_s3_bucket_versioning",
            "change": {"after": {"versioning_configuration": [{"status": "Enabled"}]}}
        }
    ]}
    allow with input as mock_input
}

# --- TEST 2: Detectar violación del GAP-01 (S3 sin KMS CMK) ---
test_deny_unencrypted_s3 {
    mock_input := {"resource_changes": [{
        "address": "aws_s3_bucket_server_side_encryption_configuration.bad_s3",
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}}
    }]}
    count(deny) > 0 with input as mock_input
}

# --- TEST 3: Detectar violación del GAP-07 (IAM con Permisos Completos *) ---
test_deny_wildcard_iam {
    mock_input := {"resource_changes": [{
        "address": "aws_iam_role_policy.bad_lambda",
        "type": "aws_iam_role_policy",
        "change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:*\"],\"Resource\":\"*\"}]}"}}
    }]}
    count(deny) > 0 with input as mock_input
}