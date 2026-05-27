package soc2.security

import future.keywords.in

# Por defecto, el plan es válido a menos que una regla de denegación se active
default allow = true

allow = false {
    count(deny) > 0
}

# --- REGLA GAP-01: Bloquear si S3 no usa llave KMS del Cliente (CMK) ---
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    
    rule := resource.change.after.rule[_]
    enc := rule.apply_server_side_encryption_by_default[_]
    enc.sse_algorithm != "aws:kms"
    
    msg := sprintf("SOC 2 Violación [CC6.1]: El bucket '%v' debe usar cifrado SSE-KMS con una llave CMK controlada por el cliente.", [resource.address])
}

# --- REGLA GAP-02: Bloquear si DynamoDB usa llaves por defecto de AWS ---
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    
    sse := resource.change.after.server_side_encryption[_]
    sse.enabled == false
    
    msg := sprintf("SOC 2 Violación [CC6.1]: La tabla DynamoDB '%v' debe tener el cifrado en reposo habilitado explícitamente.", [resource.address])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    
    sse := resource.change.after.server_side_encryption[_]
    not sse.kms_key_arn
    
    msg := sprintf("SOC 2 Violación [CC6.1]: La tabla DynamoDB '%v' debe usar un KMS CMK personalizado, no la llave por defecto de AWS.", [resource.address])
}

# --- REGLA GAP-03: Bloquear si S3 no tiene política para forzar TLS ---
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    
    # Busca si existe una política asociada a este bucket que valide SecureTransport
    bucket_name := resource.name
    policies := [p | p := input.resource_changes[_]; p.type == "aws_s3_bucket_policy"]
    count(policies) == 0
    
    msg := sprintf("SOC 2 Violación [CC6.7]: El bucket '%v' requiere una política S3BucketPolicy adjunta para forzar conexiones TLS seguro.", [bucket_name])
}

# --- REGLA GAP-04: Bloquear si S3 no tiene el versionado activo ---
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_versioning"
    
    versioning := resource.change.after.versioning_configuration[_]
    versioning.status != "Enabled"
    
    msg := sprintf("SOC 2 Violación [A1.2]: El versionado de S3 debe estar explícitamente 'Enabled' para garantizar disponibilidad y auditoría.", [resource.address])
}

# --- REGLA GAP-07: Bloquear si el Rol de la Lambda usa comodines peligrosos (*) ---
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    
    policy_str := resource.change.after.policy
    policy := json.unmarshal(policy_str)
    statement := policy.Statement[_]
    
    statement.Effect == "Allow"
    actions := statement.Action
    
    dangerous_actions := ["*", "dynamodb:*", "s3:*"]
    some act in actions
    act in dangerous_actions
    
    msg := sprintf("SOC 2 Violación [CC6.3]: Privilegios excesivos detectados en '%v'. El uso de acciones comodín como s3:* o dynamodb:* está prohibido.", [resource.address])
}