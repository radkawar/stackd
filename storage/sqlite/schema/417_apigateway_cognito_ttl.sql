ALTER TABLE apigateway_authorizers ADD COLUMN cognito_ttl_seconds INTEGER
CHECK (cognito_ttl_seconds IS NULL OR
       (authorizer_type = 'COGNITO_USER_POOLS' AND cognito_ttl_seconds BETWEEN 0 AND 3600));
