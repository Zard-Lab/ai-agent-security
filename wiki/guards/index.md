# Guard
* [acp-vulnerabilities](acp-vulnerabilities.md) - Agent Communication Protocol (ACP) implementation has security vulnerabilities.
* [actions-script-injection](actions-script-injection.md) - No untrusted GitHub-context interpolation in run: steps.
* [actions-sha-pin](actions-sha-pin.md) - GitHub Actions pinned to a commit SHA.
* [agent-headless-trust-surface](agent-headless-trust-surface.md) - A coding-agent CLI is run headlessly in CI, or checked-in settings/instruction files persist trust across every invocation.
* [agent-iam-control-plane-exposure](agent-iam-control-plane-exposure.md) - Flags an AI agent's IAM policy granting a Bedrock/SageMaker control-plane action instead of only the data-plane action its runtime actually needs.
* [agent-iam-killchain-combination](agent-iam-killchain-combination.md) - Flags an AI agent IAM policy that combines credential-access, lateral-movement, and identity-discovery action categories across the statements of one policy document, a multi-step breach-chain shape no single statement reveals.
* [agent-iam-tool-resource-unscoped](agent-iam-tool-resource-unscoped.md) - Flags an AI agent's IAM policy granting a tool-execution/data-access action with no resource-level scoping (Resource: "*").
* [agent-loop-circuit-breaker](agent-loop-circuit-breaker.md) - LLM agent loop has no iteration or time limit.
* [agent-memory-retention](agent-memory-retention.md) - Persistent agent memory constructed without a retention TTL.
* [agent-memory-security](agent-memory-security.md) - AI agent long-term memory store is insecure or poisonable.
* [agent-memory-user-scope](agent-memory-user-scope.md) - Agent memory write without user/session scoping — cross-user memory contamination.
* [agent-resume-unverified-trigger](agent-resume-unverified-trigger.md) - Unauthenticated external trigger resumes an agent session with elevated permissions.
* [agent-tool-audit-log](agent-tool-audit-log.md) - @agent.tool function has no logging — silent tool invocation.
* [agent-tool-overpermission](agent-tool-overpermission.md) - LLM agent granted excessive tool permissions.
* [agent-tool-url-fetch-ssrf](agent-tool-url-fetch-ssrf.md) - Agent tool wraps a URL-fetching sink (WebBaseLoader, requests/httpx/urlopen, sibling LangChain URL loaders) with an unvalidated, non-literal URL.
* [agentic-skills-ast](agentic-skills-ast.md) - A skill's static shape carries an unpinned external resource, a deserialization tag, or a cross-platform manifest disagreement.
* [ai-docker](ai-docker.md) - AI-specific Docker security misconfiguration.
* [ai-instruction-poisoning](ai-instruction-poisoning.md) - AI coding assistant configuration contains dangerous or poisoned instructions.
* [alb-listener-http-protocol](alb-listener-http-protocol.md) - Terraform aws_lb_listener resource serving plaintext HTTP (protocol = "HTTP").
* [ansi-escape-llm-output](ansi-escape-llm-output.md) - LLM response printed to a terminal without ANSI-escape stripping.
* [ansible-debug-echoes-auth-variable](ansible-debug-echoes-auth-variable.md) - Ansible debug task echoes a live authentication variable.
* [ansible-host-key-checking-disabled](ansible-host-key-checking-disabled.md) - ANSIBLE_HOST_KEY_CHECKING disabled — SSH MitM enabler.
* [ansible-ignore-errors-on-security-task](ansible-ignore-errors-on-security-task.md) - ignore_errors: true on a security-critical Ansible task.
* [ansible-no-log-disabled-on-secret-task](ansible-no-log-disabled-on-secret-task.md) - Ansible task explicitly disables no_log while handling a secret.
* [ansible-setuid-binary-creation](ansible-setuid-binary-creation.md) - Ansible task creates a setuid binary.
* [ansible-sudo-nopasswd](ansible-sudo-nopasswd.md) - Ansible task grants blanket sudo NOPASSWD:ALL.
* [ansible-unsafe-lookups-enabled](ansible-unsafe-lookups-enabled.md) - ALLOW_UNSAFE_LOOKUPS enabled — lookup-plugin RCE bypass.
* [api-docs-exposed](api-docs-exposed.md) - FastAPI docs exposed in production.
* [approval-parser-shell-desync](approval-parser-shell-desync.md) - A command-safety approval check parses a command differently than the shell that actually executes it.
* [argv-toctou](argv-toctou.md) - A command/argv buffer is rebuilt after approval, with no re-validation before it spawns.
* [arm-aks-rbac-disabled](arm-aks-rbac-disabled.md) - ARM-templated Azure Kubernetes Service (AKS) cluster does not enable Kubernetes RBAC.
* [arm-apim-backend-unauthenticated](arm-apim-backend-unauthenticated.md) - ARM-templated Azure API Management backend using a cleartext HTTP URL with no authentication configured.
* [arm-appservice-https-only-disabled](arm-appservice-https-only-disabled.md) - ARM-templated Azure App Service (Web App, API App, or Function App) that does not enforce HTTPS-only traffic.
* [arm-redis-ssl-disabled](arm-redis-ssl-disabled.md) - ARM-templated Azure Cache for Redis allowing unencrypted (non-SSL) connections.
* [arm-sql-tde-disabled](arm-sql-tde-disabled.md) - ARM-templated Azure SQL Database transparent data encryption (TDE) not enabled.
* [async-blocking-io](async-blocking-io.md) - Blocking I/O call inside async def stalls the event loop.
* [auth-dependency-not-applied](auth-dependency-not-applied.md) - State-changing route has no auth dependency wired.
* [auth-disabled-by-default](auth-disabled-by-default.md) - Authentication explicitly disabled by a hardcoded default.
* [auth-rate-limit-absent](auth-rate-limit-absent.md) - Auth-sensitive route has no rate-limiting protection.
* [auth-users-not-exposed-via-view](auth-users-not-exposed-via-view.md) - View exposes auth.users — leaks every user's email and password hash.
* [auto-updates-absent](auto-updates-absent.md) - Host installs OS packages but enables no automatic security updates.
* [autostart-persistence-mechanism](autostart-persistence-mechanism.md) - No OS-level autostart/persistence mechanism written from application code.
* [aws-observability-hygiene](aws-observability-hygiene.md) - AWS Terraform resource missing an observability or durability hygiene control (CloudWatch retention, S3 versioning, S3 access logging).
* [aws-weak-tls-policy](aws-weak-tls-policy.md) - AWS resource (API Gateway custom domain, OpenSearch/Elasticsearch domain, ALB/NLB listener) allows a weak or unspecified TLS policy.
* [azure-keyvault-key-no-expiration](azure-keyvault-key-no-expiration.md) - Azure Key Vault key with no expiration date.
* [azure-keyvault-purge-protection-disabled](azure-keyvault-purge-protection-disabled.md) - Azure Key Vault without purge protection.
* [azure-mssql-publicly-accessible](azure-mssql-publicly-accessible.md) - Azure SQL Server directly reachable from the internet (public_network_access_enabled not false).
* [azure-storage-account-https-only](azure-storage-account-https-only.md) - Azure Storage Account does not enforce HTTPS-only traffic (enable_https_traffic_only / https_traffic_only_enabled not true).
* [azure-storage-account-public-blob-access](azure-storage-account-public-blob-access.md) - Azure Storage Account allows public blob access (allow_blob_public_access not explicitly false).
* [background-tasks](background-tasks.md) - Fire-and-forget task without exception handling.
* [bicep-admin-username-literal](bicep-admin-username-literal.md) - Bicep resource adminUsername set to a hardcoded string literal instead of a parameter reference.
* [bicep-commandtoexecute-plaintext-settings](bicep-commandtoexecute-plaintext-settings.md) - Bicep VM CustomScript extension puts a secret-bearing commandToExecute under plaintext settings instead of protectedSettings.
* [bicep-output-secret-not-secure](bicep-output-secret-not-secure.md) - Bicep output has a secret-shaped name but no @secure() decorator.
* [bicep-param-file-insecure-secret-value](bicep-param-file-insecure-secret-value.md) - Bicep .bicepparam file assigns a secret-shaped parameter a hardcoded literal value instead of sourcing it from an environment variable or a Key Vault reference.
* [bicep-secret-param-not-secure](bicep-secret-param-not-secure.md) - Bicep param whose name looks like a secret is declared without @secure() or a secure type.
* [bicep-secure-param-in-nested-deployment](bicep-secure-param-in-nested-deployment.md) - Bicep outer-scoped nested deployment whose embedded template references a @secure() parameter or a list*() function, leaking it into cleartext deployment history.
* [bicep-secure-parameter-default](bicep-secure-parameter-default.md) - Bicep @secure() parameter given a hardcoded, non-empty literal default value.
* [bola](bola.md) - Object-level authorization (BOLA) — fetch not scoped to the caller.
* [browser-credential-store-access](browser-credential-store-access.md) - No code reads a browser's or chat client's own saved-credential store (Chromium master key, Chromium Login Data, Firefox key4.db/logins.json, Discord token grabber + webhook).
* [build-secret](build-secret.md) - Secret baked into a build (client bundle or image layer).
* [bulk-env-var-harvesting](bulk-env-var-harvesting.md) - Bulk enumeration of all environment variables.
* [cfn-authentication-password](cfn-authentication-password.md) - AWS::CloudFormation::Authentication resource carrying a literal (non-referenced) password value.
* [cfn-batch-privileged-container](cfn-batch-privileged-container.md) - No AWS Batch job definition container running in privileged mode.
* [cfn-cognito-mfa-off](cfn-cognito-mfa-off.md) - No CloudFormation Cognito User Pool with multi-factor authentication disabled.
* [cfn-cognito-unauth-identities](cfn-cognito-unauth-identities.md) - No CloudFormation Cognito Identity Pool that allows unauthenticated identities.
* [cfn-ec2-subnet-public-ip](cfn-ec2-subnet-public-ip.md) - No CloudFormation EC2 subnet that auto-assigns public IPs to every instance launched into it.
* [cfn-ecr-scan-on-push](cfn-ecr-scan-on-push.md) - No CloudFormation ECR repository without ScanOnPush vulnerability scanning enabled.
* [cfn-iam-escalation-action-no-condition](cfn-iam-escalation-action-no-condition.md) - No CloudFormation IAM policy statement grants a privilege-escalation-class action under Effect: Allow with no scoping Condition.
* [cfn-iam-notaction-with-allow](cfn-iam-notaction-with-allow.md) - Flags CloudFormation IAM policy statements that combine Effect: Allow with NotAction.
* [cfn-iam-user-direct-policy](cfn-iam-user-direct-policy.md) - No IAM policy (inline or managed) attached directly to a CloudFormation IAM user instead of via a group.
* [cfn-kms-key-rotation-not-enabled](cfn-kms-key-rotation-not-enabled.md) - No customer-managed CloudFormation KMS key without automatic rotation enabled.
* [cfn-nacl-ineffective-deny](cfn-nacl-ineffective-deny.md) - Surfaces a CloudFormation Network ACL deny entry whose CIDR block is not the full-range 0.0.0.0/0 or ::/0, for manual review.
* [cfn-rds-hardcoded-password-no-echo](cfn-rds-hardcoded-password-no-echo.md) - No literal or unmasked MasterUserPassword on a CloudFormation RDS instance or cluster.
* [cfn-rds-publicly-accessible](cfn-rds-publicly-accessible.md) - CloudFormation RDS instance directly reachable from the internet.
* [cfn-s3-public-access-canned-acl](cfn-s3-public-access-canned-acl.md) - S3 bucket resource in a CloudFormation template sets a legacy public canned ACL (PublicRead/PublicReadWrite).
* [cfn-s3-versioning-missing](cfn-s3-versioning-missing.md) - No CloudFormation S3 bucket without VersioningConfiguration Status: Enabled.
* [cfn-vpc-flow-log-missing](cfn-vpc-flow-log-missing.md) - Flags a CloudFormation template that defines a VPC but declares no AWS::EC2::FlowLog resource anywhere in the same file.
* [cfn-waf-default-allow](cfn-waf-default-allow.md) - CloudFormation classic WAF WebACL whose DefaultAction is ALLOW rather than BLOCK.
* [cfn-wildcard-principal](cfn-wildcard-principal.md) - No CloudFormation resource policy grants an action to Principal: "*" without a narrowing Condition.
* [checkout-price-from-server](checkout-price-from-server.md) - Stripe charge amount taken from client input — price can be tampered.
* [ci-image-build-no-sbom-provenance](ci-image-build-no-sbom-provenance.md) - Container image build/push with no SBOM or provenance/signing step.
* [ci-secret-env-unscoped](ci-secret-env-unscoped.md) - GitHub Actions secret used without an environment scope.
* [claude-code-compromise](claude-code-compromise.md) - AI coding assistant configuration contains code execution or steganographic exfiltration.
* [claude-hook-rce](claude-hook-rce.md) - A Claude Code hook command interpolates a shell variable with no quoting, or is defined in the personal settings.local.json rather than the reviewed settings.json.
* [claude-routines-security](claude-routines-security.md) - A Claude Code Routine grants an over-broad permission, an unstable schedule, or no audit log.
* [cleartext-secret-storage](cleartext-secret-storage.md) - Secret written to a cleartext sink (cookie or plaintext file).
* [client-side-auth-decision](client-side-auth-decision.md) - Authentication decision made in client-side JavaScript.
* [client-side-secret-literal](client-side-secret-literal.md) - Hardcoded provider API-key / secret literal in client-side JavaScript.
* [cloud-metadata-endpoint-literal](cloud-metadata-endpoint-literal.md) - Literal reference to a cloud instance-metadata endpoint.
* [cloudtrail-logging-disabled](cloudtrail-logging-disabled.md) - CloudTrail logging disabled or restricted to a single region.
* [cloudwatch-log-group-not-kms-encrypted](cloudwatch-log-group-not-kms-encrypted.md) - CloudWatch Log Group without a customer-managed KMS key.
* [code-injection-eval-exec](code-injection-eval-exec.md) - No code injection via a bare eval()/exec() sink fed dynamic content.
* [command-injection](command-injection.md) - No OS-command injection via a shell sink.
* [compose-connection-string-credential](compose-connection-string-credential.md) - Docker-compose env value with an inline connection-string credential.
* [compose-credential-env-literal](compose-credential-env-literal.md) - Docker-compose credential-shaped env key with a literal value.
* [compose-db-port-exposed](compose-db-port-exposed.md) - Datastore or admin/broker port published to the host in docker-compose.
* [compose-dns-bypass](compose-dns-bypass.md) - docker-compose service bypasses the DNS-egress-allowlist resolver.
* [compose-image-digest-missing](compose-image-digest-missing.md) - Docker-compose service image pinned to a tag but not a digest.
* [compose-logging-disabled](compose-logging-disabled.md) - Docker-compose service with logging driver explicitly disabled.
* [compose-no-network-segmentation](compose-no-network-segmentation.md) - All compose services share the implicit default network with no explicit segmentation.
* [compose-no-new-privileges](compose-no-new-privileges.md) - Docker-compose service missing no-new-privileges:true in security_opt.
* [compose-resource-limits-absent](compose-resource-limits-absent.md) - Docker-compose service with no memory or CPU resource limit.
* [compose-sensitive-host-mount](compose-sensitive-host-mount.md) - Docker-compose bind mount of a sensitive host path.
* [compose-shared-mount-propagation](compose-shared-mount-propagation.md) - Docker-compose volume using shared mount propagation.
* [compose-tmpfs-insecure-options](compose-tmpfs-insecure-options.md) - Docker-compose tmpfs mount re-enables exec/suid/dev.
* [compose-user-directive-missing](compose-user-directive-missing.md) - Docker-compose service has no user: directive (image likely runs as root).
* [compose-writable-host-root-mount](compose-writable-host-root-mount.md) - Docker-compose bind mount of a root-equivalent host path, writable.
* [compose-writable-root-filesystem](compose-writable-root-filesystem.md) - Docker-compose service missing read_only: true (writable container root filesystem).
* [content-type-magic-bytes](content-type-magic-bytes.md) - File upload validates Content-Type header only — magic bytes not checked (CWE-434).
* [cors-wildcard](cors-wildcard.md) - CORS wildcard origin.
* [credential-file-path-reference](credential-file-path-reference.md) - Literal reference to a well-known credential-file path.
* [crewai-rce-chain](crewai-rce-chain.md) - CrewAI tool usage matches the 2026-04-02 exploit chain (unsafe code exec, path traversal, or SSRF).
* [cron-systemd-persistence-write](cron-systemd-persistence-write.md) - No code writes a cron entry, systemd unit, macOS LaunchAgent/Daemon, or Windows Startup-folder file — OS-level persistence outside shell-config/registry targets.
* [csv-injection](csv-injection.md) - CSV/Excel formula injection.
* [ctypes-load-downloaded-library](ctypes-load-downloaded-library.md) - No ctypes load of a native library downloaded earlier in the same scope — fetch-then-load-into-process with no review step.
* [curl-pipe-to-shell](curl-pipe-to-shell.md) - curl/wget output piped directly into an interpreter, unverified.
* [dataset-injection](dataset-injection.md) - RAG corpus file contains embedded injection payload.
* [datastore-auth-absent](datastore-auth-absent.md) - Datastore (Redis/MongoDB) running without authentication.
* [db-role-privilege-excessive](db-role-privilege-excessive.md) - Application DB role holds excessive privilege (SUPERUSER/CREATEDB/CREATEROLE/schema ownership/broad DDL grant).
* [debug-default-off](debug-default-off.md) - DEBUG defaults to False.
* [debug-route-exposed](debug-route-exposed.md) - Route path looks like a debug/internal/deprecated endpoint left reachable.
* [default-service-credential](default-service-credential.md) - Deployed service left on a well-known factory-default credential.
* [definer-dynamic-sql](definer-dynamic-sql.md) - SECURITY DEFINER function executes arbitrary/dynamic SQL.
* [definer-function-grants](definer-function-grants.md) - SECURITY DEFINER function executable by anon/authenticated.
* [dependency-typosquat-popular](dependency-typosquat-popular.md) - A declared dependency name is one typing slip away from a popular PyPI or npm package.
* [dependency-version-floor](dependency-version-floor.md) - Dependencies meet the patched-version floor for known CVEs.
* [destructive-filesystem-command](destructive-filesystem-command.md) - No hardcoded destructive filesystem-wipe command targeting a root/home/device path.
* [dns-egress-allowlist](dns-egress-allowlist.md) - DNS resolver not configured as a default-deny egress allowlist.
* [dns-exfiltration-pattern](dns-exfiltration-pattern.md) - No DNS-exfiltration / OOB-beacon pattern in source.
* [docker-add-misuse](docker-add-misuse.md) - Dockerfile ADD used instead of COPY/RUN curl.
* [docker-apt-update-not-alone](docker-apt-update-not-alone.md) - Dockerfile updates package index in a layer separate from install.
* [docker-expose-ssh](docker-expose-ssh.md) - Dockerfile EXPOSEs the SSH port.
* [docker-latest-base-tag](docker-latest-base-tag.md) - Docker base image not pinned to a version tag.
* [docker-nonroot-user](docker-nonroot-user.md) - Container does not drop privilege to a non-root user.
* [docker-privileged-flags](docker-privileged-flags.md) - Privileged-container / host-namespace flag enables container escape.
* [docker-run-sudo](docker-run-sudo.md) - Dockerfile RUN instruction invokes sudo.
* [docker-socket-access](docker-socket-access.md) - Code references the Docker socket (container-escape vector).
* [dockerfile-credential-in-instruction](dockerfile-credential-in-instruction.md) - Dockerfile instruction embeds a plaintext credential.
* [dockerfile-run-isolation-weakening](dockerfile-run-isolation-weakening.md) - Dockerfile RUN instruction disables build sandboxing or sets dangerous permission bits.
* [dockerfile-workdir-sensitive-path](dockerfile-workdir-sensitive-path.md) - Dockerfile WORKDIR points to a sensitive system directory.
* [dom-xss-sinks](dom-xss-sinks.md) - DOM XSS sink called with a non-literal value.
* [download-execute-chain](download-execute-chain.md) - No download-then-execute chain (fetch a remote payload, run it unreviewed).
* [dynamic-import-non-literal](dynamic-import-non-literal.md) - Dynamic module import with a non-literal, attacker-influenceable name.
* [dynamodb-table-not-encrypted](dynamodb-table-not-encrypted.md) - DynamoDB table without customer-managed KMS encryption.
* [ebs-volume-not-encrypted](ebs-volume-not-encrypted.md) - EBS volume without encryption at rest.
* [ecr-repository-hygiene](ecr-repository-hygiene.md) - ECR repository missing vulnerability scanning, immutable tags, or a lifecycle policy.
* [ecr-repository-not-kms-encrypted](ecr-repository-not-kms-encrypted.md) - ECR repository without KMS encryption.
* [ecs-efs-volume-transit-encryption-disabled](ecs-efs-volume-transit-encryption-disabled.md) - Terraform aws_ecs_task_definition volume mounting EFS via efs_volume_configuration without transit_encryption enabled.
* [efs-file-system-not-encrypted](efs-file-system-not-encrypted.md) - EFS file system without encryption at rest.
* [elasticache-transit-encryption-disabled](elasticache-transit-encryption-disabled.md) - ElastiCache replication group has transit encryption disabled.
* [electron-security-misconfig](electron-security-misconfig.md) - Electron app disables a webPreferences security control.
* [empty-password-in-config](empty-password-in-config.md) - Empty password field in checked-in config file.
* [env-file-not-gitignored](env-file-not-gitignored.md) - A real .env* file exists in the repo with no .gitignore exclusion pattern covering it.
* [env-secret-console-log](env-secret-console-log.md) - Environment secret read directly inside a console.* call.
* [env-secret-in-prompt](env-secret-in-prompt.md) - Environment secret directly interpolated into a string (potential LLM prompt injection).
* [env-secret-logged](env-secret-logged.md) - Environment secret read directly inside a logging call.
* [environ-dump-to-network](environ-dump-to-network.md) - No code serializes the whole process environment and sends it to a network sink, or exfiltrates environment/credential-store content via a Telegram bot or Discord webhook.
* [error-info-leak](error-info-leak.md) - Exception details leaked into HTTP response body.
* [fail-safe-exception](fail-safe-exception.md) - Silent exception swallow — security check may fail open.
* [fail2ban-absent](fail2ban-absent.md) - SSH configured but no fail2ban brute-force protection.
* [file-system-race](file-system-race.md) - File checked then used separately — time-of-check-to-time-of-use race.
* [forwarded-header-blind-trust](forwarded-header-blind-trust.md) - X-Forwarded-For / X-Real-IP trusted in a security decision without proxy validation.
* [frontend-xss](frontend-xss.md) - Frontend XSS / SRI risk.
* [fulfill-on-completed-not-created](fulfill-on-completed-not-created.md) - Stripe fulfilment keyed on a created/pre-payment event — paid before charge.
* [gcp-kms-key-public](gcp-kms-key-public.md) - GCP KMS key / Cloud Storage bucket IAM policy grants access to allUsers/allAuthenticatedUsers.
* [gcp-kms-rotation-period-not-set](gcp-kms-rotation-period-not-set.md) - GCP KMS crypto key without a rotation period.
* [gcp-sql-publicly-accessible](gcp-sql-publicly-accessible.md) - GCP Cloud SQL instance reachable from the internet (public IP with no restriction, or a 0.0.0.0 authorized network).
* [git-in-docker](git-in-docker.md) - .git directory not excluded from Docker image.
* [go-build-supply-chain-footgun](go-build-supply-chain-footgun.md) - Go build/install supply-chain footgun in Dockerfile or CI.
* [go-pprof-exposed](go-pprof-exposed.md) - net/http/pprof registered on the default ServeMux.
* [go-sql-injection](go-sql-injection.md) - SQL query built from unparameterized string formatting/concatenation.
* [go-ssh-host-key-trust](go-ssh-host-key-trust.md) - SSH host key verification disabled (ssh.InsecureIgnoreHostKey).
* [go-template-html-escaping](go-template-html-escaping.md) - text/template used where html/template's auto-escaping is needed.
* [go-tls-verify-disabled](go-tls-verify-disabled.md) - TLS certificate verification disabled (InsecureSkipVerify: true).
* [graphql-mutation-idor](graphql-mutation-idor.md) - GraphQL mutation resolver modifies an object with no ownership check (possible IDOR).
* [guardrail-architecture](guardrail-architecture.md) - LLM application missing independent guardrail or using circular self-validation.
* [hardcoded-llm-provider-key](hardcoded-llm-provider-key.md) - Hardcoded LLM provider API key literal in source.
* [hardcoded-password-default-arg](hardcoded-password-default-arg.md) - Hardcoded password used as a function's default argument value.
* [hardcoded-private-key-in-source](hardcoded-private-key-in-source.md) - Hardcoded/committed private key material in source.
* [header-injection](header-injection.md) - Request value written into a response header (HTTP header injection).
* [hidden-executable-dotfile](hidden-executable-dotfile.md) - No hidden (dotfile) executable script committed to the repo.
* [homoglyph-source-chars](homoglyph-source-chars.md) - No homoglyph / mixed-script confusable identifiers in source.
* [hostname-regex-unsafe](hostname-regex-unsafe.md) - Hostname/URL allowlist regex is unsafe (unescaped dot or missing end anchor).
* [iac-open-ingress](iac-open-ingress.md) - World-open ingress in Terraform.
* [iam-escalation-action-no-condition](iam-escalation-action-no-condition.md) - Privilege-escalation-class IAM action granted under Effect: Allow with no scoping Condition.
* [iam-managed-admin-policy-attached](iam-managed-admin-policy-attached.md) - AWS-managed AdministratorAccess or *FullAccess-family policy attached directly.
* [iam-notaction-with-allow](iam-notaction-with-allow.md) - IAM policy statement combines Effect: "Allow" with NotAction.
* [iam-policy-attached-to-user-directly](iam-policy-attached-to-user-directly.md) - IAM policy attached directly to a user instead of a group/role.
* [iam-resource-scopable-wildcard](iam-resource-scopable-wildcard.md) - IAM policy statement grants a resource-level-permission-eligible action with Resource: "*".
* [iam-role-public-assume](iam-role-public-assume.md) - IAM role trust policy allows any AWS account to assume it.
* [iam-service-wildcard](iam-service-wildcard.md) - IAM policy statement grants a full service-wide wildcard action such as iam:* or s3:*.
* [iam-wildcard](iam-wildcard.md) - No wildcard-everything (*) IAM policy grants.
* [incomplete-url-scheme-check](incomplete-url-scheme-check.md) - URL scheme blocklist check covers javascript: but not vbscript:/data:.
* [incomplete-url-substring-sanitization](incomplete-url-substring-sanitization.md) - Raw URL substring checked against a trusted domain — bypassable.
* [incorrect-suffix-check](incorrect-suffix-check.md) - indexOf/lastIndexOf used as a homemade endsWith without handling -1.
* [input-delimiters](input-delimiters.md) - User input reaches an LLM call without delimiter wrapping.
* [insecure-cookies](insecure-cookies.md) - Cookies set with HttpOnly + Secure (+ SameSite).
* [insecure-file-permissions](insecure-file-permissions.md) - os.chmod() grants overly-permissive group/other access.
* [insecure-tempfile-mktemp](insecure-tempfile-mktemp.md) - Insecure tempfile.mktemp() usage (race condition).
* [invisible-unicode](invisible-unicode.md) - No invisible Unicode-tag smuggling in repo text.
* [java-command-injection](java-command-injection.md) - No OS-command injection via a Java Runtime.exec/ProcessBuilder sink built from concatenated or variable input.
* [java-hardcoded-password-key](java-hardcoded-password-key.md) - Hardcoded password/key literal passed as an argument to a named security-sensitive Java API.
* [java-ldap-injection](java-ldap-injection.md) - LDAP query built from string concatenation in Java application code.
* [java-path-traversal](java-path-traversal.md) - No path traversal via a Java file-construction sink built from tainted input.
* [java-sql-injection](java-sql-injection.md) - SQL query built from string concatenation in Java JDBC/Hibernate code, not parameterized.
* [java-ssrf](java-ssrf.md) - No server-side fetch from a tainted java.net.URL — the SSRF idiom new URL(input).openConnection().
* [java-tls-verify-disabled](java-tls-verify-disabled.md) - Empty (no-op) X509TrustManager checkServerTrusted/checkClientTrusted body — a client-side TLS certificate verification bypass.
* [java-unsafe-deserialization](java-unsafe-deserialization.md) - No unsafe deserialization of untrusted data (ObjectInputStream gadget chains, Jackson polymorphic typing) in Java application code.
* [java-weak-crypto](java-weak-crypto.md) - No weak / broken hash algorithm or cipher mode in Java application code.
* [java-xxe-unsafe-parsing](java-xxe-unsafe-parsing.md) - Java XML parser used to parse XML without a hardened (disallow-DOCTYPE / external-entity-off) feature set anywhere in the file.
* [js-buffer-noassert](js-buffer-noassert.md) - Buffer read/write call passes noAssert=true.
* [js-client-side-open-redirect](js-client-side-open-redirect.md) - Client-side URL redirect built from tainted page-URL data.
* [js-code-injection](js-code-injection.md) - No code injection via a JS/Node dynamic-evaluation sink fed request-derived content.
* [js-command-injection](js-command-injection.md) - No OS-command injection via a Node child_process shell sink.
* [js-cors-wildcard](js-cors-wildcard.md) - Express/Node CORS response wildcarded to any origin.
* [js-helmet-header-disabled](js-helmet-header-disabled.md) - Helmet security-header protection explicitly disabled.
* [js-host-header-email-link](js-host-header-email-link.md) - Host header used to build a link in an outgoing email.
* [js-http-to-file-access](js-http-to-file-access.md) - HTTP response data written directly to the filesystem.
* [js-insecure-download-sensitive-file](js-insecure-download-sensitive-file.md) - HTTP/FTP download URL for an executable or other sensitive file type.
* [js-loop-bound-injection](js-loop-bound-injection.md) - Loop bound taken directly from a user-controlled .length.
* [js-path-traversal](js-path-traversal.md) - No path traversal in JS/Node fs calls.
* [js-private-file-exposure](js-private-file-exposure.md) - Static-file-serving middleware configured to serve a private directory.
* [js-prototype-pollution](js-prototype-pollution.md) - Prototype-polluting property assignment.
* [js-regex-injection-dos](js-regex-injection-dos.md) - User-controlled input used to construct a regular expression.
* [js-secure-cookies](js-secure-cookies.md) - Express cookies set with HttpOnly + Secure (+ SameSite).
* [js-security-headers-absent](js-security-headers-absent.md) - Express app sets no security response headers.
* [js-server-side-open-redirect](js-server-side-open-redirect.md) - Server-side redirect target built from request input (open redirect).
* [js-sql-injection](js-sql-injection.md) - JS/Node interpolated SQL query string.
* [js-ssrf](js-ssrf.md) - JS/Node HTTP client call with a request-derived URL (SSRF).
* [js-supply-chain](js-supply-chain.md) - JS/TS dependency supply-chain hardening (lockfile, cooldown, scripts, pinning, registry).
* [js-system-prompt-injection](js-system-prompt-injection.md) - Tainted input flows into a JS/TS LLM system-role prompt.
* [js-weak-crypto](js-weak-crypto.md) - No weak / broken cryptography (JS/TS).
* [js-xxe-unsafe-parsing](js-xxe-unsafe-parsing.md) - XML parsed with libxmljs noent:true (XXE).
* [jsx-href-scheme](jsx-href-scheme.md) - JSX href/action set to unsanitized dynamic URL (javascript: XSS).
* [jwt-alg](jwt-alg.md) - JWT decoded without a pinned algorithm (alg-confusion risk).
* [jwt-claims-validated](jwt-claims-validated.md) - JWT decode disables a required claim check (exp/aud/iss/signature).
* [jwt-exp-too-long](jwt-exp-too-long.md) - JWT access-token lifetime exceeds 24 hours.
* [jwt-key-source-allowlist](jwt-key-source-allowlist.md) - JWT verification key sourced from an unverified token header (jku/x5u/jwk).
* [k8s-allow-privilege-escalation](k8s-allow-privilege-escalation.md) - Kubernetes workload doesn't explicitly disable privilege escalation.
* [k8s-automount-serviceaccount-token](k8s-automount-serviceaccount-token.md) - Kubernetes workload doesn't disable service-account token automount.
* [k8s-default-namespace](k8s-default-namespace.md) - Kubernetes resource has no namespace isolation (uses the default namespace).
* [k8s-docker-sock-mount](k8s-docker-sock-mount.md) - Kubernetes workload mounts the Docker socket.
* [k8s-host-namespace-sharing](k8s-host-namespace-sharing.md) - Kubernetes workload shares a host namespace.
* [k8s-hostpath-writable-mount](k8s-hostpath-writable-mount.md) - Kubernetes hostPath volume is mounted into a container without readOnly.
* [k8s-privileged-capabilities](k8s-privileged-capabilities.md) - Kubernetes container adds a dangerous Linux capability.
* [k8s-privileged-container](k8s-privileged-container.md) - Kubernetes container runs in privileged mode.
* [k8s-rbac-anonymous-binding](k8s-rbac-anonymous-binding.md) - Kubernetes RBAC binding grants a role to the anonymous user.
* [k8s-rbac-cluster-admin-binding](k8s-rbac-cluster-admin-binding.md) - Kubernetes RBAC binding grants the built-in cluster-admin role to a subject.
* [k8s-rbac-dangerous-verb](k8s-rbac-dangerous-verb.md) - Kubernetes Role/ClusterRole grants a dangerous RBAC verb+resource combo (escalate, bind, impersonate, serviceaccount-token creation, or privileged-namespace pod modification).
* [k8s-rbac-wildcard-rule](k8s-rbac-wildcard-rule.md) - Kubernetes Role/ClusterRole grants a wildcard resources or verbs rule.
* [k8s-readonly-root-filesystem](k8s-readonly-root-filesystem.md) - Kubernetes container doesn't set a read-only root filesystem.
* [k8s-resource-limits-absent](k8s-resource-limits-absent.md) - Kubernetes container has no CPU or memory resource limit.
* [k8s-run-as-non-root](k8s-run-as-non-root.md) - Kubernetes workload doesn't require running as non-root.
* [k8s-seccomp-apparmor-unconfined](k8s-seccomp-apparmor-unconfined.md) - Kubernetes workload opts out of seccomp/AppArmor confinement.
* [k8s-unmasked-proc-mount](k8s-unmasked-proc-mount.md) - Kubernetes container disables the default masked /proc mount.
* [k8s-unsafe-sysctl](k8s-unsafe-sysctl.md) - Kubernetes workload sets an unsafe kernel sysctl.
* [keylogging-pattern](keylogging-pattern.md) - No keylogging/input-capture library wired to a persisted-output write.
* [kinesis-stream-not-encrypted](kinesis-stream-not-encrypted.md) - Kinesis data stream without server-side encryption.
* [kms-key-disabled](kms-key-disabled.md) - KMS key explicitly disabled.
* [kms-key-rotation-not-enabled](kms-key-rotation-not-enabled.md) - Customer-managed KMS key without rotation enabled.
* [langchain-load-prompt-traversal](langchain-load-prompt-traversal.md) - LangChain load_prompt path not validated (CWE-22 / CVE-2026-34070).
* [langchain-prompt-template-injection](langchain-prompt-template-injection.md) - LangChain PromptTemplate built from a dynamic template string.
* [langchain-serialization](langchain-serialization.md) - LangChain unsafe serialization — secrets_from_env=True or langchain-core loads on dynamic content.
* [langchain-unsafe-chain](langchain-unsafe-chain.md) - LangChain chain executes model output without sandboxing.
* [ldap-injection](ldap-injection.md) - LDAP query built from unescaped untrusted input.
* [lethal-trifecta](lethal-trifecta.md) - Lethal-trifecta architecture review.
* [llm-input-size-cap](llm-input-size-cap.md) - LLM call site has no max_tokens ceiling — economic DoS risk.
* [llm-json-output-unvalidated](llm-json-output-unvalidated.md) - LLM response text parsed as JSON without Pydantic schema validation.
* [llm-output-html-sink](llm-output-html-sink.md) - LLM output flows into an HTML sink — model-driven XSS.
* [llm-output-secrets-unscanned](llm-output-secrets-unscanned.md) - LLM-generated output flows to a file-write or git-commit sink with no secret scan in between.
* [llm-output-to-sink](llm-output-to-sink.md) - LLM output flows into a code/command sink — model-driven RCE.
* [llm-query-engine-execution](llm-query-engine-execution.md) - LLM-driven SQL/code-execution query engine instantiated with no visible safeguard.
* [llm-rate-limit-absent](llm-rate-limit-absent.md) - LLM-backed route has no rate-limiting protection.
* [llm-response-logged](llm-response-logged.md) - LLM model response logged directly without redaction.
* [llm-tool-dynamic-dispatch](llm-tool-dynamic-dispatch.md) - LLM-selectable dynamic function dispatch via globals()/getattr() reflection.
* [llm-tool-result-leak](llm-tool-result-leak.md) - Exception or traceback stringified into an LLM tool-result return.
* [log-injection](log-injection.md) - User-supplied request value interpolated into a log call (CRLF injection risk).
* [markdown-render-xss](markdown-render-xss.md) - LLM output rendered as executable HTML without sanitization.
* [mass-assignment](mass-assignment.md) - ORM/SQLAlchemy model updated from full request dict without an explicit field allowlist.
* [matview-exposed](matview-exposed.md) - Public-schema materialized view has no schema-move or REVOKE mitigating its Data API exposure.
* [mcp-apps-ui-isolation](mcp-apps-ui-isolation.md) - An MCP Apps (SEP-1865) UI resource iframe is rendered with no hardening sandbox attribute.
* [mcp-config-security](mcp-config-security.md) - MCP server configuration contains dangerous misconfigurations.
* [mcp-env-placeholder-exfil](mcp-env-placeholder-exfil.md) - MCP server resolves ${VAR} placeholders in user-supplied config against its own process environment.
* [mcp-hardcoded-credential](mcp-hardcoded-credential.md) - MCP server source hardcodes a credential-shaped variable as a literal.
* [mcp-marketplace-fetch-stdio-spawn](mcp-marketplace-fetch-stdio-spawn.md) - A network fetch feeds directly into an MCP stdio server spawn in the same function.
* [mcp-noauth-default](mcp-noauth-default.md) - MCP server ships an auth check that fails open, or is unauthenticated by default.
* [mcp-oauth-flow-hardening](mcp-oauth-flow-hardening.md) - An MCP OAuth 2.1 client flow is missing PKCE, forwards tokens, or doesn't conform to the 2026-07-28 auth profile.
* [mcp-oauth-scope-creep](mcp-oauth-scope-creep.md) - An MCP server's OAuth config grants a broad/wildcard scope, or uses a dangerous authorization-URL scheme.
* [mcp-overprivileged-scope](mcp-overprivileged-scope.md) - MCP server source declares an unrestricted filesystem root or allowed-hosts scope.
* [mcp-raw-execution-tool-name](mcp-raw-execution-tool-name.md) - An MCP tool's own declared name is a raw code/command-execution primitive (eval/exec/system/subprocess/run_shell).
* [mcp-routing-desync](mcp-routing-desync.md) - MCP SEP-2243 routable header (Mcp-Method/Mcp-Name) used for routing with no cross-check against the JSON-RPC body method.
* [mcp-sampling-no-consent](mcp-sampling-no-consent.md) - MCP sampling capability wired up with no consent/elicitation gate anywhere in the repo.
* [mcp-sandbox-self-disable](mcp-sandbox-self-disable.md) - A tool/function JSON schema exposes an LLM-settable parameter that disables or weakens sandboxing.
* [mcp-server-card-integrity](mcp-server-card-integrity.md) - A remote MCP Server Card makes contradictory, unsigned, or over-broad trust claims a client would trust before connecting.
* [mcp-session-id-security](mcp-session-id-security.md) - MCP session identifier is predictable or used as sole authorization.
* [mcp-ssrf-unvalidated-destination](mcp-ssrf-unvalidated-destination.md) - MCP-reachable destination (a tool-handler URL argument, or an MCP-config server/webhook URL) reaches an outbound fetch with no host/scheme validation.
* [mcp-stateless-migration](mcp-stateless-migration.md) - Server/client code assumes the pre-2026-07-28 stateful MCP protocol, which the ratified spec removes.
* [mcp-stdio-no-sanitizer](mcp-stdio-no-sanitizer.md) - MCP server uses the SDK's STDIO transport with no argv sanitizer, allow-list, or opt-out anywhere in the repo.
* [mcp-tasks-lifecycle](mcp-tasks-lifecycle.md) - An MCP Tasks primitive is missing an owner check, retains credentials, has no TTL/cancellation, or accepts unbounded creation.
* [mcp-tool-description-injection](mcp-tool-description-injection.md) - MCP tool descriptions loaded without injection scanning.
* [mcp-tool-env-inheritance](mcp-tool-env-inheritance.md) - MCP server / agent-tool subprocess spawned with the full parent environment.
* [mcp-tool-path-traversal](mcp-tool-path-traversal.md) - An MCP tool argument or auth token reaches a filesystem path with no containment check.
* [mcp-tool-unverified](mcp-tool-unverified.md) - MCP server auto-loaded without explicit trust verification or allowlist.
* [mcp-toolgate-asymmetry](mcp-toolgate-asymmetry.md) - MCP tool gate (allowlist/read-only/non-destructive) applied in the discovery handler but absent from execution.
* [mcp-tools-list-unbounded](mcp-tools-list-unbounded.md) - MCP tool catalogue assembled from an unbounded upstream tools/list response.
* [mcp-transport-dns-rebinding](mcp-transport-dns-rebinding.md) - MCP StreamableHTTP transport exposed with no Host-header allow-list (DNS-rebinding protection).
* [mcp-transport-flip](mcp-transport-flip.md) - An MCP server config entry declares both a network transport and a stdio-launcher shape (transport-flip MITM).
* [mcp-transport-no-auth](mcp-transport-no-auth.md) - MCP server exposes an HTTP/SSE/Streamable-HTTP transport with no authentication.
* [mcp-transport-session-unauth](mcp-transport-session-unauth.md) - An MCP HTTP transport authenticates its own outbound credential but never checks an inbound one.
* [mcp-tunnel-config-security](mcp-tunnel-config-security.md) - An MCP Tunnels gateway config disables its own SSRF defense, forwards to HTTPS with no trust anchor, or leaks tunnel credentials.
* [mcp-twin-route-auth-asymmetry](mcp-twin-route-auth-asymmetry.md) - An MCP route has no auth middleware while a sibling MCP route in the same file is authenticated.
* [mcp-unsafe-auth-url-launch](mcp-unsafe-auth-url-launch.md) - MCP OAuth authorization URL opened without scheme validation or via a shell.
* [ml-artifact-committed](ml-artifact-committed.md) - Flags a binary ML model artifact (.pkl/.pt/.h5/.gguf/.onnx/...) committed directly to source control.
* [ml-gguf-template-injection](ml-gguf-template-injection.md) - Flags a committed GGUF model whose embedded Jinja chat template carries a sandbox-escape construct.
* [ml-keras-lambda-rce](ml-keras-lambda-rce.md) - Flags a committed Keras model file (.keras/.h5/.hdf5) embedding a Lambda layer or a marshalled code object.
* [ml-model-provenance](ml-model-provenance.md) - ML model downloaded or loaded without provenance verification.
* [ml-onnx-external-data](ml-onnx-external-data.md) - Flags a committed ONNX model declaring an external-data path that escapes its own directory, or an undisclosed custom operator.
* [ml-pickle-dangerous-global](ml-pickle-dangerous-global.md) - Flags a committed pickle-family model file whose opcode stream imports a dangerous global (os.system, subprocess.Popen, ...).
* [msk-cluster-transit-encryption-disabled](msk-cluster-transit-encryption-disabled.md) - MSK cluster allows plaintext broker traffic.
* [multi-agent-prompt-origin](multi-agent-prompt-origin.md) - Multi-agent pipeline forwards LLM output without trust-boundary marking.
* [next-api-route-auth-missing](next-api-route-auth-missing.md) - Next.js Route Handler with no auth check.
* [next-public-client-secret](next-public-client-secret.md) - NEXT_PUBLIC_-prefixed secret exposed in client bundle.
* [next-server-action-no-auth](next-server-action-no-auth.md) - Next.js Server Action performing a mutation with no auth check.
* [no-cache-on-sensitive](no-cache-on-sensitive.md) - Sensitive route response missing Cache-Control: no-store (ASVS 14.3.2).
* [no-pan-stored](no-pan-stored.md) - Raw card number / CVV captured, stored, or logged — PCI violation.
* [node-db-driver-hardcoded-password](node-db-driver-hardcoded-password.md) - Node DB driver configured with a hardcoded password.
* [nosql-injection-js](nosql-injection-js.md) - NoSQL query filter built from unvalidated request input (Node/Mongoose).
* [nosql-metadata-injection](nosql-metadata-injection.md) - No NoSQL operator injection (Mongo $-operators from user input).
* [npm-ignore-scripts](npm-ignore-scripts.md) - npm install scripts not blocked (missing ignore-scripts=true).
* [npm-install-script-network](npm-install-script-network.md) - An npm install-lifecycle script reaches the network, or a dependency name typosquats a trusted MCP package.
* [npm-lifecycle-script-source-sinks](npm-lifecycle-script-source-sinks.md) - A JavaScript file run by an npm install-lifecycle script steals credentials, evals a string, or self-publishes.
* [obfuscated-payload-execution](obfuscated-payload-execution.md) - No obfuscated payload (base64/hex/binary-decoded) fed to an execution sink.
* [open-redirect](open-redirect.md) - No open redirect from user input.
* [opensearch-domain-encryption-disabled](opensearch-domain-encryption-disabled.md) - OpenSearch/Elasticsearch domain has an encryption control disabled.
* [overly-large-regex-range](overly-large-regex-range.md) - Overly permissive regular-expression character range.
* [paramiko-host-key-trust](paramiko-host-key-trust.md) - Paramiko SSH client implicitly trusts the server's host key.
* [path-prefix-authz-bypass](path-prefix-authz-bypass.md) - Path containment checked with a naive startswith() (sibling-directory bypass).
* [path-traversal](path-traversal.md) - No path traversal in file serving / opening.
* [payments-user-scope](payments-user-scope.md) - Stripe payment-object fetch not scoped to the authenticated user (BOLA/IDOR).
* [pdf-embedded-javascript](pdf-embedded-javascript.md) - No embedded JavaScript / auto-run action in a PDF file.
* [pg-anon-grant](pg-anon-grant.md) - GRANT to anon/public role bypasses RLS for unauthenticated callers.
* [pg-default-privileges-public](pg-default-privileges-public.md) - Default table privileges granted to PUBLIC - every future table exposed until RLS is remembered.
* [pg-extension-in-public](pg-extension-in-public.md) - PostgreSQL extension installed in public schema.
* [pg-foreign-table-exposed](pg-foreign-table-exposed.md) - Foreign table granted to a low-trust role - no RLS is possible on it, ever.
* [pg-function-immutable-reads-session](pg-function-immutable-reads-session.md) - Function marked IMMUTABLE reads session state - a reused/cached plan serves a different user's value.
* [pg-function-leakproof](pg-function-leakproof.md) - Function marked LEAKPROOF - a false promise leaks RLS-hidden row contents.
* [pg-function-search-path](pg-function-search-path.md) - SECURITY DEFINER function missing SET search_path (search_path poisoning risk).
* [pg-graphql-table-exposed](pg-graphql-table-exposed.md) - Table visible in the pg_graphql schema to anon/authenticated.
* [pg-rls-no-policy](pg-rls-no-policy.md) - RLS enabled on table but no CREATE POLICY defined — blocks all access.
* [pg-rls-not-forced](pg-rls-not-forced.md) - RLS enabled but not FORCE'd - the table owner role still bypasses every policy.
* [pg-role-bypassrls-membership](pg-role-bypassrls-membership.md) - Role can SET ROLE to a BYPASSRLS role - an RLS-bypass path invisible from its own attributes.
* [pg-role-bypassrls](pg-role-bypassrls.md) - Role granted BYPASSRLS - skips every RLS policy, cluster-wide.
* [pg-security-definer-view](pg-security-definer-view.md) - View created without SECURITY INVOKER — bypasses caller RLS.
* [pg-ssl-required](pg-ssl-required.md) - PostgreSQL connection requires SSL.
* [pgmq-queue-exposed-in-api](pgmq-queue-exposed-in-api.md) - Supabase pgmq message queue exposed via the Data API.
* [php-code-injection](php-code-injection.md) - No PHP code injection via a non-literal eval()/assert()/create_function()/backtick sink.
* [php-command-injection](php-command-injection.md) - No PHP OS-command injection via system()/exec()/passthru()/popen()/shell_exec()/proc_open() called with a tainted argument.
* [php-extract-superglobal-overwrite](php-extract-superglobal-overwrite.md) - No extract() call directly on a request superglobal — arbitrary local-variable overwrite from user input.
* [php-file-inclusion](php-file-inclusion.md) - No PHP local/remote file inclusion (LFI/RFI) via tainted include/require or dangerous stream wrappers.
* [php-preg-replace-eval-modifier](php-preg-replace-eval-modifier.md) - No preg_replace() call using the deprecated /e (eval) modifier.
* [php-reflected-xss](php-reflected-xss.md) - No reflected XSS via a superglobal echoed/printed directly with no escaping call in the same statement.
* [php-sql-injection](php-sql-injection.md) - No PHP SQL query built by concatenation into mysql_query()/mysqli_query()/pg_query()/->query().
* [php-tls-verify-disabled](php-tls-verify-disabled.md) - No PHP cURL call disabling TLS certificate verification (CURLOPT_SSL_VERIFYHOST/VERIFYPEER).
* [php-unsafe-deserialization](php-unsafe-deserialization.md) - No unserialize() call on data that is not a hardcoded string literal.
* [pii-llm-roundtrip](pii-llm-roundtrip.md) - PII sent to an LLM and the response returned to the client with no redaction layer.
* [plugin-security](plugin-security.md) - LLM tool/plugin definition missing security controls.
* [policy-exists-rls-disabled](policy-exists-rls-disabled.md) - RLS policy defined but RLS not enabled — the policy is inert, the table is open.
* [policy-no-role-scope](policy-no-role-scope.md) - CREATE POLICY with no TO clause (or TO public) is graded by its predicate: HIGH when anon can reach rows, LOW hygiene when the predicate already scopes them.
* [policy-truncation](policy-truncation.md) - A deny/allow policy is evaluated against a truncated command while the full, untruncated command reaches the spawn call.
* [postmessage-origin](postmessage-origin.md) - postMessage handler missing origin validation.
* [privileged-field-assignment](privileged-field-assignment.md) - Privileged field written from request body with no caller-privilege check.
* [prompt-string-interp](prompt-string-interp.md) - User input directly interpolated into an LLM prompt via f-string.
* [proxy-tls-hardening](proxy-tls-hardening.md) - Reverse-proxy TLS not hardened (weak protocols / no HTTPS redirect).
* [public-table-rls](public-table-rls.md) - Exposed-schema table created without RLS.
* [pydantic-model-construct](pydantic-model-construct.md) - Pydantic model_construct() bypasses all field validators.
* [python-supply-chain](python-supply-chain.md) - Python (uv) dependency supply-chain hardening (lockfile + hashes + cooldown).
* [rag-isolation](rag-isolation.md) - RAG retrieval missing a similarity threshold or a per-tenant vector namespace.
* [rag-no-instruction-filter](rag-no-instruction-filter.md) - RAG retrieved content used in LLM prompt without active injection filtering.
* [rag-scoped-retrieval](rag-scoped-retrieval.md) - Unscoped RAG retrieval in a likely multi-tenant app.
* [rag-trust-boundary](rag-trust-boundary.md) - Retrieved RAG content reaches an LLM call without trust-boundary wrapping.
* [rate-limit-no-persistent-store](rate-limit-no-persistent-store.md) - Rate limiter has no persistent (Redis) storage backend, so limits reset and desync across worker processes.
* [rate-limit-no-user-key](rate-limit-no-user-key.md) - Rate limiter keyed only on IP address — bypassed by botnet/proxy rotation.
* [rds-backup-retention-too-short](rds-backup-retention-too-short.md) - RDS/Aurora backup retention period is too short or unset.
* [rds-publicly-accessible](rds-publicly-accessible.md) - RDS instance directly reachable from the internet.
* [rds-storage-not-encrypted](rds-storage-not-encrypted.md) - RDS instance without encryption at rest.
* [react-native-insecure-token-storage](react-native-insecure-token-storage.md) - Authentication token stored in AsyncStorage (React Native / Expo).
* [redis-glob-pattern-injection](redis-glob-pattern-injection.md) - Redis KEYS/SCAN glob pattern built from untrusted input.
* [redos](redos.md) - No catastrophic-backtracking regex (ReDoS).
* [refresh-token-plaintext](refresh-token-plaintext.md) - Refresh token written to database without hashing.
* [regex-html-sanitizer](regex-html-sanitizer.md) - Hand-rolled HTML tag-stripping via a wildcard regex.
* [request-body-size-unbounded](request-body-size-unbounded.md) - FastAPI route with a Pydantic-model request body and no size cap.
* [request-model-extra-forbid](request-model-extra-forbid.md) - FastAPI request models forbid unknown fields (mass-assignment).
* [response-model-set](response-model-set.md) - Route returns a raw DB object with no response_model — over-exposes every column.
* [reverse-shell-pattern](reverse-shell-pattern.md) - No reverse-shell pattern in source (bash /dev/tcp, netcat -e, Python socket+pty).
* [rls-anon-write-access](rls-anon-write-access.md) - Permissive policy grants the anon role write access - unauthenticated data tampering.
* [rls-auth-email-lockout](rls-auth-email-lockout.md) - RLS policy gates on auth.email() - email-change / case / plus-addressing silent lockout.
* [rls-auth-role-unknown-literal](rls-auth-role-unknown-literal.md) - Policy compares auth.role() to a role name it never returns - a lockout when equal, admit-all when negated.
* [rls-auth-uid-unwrapped](rls-auth-uid-unwrapped.md) - auth.uid()/auth.jwt() called unwrapped inside an RLS policy's USING/WITH CHECK clause, re-evaluated once per row instead of once per statement.
* [rls-auth-users-unbound-exists](rls-auth-users-unbound-exists.md) - Policy EXISTS-checks auth.users with no caller binding - passes for every authenticated user if anyone matches.
* [rls-current-setting-unqualified](rls-current-setting-unqualified.md) - Policy's current_setting() names an unqualified parameter - likely a dropped app-namespace prefix.
* [rls-current-user-tenant-key](rls-current-user-tenant-key.md) - RLS policy keys row visibility off current_user/session_user - no isolation over a pooled connection.
* [rls-fkey-to-auth-non-primary](rls-fkey-to-auth-non-primary.md) - Foreign key into the auth schema references a non-primary-key column.
* [rls-hardcoded-tenant-literal](rls-hardcoded-tenant-literal.md) - RLS policy pins an identity column to a hardcoded literal, not a per-request value.
* [rls-inverted-auth-check](rls-inverted-auth-check.md) - RLS policy has an inverted auth check (auth function IS NULL OR ...) - anonymous callers hit a NULL short-circuit.
* [rls-multiple-permissive-policies](rls-multiple-permissive-policies.md) - Multiple permissive RLS policies on one table — access is the union.
* [rls-no-user-metadata-claim](rls-no-user-metadata-claim.md) - RLS policy gates on the editable user_metadata claim — trivial privilege escalation.
* [rls-partition-inherits-bypass](rls-partition-inherits-bypass.md) - Partition/inheritance child bypasses the parent's RLS when queried directly.
* [rls-pattern-match-auth-context](rls-pattern-match-auth-context.md) - RLS policy pattern-matches a column against an auth-context value - a wildcard session value bypasses it.
* [rls-permissive-policy](rls-permissive-policy.md) - Permissive RLS policy (USING true) authorizes everyone.
* [rls-realtime-published-no-rls](rls-realtime-published-no-rls.md) - Table published to Realtime with RLS disabled - every change broadcast unfiltered.
* [rls-restrictive-only](rls-restrictive-only.md) - Table has only RESTRICTIVE policies - silent deny-all.
* [rls-update-privileged-column](rls-update-privileged-column.md) - Self-update RLS policy lets the owner write privileged columns.
* [ruby-command-injection](ruby-command-injection.md) - No OS-command injection via a Ruby shell sink built from a dynamic command string.
* [ruby-dangerous-dispatch](ruby-dangerous-dispatch.md) - No dynamic method dispatch (send/__send__/public_send/try) with a non-literal, attacker-influenceable method name in Ruby.
* [ruby-mass-assignment](ruby-mass-assignment.md) - Rails mass-assignment: Strong Parameters disabled with permit!, or a model written straight from raw request params.
* [ruby-sql-injection](ruby-sql-injection.md) - Rails/ActiveRecord raw SQL built from Ruby string interpolation instead of bind parameters.
* [ruby-tls-verify-disabled](ruby-tls-verify-disabled.md) - TLS certificate verification disabled in Ruby HTTP/OpenSSL clients via OpenSSL::SSL::VERIFY_NONE.
* [ruby-unsafe-deserialization](ruby-unsafe-deserialization.md) - No unsafe deserialization of untrusted data (Marshal / YAML.load / Oj object mode) in Ruby code.
* [ruby-unsafe-reflection](ruby-unsafe-reflection.md) - No dynamic Ruby class reflection (constantize/const_get) driven by a non-literal, attacker-influenceable name.
* [ruby-weak-crypto](ruby-weak-crypto.md) - No weak / broken hash algorithm in Ruby application code.
* [s3-bucket-canned-acl](s3-bucket-canned-acl.md) - S3 bucket AccessControl is not set to a public canned ACL (PublicRead/PublicReadWrite).
* [s3-bucket-insecure-transport-allowed](s3-bucket-insecure-transport-allowed.md) - S3 bucket policy does not deny insecure (non-TLS) transport.
* [s3-bucket-policy-wildcard-principal](s3-bucket-policy-wildcard-principal.md) - Resource policy grants an action to any AWS principal (S3 bucket / KMS key).
* [s3-mfa-delete-disabled](s3-mfa-delete-disabled.md) - S3 bucket versioning does not require MFA for object deletion.
* [s3-public-access-block-disabled](s3-public-access-block-disabled.md) - S3 public-access-block control not enforced.
* [sagemaker-notebook-not-encrypted](sagemaker-notebook-not-encrypted.md) - SageMaker notebook instance without a customer-managed encryption key.
* [sandbox-denylist-bypass](sandbox-denylist-bypass.md) - A code-execution sandbox's deny-list omits attribute-lookup/introspection bypass primitives.
* [secret-in-url-query](secret-in-url-query.md) - Secret passed as a URL query parameter (logs, history, Referer exposure).
* [secret-str-serialized](secret-str-serialized.md) - Pydantic SecretStr field leaked via serialization into a log/APM sink.
* [secrets-manager-default-kms](secrets-manager-default-kms.md) - Secrets Manager secret without a customer-managed KMS key.
* [security-headers](security-headers.md) - FastAPI app sets no security response headers.
* [sensitive-columns](sensitive-columns.md) - Sensitive-named column (password/ssn/api_key/credit_card/…) declared in a public-schema table, exposed via the Supabase Data API by definition.
* [sensitive-logging](sensitive-logging.md) - Sensitive data written to the logger.
* [service-role-key](service-role-key.md) - Supabase service_role key exposed client-side.
* [session-fixation-no-regenerate](session-fixation-no-regenerate.md) - Login route writes session without regenerating it first — session fixation.
* [session-no-csrf](session-no-csrf.md) - SessionMiddleware used without CSRF protection.
* [setup-network-call](setup-network-call.md) - setup.py performs a network call at module top level or in a cmdclass command's run(), running on every pip install/build from source.
* [sfn-observability](sfn-observability.md) - Step Functions state machine missing execution logging or X-Ray tracing.
* [shared-resource-authz](shared-resource-authz.md) - A tool exposes a mutating operation on a shared/multi-agent resource with no per-actor authorization field.
* [skill-poisoning](skill-poisoning.md) - A SKILL.md file carries a poisoning shape — post-install command, exfiltration, trusted-name typosquat, or a hidden instruction.
* [skill-untrusted-exec-path](skill-untrusted-exec-path.md) - Install/skill-setup code resolves an executable from a workspace-controlled source with no absolute-path pin.
* [slopsquatting](slopsquatting.md) - Package name confusion or TLS bypass in dependency installation.
* [sns-topic-not-encrypted](sns-topic-not-encrypted.md) - SNS topic without encryption at rest.
* [sql-race-check-then-insert](sql-race-check-then-insert.md) - Check-then-insert with no lock/conflict guard — static TOCTOU race shape.
* [sqlalchemy-text-parameterized](sqlalchemy-text-parameterized.md) - String-built SQL in text()/execute() — SQL injection.
* [sqs-queue-not-encrypted](sqs-queue-not-encrypted.md) - SQS queue without customer-managed KMS encryption.
* [ssh-allowlist-absent](ssh-allowlist-absent.md) - SSH access not restricted to an AllowUsers/AllowGroups allowlist.
* [sshd-hardening](sshd-hardening.md) - SSH daemon not hardened (password / root login / pubkey).
* [ssrf-bracketed-ipv6-bypass](ssrf-bracketed-ipv6-bypass.md) - A JS/TS SSRF guard classifies a hostname without normalizing the brackets WHATWG keeps on an IPv6 literal.
* [ssrf-dns-rebind-toctou](ssrf-dns-rebind-toctou.md) - An SSRF allow-list resolves a hostname once to validate it, then a separate fetch call re-resolves the same hostname.
* [ssrf-general](ssrf-general.md) - No SSRF from a user-controlled fetch URL.
* [ssrf-ipv6-bypass](ssrf-ipv6-bypass.md) - SSRF IPv6-mapped bypass — ipv4_mapped not checked alongside is_private/is_loopback.
* [ssrf-redirect-bypass](ssrf-redirect-bypass.md) - An SSRF allow-list check fires once on a caller's URL, then a fetch call follows a redirect past it.
* [ssti](ssti.md) - No server-side template injection.
* [staticfiles-broad-mount](staticfiles-broad-mount.md) - StaticFiles mounted at project root or filesystem root — exposes source code and secrets.
* [storage-no-rls](storage-no-rls.md) - Private-looking Supabase storage bucket has no storage.objects RLS policy referencing it.
* [string-format-injection](string-format-injection.md) - User input injected into LLM prompt via .format() or % operator.
* [stripe-payments](stripe-payments.md) - Stripe payments hygiene.
* [supabase-anon-key-rls-reachable](supabase-anon-key-rls-reachable.md) - RLS-disabled table confirmed reachable via a working client-side Supabase connection.
* [supabase-filter-injection](supabase-filter-injection.md) - Unparameterized Supabase/PostgREST filter built from untrusted input.
* [supabase-storage-public](supabase-storage-public.md) - Supabase storage bucket configured as public (unauthenticated read access).
* [supabase-vault-exposure](supabase-vault-exposure.md) - Supabase Vault material is reachable by anon or authenticated through a vault-reading SECURITY DEFINER function, a decrypted view, or a DROP and re-CREATE that resets an ACL.
* [supabase-vault-plaintext-leak](supabase-vault-plaintext-leak.md) - Supabase Vault exposure a schema dump cannot vouch for: a literal secret committed in SQL, statement logging on in a vault repo, the vault schema in the Data API's exposed-schema list, or a grant on the vault schema itself.
* [svg-embedded-script](svg-embedded-script.md) - No embedded script / event handler / javascript: URI in an SVG file.
* [system-prompt-exposure](system-prompt-exposure.md) - System prompt exposed via code-level pattern.
* [system-prompt-leak](system-prompt-leak.md) - System prompt defined with no leak-filter on model output.
* [target-blank-noopener](target-blank-noopener.md) - Anchor target="_blank" missing rel="noopener noreferrer".
* [terraform-hardcoded-secret-literal](terraform-hardcoded-secret-literal.md) - Hardcoded credential literal in a Terraform resource attribute.
* [tls-verify-disabled](tls-verify-disabled.md) - Outbound HTTP client TLS certificate verification disabled.
* [token-in-localstorage](token-in-localstorage.md) - Authentication token stored in localStorage / sessionStorage.
* [tool-callback-enforcement](tool-callback-enforcement.md) - LLM agent or tool missing confirmation callback for dangerous operations.
* [tool-chaining-exfil](tool-chaining-exfil.md) - Agent exposes both a sensitive-read tool and an external-send tool (tool-chaining exfiltration).
* [trust-boundary](trust-boundary.md) - A Claude Code settings.json misconfigures the tool-permission or MCP-server trust boundary.
* [trusted-host-absent](trusted-host-absent.md) - FastAPI app running without TrustedHostMiddleware.
* [truthy-ownership-check](truthy-ownership-check.md) - Ownership-scoping filter skipped on a falsy caller id (possible IDOR).
* [unauthenticated-file-download](unauthenticated-file-download.md) - File-download/export route with no authorization signal.
* [unawaited-async-truthy](unawaited-async-truthy.md) - No unawaited async function call used as a truthy conditional (if/while).
* [unrestricted-file-upload](unrestricted-file-upload.md) - Upload saved under the client-supplied filename — path traversal + dangerous-type write.
* [unsafe-deserialization](unsafe-deserialization.md) - No unsafe deserialization of untrusted data.
* [untrusted-package-install-source](untrusted-package-install-source.md) - No package installed directly from a URL/git ref instead of the registry.
* [upload-no-size-limit](upload-no-size-limit.md) - UploadFile route without a file size limit (memory-exhaustion DoS).
* [upstream-response-unvalidated](upstream-response-unvalidated.md) - Upstream API response used without schema validation.
* [vite-client-secret](vite-client-secret.md) - VITE_-prefixed secret exposed in client bundle.
* [vite-sourcemap-prod](vite-sourcemap-prod.md) - Vite build sourcemaps enabled - exposes source to production users.
* [vscode-tasks-auto-exec](vscode-tasks-auto-exec.md) - VSCode task auto-executes on folder open with no user confirmation.
* [weak-crypto](weak-crypto.md) - No weak / broken cryptography.
* [weak-password-length-check](weak-password-length-check.md) - Weak minimum password length check.
* [weak-secret-key-literal](weak-secret-key-literal.md) - SECRET_KEY set to a known-weak or default literal value.
* [webhook-idempotency](webhook-idempotency.md) - Stripe webhook handler missing event.id deduplication (replay / double-fulfillment risk).
* [webhook-signature-not-verified](webhook-signature-not-verified.md) - Webhook handler does not verify the sender's signature.
* [websocket-no-auth](websocket-no-auth.md) - WebSocket endpoint without authentication dependency.
* [websocket-origin](websocket-origin.md) - WebSocket accept() without cross-origin validation (CSWSH risk).
* [xpath-injection](xpath-injection.md) - XPath expression built from untrusted input.
* [xxe-safe](xxe-safe.md) - XML parsed without defusedxml (XXE risk).
* [zip-bomb](zip-bomb.md) - Unsafe archive extraction without size/count limit — Zip Bomb (CWE-409).
* [zip-slip](zip-slip.md) - Unsafe .extractall() without path validation — Zip Slip (CWE-22).
