# Backup and Restore

This guide covers backup and restore procedures for agentsh deployments.

## What to Backup

### Critical (Required)

These files are essential for system operation and must be backed up:

- **Audit database**: `<audit.storage.sqlite_path>` (default: `/var/lib/agentsh/events.db`)
  - Contains all audit events and integrity chain state
  - Loss means complete audit history is gone

- **Configuration**: `/etc/agentsh/config.yaml`
  - Main configuration file
  - Contains all runtime settings

- **Policies**: `<policies.dir>` (default: `/etc/agentsh/policies/`)
  - File policies, network policies, approval rules
  - Loss means reverting to default (permissive) behavior

### Important (Recommended)

These files should be backed up but require special handling:

- **Encryption keys**: `<audit.encryption.key_file>` and `<audit.integrity.key_file>`
  - **WARNING**: Store separately from data backups
  - Use secure key management (HashiCorp Vault, AWS Secrets Manager, etc.)
  - Without these, encrypted audit logs cannot be decrypted
  - Without integrity key, audit chain cannot be verified

- **MCP tool pins**: `~/.agentsh/mcp-pins.json`
  - Pinned tool versions for reproducibility
  - Loss means tools may update unexpectedly

### Optional

These files are typically not backed up:

- **Session data**: `<sessions.base_dir>`
  - Ephemeral by design
  - Sessions are short-lived and recreated as needed

- **Application logs**: `/var/log/agentsh/`
  - Useful for debugging but not critical
  - Consider log aggregation instead of backup

## Backup Procedures

### Manual Backup

For systems without the CLI backup command or for custom backup workflows:

```bash
# Stop agentsh (optional, for consistency)
systemctl stop agentsh

# Create backup directory with date
BACKUP_DIR="/backup/agentsh/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup audit database (most critical)
cp /var/lib/agentsh/events.db "$BACKUP_DIR/"

# Backup configuration
cp /etc/agentsh/config.yaml "$BACKUP_DIR/"

# Backup policies directory
cp -r /etc/agentsh/policies/ "$BACKUP_DIR/"

# Create compressed archive
tar -czf "$BACKUP_DIR.tar.gz" -C /backup/agentsh "$(date +%Y%m%d)"

# Clean up uncompressed directory (optional)
rm -rf "$BACKUP_DIR"

# Restart agentsh
systemctl start agentsh

# Verify backup integrity
tar -tzf "$BACKUP_DIR.tar.gz"
```

### Using agentsh CLI (Recommended)

The CLI provides automated backup with built-in verification:

```bash
# Full backup with default filename
agentsh backup --output /backup/agentsh-$(date +%Y%m%d).tar.gz

# Backup with verification
agentsh backup --output /backup/agentsh.tar.gz --verify

# Backup with custom config path
agentsh backup --output /backup/agentsh.tar.gz --config /custom/path/config.yaml
```

**Note**: CLI backup commands are placeholders pending Task 8 implementation.

### Backup to Remote Storage

For production environments, backups should be stored remotely:

```bash
# Backup and upload to S3
agentsh backup --output /tmp/backup.tar.gz --verify
aws s3 cp /tmp/backup.tar.gz s3://my-bucket/agentsh-backups/$(date +%Y%m%d).tar.gz
rm /tmp/backup.tar.gz

# Backup and upload to GCS
agentsh backup --output /tmp/backup.tar.gz --verify
gsutil cp /tmp/backup.tar.gz gs://my-bucket/agentsh-backups/$(date +%Y%m%d).tar.gz
rm /tmp/backup.tar.gz
```

## Restore Procedures

### Manual Restore

```bash
# Stop agentsh
systemctl stop agentsh

# Create restore staging directory
mkdir -p /tmp/restore

# Extract backup
tar -xzf /backup/agentsh-20260106.tar.gz -C /tmp/restore/

# Verify extracted contents
ls -la /tmp/restore/

# Restore audit database
cp /tmp/restore/events.db /var/lib/agentsh/

# Restore configuration
cp /tmp/restore/config.yaml /etc/agentsh/

# Restore policies
cp -r /tmp/restore/policies/ /etc/agentsh/

# Fix permissions
chown -R agentsh:agentsh /var/lib/agentsh/
chown -R root:agentsh /etc/agentsh/
chmod 640 /etc/agentsh/config.yaml

# Clean up staging directory
rm -rf /tmp/restore

# Start agentsh
systemctl start agentsh

# Verify audit chain integrity
agentsh audit verify --key-file /etc/agentsh/audit-integrity.key /var/log/agentsh/audit.jsonl
```

### Using agentsh CLI

```bash
# Restore with verification
agentsh restore --input /backup/agentsh.tar.gz --verify

# Dry-run (show what would be restored without making changes)
agentsh restore --input /backup/agentsh.tar.gz --dry-run
```

### Partial Restore

To restore only specific components:

```bash
# Extract to staging
tar -xzf /backup/agentsh.tar.gz -C /tmp/restore/

# Restore only policies
cp -r /tmp/restore/policies/ /etc/agentsh/

# Restore only audit database
cp /tmp/restore/events.db /var/lib/agentsh/

# Reload agentsh to pick up changes
systemctl reload agentsh
```

## Backup Schedule Recommendations

| Environment | Frequency | Retention | Off-site Copy |
|-------------|-----------|-----------|---------------|
| Development | Weekly | 2 weeks | Optional |
| Staging | Daily | 1 month | Weekly |
| Production | Hourly | 90 days | Daily |

### Cron Examples

```bash
# Development: Weekly backup on Sundays at 2 AM
0 2 * * 0 /usr/local/bin/agentsh backup --output /backup/agentsh-$(date +\%Y\%m\%d).tar.gz

# Staging: Daily backup at 3 AM
0 3 * * * /usr/local/bin/agentsh backup --output /backup/agentsh-$(date +\%Y\%m\%d).tar.gz

# Production: Hourly backup
0 * * * * /usr/local/bin/agentsh backup --output /backup/agentsh-$(date +\%Y\%m\%d-\%H).tar.gz
```

### Retention Script

```bash
#!/bin/bash
# cleanup-backups.sh - Remove backups older than retention period

BACKUP_DIR="/backup"
RETENTION_DAYS=90

find "$BACKUP_DIR" -name "agentsh-*.tar.gz" -mtime +$RETENTION_DAYS -delete
```

## Encryption Key Backup

**Critical**: Encryption keys must be backed up separately and securely. Never store keys alongside data backups.

### Why Separate Key Backup?

- If an attacker obtains your data backup, they cannot decrypt it without keys
- Keys change less frequently than data, enabling different backup strategies
- Key loss is catastrophic - encrypted data becomes permanently inaccessible

### Recommended: External Secret Manager

```bash
# HashiCorp Vault
vault kv put secret/agentsh/keys \
  integrity_key=@/etc/agentsh/audit-integrity.key \
  encryption_key=@/etc/agentsh/audit.key

# To retrieve during restore
vault kv get -field=integrity_key secret/agentsh/keys > /etc/agentsh/audit-integrity.key
vault kv get -field=encryption_key secret/agentsh/keys > /etc/agentsh/audit.key
chmod 600 /etc/agentsh/audit-integrity.key /etc/agentsh/audit.key
```

```bash
# AWS Secrets Manager
aws secretsmanager create-secret \
  --name agentsh/integrity-key \
  --secret-binary fileb:///etc/agentsh/audit-integrity.key

aws secretsmanager create-secret \
  --name agentsh/encryption-key \
  --secret-binary fileb:///etc/agentsh/audit.key

# To retrieve during restore
aws secretsmanager get-secret-value --secret-id agentsh/integrity-key \
  --query SecretBinary --output text | base64 -d > /etc/agentsh/audit-integrity.key
```

### Alternative: Encrypted Key Backup

If using external secret managers is not possible:

```bash
# Encrypt keys with GPG before backup
gpg --symmetric --cipher-algo AES256 -o /secure-backup/audit-keys.gpg \
  <(tar -c /etc/agentsh/audit-integrity.key /etc/agentsh/audit.key)

# Store GPG passphrase in a separate, secure location
# Consider using hardware security modules (HSM) for high-security environments
```

### Key Rotation Backup

When rotating keys:

1. Backup old keys before rotation
2. Generate and deploy new keys
3. Re-encrypt existing data if required
4. Update key backups in secret manager
5. Verify both old and new keys are recoverable

## Troubleshooting

### Backup Fails with Permission Denied

```bash
# Ensure backup user has read access to agentsh files
sudo chmod 640 /var/lib/agentsh/events.db
sudo chown root:backup /var/lib/agentsh/events.db
```

### Restore Fails with Integrity Verification Error

1. Ensure you are using the correct integrity key
2. Check if the backup was created with integrity enabled
3. Verify the backup file is not corrupted (check tar contents)

```bash
# Test backup file integrity
gzip -t /backup/agentsh.tar.gz && echo "Backup file OK"

# List contents without extracting
tar -tzf /backup/agentsh.tar.gz
```

### Audit Chain Broken After Restore

If the audit chain fails verification after restore:

1. This may indicate tampering or a partial restore
2. Compare the restored database with other backup copies
3. If using replication, compare with replicas
4. Document the incident and investigate the cause
