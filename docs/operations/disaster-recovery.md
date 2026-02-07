# Disaster Recovery

This guide provides disaster recovery procedures for agentsh deployments.

## Recovery Time Objectives

The following table defines recovery targets by scenario:

| Scenario | RTO (Recovery Time Objective) | RPO (Recovery Point Objective) | Priority |
|----------|-------------------------------|--------------------------------|----------|
| Server failure | 1 hour | Last backup | High |
| Data corruption | 2 hours | Last verified backup | High |
| Configuration error | 30 minutes | Last known good config | Medium |
| Complete site loss | 4 hours | Last off-site backup | Critical |
| Key compromise | 2 hours | N/A (key rotation) | Critical |

### Understanding RTO and RPO

- **RTO**: Maximum acceptable time for system to be unavailable
- **RPO**: Maximum acceptable data loss measured in time (e.g., "last hour" means up to 1 hour of data could be lost)

## Recovery Procedures

### Scenario 1: Server Failure (Same Infrastructure)

**Symptoms**: Server is unresponsive, hardware failure, OS corruption

**Recovery Steps**:

1. **Provision new server**
   ```bash
   # Provision with same OS version and specifications
   # Ensure network connectivity to same subnet
   ```

2. **Install agentsh**
   ```bash
   curl -sSL https://agentsh.io/install.sh | bash
   # Or use package manager
   apt install agentsh  # Debian/Ubuntu
   yum install agentsh  # RHEL/CentOS
   ```

3. **Restore from backup**
   ```bash
   # Download latest backup
   aws s3 cp s3://backup-bucket/agentsh-latest.tar.gz /tmp/

   # Restore using CLI
   agentsh restore --input /tmp/agentsh-latest.tar.gz
   ```

4. **Restore encryption keys from secure storage**
   ```bash
   # From HashiCorp Vault
   vault kv get -field=integrity_key secret/agentsh/keys > /etc/agentsh/audit-integrity.key
   vault kv get -field=encryption_key secret/agentsh/keys > /etc/agentsh/audit.key
   chmod 600 /etc/agentsh/audit-*.key
   ```

5. **Verify audit chain integrity**
   ```bash
   agentsh audit verify --key-file /etc/agentsh/audit-integrity.key /var/log/agentsh/audit.jsonl
   ```

6. **Start service**
   ```bash
   systemctl enable agentsh
   systemctl start agentsh
   ```

7. **Verify health**
   ```bash
   curl -s localhost:18080/health | jq .
   # Expected: {"status": "healthy", ...}
   ```

8. **Update DNS/load balancer** (if IP changed)
   ```bash
   # Update A record or load balancer target
   ```

### Scenario 2: Data Corruption

**Symptoms**: Audit verification fails, database errors, unexpected behavior

**Recovery Steps**:

1. **Stop agentsh immediately**
   ```bash
   systemctl stop agentsh
   ```

2. **Preserve corrupted data for analysis**
   ```bash
   mkdir -p /var/lib/agentsh-corrupted
   mv /var/lib/agentsh/events.db /var/lib/agentsh-corrupted/
   mv /var/log/agentsh/* /var/lib/agentsh-corrupted/
   ```

3. **Identify last known good backup**
   ```bash
   # List available backups
   aws s3 ls s3://backup-bucket/agentsh-backups/ --recursive

   # Check backup dates and select one before corruption occurred
   ```

4. **Verify backup integrity before restore**
   ```bash
   # Download candidate backup
   aws s3 cp s3://backup-bucket/agentsh-backups/20260105.tar.gz /tmp/

   # Extract and verify audit chain
   mkdir -p /tmp/verify
   tar -xzf /tmp/20260105.tar.gz -C /tmp/verify/
   agentsh audit verify --key-file /etc/agentsh/audit-integrity.key /tmp/verify/audit.jsonl

   # If verification passes, proceed with restore
   ```

5. **Restore verified backup**
   ```bash
   cp /tmp/verify/events.db /var/lib/agentsh/
   cp /tmp/verify/config.yaml /etc/agentsh/
   cp -r /tmp/verify/policies/ /etc/agentsh/
   ```

6. **Investigate corruption cause before resuming**
   - Check system logs: `journalctl -u agentsh`
   - Check disk health: `smartctl -a /dev/sda`
   - Check memory: `memtest` or `dmesg | grep -i memory`
   - Review recent changes: deployments, config updates, etc.

7. **Resume operation**
   ```bash
   systemctl start agentsh
   ```

8. **Document incident**
   - Record timeline of events
   - Root cause analysis
   - Preventive measures

### Scenario 3: Complete Site Loss

**Symptoms**: Data center outage, region failure, catastrophic event

**Recovery Steps**:

1. **Activate DR site**
   ```bash
   # Provision infrastructure in DR region
   terraform apply -var="region=us-west-2" dr-infrastructure/
   ```

2. **Retrieve off-site backups**
   ```bash
   # Backups should be in different region/provider
   aws s3 cp s3://dr-backup-bucket/agentsh-latest.tar.gz /tmp/ --region us-west-2
   ```

3. **Retrieve encryption keys from DR key storage**
   ```bash
   # Keys should be replicated to DR region
   vault kv get -field=integrity_key secret/agentsh/keys > /etc/agentsh/audit-integrity.key
   # Using DR Vault endpoint
   ```

4. **Follow Server Failure procedure** (steps 2-7 above)

5. **Update DNS to point to DR site**
   ```bash
   # Update DNS records
   # Example: Route 53 failover
   aws route53 change-resource-record-sets --hosted-zone-id ZONEID \
     --change-batch file://dns-failover.json
   ```

6. **Notify operators and users**
   - Send notification to operations team
   - Update status page
   - Communicate expected restoration time

7. **Plan primary site recovery**
   - Once primary is restored, plan data sync back
   - Consider which site becomes new primary

### Scenario 4: Key Compromise

**Symptoms**: Suspected or confirmed key exposure

**Recovery Steps**:

1. **Assess scope of compromise**
   - Which keys were exposed?
   - What data could be affected?
   - How long were keys exposed?

2. **Generate new keys immediately**
   ```bash
   # Generate new integrity key
   openssl rand -base64 32 > /etc/agentsh/audit-integrity.key.new

   # Generate new encryption key
   openssl rand -base64 32 > /etc/agentsh/audit.key.new

   chmod 600 /etc/agentsh/*.key.new
   ```

3. **If integrity key compromised**:
   - Historical audit logs may have been tampered
   - Create checkpoint marking key rotation
   - Consider audit log forensic analysis

4. **If encryption key compromised**:
   - Re-encrypt audit database with new key (not yet implemented — requires manual export and re-import of audit logs with new key)

5. **Rotate keys in production**
   ```bash
   mv /etc/agentsh/audit-integrity.key.new /etc/agentsh/audit-integrity.key
   mv /etc/agentsh/audit.key.new /etc/agentsh/audit.key

   systemctl restart agentsh
   ```

6. **Update key storage**
   ```bash
   vault kv put secret/agentsh/keys \
     integrity_key=@/etc/agentsh/audit-integrity.key \
     encryption_key=@/etc/agentsh/audit.key
   ```

7. **Document and report**
   - Record incident timeline
   - File security incident report
   - Review access controls

## Verification Checklist

After any recovery, complete this checklist before declaring recovery successful:

### Service Health

- [ ] Service starts without errors: `systemctl status agentsh`
- [ ] Health endpoint returns 200: `curl -s localhost:18080/health`
- [ ] No errors in logs: `journalctl -u agentsh --since "5 minutes ago"`

### Audit Integrity

- [ ] Audit log integrity verified:
  ```bash
  agentsh audit verify --key-file /etc/agentsh/audit-integrity.key /var/log/agentsh/audit.jsonl
  ```
- [ ] Recent events are present and readable
- [ ] Encryption/decryption working (if enabled)

### Policy and Configuration

- [ ] Policies loaded correctly: `agentsh policy list`
- [ ] Configuration values correct: `agentsh config show`
- [ ] Network policies active (if configured)
- [ ] File policies active (if configured)

### Functionality Tests

- [ ] Test session creation works:
  ```bash
  curl -X POST localhost:18080/sessions -d '{"user":"test"}'
  ```
- [ ] Test approval workflow (if enabled)
- [ ] Test webhook delivery (if configured)
- [ ] Test MCP tool execution

### External Connectivity

- [ ] Webhook endpoints reachable
- [ ] External API integrations working
- [ ] DNS resolution correct
- [ ] Load balancer health checks passing

### Monitoring and Alerting

- [ ] Metrics endpoint accessible: `curl localhost:18080/metrics`
- [ ] Alerts configured and firing appropriately
- [ ] Log aggregation receiving logs

## Contact Information

Update this section with your organization's contacts:

| Role | Contact | Escalation Time |
|------|---------|-----------------|
| On-call SRE | [your-oncall-pager] | Immediate |
| SRE Team Lead | [sre-lead-contact] | After 30 min |
| Security team | [security-contact] | Key compromise: Immediate |
| Engineering Lead | [eng-lead-contact] | After 1 hour |
| Vendor support | support@agentsh.io | After internal escalation |

### Escalation Path

1. **First 15 minutes**: On-call SRE attempts recovery
2. **15-30 minutes**: Page SRE Team Lead
3. **30-60 minutes**: Engage Security (if data-related) or Engineering
4. **60+ minutes**: Executive notification for extended outages

## Runbook Templates

### Pre-Recovery Checklist

Before starting any recovery:

- [ ] Confirm the nature of the incident
- [ ] Notify relevant stakeholders
- [ ] Identify recovery lead
- [ ] Locate most recent backup
- [ ] Confirm key availability
- [ ] Prepare recovery environment

### Post-Recovery Report Template

```
Incident Date: YYYY-MM-DD
Recovery Completed: YYYY-MM-DD HH:MM

## Summary
[Brief description of what happened]

## Timeline
- HH:MM - Incident detected
- HH:MM - Recovery started
- HH:MM - Service restored
- HH:MM - Verification completed

## Impact
- Duration: X hours Y minutes
- Data loss: [None / Describe lost data]
- Affected users: [Number/scope]

## Root Cause
[Description of what caused the incident]

## Recovery Actions
1. [Action taken]
2. [Action taken]

## Lessons Learned
- [What went well]
- [What could be improved]

## Follow-up Actions
- [ ] [Action item with owner and due date]
```

## Testing Disaster Recovery

Regular DR testing is essential. Schedule these tests:

| Test Type | Frequency | Duration |
|-----------|-----------|----------|
| Backup verification | Weekly | 15 min |
| Restore to staging | Monthly | 2 hours |
| Full DR failover | Quarterly | 4 hours |
| Key rotation drill | Bi-annually | 1 hour |

### Backup Verification Test

```bash
# Weekly automated test
#!/bin/bash
BACKUP=$(ls -t /backup/agentsh-*.tar.gz | head -1)
TEMP_DIR=$(mktemp -d)

tar -xzf "$BACKUP" -C "$TEMP_DIR"
agentsh audit verify --key-file /etc/agentsh/audit-integrity.key "$TEMP_DIR/audit.jsonl"
RESULT=$?

rm -rf "$TEMP_DIR"
exit $RESULT
```

### Restore to Staging Test

```bash
# Monthly test on staging environment
agentsh restore --input /backup/agentsh-latest.tar.gz --dry-run
# Review output, then:
agentsh restore --input /backup/agentsh-latest.tar.gz --verify
```
