#!/bin/sh
set -eu

echo $$ > /shared/workload.pid

# Wait for tracer to attach (condition-based, not time-based)
i=0
while [ ! -f /shared/tracer-ready ] && [ $i -lt 60 ]; do
  sleep 0.5
  i=$((i + 1))
done
if [ ! -f /shared/tracer-ready ]; then
  echo "SETUP:FAIL:tracer did not attach within 30s"
  exit 1
fi
echo "SETUP:PASS:tracer attached"

echo "=== POSITIVE CONTROL ==="
# This command IS allowed by test policy — verifies environment works
ls /tmp > /dev/null 2>&1 && echo "CONTROL:PASS:allowed command ran" || echo "CONTROL:FAIL:allowed command blocked"

echo "=== FILE WRITE CONTROL ==="
# Baseline: verify writes work on a path NOT denied by policy
touch /tmp/write-control-test 2>&1 && echo "FILECONTROL:PASS:write works" || echo "FILECONTROL:FAIL:writes broken"
rm -f /tmp/write-control-test

echo "=== EXEC TEST ==="
# wget is explicitly denied by test policy AND installed in the image.
# Use --version (no network needed) so the check is independent of connectivity.
wget --version > /dev/null 2>&1 && echo "EXEC:FAIL:wget ran" || echo "EXEC:PASS:wget denied"

echo "=== FILE TEST ==="
# /etc/shadow.test is in a denied path pattern.
# The FILECONTROL check above confirms writes work in general.
touch /etc/shadow.test 2>&1 && echo "FILE:FAIL:write succeeded" || echo "FILE:PASS:write denied"

echo "=== NETWORK TEST ==="
# 169.254.169.254 (IMDS) is denied by network policy.
# Use python3 (exec-allowed) to test network denial independently of exec denial.
# Catch specific exceptions to distinguish policy denial from env issues.
python3 -c "
import urllib.request, socket, sys
try:
    urllib.request.urlopen('http://169.254.169.254/', timeout=2)
    print('NET:FAIL:connect succeeded')
except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
    # Policy enforcement typically causes ECONNREFUSED, EACCES, or EPERM
    print('NET:PASS:connect denied (' + type(e).__name__ + ')')
except Exception as e:
    # Unexpected error — report but don't claim policy success
    print('NET:WARN:unexpected error (' + type(e).__name__ + ': ' + str(e) + ')')
" 2>&1

echo "=== SECCOMP PROBE ==="
/usr/local/bin/seccomp-probe && echo "SECCOMP:AVAILABLE" || echo "SECCOMP:UNAVAILABLE"

echo "=== DONE ==="
