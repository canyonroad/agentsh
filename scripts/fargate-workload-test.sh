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

echo "=== EXEC TEST ==="
# wget is explicitly denied by test policy AND installed in the image
wget --spider http://example.com 2>&1 && echo "EXEC:FAIL:wget ran" || echo "EXEC:PASS:wget denied"

echo "=== FILE TEST ==="
# /etc/shadow.test is in a denied path pattern
touch /etc/shadow.test 2>&1 && echo "FILE:FAIL:write succeeded" || echo "FILE:PASS:write denied"

echo "=== NETWORK TEST ==="
# 169.254.169.254 (IMDS) is denied by network policy
# Use python3 (exec-allowed) to test network denial independently of exec denial
python3 -c "
import urllib.request, sys
try:
    urllib.request.urlopen('http://169.254.169.254/', timeout=2)
    print('NET:FAIL:connect succeeded')
except Exception:
    print('NET:PASS:connect denied')
" 2>&1

echo "=== SECCOMP PROBE ==="
/usr/local/bin/seccomp-probe && echo "SECCOMP:AVAILABLE" || echo "SECCOMP:UNAVAILABLE"

echo "=== DONE ==="
