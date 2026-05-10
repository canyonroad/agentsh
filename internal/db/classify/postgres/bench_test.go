package postgres

import "testing"

// BenchmarkClassify_50StatementMix measures classification throughput on a
// representative 50-statement mixed workload (read/write/DDL/COPY/session/
// privilege/maintenance). Each iteration parses + classifies the entire batch
// in one Classify call, exercising the multi-statement path. Informational —
// not a CI gate.
func BenchmarkClassify_50StatementMix(b *testing.B) {
	p := New(DialectPostgres)
	sess := SessionState{}
	opts := Options{}

	// Sanity: ensure the workload parses cleanly so the bench measures the
	// happy path. A parse error would still be timed but would mask the
	// classification cost.
	stmts, err := p.Classify(representativeWorkloadSQL, sess, opts)
	if err != nil {
		b.Fatalf("Classify (sanity): %v", err)
	}
	if len(stmts) < 40 {
		b.Fatalf("expected >=40 classified statements in fixture, got %d", len(stmts))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Classify(representativeWorkloadSQL, sess, opts); err != nil {
			b.Fatalf("Classify: %v", err)
		}
	}
}

// representativeWorkloadSQL is a 50-statement mix covering the major
// classification paths: DML reads/writes, DDL, COPY, privilege, session,
// maintenance, and procedural. Statement count is checked at bench start.
const representativeWorkloadSQL = `
-- DML reads (5)
SELECT 1;
SELECT * FROM customers WHERE id = 1;
SELECT c.id, o.total FROM customers c JOIN orders o ON o.cust_id = c.id LIMIT 100;
SELECT count(*) FROM orders WHERE created_at > now() - interval '1 day';
WITH recent AS (SELECT id FROM events WHERE ts > now() - interval '1 hour') SELECT * FROM recent;

-- DML writes (5 INSERT, 3 UPDATE, 3 DELETE, 1 MERGE)
INSERT INTO audit_log (id, note) VALUES (1, 'note');
INSERT INTO audit_log (id, note) VALUES (2, 'two'), (3, 'three');
INSERT INTO totals SELECT cust_id, sum(total) FROM orders GROUP BY cust_id;
INSERT INTO sink (a, b) VALUES (1, 2) ON CONFLICT (a) DO UPDATE SET b = EXCLUDED.b;
INSERT INTO journal DEFAULT VALUES;
UPDATE users SET active = false WHERE id = 1;
UPDATE users SET last_seen = now() WHERE last_seen < now() - interval '90 days';
UPDATE orders o SET status = 'shipped' FROM shipments s WHERE s.order_id = o.id;
DELETE FROM users WHERE id = 1;
DELETE FROM sessions WHERE expires_at < now();
WITH gone AS (DELETE FROM stale RETURNING id) SELECT count(*) FROM gone;
MERGE INTO target t USING source s ON s.id = t.id WHEN MATCHED THEN UPDATE SET v = s.v WHEN NOT MATCHED THEN INSERT (id, v) VALUES (s.id, s.v);

-- EXPLAIN / PREPARE / DEALLOCATE (5)
EXPLAIN SELECT count(*) FROM orders;
EXPLAIN ANALYZE SELECT * FROM customers WHERE id = 1;
PREPARE q1 AS SELECT * FROM customers WHERE id = $1;
PREPARE q2 (int) AS UPDATE users SET active = false WHERE id = $1;
DEALLOCATE q1;

-- DDL CREATE / ALTER / DROP / TRUNCATE (10)
CREATE TABLE foo (a int, b text);
CREATE TABLE app.events (id bigserial PRIMARY KEY, payload jsonb);
CREATE INDEX foo_a_idx ON foo (a);
CREATE VIEW v_active_users AS SELECT * FROM users WHERE active;
ALTER TABLE foo ADD COLUMN c text;
ALTER TABLE foo RENAME TO foo_old;
DROP TABLE foo_old;
DROP INDEX IF EXISTS foo_a_idx;
DROP VIEW IF EXISTS v_active_users;
TRUNCATE TABLE bar;

-- COPY (4)
COPY t TO STDOUT;
COPY t FROM STDIN;
COPY t TO '/tmp/t.csv' WITH (FORMAT csv);
COPY t FROM '/tmp/t.csv' WITH (FORMAT csv);

-- Privilege (3)
GRANT SELECT ON customers TO bob;
REVOKE INSERT ON audit_log FROM bob;
GRANT USAGE ON SCHEMA app TO analytics;

-- Session (5)
SET search_path = public, app;
RESET search_path;
DISCARD ALL;
SET ROLE analytics;
RESET ROLE;

-- Maintenance / lock / notify (3)
VACUUM ANALYZE customers;
LOCK TABLE orders IN SHARE MODE;
NOTIFY channel_x, 'payload';

-- Procedural (1)
DO $$ BEGIN PERFORM 1; END $$;
`
