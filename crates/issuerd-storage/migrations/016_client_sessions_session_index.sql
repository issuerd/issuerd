-- Index client_sessions.session_id — the join column used by
-- PostgresStorage::get_user_session (userinfo, refresh, logout, session
-- validity checks on every session-bearing request).
--
-- Found by the tests/perf benchmark stack: without this index every session
-- lookup sequential-scans client_sessions, and userinfo throughput collapses
-- as the table grows (392 req/s at 71k sessions vs 2350 req/s with the index
-- on the medium benchmark tier; see docs/PERFORMANCE.md).
CREATE INDEX IF NOT EXISTS idx_client_sessions_session ON client_sessions(session_id);
