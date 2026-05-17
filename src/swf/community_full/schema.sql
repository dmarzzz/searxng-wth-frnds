-- metrics.db schema (post-#43 PR C). The legacy community-graph
-- tables (peers, pages, page_contributors, search_results, visits,
-- contributions, pending_contributions, events, embeddings) are
-- gone — that data lives in indrex.db now via the single-graph model.
-- What remains is the self-contained metrics collector's storage.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- arbitrary server state for the metrics collector.
CREATE TABLE IF NOT EXISTS kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Self-contained Prometheus-lite. The `metrics` background thread
-- inserts rows on a fixed cadence (default 10s) and a maintenance pass
-- deletes rows older than 7 days. The viz polls `/metrics/series` and
-- `/metrics/snapshot` against this table — no separate Prometheus.
CREATE TABLE IF NOT EXISTS metrics_samples (
  ts_ms       INTEGER NOT NULL,
  name        TEXT NOT NULL,
  value       REAL NOT NULL,
  labels_json TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (ts_ms, name, labels_json)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_metrics_name_ts ON metrics_samples(name, ts_ms);
