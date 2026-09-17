const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { redactHeaders, redactText } = require('./finding');

const SCHEMA_VERSION = 4;
const MIGRATIONS = [
  `
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS programs (id TEXT PRIMARY KEY, name TEXT NOT NULL, policy_url TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scope_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, program_id TEXT NOT NULL, value TEXT NOT NULL, kind TEXT NOT NULL, excluded INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(program_id) REFERENCES programs(id));
CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, program_id TEXT, target TEXT NOT NULL, state TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, config_json TEXT NOT NULL, stats_json TEXT, FOREIGN KEY(program_id) REFERENCES programs(id));
CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, request_id TEXT, method TEXT NOT NULL, url TEXT NOT NULL, status INTEGER, duration_ms INTEGER, response_headers_json TEXT, response_size INTEGER, error TEXT, created_at TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id));
CREATE TABLE IF NOT EXISTS endpoints (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL, source TEXT, status INTEGER, content_type TEXT, UNIQUE(scan_id, method, url), FOREIGN KEY(scan_id) REFERENCES scans(id));
CREATE TABLE IF NOT EXISTS technologies (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, name TEXT NOT NULL, version TEXT, confidence TEXT, evidence TEXT, UNIQUE(scan_id, name), FOREIGN KEY(scan_id) REFERENCES scans(id));
CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, scan_id TEXT, program_id TEXT, type TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL, status TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id), FOREIGN KEY(program_id) REFERENCES programs(id));
CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL, kind TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(finding_id) REFERENCES findings(id));
CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, scan_id TEXT, format TEXT NOT NULL, path TEXT, content TEXT, created_at TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id));
CREATE TABLE IF NOT EXISTS scan_events (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, event TEXT NOT NULL, payload_json TEXT, created_at TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id));
`,
  `
ALTER TABLE programs ADD COLUMN updated_at TEXT;
ALTER TABLE programs ADD COLUMN notes TEXT;
ALTER TABLE programs ADD COLUMN authorization_status TEXT NOT NULL DEFAULT 'unknown';
CREATE INDEX IF NOT EXISTS idx_scope_entries_program ON scope_entries(program_id);
CREATE INDEX IF NOT EXISTS idx_scans_program_started ON scans(program_id, started_at);
CREATE INDEX IF NOT EXISTS idx_requests_scan_created ON requests(scan_id, created_at);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan_url ON endpoints(scan_id, url);
CREATE INDEX IF NOT EXISTS idx_findings_scan_status ON findings(scan_id, status);
CREATE INDEX IF NOT EXISTS idx_events_scan_created ON scan_events(scan_id, created_at);
`
  ,
  `
ALTER TABLE requests ADD COLUMN request_headers_json TEXT;
ALTER TABLE requests ADD COLUMN response_body_snippet TEXT;
ALTER TABLE requests ADD COLUMN auth_context TEXT;
ALTER TABLE requests ADD COLUMN scope_result TEXT NOT NULL DEFAULT 'allowed';
ALTER TABLE requests ADD COLUMN replay_of INTEGER;
CREATE INDEX IF NOT EXISTS idx_requests_url ON requests(url);
`
  ,
  `
CREATE TABLE IF NOT EXISTS auth_profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, headers_json TEXT NOT NULL DEFAULT '{}', cookies_json TEXT NOT NULL DEFAULT '{}', storage_state_json TEXT, metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_auth_profiles_type ON auth_profiles(type);
ALTER TABLE requests ADD COLUMN auth_profile_id TEXT REFERENCES auth_profiles(id);
`
];

class Storage {
  constructor(filePath = path.join(process.cwd(), '.data', 'xaloac.db')) { fs.mkdirSync(path.dirname(filePath), { recursive: true }); this.db = new DatabaseSync(filePath); this.db.exec('PRAGMA foreign_keys = ON'); this.migrate(); }
  migrate() {
    this.db.exec(MIGRATIONS[0]);
    const current = Number(this.db.prepare('SELECT value FROM schema_meta WHERE key = ?').get('schemaVersion')?.value || 0);
    for (let version = current + 1; version <= SCHEMA_VERSION; version += 1) {
      this.db.exec(MIGRATIONS[version - 1]);
      this.db.prepare('INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)').run('schemaVersion', String(version));
    }
  }
  createScan(scan) { this.db.prepare('INSERT INTO scans (id, program_id, target, state, started_at, config_json) VALUES (?, ?, ?, ?, ?, ?)').run(scan.id, scan.programId || null, scan.target, scan.state || 'Queued', scan.startedAt || new Date().toISOString(), JSON.stringify(scan.config || {})); return scan.id; }
  createProgram(program) { const now = new Date().toISOString(); this.db.prepare('INSERT OR IGNORE INTO programs (id, name, policy_url, created_at, updated_at, notes, authorization_status) VALUES (?, ?, ?, ?, ?, ?, ?)').run(program.id, program.name, program.policyUrl || null, program.createdAt || now, program.updatedAt || now, program.notes || null, program.authorizationStatus || 'unknown'); return program.id; }
  listPrograms() { return this.db.prepare('SELECT * FROM programs ORDER BY created_at DESC').all(); }
  addScope(programId, value, kind = 'host', excluded = false) { this.db.prepare('INSERT INTO scope_entries (program_id, value, kind, excluded) VALUES (?, ?, ?, ?)').run(programId, value, kind, excluded ? 1 : 0); }
  createAuthProfile(profile) { const now = new Date().toISOString(); const redactedCookies = Object.fromEntries(Object.keys(profile.cookies || {}).map((name) => [name, '[REDACTED]'])); this.db.prepare('INSERT INTO auth_profiles (id, name, type, headers_json, cookies_json, storage_state_json, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(profile.id, profile.name, profile.type, JSON.stringify(redactHeaders(profile.headers || {})), JSON.stringify(redactedCookies), profile.storageState ? '[REDACTED]' : null, JSON.stringify(profile.metadata || {}), profile.createdAt || now, profile.updatedAt || now); return profile.id; }
  listAuthProfiles() { return this.db.prepare('SELECT id, name, type, metadata_json, created_at, updated_at FROM auth_profiles ORDER BY created_at DESC').all(); }
  getAuthProfile(id) { return this.db.prepare('SELECT * FROM auth_profiles WHERE id = ?').get(id) || null; }
  listScope(programId) { return this.db.prepare('SELECT * FROM scope_entries WHERE program_id = ? ORDER BY id').all(programId); }
  listFindings() {
    return this.db.prepare('SELECT * FROM findings ORDER BY created_at DESC').all().map((row) => ({
      ...JSON.parse(row.payload_json),
      id: row.id,
      scanId: row.scan_id,
      programId: row.program_id,
      type: row.type,
      severity: row.severity,
      confidence: row.confidence,
      status: row.status,
      fingerprint: row.fingerprint,
      created_at: row.created_at
    }));
  }
  listFindingsByScan(scanId) { return this.db.prepare('SELECT id, scan_id, title, type, severity, confidence, status, fingerprint, created_at FROM findings WHERE scan_id = ? ORDER BY created_at').all(scanId); }
  getFinding(id) { const row = this.db.prepare('SELECT * FROM findings WHERE id = ?').get(id); if (!row) return null; return { ...JSON.parse(row.payload_json), scanId: row.scan_id, programId: row.program_id }; }
  transitionFinding(id, status, actor = 'local-user') { const finding = this.getFinding(id); if (!finding) throw new Error('finding not found'); const previousStatus = finding.status; finding.status = status; this.db.prepare('UPDATE findings SET status = ?, payload_json = ? WHERE id = ?').run(status, JSON.stringify(finding), id); if (finding.scanId) this.addEvent(finding.scanId, 'finding.status_changed', { findingId: id, from: previousStatus, to: status, actor }); return finding; }
  createReport(report) { this.db.prepare('INSERT INTO reports (id, scan_id, format, path, content, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(report.id, report.scanId || null, report.format, report.path || null, report.content, report.createdAt || new Date().toISOString()); return report.id; }
  completeScan(id, state, stats) { this.db.prepare('UPDATE scans SET state = ?, completed_at = ?, stats_json = ? WHERE id = ?').run(state, new Date().toISOString(), JSON.stringify(stats || {}), id); }
  updateScanState(id, state) { this.db.prepare('UPDATE scans SET state = ? WHERE id = ?').run(state, id); }
  addFinding(finding, scanId, programId) { this.db.prepare('INSERT OR IGNORE INTO findings (id, scan_id, program_id, type, title, severity, confidence, status, fingerprint, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(finding.id, scanId || null, programId || null, finding.type, finding.title, finding.severity, finding.confidence, finding.status || 'New', finding.fingerprint, JSON.stringify(finding), finding.createdAt || new Date().toISOString()); }
  addEvent(scanId, event, payload = {}) { this.db.prepare('INSERT INTO scan_events (scan_id, event, payload_json, created_at) VALUES (?, ?, ?, ?)').run(scanId, event, JSON.stringify(payload), new Date().toISOString()); }
  recordResult(scanId, result) {
    for (const request of result.requests || []) this.db.prepare('INSERT INTO requests (scan_id, method, url, status, duration_ms, response_headers_json, request_headers_json, response_body_snippet, auth_context, scope_result, replay_of, auth_profile_id, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(scanId, request.method || 'GET', request.url, request.status, request.durationMs || null, JSON.stringify(redactHeaders(request.responseHeaders || {})), JSON.stringify(redactHeaders(request.requestHeaders || {})), redactText(request.responseBodySnippet || ''), request.authContext || null, request.scopeResult || 'allowed', request.replayOf || null, request.authProfileId || null, request.error || null, new Date().toISOString());
    for (const endpoint of result.endpoints || []) this.db.prepare('INSERT OR IGNORE INTO endpoints (scan_id, method, url, source) VALUES (?, ?, ?, ?)').run(scanId, 'GET', endpoint, 'crawler');
    for (const technology of result.technologies || []) this.db.prepare('INSERT OR IGNORE INTO technologies (scan_id, name, confidence, evidence) VALUES (?, ?, ?, ?)').run(scanId, technology, 'observed', 'passive discovery');
    for (const finding of result.findings || []) {
      this.addFinding(finding, scanId);
      for (const item of finding.evidence || []) this.db.prepare('INSERT INTO evidence (finding_id, kind, payload_json, created_at) VALUES (?, ?, ?, ?)').run(finding.id, item.source || 'active', JSON.stringify(item), item.timestamp || new Date().toISOString());
    }
  }
  listRequests(scanId) { return this.db.prepare('SELECT * FROM requests WHERE scan_id = ? ORDER BY id DESC').all(scanId); }
  listEndpoints(scanId) { return this.db.prepare('SELECT * FROM endpoints WHERE scan_id = ? ORDER BY id').all(scanId); }
  listScans() { return this.db.prepare('SELECT * FROM scans ORDER BY started_at DESC').all(); }
  close() { this.db.close(); }
}
module.exports = { Storage, SCHEMA_VERSION };
