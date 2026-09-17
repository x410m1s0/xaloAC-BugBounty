const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');
const { scanSite } = require('./scanner');
const { runActiveChecks } = require('./active');
const { createReflectedXssPlugin } = require('./active/xss');
const { createCorsPlugin } = require('./active/cors');
const { createPlugins } = require('./active/registry');
const { diffScans } = require('./scan-diff');
const { Storage } = require('./storage');
const { JobManager } = require('./job-manager');
const { replayRequest } = require('./http-history');
const { AuthProfileManager } = require('./auth-profiles');
const { browse } = require('./browser/engine');
const { createFinding } = require('./finding');
const { calculateRisk } = require('./risk');
const { reportData, markdownReport, htmlReport } = require('./reports');

const PORT = Number(process.env.PORT || 4173);
const MAX_BODY = 200000;
const storage = new Storage();
const authProfiles = new AuthProfileManager();
const jobs = new JobManager();
jobs.on('progress', ({ job, progress }) => storage.addEvent(job.id, `scan.${progress.phase}`, progress));
jobs.on('job', (job) => {
  if (job.state === 'Running') storage.updateScanState(job.id, 'Running');
  if (['Completed', 'Failed', 'Cancelled'].includes(job.state)) {
    const result = job.result || {};
    storage.recordResult(job.id, result);
    storage.completeScan(job.id, job.state, result.stats || {});
  }
});

function sendJson(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'" });
  response.end(JSON.stringify(payload));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk) => {
      body += chunk;
      if (body.length > MAX_BODY) reject(new Error('payload too large'));
    });
    request.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('invalid json')); }
    });
    request.on('error', reject);
  });
}

const server = http.createServer(async (request, response) => {
  if (request.method === 'GET' && request.url === '/api/programs') return sendJson(response, 200, { programs: storage.listPrograms().map((program) => ({ ...program, scope: storage.listScope(program.id) })) });
  if (request.method === 'POST' && request.url === '/api/programs') {
    try {
      const payload = await readJson(request);
      if (typeof payload.name !== 'string' || !payload.name.trim()) return sendJson(response, 400, { error: 'program name is required' });
      const id = payload.id || crypto.randomUUID();
      storage.createProgram({ id, name: payload.name.trim(), policyUrl: payload.policyUrl, notes: payload.notes, authorizationStatus: payload.authorizationStatus || 'unknown' });
      if (!storage.listScope(id).length) for (const entry of Array.isArray(payload.scope) ? payload.scope : []) if (typeof entry === 'string' && entry.trim()) storage.addScope(id, entry.trim(), 'rule', false);
      return sendJson(response, 201, { id, name: payload.name.trim(), scope: storage.listScope(id) });
    } catch (error) { return sendJson(response, 400, { error: error.message }); }
  }
  if (request.method === 'POST' && request.url === '/api/findings') {
    try {
      const payload = await readJson(request);
      if (!payload.title || !payload.targetId) return sendJson(response, 400, { error: 'title and targetId are required' });
      const finding = createFinding({ ...payload, asset: payload.asset || payload.url, status: payload.status || 'New', source: 'ui' });
      storage.addFinding(finding, payload.scanId || null, payload.targetId);
      return sendJson(response, 201, finding);
    } catch (error) { return sendJson(response, 400, { error: error.message }); }
  }
  if (request.method === 'GET' && request.url.startsWith('/api/findings/') && !request.url.endsWith('/risk') && !request.url.endsWith('/report')) {
    const finding = storage.getFinding(request.url.split('/')[3]);
    return finding ? sendJson(response, 200, finding) : sendJson(response, 404, { error: 'finding not found' });
  }
  if (request.method === 'POST' && request.url.startsWith('/api/findings/')) {
    try { const id = request.url.split('/')[3]; const payload = await readJson(request); const finding = storage.transitionFinding(id, payload.status, payload.actor || 'local-user'); return sendJson(response, 200, finding); } catch (error) { return sendJson(response, 400, { error: error.message }); }
  }
  if (request.method === 'GET' && request.url.startsWith('/api/findings/') && request.url.endsWith('/risk')) {
    const finding = storage.getFinding(request.url.split('/')[3]); if (!finding) return sendJson(response, 404, { error: 'finding not found' }); return sendJson(response, 200, calculateRisk(finding));
  }
  if (request.method === 'POST' && request.url.startsWith('/api/findings/') && request.url.endsWith('/report')) {
    try { const id = request.url.split('/')[3]; const finding = storage.getFinding(id); if (!finding) return sendJson(response, 404, { error: 'finding not found' }); const payload = await readJson(request); const format = payload.format || 'markdown'; const content = format === 'html' ? htmlReport(finding, payload.program || {}) : format === 'json' ? JSON.stringify(reportData(finding, payload.program || {}), null, 2) : markdownReport(finding, payload.program || {}); const reportId = crypto.randomUUID(); storage.createReport({ id: reportId, scanId: finding.scanId, format, content }); return sendJson(response, 201, { id: reportId, format, content }); } catch (error) { return sendJson(response, 400, { error: error.message }); }
  }
  if (request.method === 'POST' && request.url === '/api/auth-profiles') {
    try {
      const payload = await readJson(request);
      const profile = authProfiles.create(payload);
      storage.createAuthProfile({ ...payload, id: profile.id, name: profile.name, type: profile.type, metadata: profile.metadata });
      return sendJson(response, 201, profile);
    } catch (error) { return sendJson(response, 400, { error: error.message }); }
  }
  if (request.method === 'GET' && request.url === '/api/auth-profiles') return sendJson(response, 200, { profiles: [...authProfiles.profiles.values()].map((profile) => authProfiles.public(profile)) });
    if (request.method === 'POST' && request.url === '/api/browser') {
      try {
        const payload = await readJson(request);
        const target = typeof payload.url === 'string' ? payload.url.trim() : '';
        const scope = Array.isArray(payload.scope) ? payload.scope : [];
        if (!target || !scope.length) return sendJson(response, 400, { error: 'url and scope are required' });
        if (payload.authorizationConfirmed !== true) return sendJson(response, 428, { error: 'explicit authorization confirmation is required for browser testing' });
        const scanId = crypto.randomUUID();
        storage.createScan({ id: scanId, target, state: 'Running', config: { scope, mode: 'browser', authorizationConfirmed: true } });
        const result = await browse({ url: target, scope, exclude: payload.exclude, labMode: payload.labMode === true, storageState: payload.storageState, screenshot: payload.screenshot === true });
        storage.recordResult(scanId, { requests: result.events?.requests?.map((item) => ({ method: item.method, url: item.url, requestHeaders: item.headers, responseBodySnippet: '', scopeResult: 'allowed', authContext: payload.authProfileId || null })) || [], endpoints: result.events?.requests?.map((item) => item.url) || [] });
        storage.completeScan(scanId, result.state === 'complete' ? 'Completed' : result.state === 'cancelled' ? 'Cancelled' : 'Failed', { requests: result.events?.requests?.length || 0, responses: result.events?.responses?.length || 0 });
        return sendJson(response, 200, { scanId, result });
      } catch (error) { return sendJson(response, 400, { error: error.message }); }
    }
  if (request.method === 'POST' && request.url === '/api/replay') {
    try {
      const payload = await readJson(request);
      if (payload.authorizationConfirmed !== true) return sendJson(response, 428, { error: 'explicit authorization confirmation is required for replay' });
      const target = payload.request && typeof payload.request.url === 'string' ? payload.request.url : '';
      const scope = Array.isArray(payload.scope) ? payload.scope : [];
      if (!target || !scope.length) return sendJson(response, 400, { error: 'request.url and scope are required' });
      const result = await replayRequest({ request: payload.request, scope, exclude: payload.exclude, httpRequest: require('./scanner').request, labMode: payload.labMode === true });
      if (result.blocked) return sendJson(response, 403, result);
      if (payload.scanId) storage.recordResult(payload.scanId, { requests: [{ ...result, replayOf: payload.request.id }] });
      return sendJson(response, 200, result);
    } catch (error) { return sendJson(response, 400, { error: error.message }); }
  }
  if (request.method === 'POST' && request.url === '/api/active') {
    try {
      const payload = await readJson(request);
      const target = typeof payload.url === 'string' ? payload.url.trim() : '';
      const scope = Array.isArray(payload.scope) ? payload.scope.filter((item) => typeof item === 'string').slice(0, 100) : [];
      if (!target || !scope.length) return sendJson(response, 400, { error: 'url and scope are required' });
      if (payload.authorizationConfirmed !== true) return sendJson(response, 428, { error: 'explicit authorization confirmation is required for active testing' });
      const plugins = Array.isArray(payload.plugins) ? createPlugins(payload.plugins) : createPlugins(['xss', 'cors']);
      if (!plugins.length) return sendJson(response, 400, { error: 'no supported active plugins selected' });
      const scanId = crypto.randomUUID();
      storage.createScan({ id: scanId, target, state: 'Running', config: { scope, exclude: payload.exclude || [], mode: 'active', authorizationConfirmed: true, plugins: payload.plugins || ['xss', 'cors'] } });
      storage.addEvent(scanId, 'active.started', { target, plugins: plugins.map((plugin) => plugin.metadata().id) });
      const authHeaders = payload.authProfileId ? authProfiles.headers(payload.authProfileId) : {};
      const result = await runActiveChecks({ url: target, scope, exclude: payload.exclude, labMode: payload.labMode === true, authContexts: payload.authContexts || [], plugins, request: (url, options = {}) => require('./scanner').request(url, { ...options, headers: { ...authHeaders, ...(options.headers || {}) } }) });
      storage.recordResult(scanId, result);
      storage.completeScan(scanId, result.state === 'cancelled' ? 'Cancelled' : 'Completed', { findings: result.findings.length, plugins: plugins.length });
      storage.addEvent(scanId, 'active.completed', { findings: result.findings.length });
      return sendJson(response, 200, { scanId, result });
    } catch (error) { return sendJson(response, 400, { error: error.message }); }
  }
  if (request.method === 'POST' && request.url === '/api/scan') {
    try {
      const payload = await readJson(request);
      const requestedUrl = typeof payload.url === 'string' ? payload.url.trim() : '';
      const derivedScope = requestedUrl ? [new URL(requestedUrl).hostname] : [];
      const scope = Array.isArray(payload.scope) && payload.scope.length ? payload.scope.filter((item) => typeof item === 'string').slice(0, 100) : derivedScope;
      const targets = Array.isArray(payload.targets) && payload.targets.length ? payload.targets.filter((item) => typeof item === 'string').slice(0, 20) : (requestedUrl ? [requestedUrl] : []);
      if (!scope.length || !targets.length) return sendJson(response, 400, { error: 'scope and targets are required' });
      const scanId = crypto.randomUUID();
      storage.createScan({ id: scanId, target: targets[0], state: 'Running', config: { scope, exclude: payload.exclude || [], profile: payload.profile || 'standard', maxPages: payload.maxPages, delayMs: payload.delayMs }, startedAt: new Date().toISOString() });
      storage.addEvent(scanId, 'scan.started', { targetCount: targets.length });
      const results = [];
      for (const target of targets) results.push(await scanSite({ url: target, scope, exclude: payload.exclude, profile: payload.profile || 'standard', maxPages: payload.maxPages, delayMs: payload.delayMs, labMode: payload.labMode === true }));
      results.forEach((result) => storage.recordResult(scanId, result));
      storage.completeScan(scanId, 'Completed', results.reduce((summary, result) => ({ pages: summary.pages + (result.stats?.pages || 0), endpoints: summary.endpoints + (result.stats?.endpoints || 0), findings: summary.findings + (result.findings?.length || 0) }), { pages: 0, endpoints: 0, findings: 0 }));
      storage.addEvent(scanId, 'scan.completed', { results: results.length });
      return sendJson(response, 200, { scanId, scannedAt: new Date().toISOString(), results });
    } catch (error) { return sendJson(response, 400, { error: error.message }); }
  }
  if (request.method === 'POST' && request.url === '/api/jobs') {
    try {
      const payload = await readJson(request);
      const requestedUrl = typeof payload.url === 'string' ? payload.url.trim() : '';
      const scope = Array.isArray(payload.scope) && payload.scope.length ? payload.scope.filter((item) => typeof item === 'string').slice(0, 100) : (requestedUrl ? [new URL(requestedUrl).hostname] : []);
      const targets = Array.isArray(payload.targets) && payload.targets.length ? payload.targets.filter((item) => typeof item === 'string').slice(0, 20) : (requestedUrl ? [requestedUrl] : []);
      if (!scope.length || !targets.length) return sendJson(response, 400, { error: 'scope and targets are required' });
      const job = jobs.create({ url: targets[0], scope, exclude: payload.exclude, targets, profile: payload.profile || 'standard', maxPages: payload.maxPages, delayMs: payload.delayMs, labMode: payload.labMode === true });
      storage.createScan({ id: job.id, target: targets[0], state: 'Queued', config: { scope, exclude: payload.exclude || [], profile: payload.profile || 'standard', maxPages: payload.maxPages, delayMs: payload.delayMs } });
      return sendJson(response, 202, { jobId: job.id, state: job.state });
    } catch (error) { return sendJson(response, 400, { error: error.message }); }
  }
  if (request.method === 'GET' && request.url.startsWith('/api/jobs/')) { const job = jobs.get(request.url.split('/').pop()); if (!job) return sendJson(response, 404, { error: 'job not found' }); const { controller, input, ...publicJob } = job; return sendJson(response, 200, publicJob); }
  if (request.method === 'DELETE' && request.url.startsWith('/api/jobs/')) { const cancelled = jobs.cancel(request.url.split('/').pop()); return sendJson(response, cancelled ? 200 : 404, { cancelled }); }
  if (request.method === 'GET' && request.url === '/api/jobs') return sendJson(response, 200, { jobs: jobs.list() });
  if (request.url === '/health') return sendJson(response, 200, { ok: true, service: 'xaloac-engine', product: 'xaloAC Bug Bounty Security Platform' });
  if (request.method === 'GET' && request.url === '/api/scans') return sendJson(response, 200, { scans: storage.listScans() });
  if (request.method === 'GET' && request.url === '/api/findings') return sendJson(response, 200, { findings: storage.listFindings() });
  if (request.method === 'GET' && request.url.startsWith('/api/scan-diff')) {
    const query = new URL(request.url, 'http://127.0.0.1').searchParams;
    const before = query.get('before'); const after = query.get('after');
    if (!before || !after) return sendJson(response, 400, { error: 'before and after scan ids are required' });
    return sendJson(response, 200, diffScans(storage.listFindingsByScan(before), storage.listFindingsByScan(after)));
  }
  if (request.method === 'GET' && request.url.startsWith('/api/scans/') && request.url.endsWith('/requests')) return sendJson(response, 200, { requests: storage.listRequests(request.url.split('/')[3]) });
  if (request.method === 'GET' && request.url.startsWith('/api/scans/') && request.url.endsWith('/endpoints')) return sendJson(response, 200, { endpoints: storage.listEndpoints(request.url.split('/')[3]) });
  if (/%2e|%2f|%5c|\.\./i.test(request.url)) return sendJson(response, 400, { error: 'invalid path' });
  let pathname;
  try { pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname); } catch { return sendJson(response, 400, { error: 'invalid path' }); }
  const publicRoot = path.resolve(__dirname);
  const filePath = path.resolve(publicRoot, `.${pathname === '/' ? '/index.html' : pathname}`);
  if (filePath !== publicRoot && !filePath.startsWith(`${publicRoot}${path.sep}`)) return sendJson(response, 403, { error: 'forbidden' });
  fs.createReadStream(filePath).on('error', () => sendJson(response, 404, { error: 'not found' })).pipe(response);
});

server.listen(PORT, '127.0.0.1', () => console.log(`xaloAC engine listening on http://localhost:${PORT}`));
