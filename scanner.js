const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const { URL } = require('node:url');
const { validateTarget } = require('./scope');
const { resolveAndGuard } = require('./network-guard');
const { createFinding } = require('./finding');

const REQUEST_TIMEOUT = 8000;
const MAX_BODY = 250000;
const DEFAULT_MAX_PAGES = 25;
const MAX_MAX_PAGES = 100;
const USER_AGENT = 'xaloAC/1.0 authorized-security-research';

const SECURITY_HEADERS = {
  'strict-transport-security': { severity: 'medium', title: 'HSTS header missing' },
  'content-security-policy': { severity: 'medium', title: 'Content-Security-Policy header missing' },
  'x-content-type-options': { severity: 'low', title: 'X-Content-Type-Options header missing' },
  'referrer-policy': { severity: 'low', title: 'Referrer-Policy header missing' },
  'permissions-policy': { severity: 'low', title: 'Permissions-Policy header missing' }
};
const SENSITIVE_PATHS = ['/admin', '/internal', '/debug', '/backup', '/.git/', '/.env', '/actuator', '/swagger.json', '/openapi.json'];
const DISCOVERY_PATHS = ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/security.txt', '/swagger.json', '/openapi.json'];
const DEFAULT_DELAY_MS = 150;

function normalizeUrl(value, base) {
  try {
    const parsed = new URL(value, base);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    parsed.hash = '';
    return parsed.toString();
  } catch { return null; }
}

async function request(urlValue, options = {}) {
  const guard = await resolveAndGuard(new URL(urlValue).hostname, { labMode: options.labMode });
  if (!guard.allowed) return { ok: false, error: `network target blocked: ${guard.reason}`, url: urlValue, blocked: true };
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(urlValue); } catch { resolve({ ok: false, error: 'invalid URL' }); return; }
    const client = parsed.protocol === 'https:' ? https : http;
      const startedAt = Date.now();
      const requestOptions = { method: options.method || 'GET', timeout: options.timeout || REQUEST_TIMEOUT, lookup: (_hostname, _options, callback) => callback(null, guard.addresses[0], net.isIP(guard.addresses[0])), headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml,application/javascript,text/javascript,*/*;q=0.1', ...(options.headers || {}) } };
    const requestInstance = client.request(parsed, requestOptions, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { if (body.length < MAX_BODY) body += chunk; });
      response.on('end', () => resolve({ ok: true, status: response.statusCode, headers: response.headers, body, url: parsed.toString(), method: requestOptions.method, requestHeaders: requestOptions.headers, durationMs: Date.now() - startedAt }));
    });
    const abort = () => requestInstance.destroy(new Error('cancelled'));
    if (options.signal?.aborted) { abort(); return; }
    options.signal?.addEventListener('abort', abort, { once: true });
    requestInstance.on('timeout', () => requestInstance.destroy(new Error('timeout')));
    requestInstance.on('error', (error) => resolve({ ok: false, error: error.message, url: parsed.toString(), method: requestOptions.method, durationMs: Date.now() - startedAt }));
    requestInstance.end(options.body || undefined);
  });
}

function headersOf(response) { return Object.fromEntries(Object.entries(response.headers || {}).map(([key, value]) => [key.toLowerCase(), value])); }
function addFinding(findings, result, title, severity, detail, evidence, category = 'configuration') { findings.push(createFinding({ title, severity, type: category, asset: result.url, detail, evidence, source: category === 'configuration' ? 'passive-scanner' : `plugin:${category}`, confidence: severity === 'info' ? 'High' : 'Potential', reason: `Signal: ${title}. Context and impact require manual validation.`, response: { status: result.status, headers: result.headers, bodySnippet: evidence } })); }
function extractUrls(body, baseUrl) {
  const values = [];
  const pattern = /(?:href|src|action)\s*=\s*["']([^"']+)|(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest)\s*\(\s*["']([^"']+)/gi;
  let match;
  while ((match = pattern.exec(body)) !== null) { const value = match[1] || match[2]; const normalized = normalizeUrl(value, baseUrl); if (normalized) values.push(normalized); }
  return [...new Set(values)];
}
function extractForms(body, baseUrl) {
  const forms = [];
  const pattern = /<form\b([^>]*)>/gi;
  let match;
  while ((match = pattern.exec(body)) !== null) { const attrs = match[1]; const action = /action\s*=\s*["']([^"']*)/i.exec(attrs)?.[1] || baseUrl; const method = /method\s*=\s*["']([^"']*)/i.exec(attrs)?.[1] || 'get'; forms.push({ action: normalizeUrl(action, baseUrl), method: method.toLowerCase() }); }
  return forms;
}
function extractParameters(body, endpoint) {
  const parameters = [];
  const add = (name, location, source) => { if (name && !parameters.some((item) => item.name === name && item.location === location)) parameters.push({ name, location, endpoint, source, risk: /^(id|.*id|url|uri|redirect|callback|token|role|file|path)$/i.test(name) ? 'high' : 'normal' }); };
  try { new URL(endpoint).searchParams.forEach((_value, name) => add(name, 'query', 'url')); } catch { /* endpoint was already normalized */ }
  for (const match of body.matchAll(/(?:name|id|data-testid)=["']([^"']+)["']/gi)) add(match[1], 'form', 'html');
  for (const match of body.matchAll(/(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest)\s*\([^)]*?[?&]([A-Za-z0-9_-]+)=/gi)) add(match[1], 'query', 'javascript');
  return parameters;
}
function profileConfig(profile = 'standard') {
  const profiles = { quick: { maxPages: 10 }, standard: { maxPages: 25 }, deep: { maxPages: 100 }, authenticated: { maxPages: 50 }, api: { maxPages: 50 }, browser: { maxPages: 50 }, full: { maxPages: 100 } };
  return profiles[String(profile).toLowerCase()] || profiles.standard;
}
function pageFindings(result, rootUrl) {
  const findings = [];
  const headers = headersOf(result);
  Object.entries(SECURITY_HEADERS).forEach(([header, rule]) => { if (header !== 'strict-transport-security' || rootUrl.startsWith('https://')) { if (!headers[header]) addFinding(findings, result, rule.title, rule.severity, `${header} header bulunamadı.`, `HTTP ${result.status}\n${result.url}`); } });
  const cookies = Array.isArray(result.headers['set-cookie']) ? result.headers['set-cookie'] : [];
  cookies.forEach((cookie) => {
    if (rootUrl.startsWith('https://') && !/;\s*secure/i.test(cookie)) addFinding(findings, result, 'Secure cookie flag missing', 'medium', 'HTTPS yanıtındaki cookie Secure attribute içermiyor.', cookie, 'session');
    if (!/;\s*httponly/i.test(cookie)) addFinding(findings, result, 'HttpOnly cookie flag missing', 'low', 'Cookie HttpOnly attribute içermiyor.', cookie, 'session');
    if (!/;\s*samesite=/i.test(cookie)) addFinding(findings, result, 'SameSite cookie attribute missing', 'low', 'Cookie SameSite attribute içermiyor.', cookie, 'session');
  });
  if (String(headers['access-control-allow-origin'] || '').trim() === '*') addFinding(findings, result, 'Wildcard CORS policy detected', 'medium', 'Access-Control-Allow-Origin: * gözlendi.', `access-control-allow-origin: ${headers['access-control-allow-origin']}`, 'cors');
  if (result.url.endsWith('.js') && /\/\/(?:[^\n]*?)\.map\b/i.test(result.body)) addFinding(findings, result, 'JavaScript source map reference exposed', 'low', 'JavaScript asset içinde source map referansı gözlendi.', result.body.match(/sourceMappingURL=.*$/im)?.[0] || 'sourceMappingURL', 'exposure');
  if (/<title>\s*(?:default|welcome)|index of \/?\s*</i.test(result.body)) addFinding(findings, result, 'Default page or directory listing signal', 'low', 'Yanıtta default page veya directory listing sinyali gözlendi.', result.body.match(/<title>[^<]+|index of \/?/i)?.[0] || 'page marker', 'exposure');
  return findings;
}
function detectTechnologies(result) {
  const headers = headersOf(result);
  const body = result.body || '';
  const technologies = new Set();
  if (headers.server) technologies.add(`Server: ${headers.server}`);
  if (headers['x-powered-by']) technologies.add(`Powered by: ${headers['x-powered-by']}`);
  if (/__NEXT_DATA__|_next\/static/i.test(body)) technologies.add('Next.js');
  if (/ng-version|angular\.js/i.test(body)) technologies.add('Angular');
  if (/data-reactroot|react(?:dom)?/i.test(body)) technologies.add('React');
  if (/wp-content|wordpress/i.test(body)) technologies.add('WordPress');
  if (/laravel_session|laravel/i.test(body + JSON.stringify(result.headers))) technologies.add('Laravel');
  if (/graphql/i.test(body)) technologies.add('GraphQL reference');
  return [...technologies];
}

async function scanSite(input) {
  const profile = String(input.profile || 'standard').toLowerCase();
  const profileDefaults = profileConfig(profile);
  const root = normalizeUrl(input.url);
  const include = Array.isArray(input.scope) ? input.scope : [];
  const exclude = Array.isArray(input.exclude) ? input.exclude : [];
  if (!root || !validateTarget(root, include, exclude).allowed) return { state: 'blocked', target: input.url, findings: [{ title: 'Scope dışı hedef engellendi', severity: 'info', category: 'scope', detail: 'Hedef include/exclude kurallarından geçmedi.' }] };
  const rootHost = new URL(root).hostname;
  const maxPages = Math.min(Math.max(Number(input.maxPages) || profileDefaults.maxPages, 1), MAX_MAX_PAGES);
  const delayMs = Math.min(Math.max(Number(input.delayMs ?? DEFAULT_DELAY_MS), 0), 60000);
  const queue = [root, ...DISCOVERY_PATHS.map((path) => normalizeUrl(path, root))]; const visited = new Set(); const pages = []; const findings = []; const endpoints = new Set(); const forms = []; const technologies = new Set(); const parameters = []; const requests = []; const phases = [];
  const emit = (phase, detail = {}) => { phases.push({ phase, at: new Date().toISOString(), ...detail }); input.onProgress?.({ phase, ...detail }); };
  emit('scope-verified', { target: root, profile });
  let lastRequestAt = 0;
  while (queue.length && pages.length < maxPages) {
    if (input.signal?.aborted) return { state: 'cancelled', target: root, pages, endpoints: [...endpoints], forms, parameters, technologies: [...technologies], findings, requests, phases, stats: { pages: pages.length, endpoints: endpoints.size, forms: forms.length, parameters: parameters.length, technologies: technologies.size, requests: requests.length, profile } };
    const current = queue.shift();
    if (visited.has(current)) continue;
    visited.add(current);
    const waitMs = Math.max(0, delayMs - (Date.now() - lastRequestAt));
    if (waitMs) await new Promise((resolve) => { const timer = setTimeout(resolve, waitMs); input.signal?.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true }); });
    lastRequestAt = Date.now();
    const targetCheck = validateTarget(current, include, exclude);
    if (!targetCheck.allowed) { pages.push({ url: current, state: 'blocked', reason: targetCheck.reason }); continue; }
    emit('request', { url: current });
    const startedAt = Date.now();
    const result = await request(current, { labMode: input.labMode, signal: input.signal });
    requests.push({ method: 'GET', url: current, status: result.status || null, durationMs: Date.now() - startedAt, responseHeaders: result.headers || {}, requestHeaders: result.requestHeaders || {}, responseBodySnippet: String(result.body || '').slice(0, 4000), scopeResult: 'allowed', error: result.ok ? null : result.error });
    if (!result.ok) { pages.push({ url: current, state: 'unreachable', error: result.error }); continue; }
    pages.push({ url: result.url, state: 'reachable', status: result.status, contentType: result.headers['content-type'] || '' });
    findings.push(...pageFindings(result, root));
    detectTechnologies(result).forEach((technology) => technologies.add(technology));
    if (result.status >= 400) continue;
    const type = String(result.headers['content-type'] || '');
    if (!type.includes('text/html') && !type.includes('javascript')) continue;
    extractUrls(result.body, result.url).forEach((candidate) => {
      const parsed = new URL(candidate);
      if (parsed.hostname === rootHost && validateTarget(candidate, include, exclude).allowed) { endpoints.add(candidate); if (!visited.has(candidate) && queue.length < maxPages * 2) queue.push(candidate); }
    });
    parameters.push(...extractParameters(result.body, result.url));
    extractForms(result.body, result.url).forEach((form) => { if (form.action) { forms.push(form); endpoints.add(form.action); } });
    SENSITIVE_PATHS.forEach((path) => { const candidate = normalizeUrl(path, result.url); if (candidate && new URL(candidate).hostname === rootHost && /(?:robots|sitemap|swagger|openapi|debug|admin|internal)/i.test(result.body)) endpoints.add(candidate); });
  }
  const uniqueFindings = [...new Map(findings.map((finding) => [finding.fingerprint, finding])).values()];
  emit('complete', { pages: pages.length, endpoints: endpoints.size });
  return { state: 'complete', target: root, profile, pages, endpoints: [...endpoints].slice(0, 500), forms: forms.slice(0, 100), parameters: [...new Map(parameters.map((item) => [`${item.location}:${item.name}:${item.endpoint}`, item])).values()].slice(0, 1000), technologies: [...technologies], findings: uniqueFindings, requests, phases, stats: { pages: pages.length, endpoints: endpoints.size, forms: forms.length, parameters: parameters.length, technologies: technologies.size, requests: requests.length, delayMs, profile } };
}

module.exports = { scanSite, request, normalizeUrl };
