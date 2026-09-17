const { validateTarget } = require('./scope');

async function replayRequest({ request, scope, exclude = [], httpRequest, signal, labMode = false }) {
  if (!request || typeof httpRequest !== 'function') throw new TypeError('request and httpRequest are required');
  const check = validateTarget(request.url, scope, exclude);
  if (!check.allowed) return { ok: false, blocked: true, scopeResult: check.reason, url: request.url };
  return httpRequest(request.url, {
    method: request.method || 'GET',
    headers: request.headers || {},
    body: request.body,
    signal,
    labMode,
    replayOf: request.id
  });
}

module.exports = { replayRequest };