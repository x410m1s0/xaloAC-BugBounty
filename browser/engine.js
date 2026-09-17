const { chromium } = require('playwright');
const { URL } = require('node:url');
const { validateTarget } = require('../scope');
const { resolveAndGuard } = require('../network-guard');

async function browse({ url, scope = [], exclude = [], labMode = false, storageState, signal, screenshot = false }) {
  const initial = validateTarget(url, scope, exclude);
  if (!initial.allowed) return { state: 'blocked', error: initial.reason, url };
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext(storageState ? { storageState } : {});
  const events = { navigation: [], requests: [], responses: [], redirects: [], console: [], errors: [], cookies: [], storage: {}, dom: '', screenshot: null };
  let blocked = null;
  await context.route('**/*', async (route) => {
    const target = route.request().url();
    const check = validateTarget(target, scope, exclude);
    if (!check.allowed) { blocked = { url: target, reason: check.reason }; await route.abort('blockedbyclient'); return; }
    if (!labMode) {
      const guard = await resolveAndGuard(new URL(target).hostname);
      if (!guard.allowed) { blocked = { url: target, reason: guard.reason }; await route.abort('blockedbyclient'); return; }
    }
    await route.continue();
  });
  const page = await context.newPage();
  page.on('request', (request) => events.requests.push({ method: request.method(), url: request.url(), resourceType: request.resourceType(), headers: request.headers(), postData: request.postData() || null }));
  page.on('response', (response) => events.responses.push({ status: response.status(), url: response.url(), headers: response.headers() }));
  page.on('requestfailed', (request) => events.errors.push({ url: request.url(), error: request.failure()?.errorText || 'request failed' }));
  page.on('framenavigated', (frame) => { if (frame === page.mainFrame()) events.navigation.push(frame.url()); });
  page.on('console', (message) => events.console.push({ type: message.type(), text: message.text() }));
  page.on('pageerror', (error) => events.errors.push({ url: page.url(), error: error.message }));
  if (signal) signal.addEventListener('abort', () => page.close().catch(() => {}), { once: true });
  try {
    const response = await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
    events.redirects = events.responses.filter((item) => item.status >= 300 && item.status < 400);
    events.dom = await page.content();
    events.cookies = await context.cookies();
    events.storage = await page.evaluate(() => ({ localStorage: Object.fromEntries(Object.entries(localStorage)), sessionStorage: Object.fromEntries(Object.entries(sessionStorage)) }));
    if (screenshot) events.screenshot = (await page.screenshot({ type: 'png' })).toString('base64');
    return { state: signal?.aborted ? 'cancelled' : blocked ? 'blocked' : 'complete', status: response?.status() || null, finalUrl: page.url(), events };
  } catch (error) {
    return { state: signal?.aborted ? 'cancelled' : blocked ? 'blocked' : 'failed', error: error.message, finalUrl: page.url(), events };
  } finally {
    await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
}

module.exports = { browse };
