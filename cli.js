#!/usr/bin/env node
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { scanSite } = require('./scanner');
const { Storage } = require('./storage');

function usage() {
  console.log(`xaloAC CLI - authorized web assessment

Usage:
  node cli.js --url https://target.example [options]

Commands:
  program create --name <name> [--policy-url <url>]
  program list [--json]
  scope add --program-id <id> --value <scope> [--exclude]
  scope list --program-id <id> [--json]
  scan list [--json]
  finding list [--json]

Options:
  --url <url>          Required HTTPS target URL
  --max-pages <n>     Crawl limit (1-100, default 25)
  --delay-ms <n>      Minimum delay between requests (default 150)
  --profile <name>    Scan profile: quick, standard, deep, authenticated, api, browser, full
  --out <directory>   Output directory (default ./xaloac-results)
  --json              Write JSON result (default: enabled)
  --markdown          Write Markdown report
  --html              Write standalone HTML report
  --help              Show this help

Examples:
  node cli.js --url https://target.example --max-pages 50 --markdown
  npm run assess -- --url https://target.example --out ./reports --markdown
`);
}

function flagValue(argumentsList, flag) { const index = argumentsList.indexOf(flag); return index >= 0 ? argumentsList[index + 1] : undefined; }
function hasFlag(argumentsList, flag) { return argumentsList.includes(flag); }
async function runCommand(argumentsList) {
  const [resource, action] = argumentsList; const storage = new Storage(); const json = hasFlag(argumentsList, '--json');
  if (resource === 'program' && action === 'create') { const result = { id: crypto.randomUUID(), name: flagValue(argumentsList, '--name'), policyUrl: flagValue(argumentsList, '--policy-url') }; if (!result.name) throw new Error('--name is required'); storage.createProgram(result); console.log(json ? JSON.stringify(result) : `Program created: ${result.id}`); return true; }
  if (resource === 'program' && action === 'list') { const rows = storage.listPrograms(); console.log(json ? JSON.stringify(rows) : rows.map((row) => `${row.id}  ${row.name}`).join('\n')); return true; }
  if (resource === 'scope' && action === 'add') { const programId = flagValue(argumentsList, '--program-id'); const value = flagValue(argumentsList, '--value'); if (!programId || !value) throw new Error('--program-id and --value are required'); storage.addScope(programId, value, 'rule', hasFlag(argumentsList, '--exclude')); const result = { programId, value, excluded: hasFlag(argumentsList, '--exclude') }; console.log(json ? JSON.stringify(result) : `Scope added: ${value}`); return true; }
  if (resource === 'scope' && action === 'list') { const rows = storage.listScope(flagValue(argumentsList, '--program-id')); console.log(json ? JSON.stringify(rows) : rows.map((row) => `${row.excluded ? 'EXCLUDE' : 'INCLUDE'}  ${row.value}`).join('\n')); return true; }
  if (resource === 'scan' && action === 'list') { const rows = storage.listScans(); console.log(json ? JSON.stringify(rows) : rows.map((row) => `${row.id}  ${row.state}  ${row.target}`).join('\n')); return true; }
  if (resource === 'finding' && action === 'list') { const rows = storage.listFindings(); console.log(json ? JSON.stringify(rows) : rows.map((row) => `${row.severity}  ${row.status}  ${row.title}`).join('\n')); return true; }
  return false;
}

function parseArgs(argumentsList) {
  const options = { maxPages: 25, delayMs: 150, out: path.resolve('xaloac-results'), markdown: false, html: false };
  for (let index = 0; index < argumentsList.length; index += 1) {
    const argument = argumentsList[index];
    if (argument === '--help') options.help = true;
    else if (argument === '--url') options.url = argumentsList[++index];
    else if (argument === '--max-pages') options.maxPages = Number(argumentsList[++index]);
    else if (argument === '--delay-ms') options.delayMs = Number(argumentsList[++index]);
    else if (argument === '--profile') { options.profile = argumentsList[++index]; if (!['quick', 'standard', 'deep', 'authenticated', 'api', 'browser', 'full'].includes(options.profile)) throw new Error('--profile must be quick, standard, deep, authenticated, api, browser, or full'); }
    else if (argument === '--out') options.out = path.resolve(argumentsList[++index]);
    else if (argument === '--markdown') options.markdown = true;
    else if (argument === '--html') options.html = true;
    else if (argument === '--json') options.json = true;
    else throw new Error(`Unknown option: ${argument}`);
  }
  return options;
}

function htmlReport(result) { const escape = (value = '') => String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character])); const findings = (result.findings || []).map((finding) => `<article><h2>[${escape(finding.severity)}] ${escape(finding.title)}</h2><p><strong>Confidence:</strong> ${escape(finding.confidence)} · <strong>Asset:</strong> ${escape(finding.asset)}</p><p>${escape(finding.description || finding.detail)}</p><pre>${escape(JSON.stringify(finding.evidence, null, 2))}</pre></article>`).join(''); return `<!doctype html><html lang="en"><meta charset="utf-8"><title>xaloAC Assessment</title><style>body{font:15px system-ui;max-width:980px;margin:40px auto;padding:0 20px;color:#152126}header{border-bottom:2px solid #2bc3bd;padding-bottom:20px}article{border:1px solid #dbe6e2;border-radius:6px;padding:18px;margin:18px 0}pre{background:#f3f6f5;padding:12px;white-space:pre-wrap}small{color:#65777a}</style><header><h1>xaloAC Assessment Report</h1><p>${escape(result.target)} · ${escape(result.state)}</p><small>Generated ${new Date().toISOString()}</small></header><h2>Findings (${result.findings?.length || 0})</h2>${findings || '<p>No automated findings. Manual validation is required.</p>'}<h2>Endpoints (${result.endpoints?.length || 0})</h2><ul>${(result.endpoints || []).map((endpoint) => `<li>${escape(endpoint)}</li>`).join('')}</ul></html>`; }

function markdownReport(result) {
  const lines = [
    `# xaloAC Assessment Report`,
    ``,
    `- Target: ${result.target}`,
    `- State: ${result.state}`,
    `- Generated: ${new Date().toISOString()}`,
    `- Pages: ${result.stats?.pages || 0}`,
    `- Endpoints: ${result.stats?.endpoints || 0}`,
    `- Forms: ${result.stats?.forms || 0}`,
    ``,
    `## Findings`,
    ``
  ];
  if (!result.findings?.length) lines.push('No automated findings. Manual validation is still required.', '');
  for (const finding of result.findings || []) {
    lines.push(`### [${finding.severity.toUpperCase()}] ${finding.title}`, '', `- Category: ${finding.category}`, `- Asset: ${finding.asset}`, `- Detail: ${finding.detail}`, '', '**Evidence**', '```text', finding.evidence || 'No evidence captured', '```', '');
  }
  lines.push('## Discovered Endpoints', '');
  for (const endpoint of result.endpoints || []) lines.push(`- ${endpoint}`);
  lines.push('', '## Discovered Forms', '');
  for (const form of result.forms || []) lines.push(`- ${form.method.toUpperCase()} ${form.action}`);
  lines.push('', '> Automated findings are candidates for manual validation. Only test targets you are explicitly authorized to assess.');
  return lines.join('\n');
}

async function main() {
  const argumentsList = process.argv.slice(2);
  if (['program', 'scope', 'scan', 'finding'].includes(argumentsList[0]) && argumentsList[1] !== 'start') { if (await runCommand(argumentsList)) return; }
  const options = parseArgs(argumentsList[0] === 'scan' && argumentsList[1] === 'start' ? argumentsList.slice(2) : argumentsList);
  if (options.help) { usage(); return; }
  if (!options.url) throw new Error('--url is required');
  if (!/^https:\/\//i.test(options.url)) throw new Error('Only HTTPS URLs are accepted');
  if (!Number.isInteger(options.maxPages) || options.maxPages < 1 || options.maxPages > 100) throw new Error('--max-pages must be an integer between 1 and 100');
  if (!Number.isInteger(options.delayMs) || options.delayMs < 0 || options.delayMs > 60000) throw new Error('--delay-ms must be an integer between 0 and 60000');
  if (!options.json) console.log(`Starting authorized assessment: ${options.url}`);
  const result = await scanSite({ url: options.url, scope: [new URL(options.url).hostname], profile: options.profile || 'standard', maxPages: options.maxPages, delayMs: options.delayMs });
  await fs.mkdir(options.out, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const baseName = path.join(options.out, `assessment-${stamp}`);
  await fs.writeFile(`${baseName}.json`, JSON.stringify(result, null, 2), 'utf8');
  if (options.markdown) await fs.writeFile(`${baseName}.md`, markdownReport(result), 'utf8');
  if (options.html) await fs.writeFile(`${baseName}.html`, htmlReport(result), 'utf8');
  if (options.json) console.log(JSON.stringify({ target: options.url, state: result.state, files: { json: `${baseName}.json`, markdown: options.markdown ? `${baseName}.md` : null, html: options.html ? `${baseName}.html` : null }, stats: result.stats, findings: result.findings?.length || 0 }));
  else { console.log(`Completed: ${result.stats?.pages || 0} pages, ${result.stats?.endpoints || 0} endpoints, ${result.findings?.length || 0} findings`); console.log(`JSON: ${baseName}.json`); if (options.markdown) console.log(`Markdown: ${baseName}.md`); if (options.html) console.log(`HTML: ${baseName}.html`); }
}

main().catch((error) => { console.error(`Error: ${error.message}`); process.exitCode = 1; });
