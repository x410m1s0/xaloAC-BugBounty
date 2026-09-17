const net = require('node:net');
const { URL } = require('node:url');

function toUrl(value) { return new URL(value.includes('://') ? value : `https://${value}`); }
function ipv4Number(value) { return value.split('.').reduce((number, octet) => (number * 256) + Number(octet), 0); }
function ipv4InCidr(address, range) { const [network, bitsText] = range.split('/'); const bits = Number(bitsText); if (net.isIP(address) !== 4 || net.isIP(network) !== 4 || bits < 0 || bits > 32) return false; const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0; return (ipv4Number(address) & mask) === (ipv4Number(network) & mask); }
function hostMatches(host, pattern) { const normalizedHost = host.toLowerCase().replace(/\.$/, ''); const normalizedPattern = pattern.toLowerCase().replace(/\.$/, ''); if (normalizedPattern.startsWith('*.')) return normalizedHost.endsWith(`.${normalizedPattern.slice(2)}`) && normalizedHost !== normalizedPattern.slice(2); return normalizedHost === normalizedPattern; }
function parseScopeEntry(entry) {
  const raw = String(entry).trim();
  if (!raw) return null;
  const cidrMatch = raw.match(/^([^/]+)\/(\d+)$/);
  if (cidrMatch && net.isIP(cidrMatch[1])) return { cidr: raw };
  const hasScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(raw);
  const withoutScheme = raw.replace(/^[a-z][a-z\d+.-]*:\/\//i, '');
  const candidate = hasScheme ? raw : `https://${raw}`;
  let parsed;
  try { parsed = new URL(candidate); } catch { return null; }
  const authority = withoutScheme.split('/')[0];
  const hostPattern = authority.startsWith('[') ? authority.slice(1, authority.indexOf(']')) : authority.split(':')[0];
  const portMatch = authority.match(/:(\d+)$/);
  const pathIndex = withoutScheme.indexOf('/');
  const pathPattern = pathIndex >= 0 ? withoutScheme.slice(pathIndex) : '';
  return { hostPattern, port: portMatch ? Number(portMatch[1]) : null, protocol: hasScheme ? parsed.protocol : null, pathPattern };
}

function pathMatches(pathname, pattern) {
  if (!pattern || pattern === '/') return true;
  const prefix = pattern.endsWith('*') ? pattern.slice(0, -1) : pattern;
  return pathname === prefix || pathname.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`);
}

function entryMatches(urlValue, entry) {
  let parsed;
  try { parsed = new URL(urlValue); } catch { return false; }
  const rule = parseScopeEntry(entry);
  if (!rule) return false;
  if (rule.cidr) return net.isIP(parsed.hostname) === 4 && ipv4InCidr(parsed.hostname, rule.cidr);
  if (!hostMatches(parsed.hostname, rule.hostPattern)) return false;
  const effectivePort = Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80));
  if (rule.port !== null && effectivePort !== rule.port) return false;
  if (rule.protocol && parsed.protocol !== rule.protocol) return false;
  return pathMatches(parsed.pathname, rule.pathPattern);
}
function validateTarget(urlValue, include = [], exclude = []) { const normalized = (() => { try { const parsed = new URL(urlValue); parsed.hash = ''; return parsed.toString(); } catch { return null; } })(); if (!normalized) return { allowed: false, reason: 'invalid-url' }; if (!['http:', 'https:'].includes(new URL(normalized).protocol)) return { allowed: false, reason: 'unsupported-scheme' }; if (!include.some((entry) => entryMatches(normalized, entry))) return { allowed: false, reason: 'outside-include' }; if (exclude.some((entry) => entryMatches(normalized, entry))) return { allowed: false, reason: 'matched-exclude' }; return { allowed: true, url: normalized }; }
module.exports = { entryMatches, validateTarget, ipv4InCidr };
