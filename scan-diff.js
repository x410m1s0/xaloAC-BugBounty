function indexFindings(findings = []) { return new Map(findings.map((finding) => [finding.fingerprint, finding])); }
function diffScans(before = [], after = []) {
  const left = indexFindings(before); const right = indexFindings(after);
  const added = after.filter((finding) => !left.has(finding.fingerprint));
  const removed = before.filter((finding) => !right.has(finding.fingerprint));
  const changed = after.filter((finding) => left.has(finding.fingerprint) && JSON.stringify({ severity: finding.severity, status: finding.status }) !== JSON.stringify({ severity: left.get(finding.fingerprint).severity, status: left.get(finding.fingerprint).status }));
  return { added, removed, changed, persistent: after.filter((finding) => left.has(finding.fingerprint) && !changed.includes(finding)) };
}
module.exports = { diffScans };