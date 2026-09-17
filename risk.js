const SEVERITY_WEIGHT = { critical: 10, high: 8, medium: 5, low: 2, informational: 0.5 };
const CONFIDENCE_WEIGHT = { confirmed: 1, high: 0.9, medium: 0.7, low: 0.4, potential: 0.5 };

function calculateRisk(finding, context = {}) {
  const severity = String(finding.severity || 'informational').toLowerCase();
  const confidence = String(finding.confidence || 'potential').toLowerCase();
  const exposure = Number(context.exposure ?? 1);
  const criticality = Number(context.assetCriticality ?? 1);
  const authentication = Number(context.authenticationRequired ? 0.75 : 1);
  const exploitability = Number(context.exploitability ?? 1);
  const impact = Number(context.impact ?? (SEVERITY_WEIGHT[severity] || 0.5) / 10);
  const score = Math.max(0, Math.min(100, (SEVERITY_WEIGHT[severity] || 0.5) * 10 * (CONFIDENCE_WEIGHT[confidence] || 0.5) * exposure * criticality * authentication * exploitability * Math.max(impact, 0.1)));
  return { score: Math.round(score * 10) / 10, severity: score >= 90 ? 'Critical' : score >= 70 ? 'High' : score >= 40 ? 'Medium' : score > 0 ? 'Low' : 'None', factors: { severity, confidence, exposure, criticality, authentication, exploitability, impact } };
}

module.exports = { calculateRisk };