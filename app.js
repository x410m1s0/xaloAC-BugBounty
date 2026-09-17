const state = {
  targets: [],
  findings: [],
  selectedFinding: null,
  theme: localStorage.getItem('xaloac-theme') || 'light',
};
let currentFilter = 'all';

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escapeHtml = (value = '') => String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
const severityScores = { critical: 9.5, high: 8.2, medium: 5.6, low: 2.8, informational: 0.5 };
const severityLabels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' };
const translations = {
  tr: { eyebrow: 'GÜVENLİK ARAŞTIRMA ALANI', local: 'YEREL ÇALIŞMA ALANI', heroTitle: 'Yetkili güvenlik araştırmanı<br><em>tek yerde yönet.</em>', heroCopy: "Scope'u tanımla, düşük etkili taramayı çalıştır, kanıtı düzenle ve raporu hazırla.", workspace: 'ÇALIŞMA ALANI', privacy: 'Yerel gizlilik modu', privacyDetail: 'Telemetri yok · yalnızca localhost', export: '⇩ Çalışma alanını dışa aktar', activePrograms: 'Aktif programlar', scopeDefined: '● Scope tanımlı', openFindings: 'Açık bulgular', triageWaiting: 'Triaged bekliyor', averageRisk: 'Ortalama risk skoru', weeklyWork: 'Bu haftaki çalışma', previousWeek: '+ 0.0s / önceki hafta', researchLog: 'ARAŞTIRMA GÜNLÜĞÜ', recentActivity: 'Son aktiviteler', viewAll: 'Tümünü gör →', nextMove: 'SONRAKİ ADIM', focusArea: 'Odak alanı', createScope: 'Scope oluştur →', footer: 'Bug Bounty Security Platform · x410m1s0 tarafından geliştirildi', overview: 'Genel Bakış', targets: 'Hedefler & Scope', findings: 'Bulgular', reports: 'Rapor merkezi', newFinding: '＋ Yeni bulgu' },
  en: { eyebrow: 'SECURITY RESEARCH WORKSPACE', local: 'LOCAL WORKSPACE', heroTitle: 'Manage authorized security<br><em>research in one place.</em>', heroCopy: 'Define scope, run a low-impact scan, organize evidence and prepare the report.', workspace: 'WORKSPACE', privacy: 'Local privacy mode', privacyDetail: 'No telemetry · localhost only', export: '⇩ Export workspace', activePrograms: 'Active programs', scopeDefined: '● Scope defined', openFindings: 'Open findings', triageWaiting: 'Awaiting triage', averageRisk: 'Average risk score', weeklyWork: 'This week', previousWeek: '+ 0.0h / previous week', researchLog: 'RESEARCH LOG', recentActivity: 'Recent activity', viewAll: 'View all →', nextMove: 'NEXT MOVE', focusArea: 'Focus area', createScope: 'Create scope →', footer: 'Bug Bounty Security Platform · Developed by x410m1s0', overview: 'Overview', targets: 'Targets & Scope', findings: 'Findings', reports: 'Report center', newFinding: '＋ New finding' },
};
let language = localStorage.getItem('xaloac-language') || 'tr';

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { 'content-type': 'application/json', ...(options.headers || {}) }, ...options });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `İstek başarısız (${response.status})`);
  return payload;
}

function toast(message, type = 'info') {
  const element = $('#toast');
  element.textContent = message;
  element.dataset.type = type;
  element.classList.add('show');
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => element.classList.remove('show'), 3200);
}

function switchView(view) {
  $$('.view').forEach((item) => item.classList.toggle('active', item.id === `view-${view}`));
  $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === view));
  $('#page-title').textContent = translations[language][view];
  if (view === 'reports') renderReport();
}

function applyLanguage() {
  const copy = translations[language];
  $$('[data-i18n]').forEach((element) => { element.innerHTML = copy[element.dataset.i18n]; });
  $$('.nav-item').forEach((button) => {
    const label = button.dataset.view === 'overview' ? copy.overview : button.dataset.view === 'targets' ? copy.targets : button.dataset.view === 'findings' ? copy.findings : copy.reports;
    const textNode = [...button.childNodes].find((node) => node.nodeType === Node.TEXT_NODE);
    if (textNode) textNode.textContent = ` ${label}`;
  });
  $('#quick-finding').textContent = copy.newFinding;
  renderOverview();
  switchView(document.querySelector('.view.active')?.id.replace('view-', '') || 'overview');
}

function renderOverview() {
  const open = state.findings.filter((finding) => !['submitted', 'closed'].includes(finding.status));
  const average = state.findings.length ? state.findings.reduce((sum, finding) => sum + (severityScores[finding.severity] || 0), 0) / state.findings.length : 0;
  $('#metric-programs').textContent = state.targets.length;
  $('#metric-open').textContent = open.length;
  $('#metric-open-foot').textContent = translations[language].triageWaiting;
  $('#metric-risk').textContent = average.toFixed(1);
  $('#metric-risk-foot').textContent = average >= 7 ? (language === 'en' ? 'High priority area' : 'Yüksek öncelik alanı') : average ? (language === 'en' ? 'Controlled risk profile' : 'Kontrollü risk profili') : (language === 'en' ? 'No data yet' : 'Henüz veri yok');
  $('#nav-findings-count').textContent = open.length;
  $('#focus-title').textContent = state.targets.length ? (open.length ? (language === 'en' ? 'Triage open findings' : 'Açık bulguları triage et') : (language === 'en' ? 'Record your first finding' : 'İlk bulgunu kaydet')) : (language === 'en' ? 'Add your first program' : 'İlk programını ekle');
  $('#focus-copy').textContent = state.targets.length ? (language === 'en' ? 'Complete evidence, assess risk and prepare the report.' : 'Kanıtı tamamla, riski değerlendir ve raporu teslimata hazırla.') : (language === 'en' ? 'Define an authorized target and its allowed scope.' : 'Yetkili olduğun hedefi ve izinli scope varlıklarını tanımla.');
  const activities = [...state.findings].slice(0, 5);
  $('#activity-list').innerHTML = activities.length ? activities.map((finding) => `<div class="activity-row"><span class="activity-bullet"></span><div class="activity-text"><strong>${escapeHtml(finding.title)}</strong><span class="activity-time">${severityLabels[finding.severity] || 'Info'} · ${new Date(finding.created_at || Date.now()).toLocaleDateString(language === 'en' ? 'en-US' : 'tr-TR')}</span></div></div>`).join('') : `<div class="empty-state"><p>${language === 'en' ? 'No activity yet. Add an authorized program to begin.' : 'Henüz aktivite yok. Yetkili bir program ekleyerek başla.'}</p></div>`;
}

function renderTargets() {
  const list = $('#target-list');
  if (!state.targets.length) {
    list.innerHTML = '<div class="panel empty-state" style="padding:60px 20px"><div class="empty-icon">◎</div><h3>Henüz program yok</h3><p>İlk programını ve izinli scope varlıklarını tanımla.</p></div>';
    return;
  }
  list.innerHTML = state.targets.map((target) => {
    const findings = state.findings.filter((finding) => finding.programId === target.id || finding.targetId === target.id);
    return `<article class="target-card"><div><h3>${escapeHtml(target.name)}</h3><span class="target-platform">${escapeHtml(target.platform || 'Local assessment')}</span><div class="scope-chips">${target.scope.map((host) => `<span class="scope-chip">${escapeHtml(host)}</span>`).join('')}</div></div><div class="target-stats"><strong>${findings.length}</strong><small>bulgu</small></div><div class="target-actions"><button class="small-button" data-target-findings="${target.id}">Bulguları gör →</button></div></article>`;
  }).join('');
}

function renderFindings() {
  const query = ($('#finding-search')?.value || '').toLowerCase();
  const counts = { all: state.findings.length, draft: 0, ready: 0, submitted: 0 };
  state.findings.forEach((finding) => { counts[finding.status] = (counts[finding.status] || 0) + 1; });
  Object.entries(counts).forEach(([key, value]) => { const element = $(`#filter-${key}`); if (element) element.textContent = value; });
  const findings = state.findings.filter((finding) => (currentFilter === 'all' || finding.status === currentFilter) && `${finding.title} ${finding.asset || ''} ${finding.summary || ''}`.toLowerCase().includes(query));
  $('#finding-list').innerHTML = findings.length ? findings.map((finding) => `<article class="finding-card"><span class="severity-line severity-${finding.severity}"></span><div><h3>${escapeHtml(finding.title)}</h3><div class="finding-meta">${escapeHtml(finding.asset || 'Asset belirtilmedi')} · ${escapeHtml((state.targets.find((target) => target.id === (finding.programId || finding.targetId)) || {}).name || 'Program')}</div><p class="finding-summary">${escapeHtml(finding.summary || 'Detayları açarak kanıt ve etki bilgisini tamamla.')}</p></div><div class="finding-right"><span class="severity-badge">${severityLabels[finding.severity] || 'Info'}</span><br><span class="status-badge">${finding.status === 'submitted' ? 'Gönderildi' : finding.status === 'ready' ? 'Raporlanabilir' : 'Taslak'}</span><br><button class="small-button" data-open-report="${finding.id}">Raporu aç</button></div></article>`).join('') : '<div class="panel empty-state" style="padding:70px 20px"><div class="empty-icon">◉</div><h3>Bu filtrede bulgu yok</h3><p>Yeni bulgu kaydettiğinde burada görünecek.</p></div>';
}

function renderTargetOptions() {
  $('#finding-target').innerHTML = '<option value="">Program seç...</option>' + state.targets.map((target) => `<option value="${target.id}">${escapeHtml(target.name)}</option>`).join('');
}

function renderReport() {
  const finding = state.findings.find((item) => item.id === state.selectedFinding);
  if (!finding) {
    $('#report-title').textContent = 'Bir bulgu seç';
    $('#report-content').innerHTML = '<div class="empty-state"><div class="empty-icon">▤</div><h3>Rapor önizlemesi hazır değil</h3><p>Bulgular ekranından bir rapor seç.</p></div>';
    return;
  }
  const target = state.targets.find((item) => item.id === (finding.programId || finding.targetId));
  $('#report-title').textContent = finding.title;
  $('#report-content').innerHTML = `<article class="report-document"><h2>${escapeHtml(finding.title)}</h2><div class="report-meta">${severityLabels[finding.severity] || 'Info'} · ${escapeHtml(target?.name || 'Program')} · xaloAC</div><h4>Summary</h4><p>${escapeHtml(finding.summary || finding.title)}</p><h4>Asset / Endpoint</h4><pre>${escapeHtml(finding.asset || 'Belirtilmedi')}</pre><h4>Steps to reproduce</h4><p>${escapeHtml(finding.steps || 'Adımlar eklenmedi.').replace(/\n/g, '<br>')}</p><h4>Evidence & notes</h4><p>${escapeHtml(finding.evidence || 'Kanıt notu eklenmedi.').replace(/\n/g, '<br>')}</p><h4>Suggested remediation</h4><p>Sunucu tarafında yetkilendirme ve input doğrulamasını kaynak nesnesi seviyesinde uygulayın; düzeltmeyi negatif testlerle doğrulayın.</p></article>`;
}

async function loadWorkspace() {
  $('#save-status-text').textContent = 'SQLite yükleniyor';
  try {
    const [programs, findings] = await Promise.all([api('/api/programs'), api('/api/findings')]);
    state.targets = (programs.programs || []).map((program) => ({ id: program.id, name: program.name, platform: program.notes || '', scope: (program.scope || []).filter((entry) => !entry.excluded).map((entry) => entry.value), createdAt: program.created_at }));
    state.findings = findings.findings || [];
    $('#save-status-text').textContent = 'SQLite bağlı';
    renderAll();
  } catch (error) {
    $('#save-status-text').textContent = 'SQLite bağlantısı yok';
    toast(error.message, 'error');
  }
}

async function submitProgram(event) {
  event.preventDefault();
  const scope = $('#target-scope').value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
  if (!scope.length) return toast('En az bir scope girdisi gerekli', 'error');
  try {
    const payload = { id: `program-${Date.now()}`, name: $('#target-name').value.trim(), notes: $('#target-platform').value.trim(), scope, authorizationStatus: 'confirmed' };
    await api('/api/programs', { method: 'POST', body: JSON.stringify(payload) });
    $('#target-form').reset();
    await loadWorkspace();
    toast('Program ve scope SQLite’a kaydedildi', 'success');
  } catch (error) { toast(error.message, 'error'); }
}

async function submitFinding(event) {
  event.preventDefault();
  const payload = { id: `finding-${Date.now()}`, title: $('#finding-title').value.trim(), targetId: $('#finding-target').value, severity: $('#finding-severity').value, asset: $('#finding-asset').value.trim(), summary: $('#finding-summary').value.trim(), steps: $('#finding-steps').value.trim(), evidence: $('#finding-evidence').value.trim(), status: 'draft' };
  if (!payload.targetId) return toast('Önce bir program seç', 'error');
  try {
    await api('/api/findings', { method: 'POST', body: JSON.stringify(payload) });
    closeFindingModal();
    await loadWorkspace();
    toast('Bulgu SQLite’a kaydedildi', 'success');
  } catch (error) { toast(error.message, 'error'); }
}

async function runScan() {
  const target = state.targets[0];
  const url = $('#scan-url').value.trim() || target?.scope?.find((entry) => /^https?:\/\//i.test(entry));
  if (!url) return toast('Taranacak HTTPS URL gir veya URL içeren bir scope ekle', 'error');
  if (!/^https:\/\//i.test(url)) return toast('Güvenlik için yalnızca HTTPS hedefleri kabul edilir', 'error');
  const button = $('#scan-scope');
  button.disabled = true;
  $('#scan-status').textContent = 'Crawl çalışıyor…';
  try {
    const host = new URL(url).hostname;
    const payload = await api('/api/scan', { method: 'POST', body: JSON.stringify({ scope: [host], targets: [url], maxPages: 25 }) });
    const result = payload.results?.[0];
    $('#scan-status').textContent = `Tamamlandı · ${result?.stats?.pages || 0} sayfa · ${result?.stats?.endpoints || 0} endpoint`;
    await loadWorkspace();
    toast('Tarama tamamlandı; sonuçlar SQLite’a yazıldı', 'success');
  } catch (error) { $('#scan-status').textContent = `Tarama başarısız: ${error.message}`; toast(error.message, 'error'); }
  finally { button.disabled = false; }
}

function openFindingModal() { renderTargetOptions(); $('#finding-modal').classList.add('open'); $('#finding-title').focus(); }
function closeFindingModal() { $('#finding-modal').classList.remove('open'); $('#finding-form').reset(); }
function renderAll() { renderOverview(); renderTargets(); renderFindings(); renderTargetOptions(); renderReport(); document.body.classList.toggle('dim-mode', state.theme === 'dim'); }

function wireEvents() {
  $$('.nav-item').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.view)));
  $$('[data-view-link]').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.viewLink)));
  $('#new-target').addEventListener('click', () => $('#target-form-panel').scrollIntoView({ behavior: 'smooth' }));
  $('#target-form').addEventListener('submit', submitProgram);
  $('#new-finding').addEventListener('click', openFindingModal);
  $('#quick-finding').addEventListener('click', openFindingModal);
  $('#report-new-finding').addEventListener('click', openFindingModal);
  $('#finding-form').addEventListener('submit', submitFinding);
  $('#cancel-finding').addEventListener('click', closeFindingModal);
  $('#close-finding').addEventListener('click', closeFindingModal);
  $('#finding-modal').addEventListener('click', (event) => { if (event.target.id === 'finding-modal') closeFindingModal(); });
  $('#finding-search').addEventListener('input', renderFindings);
  $$('.filter').forEach((button) => button.addEventListener('click', () => { currentFilter = button.dataset.filter; $$('.filter').forEach((item) => item.classList.toggle('active', item === button)); renderFindings(); }));
  $('#finding-list').addEventListener('click', (event) => { const button = event.target.closest('[data-open-report]'); if (button) { state.selectedFinding = button.dataset.openReport; switchView('reports'); } });
  $('#target-list').addEventListener('click', (event) => { const button = event.target.closest('[data-target-findings]'); if (button) { switchView('findings'); } });
  $('#copy-report').addEventListener('click', async () => { try { await navigator.clipboard.writeText($('#report-content').innerText); toast('Rapor panoya kopyalandı', 'success'); } catch { toast('Kopyalama engellendi', 'error'); } });
  $('#theme-toggle').addEventListener('click', () => { state.theme = state.theme === 'light' ? 'dim' : 'light'; localStorage.setItem('xaloac-theme', state.theme); renderAll(); });
  $('#language-select').value = language;
  $('#language-select').addEventListener('change', (event) => { language = event.target.value; localStorage.setItem('xaloac-language', language); applyLanguage(); });
  $('#scan-scope').addEventListener('click', runScan);
  $('#export-button').addEventListener('click', () => { const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), targets: state.targets, findings: state.findings }, null, 2)], { type: 'application/json' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `xaloac-export-${new Date().toISOString().slice(0, 10)}.json`; link.click(); URL.revokeObjectURL(link.href); });
}

wireEvents();
renderAll();
applyLanguage();
loadWorkspace();
