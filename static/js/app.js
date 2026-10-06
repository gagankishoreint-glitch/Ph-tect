// ============================================
// DOM Elements & State
// ============================================
const tabs = document.querySelectorAll('.tab');
const tabContents = document.querySelectorAll('.tab-content');
const loadingOverlay = document.getElementById('loadingOverlay');
const loadingText = document.getElementById('loadingText');

let lastAnalyzedEmail = null;
let qrImageData = null;

// ============================================
// Tab Switching
// ============================================
tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        tabContents.forEach(content => {
            content.classList.remove('active');
            if (content.id === `${targetTab}-tab`) content.classList.add('active');
        });
        if (targetTab === 'history') loadHistory();
        if (targetTab === 'learn') loadLearningContent();
    });
});

// Loading State
function showLoading(msg = 'Analyzing...') { loadingText.textContent = msg; loadingOverlay.classList.add('show'); }
function hideLoading() { loadingOverlay.classList.remove('show'); }

// ============================================
// Email Analysis
// ============================================
document.getElementById('emailForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const sender = document.getElementById('sender').value.trim();
    const subject = document.getElementById('subject').value.trim();
    const body = document.getElementById('body').value.trim();
    if (!sender || !subject) { alert('Please provide sender and subject'); return; }
    
    showLoading('Analyzing email...');
    try {
        const res = await fetch('/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sender, subject, body }) });
        const data = await res.json();
        if (data.success) { window.lastEmailAnalysis = data; lastAnalyzedEmail = { subject, body }; displayEmailResults(data); }
        else alert('Error: ' + data.error);
    } catch (e) { alert('Failed to analyze email'); }
    finally { hideLoading(); }
});

function displayEmailResults(data) {
    const r = document.getElementById('emailResults'); r.style.display = 'block';
    document.getElementById('emailResultsHeader').style.borderLeft = `5px solid ${data.risk_color}`;
    document.getElementById('emailRiskIcon').textContent = data.risk_icon;
    document.getElementById('emailRiskLevel').textContent = data.risk_level;
    document.getElementById('emailRiskLevel').style.color = data.risk_color;
    document.getElementById('emailScore').textContent = data.danger_score;
    document.getElementById('emailScore').style.color = data.risk_color;
    document.getElementById('emailAdvice').textContent = data.advice;
    document.getElementById('emailAdvice').style.borderColor = data.risk_color;
    
    const fl = document.getElementById('emailFindings'); fl.innerHTML = '';
    if (data.reasons?.length) data.reasons.forEach(r => { const li = document.createElement('li'); li.textContent = r; fl.appendChild(li); });
    else fl.innerHTML = '<li style="color: var(--success);">✅ No suspicious indicators</li>';
    
    const us = document.getElementById('emailUrlsSection'), ul = document.getElementById('emailUrls');
    if (data.extracted_urls?.length) {
        us.style.display = 'block'; ul.innerHTML = '';
        data.extracted_urls.forEach(u => { const li = document.createElement('li'); li.innerHTML = `<span class="url-text">${truncate(u,50)}</span><button class="btn btn-sm btn-secondary" onclick="analyzeUrlFromEmail('${esc(u)}')">Analyze</button>`; ul.appendChild(li); });
    } else us.style.display = 'none';
    
    document.getElementById('emailMlProb').textContent = `${data.ml_probability}% (${data.ml_confidence})`;
    r.scrollIntoView({ behavior: 'smooth' });
}

// ============================================
// URL Analysis
// ============================================
document.getElementById('urlForm').addEventListener('submit', async (e) => { e.preventDefault(); await analyzeUrl(false); });
document.getElementById('quickCheckBtn').addEventListener('click', async () => { await analyzeUrl(true); });

async function analyzeUrl(quick = false) {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) { alert('Please enter a URL'); return; }
    showLoading(quick ? 'Quick checking...' : 'Deep analysis...');
    document.getElementById('quickResult').style.display = 'none';
    document.getElementById('urlResults').style.display = 'none';
    
    try {
        const res = await fetch(quick ? '/quick-url-check' : '/analyze-url', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
        const data = await res.json();
        if (data.success) { if (quick) displayQuickResult(data); else { window.lastUrlAnalysis = data; displayUrlResults(data); } }
        else alert('Error: ' + data.error);
    } catch (e) { alert('Failed to analyze URL'); }
    finally { hideLoading(); }
}

function displayQuickResult(d) {
    const r = document.getElementById('quickResult'); r.style.display = 'block';
    document.getElementById('quickVerdict').textContent = d.verdict;
    document.getElementById('quickVerdict').style.color = d.color;
    document.getElementById('quickDetails').innerHTML = (d.findings.length ? d.findings.map(f => `⚠️ ${f}`).join('<br>') : '✅ No threats') + `<br><small style="color:var(--text-muted)">${d.note}</small>`;
}

function displayUrlResults(d) {
    const r = document.getElementById('urlResults'); r.style.display = 'block';
    document.getElementById('urlResultsHeader').style.borderLeft = `5px solid ${d.risk_color}`;
    document.getElementById('urlRiskIcon').textContent = d.risk_icon;
    document.getElementById('urlRiskLevel').textContent = d.risk_level;
    document.getElementById('urlRiskLevel').style.color = d.risk_color;
    document.getElementById('urlScore').textContent = d.danger_score;
    document.getElementById('urlScore').style.color = d.risk_color;
    document.getElementById('urlSummary').textContent = d.summary;
    document.getElementById('urlSummary').style.borderColor = d.risk_color;
    
    displayInfo('domainInfo', d.domain_info, ['domain','registrar','creation_date','domain_age_days','expiration_date','registrant_country']);
    displayInfo('sslInfo', d.ssl_info, ['issuer','valid_until','days_until_expiry'], d.ssl_info?.has_ssl);
    displayInfo('redirectInfo', d.redirect_info, ['redirect_count','uses_shortener','crosses_domains','final_url']);
    displayInfo('dnsInfo', d.dns_info, ['a_records','mx_records','ns_records']);
    displayInfo('contentInfo', d.content_info, ['page_title','has_login_form','has_password_field','requests_sensitive_info']);
    
    const fl = document.getElementById('urlFindings'); fl.innerHTML = '';
    if (d.reasons?.length) d.reasons.forEach(r => { const li = document.createElement('li'); li.textContent = r; fl.appendChild(li); });
    else fl.innerHTML = '<li style="color: var(--success);">✅ No risk factors</li>';
    
    setupCollapsibles();
    r.scrollIntoView({ behavior: 'smooth' });
}

function displayInfo(id, info, fields, valid = true) {
    const c = document.getElementById(id);
    if (!info?.success && valid !== false) { c.innerHTML = '<p style="color:var(--text-muted)">Unavailable</p>'; return; }
    c.innerHTML = '<div class="info-grid">' + fields.map(f => {
        let v = info[f]; if (Array.isArray(v)) v = v.join(', ') || 'None';
        if (typeof v === 'boolean') v = v ? 'Yes ⚠️' : 'No';
        return `<div class="info-item"><div class="info-label">${f.replace(/_/g,' ')}</div><div class="info-value">${v || 'N/A'}</div></div>`;
    }).join('') + '</div>';
}

function analyzeUrlFromEmail(url) {
    document.querySelector('[data-tab="url"]').click();
    document.getElementById('urlInput').value = url;
    setTimeout(() => analyzeUrl(false), 300);
}

// ============================================
// Bulk URL Scanner
// ============================================
async function bulkScanUrls() {
    const urls = document.getElementById('bulkUrls').value.split('\n').filter(u => u.trim());
    if (!urls.length) { alert('Enter URLs'); return; }
    if (urls.length > 10) { alert('Max 10 URLs'); return; }
    
    showLoading(`Scanning ${urls.length} URLs...`);
    try {
        const res = await fetch('/bulk-url-check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ urls }) });
        const data = await res.json();
        if (data.success) {
            const c = document.getElementById('bulkResults'); c.style.display = 'block';
            c.innerHTML = data.results.map(r => {
                const col = r.risk_score >= 60 ? 'var(--danger)' : r.risk_score >= 30 ? 'var(--warning)' : 'var(--success)';
                return `<div class="bulk-item"><div class="bulk-url">${truncate(r.url,50)}</div><span class="bulk-risk" style="background:${col};color:white">${r.risk_level||'Error'}</span></div>`;
            }).join('');
        }
    } catch (e) { alert('Failed'); }
    finally { hideLoading(); }
}

// URL Expander
async function expandUrl() {
    const url = document.getElementById('shortUrl').value.trim();
    if (!url) { alert('Enter URL'); return; }
    showLoading('Expanding...');
    try {
        const res = await fetch('/expand-url', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
        const d = await res.json();
        if (d.success) {
            const r = document.getElementById('expandResult'); r.style.display = 'block';
            r.innerHTML = `<strong>Original:</strong> ${d.original_url}<br><strong>Final:</strong> ${d.final_url}<br><strong>Redirects:</strong> ${d.redirect_count}`;
        }
    } catch (e) { alert('Failed'); }
    finally { hideLoading(); }
}

// ============================================
// QR Scanner
// ============================================
const qrArea = document.getElementById('qrUploadArea'), qrInput = document.getElementById('qrFileInput');
qrArea.addEventListener('click', () => qrInput.click());
qrArea.addEventListener('dragover', e => { e.preventDefault(); qrArea.classList.add('dragover'); });
qrArea.addEventListener('dragleave', () => qrArea.classList.remove('dragover'));
qrArea.addEventListener('drop', e => { e.preventDefault(); qrArea.classList.remove('dragover'); if (e.dataTransfer.files.length) handleQrFile(e.dataTransfer.files[0]); });
qrInput.addEventListener('change', e => { if (e.target.files.length) handleQrFile(e.target.files[0]); });

function handleQrFile(file) {
    if (!file.type.startsWith('image/')) { alert('Upload image'); return; }
    const reader = new FileReader();
    reader.onload = e => {
        qrImageData = e.target.result;
        document.getElementById('qrPreviewImg').src = qrImageData;
        document.getElementById('qrPreview').style.display = 'block';
        qrArea.style.display = 'none';
        document.getElementById('scanQrBtn').disabled = false;
    };
    reader.readAsDataURL(file);
}

function clearQrPreview() {
    qrImageData = null;
    document.getElementById('qrPreview').style.display = 'none';
    qrArea.style.display = 'block';
    document.getElementById('scanQrBtn').disabled = true;
    document.getElementById('qrResults').style.display = 'none';
}

async function scanQrCode() {
    if (!qrImageData) { alert('Upload QR image'); return; }
    showLoading('Scanning QR...');
    try {
        const res = await fetch('/scan-qr', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ image: qrImageData }) });
        const d = await res.json();
        document.getElementById('qrResults').style.display = 'block';
        document.getElementById('qrResultsBody').innerHTML = d.success && d.results ? d.results.map(r => `<div style="padding:15px;background:var(--bg-input);border-radius:8px;margin-bottom:15px"><div style="font-family:monospace;word-break:break-all">${esc(r.data)}</div>${r.is_url ? `<button class="btn btn-primary btn-sm" style="margin-top:10px" onclick="analyzeUrlFromEmail('${esc(r.data)}')">Analyze URL</button>` : ''}</div>`).join('') : `<p style="color:var(--danger)">❌ ${d.error || 'No QR found'}</p>`;
    } catch (e) { alert('Failed'); }
    finally { hideLoading(); }
}

// ============================================
// Header Analyzer
// ============================================
async function analyzeHeaders() {
    const headers = document.getElementById('headerInput').value.trim();
    if (!headers) { alert('Paste headers'); return; }
    showLoading('Analyzing headers...');
    try {
        const res = await fetch('/analyze-headers', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ headers }) });
        const d = await res.json();
        document.getElementById('headerResults').style.display = 'block';
        if (d.success) {
            const a = d.authentication;
            document.getElementById('headerResultsBody').innerHTML = `
                <h3>📧 Basic Info</h3>
                <div class="info-grid">
                    <div class="info-item"><div class="info-label">From</div><div class="info-value">${esc(d.basic_info.from||'N/A')}</div></div>
                    <div class="info-item"><div class="info-label">Subject</div><div class="info-value">${esc(d.basic_info.subject||'N/A')}</div></div>
                </div>
                <h3 style="margin-top:20px">🔐 Authentication</h3>
                <div class="info-grid">
                    <div class="info-item"><div class="info-label">SPF</div><div class="info-value" style="color:${authCol(a.spf.status)}">${a.spf.status.toUpperCase()}</div></div>
                    <div class="info-item"><div class="info-label">DKIM</div><div class="info-value" style="color:${authCol(a.dkim.status)}">${a.dkim.status.toUpperCase()}</div></div>
                    <div class="info-item"><div class="info-label">DMARC</div><div class="info-value" style="color:${authCol(a.dmarc.status)}">${a.dmarc.status.toUpperCase()}</div></div>
                    <div class="info-item"><div class="info-label">Risk</div><div class="info-value">${d.risk_level.toUpperCase()} (${d.risk_score})</div></div>
                </div>
                ${d.security_analysis.length ? `<h3 style="margin-top:20px">⚠️ Findings</h3><ul class="findings-list">${d.security_analysis.map(f=>`<li><strong>${f.severity}:</strong> ${f.finding}</li>`).join('')}</ul>` : ''}
            `;
        } else document.getElementById('headerResultsBody').innerHTML = `<p style="color:var(--danger)">❌ ${d.error}</p>`;
    } catch (e) { alert('Failed'); }
    finally { hideLoading(); }
}

function authCol(s) { return s === 'pass' ? 'var(--success)' : s === 'fail' ? 'var(--danger)' : 'var(--warning)'; }

// ============================================
// History
// ============================================
async function loadHistory(type = null) {
    try {
        const res = await fetch(type ? `/history?type=${type}` : '/history');
        const d = await res.json();
        if (d.success) { displayStats(d.stats); displayHistory(d.scans); }
    } catch (e) { console.error(e); }
}

function displayStats(s) {
    document.getElementById('totalScans').textContent = s.total_scans || 0;
    document.getElementById('emailScans').textContent = s.by_type?.email || 0;
    document.getElementById('urlScans').textContent = s.by_type?.url || 0;
    document.getElementById('highRiskCount').textContent = s.high_risk_count || 0;
}

function displayHistory(scans) {
    const c = document.getElementById('historyList');
    if (!scans?.length) { c.innerHTML = '<p class="empty-state">No scans yet</p>'; return; }
    c.innerHTML = scans.map(s => {
        const col = s.risk_level.toLowerCase().includes('high') ? 'var(--danger)' : s.risk_level.toLowerCase().includes('medium') ? 'var(--warning)' : 'var(--success)';
        return `<div class="history-item"><div class="history-info"><div class="history-type">${s.type}</div><div class="history-target">${truncate(s.target,60)}</div><div class="history-time">${new Date(s.timestamp).toLocaleString()}</div></div><span class="history-risk" style="background:${col};color:white">${s.risk_score}</span></div>`;
    }).join('');
}

function filterHistory(type, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    loadHistory(type === 'all' ? null : type);
}

async function searchHistory() {
    const q = document.getElementById('historySearch').value.trim();
    if (!q) { loadHistory(); return; }
    const res = await fetch(`/history/search?q=${encodeURIComponent(q)}`);
    const d = await res.json();
    if (d.success) displayHistory(d.results);
}

async function clearHistory() {
    if (!confirm('Clear all history?')) return;
    await fetch('/history/clear', { method: 'POST' });
    loadHistory();
}

// ============================================
// Threat Feed
// ============================================
async function loadThreatFeed() {
    showLoading('Loading threats...');
    try {
        const res = await fetch('/threat-feed');
        const d = await res.json();
        document.getElementById('threatFeed').innerHTML = d.success && d.feed.items.length ? 
            `<p style="font-size:0.8rem;color:var(--text-muted);margin-bottom:15px">Sources: ${d.feed.sources.join(', ')}</p>` +
            d.feed.items.slice(0,20).map(i => `<div class="threat-item"><div class="threat-url">${truncate(i.url,60)}</div><div class="threat-meta">${i.source} • ${i.threat_type||'phishing'}</div></div>`).join('') :
            '<p class="empty-state">No threats</p>';
    } catch (e) { document.getElementById('threatFeed').innerHTML = '<p class="empty-state">Failed to load</p>'; }
    finally { hideLoading(); }
}

// ============================================
// Learning Center
// ============================================
async function loadLearningContent() {
    try {
        const [tips, types, actions] = await Promise.all([
            fetch('/learning/tips').then(r => r.json()),
            fetch('/learning/types').then(r => r.json()),
            fetch('/learning/actions').then(r => r.json())
        ]);
        
        if (tips.success) document.getElementById('phishingTips').innerHTML = tips.tips.map(t => `<div class="tip-card"><h4>${t.title}</h4><p>${t.description}</p><div class="tip-example">${t.example}</div></div>`).join('');
        if (types.success) document.getElementById('phishingTypes').innerHTML = types.types.map(t => `<div class="type-card"><h4>${t.type}</h4><p>${t.description}</p><p style="font-size:0.8rem;color:var(--text-muted)">Targets: ${t.targets}</p></div>`).join('');
        if (actions.success) {
            const a = actions.actions;
            document.getElementById('whatToDo').innerHTML = `
                <div class="action-card"><h4>📧 Received Suspicious Email</h4><ul>${a.if_received.map(x=>`<li>${x}</li>`).join('')}</ul></div>
                <div class="action-card"><h4>🖱️ Clicked a Link</h4><ul>${a.if_clicked.map(x=>`<li>${x}</li>`).join('')}</ul></div>
                <div class="action-card"><h4>🔐 Entered Information</h4><ul>${a.if_entered_info.map(x=>`<li>${x}</li>`).join('')}</ul></div>
            `;
        }
    } catch (e) { console.error(e); }
}

// ============================================
// PDF Reports
// ============================================
async function generateEmailReport() {
    if (!window.lastEmailAnalysis) { alert('No analysis'); return; }
    showLoading('Generating PDF...');
    try {
        const res = await fetch('/generate-report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'email', data: window.lastEmailAnalysis }) });
        if (res.ok) { const blob = await res.blob(); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `email_report_${Date.now()}.pdf`; a.click(); }
        else alert('Failed - PDF may not be available');
    } catch (e) { alert('Failed'); }
    finally { hideLoading(); }
}

async function generateUrlReport() {
    if (!window.lastUrlAnalysis) { alert('No analysis'); return; }
    showLoading('Generating PDF...');
    try {
        const res = await fetch('/generate-report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'url', data: window.lastUrlAnalysis }) });
        if (res.ok) { const blob = await res.blob(); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `url_report_${Date.now()}.pdf`; a.click(); }
        else alert('Failed');
    } catch (e) { alert('Failed'); }
    finally { hideLoading(); }
}

// Feedback
async function submitFeedback(isPhishing) {
    if (!lastAnalyzedEmail) { alert('No email'); return; }
    await fetch('/feedback', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subject: lastAnalyzedEmail.subject, body: lastAnalyzedEmail.body, is_phishing: isPhishing }) });
    alert('Thank you!');
}

// ============================================
// Utilities
// ============================================
function setupCollapsibles() {
    document.querySelectorAll('.collapsible .section-toggle').forEach(t => { t.onclick = function() { this.parentElement.classList.toggle('open'); }; });
}

function truncate(t, n) { return t.length > n ? t.substring(0, n-3) + '...' : t; }
function esc(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

// Init
document.addEventListener('DOMContentLoaded', () => { setupCollapsibles(); console.log('🛡️ Phishing Intelligence Platform v5.0'); });



// ============================================
// ADD THESE FUNCTIONS TO THE END OF YOUR app.js
// ============================================

// ============================================
// Screenshot
// ============================================
// ============================================
// REPLACE your captureScreenshot function in app.js with this one
// ============================================

async function captureScreenshot() {
    if (!window.lastUrlAnalysis) { 
        alert('Analyze a URL first'); 
        return; 
    }
    
    const url = window.lastUrlAnalysis.url;
    const section = document.getElementById('screenshotSection');
    const preview = document.getElementById('screenshotPreview');
    
    section.style.display = 'block';
    preview.innerHTML = '<div class="screenshot-loading" style="padding:40px;text-align:center;color:var(--text-secondary);">📸 Capturing screenshot...</div>';
    
    try {
        const res = await fetch('/screenshot', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        
        console.log('Screenshot response:', data); // Debug log
        
        if (data.success) {
            let html = '';
            
            // Show safety warnings if any
            if (data.safety && data.safety.warnings && data.safety.warnings.length > 0) {
                html += `<div style="background:rgba(245,158,11,0.1);border:1px solid var(--warning);border-radius:8px;padding:10px;margin-bottom:15px;font-size:0.85rem;color:var(--warning);">⚠️ ${data.safety.warnings.join(', ')}</div>`;
            }
            
            // Display the screenshot
            if (data.screenshot_base64) {
                html += `<img src="data:image/png;base64,${data.screenshot_base64}" alt="Screenshot" style="max-width:100%;border-radius:8px;border:1px solid var(--border-color);">`;
            } else if (data.screenshot_url) {
                html += `<img src="${data.screenshot_url}" alt="Screenshot" style="max-width:100%;border-radius:8px;border:1px solid var(--border-color);" onerror="this.onerror=null;this.src='';this.alt='Screenshot could not be loaded';this.style.padding='40px';this.style.background='var(--bg-input)';this.style.display='block';this.style.textAlign='center';">`;
                if (data.note) {
                    html += `<p style="font-size:0.8rem;color:var(--text-muted);margin-top:10px;text-align:center;">${data.note}</p>`;
                }
            } else {
                html = '<p style="color:var(--text-muted);text-align:center;padding:20px;">Screenshot captured but no image data received</p>';
            }
            
            preview.innerHTML = html;
        } else {
            preview.innerHTML = `<p style="color:var(--danger);text-align:center;padding:20px;">❌ ${data.error || 'Screenshot failed'}</p>`;
        }
    } catch (e) {
        console.error('Screenshot error:', e);
        preview.innerHTML = '<p style="color:var(--danger);text-align:center;padding:20px;">❌ Failed to capture screenshot - network error</p>';
    }
}
