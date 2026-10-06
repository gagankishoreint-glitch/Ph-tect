// Popup script for Phishing Link Analyzer
const API_BASE_URL = 'https://enterprise-phishing-detector.onrender.com';

const urlInput = document.getElementById('urlInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const quickBtn = document.getElementById('quickBtn');
const loading = document.getElementById('loading');
const result = document.getElementById('result');
const error = document.getElementById('error');

document.addEventListener('DOMContentLoaded', async () => {
  const data = await chrome.storage.local.get(['currentUrl', 'result', 'analyzing']);
  if (data.analyzing) {
    showLoading();
  } else if (data.result && data.result.success) {
    displayResult(data.result, data.currentUrl);
  }
});

analyzeBtn.addEventListener('click', () => {
  const url = urlInput.value.trim();
  if (url) analyzeUrl(url, false);
});

quickBtn.addEventListener('click', () => {
  const url = urlInput.value.trim();
  if (url) analyzeUrl(url, true);
});

urlInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    const url = urlInput.value.trim();
    if (url) analyzeUrl(url, false);
  }
});

async function analyzeUrl(url, quickCheck = false) {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  
  showLoading();
  hideError();
  
  try {
    const endpoint = quickCheck ? '/quick-url-check' : '/analyze-url';
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    
    const data = await response.json();
    
    if (data.success) {
      displayResult(data, url);
      await chrome.storage.local.set({ currentUrl: url, result: data, analyzing: false });
    } else {
      showError(data.error || 'Analysis failed');
    }
  } catch (err) {
    showError('Could not connect to server.');
    console.error(err);
  }
  
  hideLoading();
}

function displayResult(data, url) {
  result.classList.add('show');
  
  const score = data.danger_score || data.risk_score || 0;
  const level = data.risk_level || data.verdict || 'Unknown';
  
  let icon, color;
  if (score >= 60) { icon = '🚨'; color = '#ef4444'; }
  else if (score >= 30) { icon = '⚠️'; color = '#f59e0b'; }
  else { icon = '✅'; color = '#10b981'; }
  
  document.getElementById('riskIcon').textContent = icon;
  document.getElementById('riskLevel').textContent = level;
  document.getElementById('riskLevel').style.color = color;
  document.getElementById('riskScore').textContent = score;
  document.getElementById('riskScore').style.color = color;
  document.getElementById('urlDisplay').textContent = url;
  
  const findingsContainer = document.getElementById('findings');
  const reasons = data.reasons || data.findings || [];
  
  if (reasons.length > 0) {
    findingsContainer.innerHTML = `
      <h4>⚠️ Risk Factors</h4>
      ${reasons.slice(0, 5).map(r => `<div class="finding-item"><span>•</span><span>${escapeHtml(r)}</span></div>`).join('')}
      ${reasons.length > 5 ? `<div class="finding-item">+ ${reasons.length - 5} more...</div>` : ''}
    `;
  } else {
    findingsContainer.innerHTML = '<div class="finding-item" style="color: #10b981;">✅ No risk factors detected</div>';
  }
  
  document.getElementById('openFull').href = API_BASE_URL;
}

function showLoading() { loading.style.display = 'block'; result.classList.remove('show'); }
function hideLoading() { loading.style.display = 'none'; }
function showError(message) { error.textContent = message; error.style.display = 'block'; result.classList.remove('show'); }
function hideError() { error.style.display = 'none'; }
function escapeHtml(text) { const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }
