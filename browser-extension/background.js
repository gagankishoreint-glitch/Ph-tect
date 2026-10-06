// Background service worker for Phishing Link Analyzer

// Your deployed API URL - UPDATE THIS after deploying
const API_BASE_URL = 'https://enterprise-phishing-detector.onrender.com';

// Create context menu on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'analyzeLink',
    title: '🛡️ Analyze Link for Phishing',
    contexts: ['link']
  });
  
  chrome.contextMenus.create({
    id: 'quickCheck',
    title: '⚡ Quick Check Link',
    contexts: ['link']
  });
  
  console.log('Phishing Link Analyzer extension installed');
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.linkUrl;
  
  if (info.menuItemId === 'analyzeLink') {
    await analyzeUrl(url, false);
  } else if (info.menuItemId === 'quickCheck') {
    await analyzeUrl(url, true);
  }
});

// Analyze URL function
async function analyzeUrl(url, quickCheck = false) {
  try {
    await chrome.storage.local.set({ 
      analyzing: true, 
      currentUrl: url,
      result: null 
    });
    
    const endpoint = quickCheck ? '/quick-url-check' : '/analyze-url';
    
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    
    const data = await response.json();
    
    await chrome.storage.local.set({
      analyzing: false,
      currentUrl: url,
      result: data,
      timestamp: Date.now()
    });
    
    if (data.success) {
      const riskScore = data.danger_score || data.risk_score || 0;
      const riskLevel = data.risk_level || data.verdict || 'Unknown';
      
      let notificationTitle = '🛡️ Link Analysis Complete';
      
      if (riskScore >= 60) {
        notificationTitle = '🚨 HIGH RISK DETECTED!';
      } else if (riskScore >= 30) {
        notificationTitle = '⚠️ Suspicious Link';
      } else {
        notificationTitle = '✅ Link Appears Safe';
      }
      
      chrome.notifications?.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: notificationTitle,
        message: `${riskLevel}\nScore: ${riskScore}/100\nClick extension icon for details.`,
        priority: riskScore >= 60 ? 2 : 1
      });
    }
    
  } catch (error) {
    console.error('Analysis error:', error);
    await chrome.storage.local.set({
      analyzing: false,
      result: { success: false, error: error.message },
      timestamp: Date.now()
    });
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getApiUrl') {
    sendResponse({ apiUrl: API_BASE_URL });
  }
  return true;
});
