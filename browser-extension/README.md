# 🛡️ Phishing Link Analyzer - Browser Extension

A Chrome/Edge browser extension that lets you right-click any link to analyze it for phishing threats.

## Installation

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select this `browser-extension` folder

## Before Using

Add icons to the `icons/` folder:
- `icon16.png` - 16x16 pixels
- `icon48.png` - 48x48 pixels  
- `icon128.png` - 128x128 pixels

You can download shield icons from https://favicon.io/emoji-favicons/shield/

## Usage

### Right-Click Menu
1. Right-click any link on a webpage
2. Select "🛡️ Analyze Link for Phishing"
3. A notification will show the result

### Popup
1. Click the extension icon
2. Paste any URL
3. Click "Analyze" or "Quick"

## Files

- `manifest.json` - Extension configuration
- `background.js` - Background service worker
- `popup.html` - Popup UI
- `popup.js` - Popup logic
- `icons/` - Extension icons
