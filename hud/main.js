const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 920,
    backgroundColor: '#080a10',
    title: 'GLACIER // HUD',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile('index.html');
}

// Runs in Node (main process), not the renderer's browser context - so
// there is no CORS restriction at all, regardless of what method or
// body is used. Supports GET (with query params) and POST/PATCH/DELETE
// (with JSON bodies where relevant), which is everything the glacier
// API needs.
ipcMain.handle('api-request', async (event, { baseUrl, apiPath, method, params, body }) => {
  let url = baseUrl.replace(/\/$/, '') + apiPath;
  const opts = { method: method || 'GET', headers: {} };

  if (params && Object.keys(params).length) {
    const qs = new URLSearchParams(params).toString();
    url += (url.includes('?') ? '&' : '?') + qs;
  }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }

  try {
    const res = await fetch(url, opts);
    let data;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) {
      return { ok: false, status: res.status, error: (data && data.error) || 'HTTP ' + res.status };
    }
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

// Native save dialog for the report export feature - the renderer builds
// the HTML report content, this actually writes it to disk.
ipcMain.handle('save-report', async (event, { defaultName, content }) => {
  const win = BrowserWindow.getFocusedWindow();
  const result = await dialog.showSaveDialog(win, {
    defaultPath: defaultName,
    filters: [{ name: 'HTML Report', extensions: ['html'] }],
  });
  if (result.canceled || !result.filePath) {
    return { ok: false, canceled: true };
  }
  try {
    fs.writeFileSync(result.filePath, content, 'utf-8');
    return { ok: true, path: result.filePath };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
