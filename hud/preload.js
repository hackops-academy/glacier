const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('glacierBridge', {
  request: (baseUrl, apiPath, opts) =>
    ipcRenderer.invoke('api-request', { baseUrl, apiPath, ...opts }),
  saveReport: (defaultName, content) =>
    ipcRenderer.invoke('save-report', { defaultName, content }),
});
