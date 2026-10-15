const { app, BrowserWindow, protocol, net, session } = require('electron');
const { mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { resolve, relative, isAbsolute, join } = require('node:path');
const { pathToFileURL } = require('node:url');
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const profile = join(config.root, `profile-${config.width}`);
mkdirSync(profile, { recursive: true }); app.setPath('userData', profile);
protocol.registerSchemesAsPrivileged([{ scheme: 'pmapp', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: false } }]);
app.whenReady().then(async () => {
  let win;
  try {
    protocol.handle('pmapp', request => {
      const url = new URL(request.url);
      const file = resolve(config.root, `.${decodeURIComponent(url.pathname)}`);
      const relation = relative(config.root, file);
      if (url.hostname !== 'local' || request.method !== 'GET' || relation.startsWith('..') || isAbsolute(relation)) return new Response('Denied', { status: 403 });
      return net.fetch(pathToFileURL(file).toString());
    });
    session.defaultSession.webRequest.onHeadersReceived((details, callback) => callback({ responseHeaders: {
      ...details.responseHeaders, 'Content-Security-Policy': [config.csp], 'X-Content-Type-Options': ['nosniff']
    } }));
    session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    // Offscreen synthetic fixture has no production preload or secret-bearing state.
    win = new BrowserWindow({ width: config.width, height: config.height, useContentSize: true, show: false,
      webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true, webviewTag: false, backgroundThrottling: false, offscreen: true } });
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    await win.loadURL('pmapp://local/index.html');
    win.webContents.focus();
    const deadline = Date.now() + 30000;
    let result;
    let workspaceCaptured = false;
    while (!result && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100));
      result = await win.webContents.executeJavaScript('window.__historyTestResult');
      if (!workspaceCaptured && await win.webContents.executeJavaScript('!!document.querySelector(".explorer-grid") && !document.querySelector(".modal-backdrop")')) {
        writeFileSync(join(config.root, `workspace-${config.width}.png`), (await win.webContents.capturePage()).toPNG());
        workspaceCaptured = true;
      }
    }
    if (!result) throw new Error('History fixture timed out');
    writeFileSync(join(config.root, `result-${config.width}.json`), JSON.stringify(result, null, 2));
    writeFileSync(join(config.root, `history-${config.width}.png`), (await win.webContents.capturePage()).toPNG());
    console.log(JSON.stringify(result));
    win.destroy();
    app.exit(result.passed ? 0 : 1);
  } catch (error) {
    console.error(error.message); win?.destroy(); app.exit(1);
  }
});
