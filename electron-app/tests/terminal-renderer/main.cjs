const { app, BrowserWindow, protocol, net, session } = require('electron');
const { readFileSync, writeFileSync } = require('node:fs');
const { resolve, relative, isAbsolute, join } = require('node:path');
const { pathToFileURL } = require('node:url');
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
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
    win = new BrowserWindow({ width: config.width, height: config.height, useContentSize: true, show: false,
      webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true, webviewTag: false, backgroundThrottling: false, offscreen: true } });
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    await win.loadURL('pmapp://local/index.html');
    win.webContents.focus();
    const deadline = Date.now() + 30000;
    let result;
    while (!result && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100));
      result = await win.webContents.executeJavaScript('window.__terminalTestResult');
    }
    if (!result) throw new Error('Terminal fixture timed out');
    writeFileSync(join(config.root, `result-${config.width}.json`), JSON.stringify(result, null, 2));
    writeFileSync(join(config.root, `terminal-${config.width}.png`), (await win.webContents.capturePage()).toPNG());
    console.log(JSON.stringify(result));
    win.destroy();
    app.exit(result.passed ? 0 : 1);
  } catch (error) {
    console.error(error.message); win?.destroy(); app.exit(1);
  }
});
