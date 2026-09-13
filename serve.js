#!/usr/bin/env node
/**
 * 零依赖静态服务器（自用）。
 *
 * 为什么必须有它：WebUSB 只能在**安全上下文**里用（https 或 http://localhost），
 * 直接双击 dist/index.html（file://）打不开设备；而页面还要 fetch 证书、动态 import
 * 模块，也都得走 http。
 *
 * 它把**项目根**当站点根 —— 于是 /dist/ 是页面、/src/ 是源码回退路径；
 * 并且给所有响应加 `Cache-Control: no-store`：改完源码刷新就能看到，不会被浏览器缓存住
 * （构建产物尤其容易被缓存住，踩过）。
 *
 * 用法：node serve.js [--port 8765]
 *       然后打开  http://127.0.0.1:8765/dist/
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const argv = process.argv.slice(2);
const portIdx = argv.indexOf('--port');
const PORT = portIdx >= 0 ? Number(argv[portIdx + 1]) : Number(process.env.PORT || 8765);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.pem': 'application/x-pem-file',
  '.apk': 'application/vnd.android.package-archive',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
};

http
  .createServer((req, res) => {
    const url = decodeURIComponent(String(req.url || '/').split('?')[0]);
    if (url === '/' || url === '') {
      res.writeHead(302, { Location: '/dist/' });
      return res.end();
    }
    // 只允许访问项目内的文件（把 .. 之类挡掉）
    const rel = path.normalize(url).replace(/^(\.[/\\])+/, '').replace(/^[/\\]+/, '');
    let file = path.join(ROOT, rel);
    try {
      if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
    } catch (e) {
      /* 不存在就当 404 处理 */
    }
    fs.readFile(file, (err, data) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end('404 ' + rel);
      }
      res.writeHead(200, {
        'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
        'Cache-Control': 'no-store',
      });
      res.end(data);
    });
  })
  .listen(PORT, '127.0.0.1', () => {
    console.log('已启动（no-store）：');
    console.log('  页面  http://127.0.0.1:' + PORT + '/dist/');
    console.log('  说明  WebUSB 要求安全上下文 —— localhost 算，file:// 不算；别双击 index.html。');
  });
