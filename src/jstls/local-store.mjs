/**
 * local-store.mjs —— **在页面里**假冒索尼商店（对应 backend/market.py）。
 *
 * 它把「我们以前跑在 127.0.0.1 上的那个 https 服务」整个搬进浏览器：终结 TLS 用
 * TlsServerSession，应答规则照抄上游 LocalMarketServer，spk 用 spk.mjs 现场打。
 *
 * 对外接口刻意做成与老的 `src/bridge.js`（BackendBridge，已删）**同形**，
 * （open/send/poll/closeConn + CLOSED），这样 installer.js 的主循环一行都不用改：
 *   以前：相机字节 → WebSocket → Python ssl → market.py
 *   现在：相机字节 → 就在这儿 → tls-server.mjs → 本文件
 */

import { bytesFromHex, concat, latin1, latin1Bytes, utf8Bytes } from './bytes.mjs';
import { parsePem } from './rsa.mjs';
import { TlsServerSession } from './tls-server.mjs';
import * as spk from './spk.mjs';
import * as xpd from './xpd.mjs';
import * as K from './sony-keys.mjs';
// ⚠️ **必须用 installer.js 里那个符号，不能自己 new 一个**（真机踩过）：
//     installer.js 的主循环靠 `chunk === CLOSED` 判断「对端关了 ⇒ 给相机发 ProxyEnd」，
//     而 Symbol() 每次调用都是**新的**、跨模块永不相等 ⇒ 那条分支成了死代码，
//     表现是：相机拿到 dlandinstall 应答、发完 close_notify 后就不再往下走（不开下载那条隧道）。
import { CLOSED } from '../installer.js';

/** 与老的 bridge.js（已删）的 CLOSED 语义一致（每条连接用完就报一次）。 */
export { CLOSED };

const JSON_MIME = K.SPK_MIME_TYPE; // 上游怪癖：JSON 也用 spk 的 mime，相机只认这个

/** 相机随后 GET 的就是这个（host 会被我们忽略，上游 market.py 也是这么写的）。 */
const SPK_URL = 'https://127.0.0.1/';

/** 极简 printf：把 %s/%d 依次换掉（tls-server 里就是这么写日志的）。 */
export function sprintf(fmt, args) {
  let i = 0;
  return String(fmt).replace(/%[sd]/g, () => (i < args.length ? String(args[i++]) : '%'));
}

function jsonBody(headers, data) {
  const head = headers.join('\r\n');
  return concat(latin1Bytes(head + '\r\n\r\n'), data);
}

export class LocalMarketStore {
  /**
   * @param {object} opts
   *   prim       原语（purePrimitives()）
   *   certPem    证书 PEM 文本（certs/localtest.me.pem）
   *   apk        要装的 apk 字节
   *   appName    上报给相机的 app 名（与上游一样默认 'app'）
   *   onLog      日志
   *   onEvent    (kind, payload) 事件（camera-report / spk-served / result …）
   */
  constructor(opts) {
    this.prim = opts.prim;
    this.onLog = opts.onLog || (() => {});
    this.onEvent = opts.onEvent || (() => {});
    this.appName = opts.appName || 'app';
    this.apk = opts.apk || null;
    this.result = null;
    this.cameraReport = null;
    this.spkBytes = 0;
    this.firstPost = null;

    const parsed = parsePem(opts.certPem);
    this.key = parsed.key;
    this.certs = parsed.certs;
    this.sessions = new Map();
    this.closedIds = new Set();
    this.pending = new Map(); // connId -> 待取走的字节
    // RFC 5077 会话票表（**跨连接共用**）：相机在下载那条连接上会拿票来续会。
    // 当年跑通那次对面是 OpenSSL，它给票；我们不给的话就与实测过的形状不一样了。
    this.tickets = new Map();
  }

  /** 换一个要装的 apk（界面里选完文件调用）。 */
  setApk(bytes, appName) {
    this.apk = bytes;
    if (appName) this.appName = appName;
  }

  /** 生成 xpd（界面里「② 安装」开始时调用，等价于后台 startTask）。 */
  startTask() {
    return xpd.build();
  }

  // ---------------------------------------------------------------- bridge 接口
  open(connId, host, port) {
    this.closedIds.delete(connId);
    const session = new TlsServerSession({
      prim: this.prim,
      key: this.key,
      certs: this.certs,
      tickets: this.tickets,
      label: 'conn' + connId,
      log: (m, ...rest) => this.onLog(sprintf(m, rest)),
      requestHandler: (req) => this._onHttpRequest(connId, req),
    });
    this.sessions.set(connId, session);
    this.pending.set(connId, new Uint8Array(0));
    this.onLog('      fake store (in-page): camera wants ' + host + ':' + port + ' → we terminate TLS ourselves');
  }

  send(connId, data) {
    const session = this.sessions.get(connId);
    if (session === undefined) return;
    session.feed(data);
    this._collect(connId, session);
  }

  /** 返回 Uint8Array（要给相机发的字节）/ CLOSED（对端已关）/ null（暂时没话说）。 */
  poll(connId) {
    const session = this.sessions.get(connId);
    const chunk = this.pending.get(connId);
    // 先把还没发出去的字节交出去，再报「已关」——否则最后一条记录/alert 会丢
    if (chunk !== undefined && chunk.length) {
      this.pending.set(connId, new Uint8Array(0));
      return chunk;
    }
    if (session === undefined) return null;
    if (session.closed) {
      this.sessions.delete(connId);
      if (!this.closedIds.has(connId)) {
        this.closedIds.add(connId);
        return CLOSED;
      }
      return null;
    }
    return null;
  }

  closeConn(connId) {
    const session = this.sessions.get(connId);
    if (session !== undefined) session.shutdown();
    this.sessions.delete(connId);
    this.closedIds.add(connId);
  }

  /** 相机主动断开（对应 Python 侧 socket EOF）。 */
  _collect(connId, session) {
    const out = session.drain();
    if (out !== null) {
      this.pending.set(connId, concat(this.pending.get(connId) || new Uint8Array(0), out));
    }
  }

  // ---------------------------------------------------------------- 假商店的应答规则
  _onHttpRequest(connId, req) {
    this.onLog(
      '      [conn' + connId + '] HTTP request: ' + req.method + ' ' + req.url +
        ' (body ' + req.body.length + ' bytes, Content-Length=' + (req.headers['content-length'] || 'none') + ')'
    );
    if (req.method === 'POST') {
      const first = this.result === null;
      if (first) {
        this.firstPost = req.body;
        this.cameraReport = req.body;
        this.onEvent('camera-report', req.body);
      } else {
        this.onEvent('camera-result', req.body);
      }
      this.result = req.body;
      const body = first && this.apk !== null ? this._installAction() : latin1Bytes('{"actions": []}');
      this.onLog(
        '      [conn' + connId + '] → responding ' + (first && this.apk !== null ? 'with the "go download and install" action' : 'with empty actions') +
          ' (' + body.length + ' bytes' + (first ? ', first report of this task' : ', the camera handing in its result') + ')'
      );
      const head = [
        'HTTP/1.1 200 OK',
        // 下面两行与当年跑通那次的应答同形（Python 的 BaseHTTPRequestHandler 会自动加
        // Server/Date）。内容无关紧要，但既然有一个实测跑通的样本，就别自己少东西。
        'Server: LocalMarketServer/1.0',
        'Date: ' + new Date().toUTCString(),
        'Connection: Keep-Alive',
        'Content-Type: ' + JSON_MIME,
        'Content-Length: ' + body.length,
      ];
      this.onLog(
        '      [conn' + connId + '] response to send (' + (head.join('\r\n').length + 4 + body.length) + ' bytes):\n' +
          head.map((h) => '        ' + h).join('\n') +
          '\n        ' + latin1(body)
      );
      return jsonBody(head, body);
    }

    // GET → 现场打 spk 吐给相机
    if (this.apk === null) {
      const body = latin1Bytes('{"actions": []}');
      return jsonBody(
        ['HTTP/1.1 200 OK', 'Connection: Keep-Alive', 'Content-Type: ' + JSON_MIME, 'Content-Length: ' + body.length],
        body
      );
    }
    const data = spk.dump(this.apk);
    this.spkBytes = data.length;
    this.onEvent('spk-served', data.length);
    return jsonBody(
      [
        'HTTP/1.1 200 OK',
        'Connection: Keep-Alive',
        'Content-Type: ' + K.SPK_MIME_TYPE,
        'Content-Length: ' + data.length,
        'Content-Disposition: attachment;filename="app' + K.SPK_EXTENSION + '"',
      ],
      data
    );
  }

  /**
   * 「去下载并安装」动作。
   *
   * **与上游 `json.dumps(...)` 逐字节同形**（连 `": "` / `", "` 那两处空格都照拄）：
   * 相机那侧是 2013 年的手写解析器，当年跑通那次的正文是 128 字节（带空格）。
   * 紧凑写法少 9 字节而没有任何好处，这种地方不值得自己省事。
   */
  _installAction() {
    return utf8Bytes(
      '{"actions": [{"command": "dlandinstall", "args": ' +
        JSON.stringify(SPK_URL) +
        ', "attrs": [{"attrname": "appname", "attrvalue": ' +
        JSON.stringify(this.appName) +
        '}]}]}'
    );
  }
}

export { bytesFromHex };
