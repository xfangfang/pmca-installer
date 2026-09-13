/**
 * tls-server.mjs —— 在（浏览器/Node 里）**当相机的 TLS 服务端**，替掉 backend 那一整套。
 *
 * 这是「彻底变成静态网页」的关键：相机把 TLS 裸字节经 USB 交给我们，以前我们把它经 WebSocket
 * 倒给本机 Python 的 ssl 去终结；现在就地终结 —— 于是假商店、spk、xpd 全在页面里，
 * 没有后端、没有网络。
 *
 * 状态机（只做相机要的那条路：TLS1.0 + RSA 密钥交换 + AES-CBC-SHA）：
 *   expectCH      收 ClientHello（挑 0x0035/0x002f）→ 回 ServerHello + Certificate + ServerHelloDone
 *   expectCKE     收 ClientKeyExchange → 裸 RSA 解 premaster → 推 master secret/key block
 *   expectCCS     收（明文）ChangeCipherSpec
 *   expectFin     收**加密**的 Finished（seq 0）→ 校验 verify_data
 *                 → 回 ChangeCipherSpec + 加密的 Finished（seq 0）
 *   established   解应用数据 → 交给 requestHandler(HTTP 请求) → 把返回的字节加密发回
 *
 * 会话票（RFC 5077）：相机给了 ticket 扩展 ⇒ ServerHello 里回一个空的同名扩展，
 * 并在客户端 Finished 之后补一张 NewSessionTicket（顺序 = 票 → CCS → Finished，与 OpenSSL 一致）。
 * **但我们不续会**：客户端带票回来时一律回完整握手（并补发新票）—— RFC 5077 Figure 4 就是这条。
 * 为什么不做简握手：客户端那条 Finished 的握手串，拿 OpenSSL 客户端实测对不上
 *（服务端那条对得上，见下文），而简握手我们没有任何实测支撑；完整握手则是真机跑通过的那条。
 *
 * 有意与上游（Python 的 ssl）不同、但合规的地方：
 *   · 不续会（见上）；
 *   · ServerHello 里带一个**空的 renegotiation_info**（客户端带了 SCSV，回它最稳）。
 */

import {
  HS,
  RECORD,
  SUITES,
  TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
  Transcript,
  buildCertificate,
  buildFinished,
  buildServerHello,
  buildServerHelloDone,
  concat,
  decryptRecord,
  deriveKeys,
  encryptRecord,
  finishedVerifyData,
  handshake,
  lenPrefix,
  parseClientHello,
  record,
  splitRecords,
  toHex,
} from './tls10.mjs';
import { rsaDecryptPkcs1 } from './rsa.mjs';

const MAX_PLAINTEXT = 16384; // 单条记录的明文上限（TLS 规定）

const EXT_SESSION_TICKET = 0x0023;

/**
 * 服务端挑套件的顺序。
 *
 * **照抄当年真机跑通那次的 OpenSSL 选择（0x0035 AES_256_CBC_SHA）**：相机两个都给了，
 * 选哪个都合规，但既然 0x0035 是实测跑通过的那一个，就别自己多留一个变量
 * （测试里仍可用 preferSuite 强制指定 —— 回放真机录到的记录时必须用当年那个）。
 */
const SERVER_SUITE_ORDER = [0x0035, 0x002f];

/** 空的 session_ticket 扩展（服务端回它 = 「我支持票」） */
const EMPTY_TICKET_EXT = concat(new Uint8Array([0x00, EXT_SESSION_TICKET]), new Uint8Array([0x00, 0x00]));

export class TlsServerSession {
  /**
   * @param {object} opts
   *   prim            原语（purePrimitives() 或 nodePrimitives()）
   *   key             证书私钥 { n, e, d }（rsa.mjs 的 parsePem 给）
   *   certs           证书链（Uint8Array[]）
   *   requestHandler  (request) => Uint8Array|Promise<Uint8Array>；请求 = {method,url,headers,body}
   *   log             日志
   *   label           日志前缀（连接号之类）
   *   tickets         会话票表（**跨连接共用**的 Map：ticketHex -> {master, suiteId}）
   *   ticketLen       票的长度（当年 OpenSSL 发的是 160 字节，就照这个来）
   */
  constructor(opts) {
    this.prim = opts.prim;
    this.key = opts.key;
    this.certs = opts.certs;
    this.requestHandler = opts.requestHandler;
    this.log = opts.log || (() => {});
    this.label = opts.label || 'tls';

    this.inBuf = new Uint8Array(0);
    this.outQueue = [];
    this.state = 'expectCH';
    this.closed = false;
    // 调试/回放用：指定优先套件（不指定就按 SERVER_SUITE_ORDER 挑）。
    // 回放真机记录时必须指定成当年那个，否则密钥不一样，相机的 Finished/应用数据都解不开。
    this.preferSuite = opts.preferSuite === undefined ? null : opts.preferSuite;
    // RFC 5077 会话票：tickets 是**跨连接共用**的 Map（由 LocalMarketStore 建），
    // ticketHex -> { master, suiteId }。我们发得出票，但**不拿它续会** ——
    // 客户端把票带回来时只用来打一行日志（见 _onClientHello 里那段注释）。
    this.tickets = opts.tickets || new Map();
    this.ticketLen = opts.ticketLen === undefined ? 160 : opts.ticketLen;
    this.ticketOffered = false;

    this.clientSeq = 0;
    this.serverSeq = 0;
    this.transcript = new Transcript();
    this.httpBuf = new Uint8Array(0);
    this.handshakeT0 = Date.now();
    this.requestCount = 0;
  }

  /** 相机那边来的字节。 */
  feed(bytes) {
    if (this.closed) return;
    this.inBuf = concat(this.inBuf, bytes);
    const { records, rest } = splitRecords(this.inBuf);
    this.inBuf = rest;
    for (const rec of records) {
      try {
        this._onRecord(rec);
      } catch (e) {
        this._fail(String(e && e.message ? e.message : e));
        return;
      }
      if (this.closed) return;
    }
  }

  /** 取出要发回相机的字节（可能为空）。 */
  drain() {
    if (!this.outQueue.length) return null;
    return concat(...this.outQueue.splice(0, this.outQueue.length));
  }

  _send(bytes) {
    this.outQueue.push(bytes);
  }

  _alert(level, description) {
    this._send(record(RECORD.ALERT, new Uint8Array([level, description])));
  }

  _fail(why) {
    this.log('  ✗ [' + this.label + '] TLS session failed: ' + why);
    if (!this.closed) {
      this._alert(2, 40); // fatal / handshake_failure
      this.closed = true;
    }
  }

  _onRecord(rec) {
    if (rec.type === RECORD.CHANGE_CIPHER_SPEC) {
      if (this.state !== 'expectCCS') {
        throw new Error('ChangeCipherSpec at the wrong time (state=' + this.state + ')');
      }
      if (rec.payload.length !== 1 || rec.payload[0] !== 1) throw new Error('bad ChangeCipherSpec content');
      this.state = 'expectFin';
      return;
    }

    if (rec.type === RECORD.ALERT) {
      // 明文 alert（握手期间）或加密 alert（建立之后）
      if (this.state === 'established') {
        const plain = decryptRecord(this.prim, this.clientCtx, rec, this.clientSeq++);
        this.log('  [' + this.label + '] alert from camera: level=%d desc=%d', plain[0], plain[1]);
      } else {
        this.log('  [' + this.label + '] alert from camera: level=%d desc=%d', rec.payload[0], rec.payload[1]);
      }
      this.closed = true;
      return;
    }

    if (this.state === 'expectCH') {
      if (rec.type !== RECORD.HANDSHAKE) throw new Error('waiting for ClientHello but got record type ' + rec.type);
      if (rec.payload[0] !== HS.CLIENT_HELLO) throw new Error('the first handshake message is not ClientHello');
      this._onClientHello(rec.payload);
      return;
    }

    if (this.state === 'expectCKE') {
      if (rec.type !== RECORD.HANDSHAKE || rec.payload[0] !== HS.CLIENT_KEY_EXCHANGE) {
        throw new Error('waiting for ClientKeyExchange but got record type ' + rec.type);
      }
      this.transcript.add(rec.payload);
      this._onClientKeyExchange(rec.payload);
      return;
    }

    if (this.state === 'expectFin') {
      if (rec.type !== RECORD.HANDSHAKE) throw new Error('waiting for Finished but got record type ' + rec.type);
      const plain = decryptRecord(this.prim, this.clientCtx, rec, this.clientSeq++);
      this._onClientFinished(plain);
      return;
    }

    if (this.state === 'established') {
      if (rec.type !== RECORD.APPLICATION_DATA) throw new Error('after the handshake only application data is expected, got ' + rec.type);
      const plain = decryptRecord(this.prim, this.clientCtx, rec, this.clientSeq++);
      this._onAppData(plain);
      return;
    }

    throw new Error('got record type ' + rec.type + ' in state ' + this.state);
  }

  // ---------------------------------------------------------------- 握手
  _onClientHello(payload) {
    const hello = parseClientHello(payload.subarray(4));
    this.log('  [' + this.label + '] ClientHello: version 0x%s, suites %s, %d extensions',
      hello.version.toString(16),
      hello.suites.map((s) => '0x' + s.toString(16)).join(' '),
      hello.extensions.length);
    if (hello.version !== 0x0301) {
      this.log('  [' + this.label + '] (the client version is not 0x0301; we still answer as TLS1.0)');
    }

    const ticketExt = hello.extensions.find((e) => e.type === EXT_SESSION_TICKET);
    this.ticketOffered = !!ticketExt;
    const hasScsv = hello.suites.indexOf(TLS_EMPTY_RENEGOTIATION_INFO_SCSV) >= 0;
    this.clientRandom = hello.random;
    this.serverRandom = this.prim.random(32);
    this.transcript.add(payload); // ClientHello

    // ---- ① 客户端带了票：**我们认得出，但依然走完整握手**（RFC 5077 的 Figure 4）
    //
    // 为什么不续会（这是实测定的，不是偷懒）：
    //   简握手（abbreviated）里，**客户端**那条 Finished 的 handshake_messages 用 OpenSSL 客户端
    //   没对上 —— 服务端那条按 [CH, SH] 算是对的（拿录到的真机 conn2 逐字节验过），
    //   但客户端那条对 [CH, SH] 以及十几种变体（去票/空票/空 sid/去 renegotiation_info/顺序颠倒…）
    //   都对不上；而所有实现都认下了它。既然对不上就说明简握手这条路上还有我们没吃透的东西，
    //   而**完整握手是实测跑通的那条路**：RFC 5077 §3.2 明确允许「票验不过就退回完整握手」，
    //   RFC 5246 §7.4.1.3 也要求客户端「任何一次握手都要准备好做完整协商」
    //   （真实索尼服务器会轮换票密钥，相机那侧本来就必须能兜住）。
    //   ⇒ 宁可少一个特性，也不要在一个「没验证过」的分支上翻车。
    if (ticketExt && ticketExt.data.length) {
      this.log(
        '  [' + this.label + '] client came back with a ticket (%d bytes, %s) → falling back to a full handshake per RFC 5077 (and sending a new ticket)',
        ticketExt.data.length,
        this.tickets.has(toHex(ticketExt.data)) ? 'one we issued' : 'not one we issued'
      );
    }

    // ---- ② 完整握手
    // 挑套件：默认按 SERVER_SUITE_ORDER（0x0035 优先，照抄当年跑通那次）；
    // 若显式指定了 preferSuite 且客户端也给了，就用它（回放真机记录要用）。
    let suiteId = null;
    if (this.preferSuite !== null && SUITES[this.preferSuite] && hello.suites.indexOf(this.preferSuite) >= 0) {
      suiteId = this.preferSuite;
    } else {
      for (const s of SERVER_SUITE_ORDER) {
        if (SUITES[s] && hello.suites.indexOf(s) >= 0) {
          suiteId = s;
          break;
        }
      }
    }
    if (suiteId === null) throw new Error('the client offered no usable AES-CBC-SHA suite');

    this.suiteId = suiteId;
    // 客户端给了 ticket 扩展 ⇒ ServerHello 里回一个空的同名扩展（=「我支持票」），
    // 并在 Finished 之后补一张 NewSessionTicket。这样我们的握手形状与当年跑通的
    // OpenSSL 完全一致 —— 少这一个扩展的话，客户端就不会带票回来续会了。
    const serverHello = buildServerHello(
      this.prim,
      suiteId,
      this.serverRandom,
      new Uint8Array(0),
      ticketExt ? [EMPTY_TICKET_EXT] : []
    );
    const certificate = buildCertificate(this.certs);
    const done = buildServerHelloDone();
    this.transcript.add(serverHello);
    this.transcript.add(certificate);
    this.transcript.add(done);
    this._send(concat(
      record(RECORD.HANDSHAKE, serverHello),
      record(RECORD.HANDSHAKE, certificate),
      record(RECORD.HANDSHAKE, done)
    ));
    this.log(
      '  [' + this.label + '] handshake: TLS1.0 + ' + SUITES[suiteId].name +
        (hasScsv ? ' (client sent SCSV, so ServerHello carries an empty renegotiation_info)' : '') +
        (ticketExt ? ', replied with an empty session_ticket (the session ticket follows)' : ', no session ticket') +
        ', certificate chain ' + certificate.length + ' bytes'
    );
    this.state = 'expectCKE';
  }

  _onClientKeyExchange(payload) {
    const blockLen = (payload[4] << 8) | payload[5];
    const premaster = rsaDecryptPkcs1(this.key, payload.subarray(6, 6 + blockLen));
    if (premaster.length !== 48) throw new Error('premaster length is not 48 (' + premaster.length + ')');
    const ver = (premaster[0] << 8) | premaster[1];
    const keys = deriveKeys(this.prim, premaster, this.clientRandom, this.serverRandom, this.suiteId);
    this._loadKeys(keys);
    this.log(
      '  [' + this.label + '] keys ready: premaster 48 bytes (version 0x%s), client_write_key %d bytes',
      ver.toString(16),
      keys.clientKey.length
    );
    this.state = 'expectCCS';
  }

  /** 把密钥材料装进客户端/服务端两个方向的状态。 */
  _loadKeys(keys) {
    this.keys = keys;
    this.suiteId = keys.suiteId;
    this.clientCtx = { key: keys.clientKey, mac: keys.clientMac, iv: new Uint8Array(keys.clientIv) };
    this.serverCtx = { key: keys.serverKey, mac: keys.serverMac, iv: new Uint8Array(keys.serverIv) };
  }

  _onClientFinished(plain) {
    if (plain[0] !== HS.FINISHED) throw new Error('expected Finished but got handshake type ' + plain[0]);
    const verifyData = plain.subarray(4, 4 + 12);
    const want = finishedVerifyData(this.prim, this.keys.master, 'client finished', this.transcript.bytes());
    if (toHex(verifyData) !== toHex(want)) {
      throw new Error('bad verify_data in the client Finished (camera ' + toHex(verifyData) + ', ours ' + toHex(want) + ')');
    }
    this.log('  [' + this.label + '] ★ camera Finished verified (%d ms)', Date.now() - this.handshakeT0);

    // 服务端的 Finished 要把客户端的 Finished 也算进 transcript
    this.transcript.add(plain);
    // RFC 5077 的顺序：NewSessionTicket 在 CCS/Finished **之前**（与当年 OpenSSL 一致）。
    // 票是我们自己发的不透明值，认得出就能在下载那条连接上走简握手。
    // ⚠️ 它比服务端 Finished 早发 ⇒ **必须算进握手串**，否则 Finished 的 verify_data 会错
    //（真 OpenSSL 客户端会当场 `tls_process_finished: digest check failed` 拒掉我们）。
    if (this.ticketOffered && this.ticketLen > 0) {
      const ticket = this.prim.random(this.ticketLen);
      this.tickets.set(toHex(ticket), { master: this.keys.master, suiteId: this.suiteId });
      const tmsg = handshake(HS.NEW_SESSION_TICKET, concat(new Uint8Array([0, 0, 0, 0]), lenPrefix(ticket.length, 2), ticket));
      this.transcript.add(tmsg);
      this._send(record(RECORD.HANDSHAKE, tmsg));
      this.log('  [' + this.label + '] session ticket sent (%d bytes) → the camera will reuse it on the download connection', ticket.length);
    }
    this._send(record(RECORD.CHANGE_CIPHER_SPEC, new Uint8Array([1])));
    const fin = buildFinished(this.prim, this.keys.master, 'server finished', this.transcript.bytes());
    this._send(encryptRecord(this.prim, this.serverCtx, RECORD.HANDSHAKE, fin, this.serverSeq++));
    this.state = 'established';
  }

  // ---------------------------------------------------------------- 应用数据
  _onAppData(plain) {
    this.httpBuf = concat(this.httpBuf, plain);
    for (;;) {
      const req = this._takeRequest();
      if (req === null) return;
      this.requestCount++;
      // handler 是同步的就当场答（假商店就是同步的：spk 也是现场打的）；
      // 万一将来接了个异步的来源，也支持 Promise —— 但调用方得继续 poll/drain。
      const resp = this.requestHandler(req);
      if (resp && typeof resp.then === 'function') {
        resp.then(
          (r) => {
            if (!this.closed) this._sendResponse(r);
          },
          (e) => this._fail('error while handling the request: ' + (e && e.message ? e.message : e))
        );
      } else {
        this._sendResponse(resp);
      }
    }
  }

  /** 从缓冲区里切出一条完整的 HTTP 请求（没有就返回 null）。 */
  _takeRequest() {
    const sep = this._findHeaderEnd();
    if (sep < 0) return null;
    const head = this.httpBuf.subarray(0, sep);
    const text = Array.prototype.map.call(head, (b) => String.fromCharCode(b)).join('');
    const lines = text.split('\r\n');
    const first = lines[0].split(' ');
    const headers = {};
    for (let i = 1; i < lines.length; i++) {
      const idx = lines[i].indexOf(': ');
      if (idx > 0) headers[lines[i].slice(0, idx).toLowerCase()] = lines[i].slice(idx + 2);
    }
    const contentLength = parseInt(headers['content-length'] || '0', 10) || 0;
    const bodyStart = sep + 4;
    if (this.httpBuf.length < bodyStart + contentLength) return null; // 还没收全
    const body = this.httpBuf.subarray(bodyStart, bodyStart + contentLength);
    this.httpBuf = this.httpBuf.subarray(bodyStart + contentLength);
    return { method: first[0], url: first[1], protocol: first[2], headers, body };
  }

  _findHeaderEnd() {
    for (let i = 0; i + 3 < this.httpBuf.length; i++) {
      if (this.httpBuf[i] === 13 && this.httpBuf[i + 1] === 10 && this.httpBuf[i + 2] === 13 && this.httpBuf[i + 3] === 10) {
        return i;
      }
    }
    return -1;
  }

  /**
   * 把一条 HTTP 响应发给相机。
   *
   * **头一块、正文一块分成两条记录** —— 当年跑通那次的 Python（`BaseHTTPRequestHandler`
   * 先把头 flush 出去、再写正文）就是这个形状（抓包里看得到：APP 202 字节的头、
   * 再 APP 128 字节的正文）。相机对那种形状是验过的，而把头和正文挤在同一条记录里
   * 没有先例 —— 这种地方不值得自己省事。
   */
  _sendResponse(resp) {
    const sep = this._indexOfHeaderEnd(resp);
    const parts = sep < 0 ? [resp] : [resp.subarray(0, sep + 4), resp.subarray(sep + 4)];
    for (const part of parts) {
      if (!part.length) continue;
      for (let i = 0; i < part.length; i += MAX_PLAINTEXT) {
        const chunk = part.subarray(i, Math.min(i + MAX_PLAINTEXT, part.length));
        this._send(encryptRecord(this.prim, this.serverCtx, RECORD.APPLICATION_DATA, chunk, this.serverSeq++));
      }
    }
  }

  /** 在整段字节里找第一个 \r\n\r\n（返回其起点，含结尾 4 字节） */
  _indexOfHeaderEnd(bytes) {
    for (let i = 0; i + 3 < bytes.length; i++) {
      if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) return i;
    }
    return -1;
  }

  /** 主动收摊（HTTP 都答完后我们可以自己关；相机通常也会发 close_notify）。 */
  shutdown() {
    this.closed = true;
  }
}
