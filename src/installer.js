/**
 * 安装主循环 —— PMCA `pmca/installer/__init__.py: install()` 的 1:1 移植。
 *
 * 与 PMCA 的差别只有一处：PMCA 用 `select()` 轮询本地 socket，这里改成问 bridge
 * （后端的 TCP 管道）有没有数据要送给相机。其余顺序、判断、错误处理全部照抄。
 *
 * 循环骨架：
 *   1. 清空相机缓冲区 → 握手（宣告 TCPT+REST）
 *   2. REST POST /task/start 把 xpd 投给相机 → 相机回 {resultCode, message}
 *   3. 主循环：
 *        · 若代理连接有数据 → 送给相机（sendSslData）；对端关了 → sendSslEnd
 *        · 否则收相机的下一条消息
 *        · 相机要连某个 host:port → 交给 bridge（后端一律接到本地假商店）
 *        · 相机把 TLS 字节发上来 → 原样写进 bridge
 *        · REST /task/progress → 报进度；/task/complete → 收工
 */

import { asBytes, latin1, utf8, toHex, concat, sleep } from './bytes.js';

export const XPD_MIME_TYPE = 'application/x-psn-dstartup2';

/**
 * 一条 ProxyData 消息的最大字节数（= 上游 `sock.recv(2 ** 14)`）。
 *
 * 上游那边这个上限是 socket 读缓冲**天然**给的；我们页面内的假商店一次能把整个 spk 吐出来，
 * 不管一下就会撞上相机的 `PTP_RC_TooMuchData`（0xa809）—— 真机就这么卡在 spk 下发上。
 */
export const SSL_CHUNK_MAX = 2 ** 14;

/**
 * bridge.poll() 的返回值：对端已关闭。
 *
 * ⚠️ **任何 bridge 都必须 import 这一个，不能自己 new 一个同名符号**：
 *   `Symbol()` 每次调用都是新的、跨模块永不相等 ⇒ 主循环里 `chunk === CLOSED`
 *   会变成死代码（真机踩过：相机拿到 dlandinstall 应答后就不再往下走，因为它一直在等
 *   我们那句 ProxyEnd）。当初 `src/jstls/local-store.mjs` 就是自己 new 了一个。
 */
export const CLOSED = Symbol('tcp-closed');

/** PMCA `_buildRequest`：`POST <endpoint> REST/1.0\r\nContent-type: ...\r\n\r\n<body>` */
export function buildRequest(endpoint, contentType, data) {
  return concat(
    asBytes('POST ' + endpoint + ' REST/1.0\r\n'),
    asBytes('Content-type: ' + contentType + '\r\n\r\n'),
    data
  );
}

/**
 * 把报文按 `\r\n\r\n` 切开，**只取前两段**（= 头部 / 正文）。
 *
 * ⚠️ 必须与上游 PMCA 逐字对齐：
 *     headers, data = data.split(b'\r\n\r\n')[:2]
 * 它是「切全部、取前两个」⇒ 正文只到**第二个** `\r\n\r\n` 为止，后面多余的内容直接丢掉。
 * 我一开始写成了「取第一个分隔符之后的全部」，于是把后面那一段也当成正文 ⇒
 * 真机上就报 `Unexpected non-whitespace character after JSON at position 47`。
 * 相机的响应确实是「一段 HTTP + 后面又跟了东西」这种形状。
 */
function splitHttp(data) {
  const sep = asBytes('\r\n\r\n');
  const parts = [];
  let start = 0;
  for (;;) {
    let found = -1;
    for (let i = start; i + 4 <= data.length; i++) {
      if (data[i] === 13 && data[i + 1] === 10 && data[i + 2] === 13 && data[i + 3] === 10) {
        found = i;
        break;
      }
    }
    if (found < 0) {
      parts.push(data.subarray(start));
      break;
    }
    parts.push(data.subarray(start, found));
    start = found + 4;
  }
  if (parts.length < 2) throw new Error('no \\r\\n\\r\\n found in the HTTP message');
  return { head: parts[0], body: parts[1] };
}

function parseHttp(data) {
  const { head, body } = splitHttp(data);
  const lines = latin1(head).split('\r\n');
  const headers = {};
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(': ');
    if (idx > 0) headers[line.slice(0, idx)] = line.slice(idx + 2);
  }
  return { firstLine: lines[0], headers, body };
}

const TLS_VERSIONS = { 0x0300: 'SSLv3', 0x0301: 'TLS1.0', 0x0302: 'TLS1.1', 0x0303: 'TLS1.2', 0x0304: 'TLS1.3' };

/**
 * 从 TLS 记录头读出「记录类型 / 协议版本」。
 * 用途：相机若是 SSLv3 或 TLS1.0 的老栈，Java 标准库 ssl 可能谈不拢（见 README 的 SSLv3 说明），
 * 这一行日志能让人一眼看出要不要换 TLS 终结实现。
 */
function describeTls(data) {
  if (data.length < 3) return '(too short)';
  const version = (data[1] << 8) | data[2];
  const kind =
    { 0x16: 'Handshake', 0x14: 'ChangeCipherSpec', 0x15: 'Alert', 0x17: 'ApplicationData' }[data[0]] ||
    `0x${data[0].toString(16)}`;
  return `${kind} / ${TLS_VERSIONS[version] || '0x' + version.toString(16)}`;
}

/** JSON 解析失败时把原文一并抛出来 —— 否则只能看着一句 “position 47” 猜。 */
function humanKiB(n) {
  return n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1024 / 1024).toFixed(2)} MiB`;
}

function parseJson(data, what) {
  const text = utf8(data);
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(
      `${what} JSON parse failed: ${e.message}\n` +
        `  body (${data.length} bytes): ${JSON.stringify(text.slice(0, 240))}\n` +
        `  hex: ${toHex(data.subarray(0, 96))}`
    );
  }
}

export function parseRequest(data) {
  const { firstLine, headers, body } = parseHttp(data);
  const [method, url, protocol] = firstLine.split(' ', 3);
  return { protocol, method, url, headers, body };
}

export function parseResponse(data) {
  const { firstLine, headers, body } = parseHttp(data);
  const [protocol, code, ...status] = firstLine.split(' ');
  return { protocol, code: Number(code), status: status.join(' '), headers, body };
}

export function parseResult(data) {
  const json = parseJson(data, 'camera result');
  return { code: json.resultCode, message: json.message };
}

/**
 * 相机拒绝任务时，把话说明白。
 *
 * 真机实测（ILCE-5100）：上一条任务被中断过（解析失败、关页面、Ctrl-C）之后，相机的下载 app
 * 会一直「占着」任务槽，之后每次 /task/start 都回
 *     {"message":"Start not accepted","resultCode":10}
 * 而这个锁**不会自己松开**：实测发 Bye、给 fd 0..7 补发 ProxyEnd、USB 端口复位都无效，
 * 只有拔插 USB 线（相机离开 app 安装模式、下载 app 复位）才恢复。
 * 所以在界面上必须直说，否则用户会以为是网络问题、反复重试。
 */
export function describeCameraRefusal(result) {
  const message = (result && result.message) || '(no message)';
  const code = result && result.code;
  const base = `camera refused the task: ${message} (resultCode ${code})`;
  if (/not accepted/i.test(message) || code === 10) {
    return (
      `${base}\n` +
      '  ⇒ the camera still holds an unfinished task from a previous run (that is what happens when an install is interrupted).\n' +
      '     This lock never clears by itself: sending Bye, re-sending ProxyEnd and resetting the USB port were all tried, in vain.\n' +
      '     Fix: unplug the USB cable and plug it back in (the camera leaves app install mode and the download app resets),\n' +
      '           then press ① Switch mode → ② Install again. While it stays in this mode, every retry will be refused.'
    );
  }
  return base;
}

export function parseStatus(data) {
  const json = parseJson(data, 'camera progress');
  return { status: json.status, message: json['status text'], percent: json.percent, totalSize: json['total size'] };
}

/**
 * 跑完一次安装。
 * @returns {Promise<{code:number,message:string}>} 相机的最终结果
 */
export async function runInstall({
  dev,
  bridge,
  xpdBytes,
  onStatus = () => {},
  onLog = () => {},
  idleDelayMs = 2,
  maxIdleRounds = 0,
  drainQuietMs = 150,
}) {
  const dropped = await dev.emptyBuffer(drainQuietMs);
  if (dropped) onLog(`(cleared ${dropped} queued messages before starting)`);

  const protocols = await dev.sendInit();
  onLog(`camera handshake done, protocols: ${protocols.map(([n, id]) => `${n}(0x${id.toString(16)})`).join(', ')}`);

  // ⚠️ 这里**只投出去、不要求下一条就是响应**：
  // 相机里的下载 app 是独立线程。上一条任务被我们半路丢下（解析失败/关页面）时，
  // 它的消息会姗姗来迟 —— 于是「等 /task/start 的响应」时先收到的可能是上一条任务
  // 留下的 REST 请求。上游 PMCA 在这种情况下直接抛 `Wrong response`，真机上也就是
  // 那句 `期望 response，收到 request`，整个安装当场卡死。
  // 现在改成状态机：state='start' 期间收到的 REST 请求一律记为「上一条任务的残留」跳过，
  // 真正的响应一到再切到 'running'。
  await dev.sendStartRequest(buildRequest('/task/start', XPD_MIME_TYPE, xpdBytes));
  onLog(`xpd submitted (${xpdBytes.length} bytes of body), waiting for the camera`);

  let state = 'start'; // start → running
  let connectionId = 0;
  let relayedBytes = 0;
  let relayedChunks = 0;
  let sock = null;
  let idleRounds = 0;
  let tlsSeen = false;
  // 相机不说话时要能看出来「我们还活着、在等它」—— 否则日志停在一行会让人以为是卡死了。
  // （命令行版一直有这句；页面版补上，真机排查少猜一次。）
  const HEARTBEAT_MS = 10000;
  let lastActivity = Date.now();
  let nextHeartbeat = lastActivity + HEARTBEAT_MS;

  for (;;) {
    if (sock !== null) {
      const chunk = bridge.poll(sock);
      if (chunk === CLOSED) {
        onLog('fake store closed the connection → telling the camera (ProxyEnd)');
        await dev.sendSslEnd(sock);
        sock = null;
      } else if (chunk && chunk.length) {
        // ⚠️ 一条 ProxyData 消息最多 2^14 字节 —— 这是上游的口径：PMCA 那边是
        //    `resp = sock.recv(2 ** 14)`，socket 读缓冲**天然**把数据切开。
        //    我们页面内的假商店没有这层限制（一次能吐出整个 spk）⇒ 真机在 spk 下发的
        //    第一块就撞上 `MTP 错误 0xa809`（= 上游 `PTP_RC_TooMuchData`，相机说这条消息太大）。
        //    所以这里必须自己切，切法照抄上游：每块 ≤ 2^14。
        for (let off = 0; off < chunk.length; off += SSL_CHUNK_MAX) {
          const part = chunk.subarray(off, Math.min(off + SSL_CHUNK_MAX, chunk.length));
          // 只打小包（握手/HTTP 应答这种几十到几百字节的）；spk 那种十几 KB 的只记总量，
          // 否则日志会被刷掉 —— 出问题时这几行正是「到底有没有把应答送出去」的证据。
          if (part.length <= 4096) {
            onLog(`↑ back to camera: ${part.length} bytes`);
          } else {
            relayedBytes += part.length;
            if (relayedChunks === 0) onLog(`↑ back to camera: large chunk (spk download, ${humanKiB(relayedBytes)} so far)`);
            relayedChunks++;
          }
          await dev.sendSslData(sock, part);
        }
      }
    }

    const msg = await dev.receive();
    if (msg === null) {
      idleRounds++;
      if (maxIdleRounds && idleRounds > maxIdleRounds) {
        throw new Error('the camera has been silent for too long (idle limit)');
      }
      if (Date.now() > nextHeartbeat) {
        nextHeartbeat = Date.now() + HEARTBEAT_MS;
        onLog(`…waiting for the camera (${Math.round((Date.now() - lastActivity) / 1000)} s with no message)`);
      }
      // 相机没话说时也会回「无数据」，所以这里必须让出一点时间，避免把 CPU 打满
      await sleep(idleDelayMs);
      continue;
    }
    idleRounds = 0;
    lastActivity = Date.now();
    nextHeartbeat = lastActivity + HEARTBEAT_MS;

    if (msg.kind === 'init') {
      continue; // 多余的 hello，忽略
    }
    if (msg.kind === 'sslStart') {
      connectionId = msg.connectionId;
      sock = msg.connectionId;
      onLog(`camera wants a TLS tunnel: ${msg.host}:${msg.port} → handing it to the local fake store`);
      bridge.open(msg.connectionId, msg.host, msg.port);
      continue;
    }
    if (msg.kind === 'sslData') {
      if (sock !== null && msg.connectionId === connectionId) {
        if (!tlsSeen) {
          // 只打第一包：相机若是 SSLv3/TLS1.0 的老栈，这里一眼就能看出来
          tlsSeen = true;
          onLog(`first TLS record from the camera: ${msg.data.length} bytes, ${describeTls(msg.data)}`);
        }
        bridge.send(msg.connectionId, msg.data);
      }
      continue;
    }
    if (msg.kind === 'sslEnd') {
      if (sock !== null && msg.connectionId === connectionId) {
        onLog('the camera closed the tunnel itself (ProxyDisconnect)');
        bridge.closeConn(msg.connectionId);
        sock = null;
      }
      continue;
    }
    if (msg.kind === 'response') {
      if (state !== 'start') {
        onLog('(extra REST response, ignored)');
        continue;
      }
      const resp = parseResponse(msg.data);
      let result;
      try {
        result = parseResult(resp.body);
      } catch (e) {
        throw new Error(`cannot parse the camera's /task/start response (HTTP ${resp.code}): ${e.message}`);
      }
      if (result.code !== 0) throw new Error(describeCameraRefusal(result));
      onLog(
        `camera response to /task/start: ${resp.protocol} ${resp.code} ${resp.status} → xpd accepted, starting the download/install flow`
      );
      state = 'running';
      continue;
    }
    if (msg.kind === 'request') {
      const request = parseRequest(msg.data);
      if (state === 'start') {
        // 上一条任务残留的请求（进度/收尾）。在我们自己的任务开始前收到它不是错误。
        onLog(`(skipping a leftover REST request from the previous task: ${request.method} ${request.url})`);
        continue;
      }
      if (request.url === '/task/progress') {
        onStatus(parseStatus(request.body));
      } else if (request.url === '/task/complete') {
        const final = parseResult(request.body);
        await dev.sendEnd();
        return final;
      } else {
        throw new Error(`unknown REST endpoint: ${request.url}`);
      }
      continue;
    }
    throw new Error(`unexpected message: ${msg.kind}`);
  }
}
