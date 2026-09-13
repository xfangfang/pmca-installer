/**
 * 最小 TLS 1.0 服务端（只做相机要的那一条路：RSA 密钥交换 + AES-CBC-SHA）。
 *
 * 依据是真机指纹（见 webinstaller/tests/tls/README.md）：相机只会 TLS1.0，
 * ClientHello 只给 0x002f/0x0035（AES-CBC-SHA）+ SCSV，扩展只有一个 session_ticket
 * ⇒ 不需要 ECDHE、不需要 GCM、不需要 SNI/ALPN，也不需要会话复用。
 *
 * 算法原语从外面注入（`prim`），因为浏览器与 Node 提供的东西不完全一样：
 *   prim.hmac(算法, key, data)        —— 'sha1'/'md5'（WebCrypto 两个都有）
 *   prim.aesCbcEncrypt(key, iv, data) —— **裸 CBC**：自己按 PKCS#7 补填充（TLS1.0 的填充就是 PKCS#7）
 *   prim.aesCbcDecrypt(key, iv, ct)   —— 返回「去掉了填充的 明文||MAC」
 *   prim.random(n)
 * MD5 不走注入 —— 用我们自己那份（WebCrypto 没有 MD5），见 md5.mjs。
 *
 * ⚠️ 一个容易踩的点：**TLS 1.0 没有每记录显式 IV**（那是 TLS1.1 才加的）。
 * 第一条加密记录的 IV 来自 key block，之后每条用**上一条密文的最后一整块**。
 */

import { md5 } from './md5.mjs';

export const RECORD = { CHANGE_CIPHER_SPEC: 20, ALERT: 21, HANDSHAKE: 22, APPLICATION_DATA: 23 };
export const HS = {
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  NEW_SESSION_TICKET: 4,
  CERTIFICATE: 11,
  SERVER_HELLO_DONE: 14,
  CLIENT_KEY_EXCHANGE: 16,
  FINISHED: 20,
};

/** 相机给的套件表；只有这两个是真套件，另一个是 SCSV。 */
export const SUITES = {
  0x002f: { name: 'TLS_RSA_WITH_AES_128_CBC_SHA', keyLen: 16, macLen: 20, ivLen: 16 },
  0x0035: { name: 'TLS_RSA_WITH_AES_256_CBC_SHA', keyLen: 32, macLen: 20, ivLen: 16 },
};
export const TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff;

export const VERSION_TLS10 = 0x0301;

// ---------------------------------------------------------------- 小工具
export function concat(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function ascii(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
  return s;
}

export function latin1(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

/** 大端长度前缀（TLS 到处都用）。sizeBytes=1/2/3。 */
export function lenPrefix(n, sizeBytes) {
  const out = new Uint8Array(sizeBytes);
  for (let i = sizeBytes - 1; i >= 0; i--) {
    out[i] = n & 0xff;
    n >>= 8;
  }
  return out;
}

/** 拼一条握手消息：type(1) + length(3) + body。 */
export function handshake(type, body) {
  return concat(new Uint8Array([type]), lenPrefix(body.length, 3), body);
}

/** 拼一条 TLS 记录：type(1) + version(2) + length(2) + payload。 */
export function record(type, payload, version = VERSION_TLS10) {
  return concat(new Uint8Array([type, version >> 8, version & 0xff]), lenPrefix(payload.length, 2), payload);
}

export function splitRecords(data) {
  const out = [];
  let p = 0;
  while (p + 5 <= data.length) {
    const len = (data[p + 3] << 8) | data[p + 4];
    if (p + 5 + len > data.length) break;
    out.push({ type: data[p], version: (data[p + 1] << 8) | data[p + 2], payload: data.subarray(p + 5, p + 5 + len) });
    p += 5 + len;
  }
  return { records: out, rest: data.subarray(p) };
}

// ---------------------------------------------------------------- PRF（TLS 1.0：MD5 与 SHA1 各半）
function pHash(prim, algo, secret, seed, len) {
  const out = new Uint8Array(len);
  let a = seed;
  let pos = 0;
  while (pos < len) {
    a = prim.hmac(algo, secret, a); // A(i) = HMAC(secret, A(i-1))，A(0) = seed
    const block = prim.hmac(algo, secret, concat(a, seed));
    const n = Math.min(block.length, len - pos);
    out.set(block.subarray(0, n), pos);
    pos += n;
  }
  return out;
}

export function prf(prim, secret, label, seed, len) {
  const labelSeed = concat(ascii(label), seed);
  const half = Math.ceil(secret.length / 2);
  const s1 = secret.subarray(0, half);
  const s2 = secret.subarray(secret.length - (secret.length - half));
  const a = pHash(prim, 'md5', s1, labelSeed, len);
  const b = pHash(prim, 'sha1', s2, labelSeed, len);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** 密钥调度：premaster → master secret → key block → 六个密钥材料。 */
export function deriveKeys(prim, premaster, clientRandom, serverRandom, suiteId) {
  const master = masterSecret(prim, premaster, clientRandom, serverRandom);
  return expandKeys(prim, master, clientRandom, serverRandom, suiteId);
}

/** master secret（会话复用时直接用上次那个，不要再算一遍）。 */
export function masterSecret(prim, premaster, clientRandom, serverRandom) {
  return prf(prim, premaster, 'master secret', concat(clientRandom, serverRandom), 48);
}

/** master secret → 六个密钥材料。会话复用时要拿原来的 master 重跑这一步。 */
export function expandKeys(prim, master, clientRandom, serverRandom, suiteId) {
  const suite = SUITES[suiteId];
  if (!suite) throw new Error(`unsupported cipher suite 0x${suiteId.toString(16)}`);
  const need = 2 * suite.macLen + 2 * suite.keyLen + 2 * suite.ivLen;
  const kb = prf(prim, master, 'key expansion', concat(serverRandom, clientRandom), need);
  let p = 0;
  const take = (n) => {
    const v = kb.subarray(p, p + n);
    p += n;
    return v;
  };
  return {
    suite,
    suiteId,
    master,
    clientMac: take(suite.macLen),
    serverMac: take(suite.macLen),
    clientKey: take(suite.keyLen),
    serverKey: take(suite.keyLen),
    clientIv: take(suite.ivLen),
    serverIv: take(suite.ivLen),
  };
}

// ---------------------------------------------------------------- 记录层（MAC-then-encrypt）
function macInput(seq, type, version, data) {
  const head = new Uint8Array(13);
  const dv = new DataView(head.buffer);
  dv.setUint32(0, Math.floor(seq / 4294967296));
  dv.setUint32(4, seq >>> 0);
  head[8] = type;
  head[9] = version >> 8;
  head[10] = version & 0xff;
  dv.setUint16(11, data.length);
  return concat(head, data);
}

export function recordMac(prim, macSecret, seq, type, version, data) {
  return prim.hmac('sha1', macSecret, macInput(seq, type, version, data));
}

/** 加密一条记录（自己补 PKCS#7 填充）。返回完整记录字节。 */
export function encryptRecord(prim, ctx, type, data, seq) {
  const mac = recordMac(prim, ctx.mac, seq, type, VERSION_TLS10, data);
  const cipher = prim.aesCbcEncrypt(ctx.key, ctx.iv, concat(data, mac));
  ctx.iv = cipher.subarray(cipher.length - 16); // 下一条记录的 IV = 本条密文的最后一整块
  return record(type, cipher);
}

/** 解一条记录：验 MAC、去掉填充，返回明文。ctx = { key, mac, iv }。 */
export function decryptRecord(prim, ctx, rec, seq) {
  const body = prim.aesCbcDecrypt(ctx.key, ctx.iv, rec.payload); // 已去掉填充
  ctx.iv = rec.payload.subarray(rec.payload.length - 16);
  const dataLen = body.length - ctx.mac.length;
  if (dataLen < 0) throw new Error('the decrypted record is shorter than its MAC');
  const data = body.subarray(0, dataLen);
  const mac = body.subarray(dataLen);
  const want = recordMac(prim, ctx.mac, seq, rec.type, rec.version, data);
  if (toHex(mac) !== toHex(want)) throw new Error(`record MAC check failed (seq=${seq})`);
  return data;
}

// ---------------------------------------------------------------- 握手消息
export function parseClientHello(body) {
  const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
  let p = 0;
  const version = dv.getUint16(p);
  p += 2;
  const random = body.subarray(p, p + 32);
  p += 32;
  const sidLen = body[p];
  p += 1;
  const sessionId = body.subarray(p, p + sidLen);
  p += sidLen;
  const suiteLen = dv.getUint16(p);
  p += 2;
  const suites = [];
  for (let i = 0; i < suiteLen; i += 2) suites.push(dv.getUint16(p + i));
  p += suiteLen;
  const compLen = body[p];
  p += 1;
  const compression = body.subarray(p, p + compLen);
  p += compLen;
  const extensions = [];
  if (p + 2 <= body.length) {
    const extLen = dv.getUint16(p);
    p += 2;
    const end = Math.min(body.length, p + extLen);
    while (p + 4 <= end) {
      const type = dv.getUint16(p);
      const len = dv.getUint16(p + 2);
      extensions.push({ type, data: body.subarray(p + 4, p + 4 + len) });
      p += 4 + len;
    }
  }
  return { version, random, sessionId, suites, compression, extensions };
}

export function parseServerHello(body) {
  const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
  let p = 0;
  const version = dv.getUint16(p);
  p += 2;
  const random = body.subarray(p, p + 32);
  p += 32;
  const sidLen = body[p];
  p += 1;
  const sessionId = body.subarray(p, p + sidLen);
  p += sidLen;
  const suite = dv.getUint16(p);
  p += 2;
  const compression = body[p];
  return { version, random, sessionId, suite, compression };
}

/** ServerHello。扩展默认给一个空的 renegotiation_info（客户端带了 SCSV，回它最稳）。 */
export function buildServerHello(prim, suiteId, serverRandom, sessionId = new Uint8Array(0), extraExtensions = []) {
  const exts = [concat(new Uint8Array([0xff, 0x01]), new Uint8Array([0x00, 0x01, 0x00]))];
  for (const e of extraExtensions) exts.push(e);
  const extBlock = concat(lenPrefix(exts.reduce((n, e) => n + e.length, 0), 2), ...exts);
  const body = concat(
    new Uint8Array([VERSION_TLS10 >> 8, VERSION_TLS10 & 0xff]),
    serverRandom,
    lenPrefix(sessionId.length, 1),
    sessionId,
    lenPrefix(suiteId, 2),
    new Uint8Array([0x00]), // compression = null
    extBlock
  );
  return handshake(HS.SERVER_HELLO, body);
}

/** Certificate（链顺序照 PEM 里的顺序）。 */
export function buildCertificate(certs) {
  const parts = [];
  for (const c of certs) parts.push(lenPrefix(c.length, 3), c);
  const list = concat(...parts);
  return handshake(HS.CERTIFICATE, concat(lenPrefix(list.length, 3), list));
}

export function buildServerHelloDone() {
  return handshake(HS.SERVER_HELLO_DONE, new Uint8Array(0));
}

export function buildClientKeyExchange(cipherBlock) {
  return handshake(HS.CLIENT_KEY_EXCHANGE, concat(lenPrefix(cipherBlock.length, 2), cipherBlock));
}

/** Finished 要的 verify_data = PRF(master, 标签, MD5(handshake_messages)+SHA1(handshake_messages))[0..12] */
export function finishedVerifyData(prim, master, label, transcript, len = 12) {
  const seed = concat(md5(transcript), prim.hash('sha1', transcript));
  return prf(prim, master, label, seed, len);
}

export function buildFinished(prim, master, label, transcript) {
  return handshake(HS.FINISHED, finishedVerifyData(prim, master, label, transcript));
}

/** 握手消息流的累加器（Finished 要用它的 MD5+SHA1）。 */
export class Transcript {
  constructor() {
    this.parts = [];
    this.length = 0;
  }

  add(bytes) {
    this.parts.push(bytes);
    this.length += bytes.length;
  }

  bytes() {
    return concat(...this.parts);
  }
}
