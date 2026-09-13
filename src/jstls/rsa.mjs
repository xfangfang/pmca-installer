/**
 * 裸 RSA（BigInt）+ PEM/DER 解析 —— 浏览器里也要能跑。
 *
 * 为什么不能用 WebCrypto：它只给 RSA-OAEP / RSA-PSS / PKCS#1 v1.5 **签名**，
 * **没有"裸模幂"**。而 TLS 1.0 的 RSA 密钥交换要求服务端做
 *     m = c^d mod n          （PKCS#1 v1.5 填充，自己解）
 * 好在一次 2048 位模幂用 BigInt 写出来就二十行，几十毫秒的事。
 * （同一份代码后面还能用来造 spk：那个是公钥方向 `pow(m, 65537, n)`。）
 */

/** 模幂：base^exp mod mod（平方-乘法，BigInt）。 */
export function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

export function bytesToBigInt(bytes) {
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/** 定长大端输出（len 省略时用最短表示）。 */
export function bigIntToBytes(value, len) {
  let size = len;
  if (size === undefined) size = Math.max(1, Math.ceil(value.toString(16).length / 2));
  const out = new Uint8Array(size);
  let x = value;
  for (let i = out.length - 1; i >= 0 && x > 0n; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** 手写 base64 解码（Node 的 Buffer 在浏览器里没有，atob 在 Node 12 里没有）。 */
export function base64Decode(text) {
  const clean = text.replace(/[^A-Za-z0-9+/=]/g, '');
  const out = [];
  let bits = 0;
  let acc = 0;
  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i];
    if (ch === '=') break;
    acc = (acc << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** 把 PEM 文本拆成 [{ label, der }]（顺序即文件里的顺序）。 */
export function pemBlocks(text) {
  const out = [];
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
  let m = re.exec(text);
  while (m !== null) {
    out.push({ label: m[1], der: base64Decode(m[2]) });
    m = re.exec(text);
  }
  return out;
}

// ---------------------------------------------------------------- 最小 DER
function readTlv(buf, pos) {
  const tag = buf[pos];
  let i = pos + 1;
  let len = buf[i];
  i += 1;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let k = 0; k < n; k++) {
      len = (len << 8) | buf[i];
      i += 1;
    }
  }
  return { tag, start: i, end: i + len, next: i + len };
}

/**
 * 解析 RSA 私钥（DER）→ { n, e, d }。
 * 支持 PKCS#1（`RSA PRIVATE KEY`）与 PKCS#8（`PRIVATE KEY`，里面再套一层 PKCS#1）。
 * 判据：version 之后的那个元素是 INTEGER ⇒ PKCS#1；是 SEQUENCE ⇒ PKCS#8。
 */
export function parseRsaPrivateKey(der) {
  const seq = readTlv(der, 0);
  if (seq.tag !== 0x30) throw new Error(`private key is not a SEQUENCE (DER header 0x${seq.tag.toString(16)})`);
  const version = readTlv(der, seq.start);
  if (version.tag !== 0x02) throw new Error('the first private key item is not an INTEGER');
  const next = readTlv(der, version.next);
  if (next.tag === 0x30) {
    // PKCS#8：version, AlgorithmIdentifier, OCTET STRING(PKCS#1)
    const oct = readTlv(der, next.next);
    if (oct.tag !== 0x04) throw new Error('no OCTET STRING found inside the PKCS#8 key');
    return parseRsaPrivateKey(der.subarray(oct.start, oct.end));
  }
  if (next.tag !== 0x02) throw new Error('no modulus INTEGER found inside the PKCS#1 key');
  const n = next;
  const e = readTlv(der, n.next);
  const d = readTlv(der, e.next);
  return {
    n: bytesToBigInt(der.subarray(n.start, n.end)),
    e: bytesToBigInt(der.subarray(e.start, e.end)),
    d: bytesToBigInt(der.subarray(d.start, d.end)),
    // DER 的 INTEGER 正数可能带一个前导 0x00 ⇒ 模数字节数要按位长算（RSA 密文长度就是这个数）
    modulusBytes: Math.ceil(bytesToBigInt(der.subarray(n.start, n.end)).toString(2).length / 8),
  };
}

/** 从一个 .pem 文件里取出：私钥 + 证书链（按文件顺序）。 */
export function parsePem(text) {
  const blocks = pemBlocks(text);
  let key = null;
  const certs = [];
  for (const b of blocks) {
    if (b.label === 'RSA PRIVATE KEY' || b.label === 'PRIVATE KEY') key = parseRsaPrivateKey(b.der);
    else if (b.label === 'CERTIFICATE') certs.push(b.der);
  }
  if (key === null) throw new Error('no private key block in the PEM');
  return { key, certs };
}

/**
 * RSA 私钥解 PKCS#1 v1.5 加密块（TLS 1.0 的 ClientKeyExchange 就长这样）。
 * 结构：00 02 <随机非零填充> 00 <数据>
 */
export function rsaDecryptPkcs1(key, cipher) {
  const m = modPow(bytesToBigInt(cipher), key.d, key.n);
  const em = bigIntToBytes(m, cipher.length);
  if (em[0] !== 0x00 || em[1] !== 0x02) {
    throw new Error(`wrong PKCS#1 v1.5 block header: ${em[0].toString(16)} ${em[1].toString(16)}`);
  }
  let i = 2;
  while (i < em.length && em[i] !== 0) i++;
  if (i >= em.length) throw new Error('no 0x00 separator in the PKCS#1 v1.5 block');
  return em.subarray(i + 1);
}
