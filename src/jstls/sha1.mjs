/**
 * 纯 JS SHA-1 与 HMAC-SHA1。
 *
 * 为什么要自己写：TLS 1.0 的记录层 MAC 就是 HMAC-SHA1（`TLS_RSA_WITH_AES_128/256_CBC_SHA`）。
 * 浏览器里 WebCrypto 其实**有** HMAC-SHA1，但它是异步的 —— 而记录层是同步的逐块处理，
 * 混进 async 会把整条链路搅浑。既然 MD5/AES 都已经自写，SHA-1 也一并自写，
 * 这套代码就变成「零依赖、同步、Node 与浏览器同一份」。
 *
 * 正确性：crypto-test.mjs 里对着 Node 的 crypto 逐字节比（含多块/边界长度）。
 */

const K = new Uint32Array([0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]);

function rotl(v, n) {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

/** SHA-1：返回 20 字节。 */
export function sha1(input) {
  const msg = input instanceof Uint8Array ? input : new Uint8Array(input);
  const len = msg.length;
  // 0x80 + 补零到 56 (mod 64) + 64 位大端比特长度
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(msg);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(len / 536870912), false);
  dv.setUint32(padded.length - 4, (len << 3) >>> 0, false);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    for (let i = 0; i < 80; i++) {
      let f;
      let k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = K[0];
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = K[1];
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = K[2];
      } else {
        f = b ^ c ^ d;
        k = K[3];
      }
      const tmp = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = tmp;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, h0, false);
  odv.setUint32(4, h1, false);
  odv.setUint32(8, h2, false);
  odv.setUint32(12, h3, false);
  odv.setUint32(16, h4, false);
  return out;
}

/** HMAC（通用：传 hash 函数与它的块长）。 */
export function hmac(hashFn, blockSize, key, data) {
  let k = key instanceof Uint8Array ? key : new Uint8Array(key);
  if (k.length > blockSize) k = hashFn(k);
  const pad = new Uint8Array(blockSize);
  pad.set(k);
  const inner = new Uint8Array(blockSize);
  const outer = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    inner[i] = pad[i] ^ 0x36;
    outer[i] = pad[i] ^ 0x5c;
  }
  return hashFn(concat(outer, hashFn(concat(inner, data))));
}

/** HMAC-SHA1（TLS 记录层用）。 */
export function hmacSha1(key, data) {
  return hmac(sha1, 64, key, data);
}

// 这里放一个最小的 concat，避免为了一个函数再引一个模块
function concat(...parts) {
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

export { concat };
