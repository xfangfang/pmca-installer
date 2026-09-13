/**
 * 纯 JS MD5 —— 浏览器里也要能跑。
 *
 * 为什么自己写：TLS 1.0 的 PRF 是 `P_MD5(S1,…) XOR P_SHA1(S2,…)`，Finished 里也要 MD5，
 * 而 **WebCrypto 不提供 MD5**（不在规范允许的算法表里）⇒ 想把 TLS 服务端搬进浏览器，
 * 这一块必须自带。这里只依赖 Uint8Array / Uint32Array，Node 与浏览器通用。
 *
 * 正确性由 replay.mjs 对着 Node 的 crypto md5 逐字节校验（含 55/56/64/65 字节这些边界）。
 */

const SHIFT = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;

function rotl(v, n) {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

export function md5(input) {
  const msg = input instanceof Uint8Array ? input : new Uint8Array(input);
  const len = msg.length;

  // 0x80，补零到 56 (mod 64)，再放 64 位小端比特长度
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(msg);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, (len << 3) >>> 0, true);
  dv.setUint32(padded.length - 4, Math.floor(len / 536870912), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  const x = new Uint32Array(16);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) x[i] = dv.getUint32(off + i * 4, true);
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    for (let i = 0; i < 64; i++) {
      let f;
      let g;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      const tmp = d;
      d = c;
      c = b;
      b = (b + rotl((a + f + K[i] + x[g]) >>> 0, SHIFT[i])) >>> 0;
      a = tmp;
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, a0, true);
  odv.setUint32(4, b0, true);
  odv.setUint32(8, c0, true);
  odv.setUint32(12, d0, true);
  return out;
}
