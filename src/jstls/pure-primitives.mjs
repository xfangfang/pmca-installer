/**
 * 纯 JS 原语适配器：不依赖 Node、也不依赖 WebCrypto（同步！）。
 *
 * 与 node-primitives.mjs 是同一个接口，所以 tls10.mjs 不知道自己在哪跑：
 *   hmac(algo, key, data) / hash(algo, data) / aesCbcEncrypt / aesCbcDecrypt / random(n)
 * 浏览器里 `random` 走 crypto.getRandomValues（同步、任何 secure context 都有）。
 *
 * 这就是「搬进浏览器」的关键一步：MD5 / SHA-1 / SHA-256 / AES-CBC / 裸 RSA 全在这套里，
 * 唯一还借外部的是随机数。
 */

import { md5 } from './md5.mjs';
import { sha1, hmacSha1 } from './sha1.mjs';
import { sha256, hmacSha256 } from './sha256.mjs';
import { scheduleKey, cbcEncrypt, cbcDecrypt } from './aes.mjs';

function webRandom(n) {
  const g = typeof globalThis !== 'undefined' ? globalThis : {};
  if (g.crypto && typeof g.crypto.getRandomValues === 'function') {
    const out = new Uint8Array(n);
    g.crypto.getRandomValues(out);
    return out;
  }
  // Node 12 的 globalThis 也有 crypto.getRandomValues（>=15 才有）；兜底用 node 的 crypto
  throw new Error('no secure random source available (crypto.getRandomValues)');
}

export function purePrimitives(options = {}) {
  const random = options.random || webRandom;
  const keyCache = new Map();
  const sched = (key) => {
    const id = key.length + ':' + Array.prototype.join.call(key, ',');
    let s = keyCache.get(id);
    if (s === undefined) {
      s = scheduleKey(key);
      if (keyCache.size > 64) keyCache.clear();
      keyCache.set(id, s);
    }
    return s;
  };

  return {
    hmac(algo, key, data) {
      if (algo === 'sha1') return hmacSha1(key, data);
      if (algo === 'sha256') return hmacSha256(key, data);
      if (algo === 'md5') {
        // MD5 的 HMAC（TLS 1.0 的 PRF 用它）
        const blockSize = 64;
        let k = key;
        if (k.length > blockSize) k = md5(k);
        const inner = new Uint8Array(blockSize);
        const outer = new Uint8Array(blockSize);
        for (let i = 0; i < blockSize; i++) {
          inner[i] = (i < k.length ? k[i] : 0) ^ 0x36;
          outer[i] = (i < k.length ? k[i] : 0) ^ 0x5c;
        }
        return md5(join(outer, md5(join(inner, data))));
      }
      throw new Error(`unimplemented HMAC algorithm: ${algo}`);
    },

    hash(algo, data) {
      if (algo === 'sha1') return sha1(data);
      if (algo === 'sha256') return sha256(data);
      if (algo === 'md5') return md5(data);
      throw new Error(`unimplemented digest algorithm: ${algo}`);
    },

    /** TLS 填充口径：`padLen` 个值为 padLen 的字节 + 1 个长度字节（padLen 可为 0）。 */
    aesCbcEncrypt(key, iv, data) {
      const padLen = (16 - ((data.length + 1) % 16)) % 16;
      const padded = new Uint8Array(data.length + padLen + 1);
      padded.set(data);
      padded.fill(padLen, data.length);
      return cbcEncrypt(sched(key), iv, padded);
    },

    aesCbcDecrypt(key, iv, cipherText) {
      const out = cbcDecrypt(sched(key), iv, cipherText);
      if (out.length < 1) throw new Error('decrypted result is empty');
      const padLen = out[out.length - 1];
      const total = padLen + 1;
      if (total > out.length) throw new Error(`invalid TLS padding length: ${padLen}`);
      for (let i = out.length - total; i < out.length; i++) {
        if (out[i] !== padLen) throw new Error(`inconsistent TLS padding bytes (the last should be ${padLen})`);
      }
      return out.subarray(0, out.length - total);
    },

    random,
  };
}

function join(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}
