/**
 * spk.mjs —— 纯 JS 打包 spk（与 backend/spk.py 逐字节等价）。
 *
 * spk 是相机的安装包容器：
 *     '1spk' | keyOffset(int32le) | keySize(int32le) | encryptedKey(256B) | encryptedData
 * 「加密」的真相：AES key = pow(SAMPLE_SPK_KEY, 65537, RSA_MODULUS) 的最短字节表示（16 字节），
 * 而那个模数是**公钥**（相机自带）⇒ 任何人都能造出相机愿意装的 spk。
 * 数据按 SPK_BLOCK_SIZE 分块，每块各自按 PKCS#7 补齐后用 AES-ECB 加密。
 *
 * 正确性：server-test.mjs 里对着 Python 那份 spk 做逐字节比对（含真实 apk）。
 */

import { concat, bytesFromHex, latin1Bytes } from './bytes.mjs';
import { scheduleKey, ecbEncrypt, ecbDecrypt } from './aes.mjs';
import { modPow, bytesToBigInt, bigIntToBytes } from './rsa.mjs';
import * as K from './sony-keys.mjs';

let cachedKey = null;

/** 由样板块推出 AES key（16 字节）。 */
export function aesKey() {
  if (cachedKey === null) {
    const r = modPow(bytesToBigInt(K.SAMPLE_SPK_KEY), K.RSA_EXPONENT, K.RSA_MODULUS);
    const b = bigIntToBytes(r); // 最短大端表示
    if (b.length !== 16 && b.length !== 24 && b.length !== 32) {
      throw new Error(`derived AES key has an unexpected length: ${b.length} bytes`);
    }
    cachedKey = b;
  }
  return cachedKey;
}

/** PKCS#7 补齐到 16 的倍数（已对齐时补满一整块 —— 与上游一致，别"优化"掉）。 */
function padBlock(chunk, size) {
  const n = size - (chunk.length % size);
  const out = new Uint8Array(chunk.length + n);
  out.set(chunk);
  out.fill(n, chunk.length);
  return out;
}

function unpadBlock(data) {
  return data.subarray(0, data.length - data[data.length - 1]);
}

function u32le(n) {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
}

/** 把 apk 打包成 spk。 */
export function dump(apk) {
  const sched = scheduleKey(aesKey());
  const parts = [];
  for (let i = 0; i < apk.length; i += K.SPK_BLOCK_SIZE) {
    const chunk = apk.subarray(i, i + K.SPK_BLOCK_SIZE);
    parts.push(ecbEncrypt(sched, padBlock(chunk, K.SPK_PADDING_SIZE)));
  }
  return concat(
    latin1Bytes('1spk'),
    u32le(0), // keyOffset
    u32le(K.SAMPLE_SPK_KEY.length),
    K.SAMPLE_SPK_KEY,
    concat(...parts)
  );
}

/** 解出 spk 里的 apk（只给自测用）。 */
export function parse(spk) {
  const magic = latin1Bytes('1spk');
  for (let i = 0; i < 4; i++) {
    if (spk[i] !== magic[i]) throw new Error('bad spk magic');
  }
  const dv = new DataView(spk.buffer, spk.byteOffset, spk.byteLength);
  const keyHeaderOffset = 8 + dv.getInt32(4, true);
  const keySize = dv.getInt32(keyHeaderOffset, true);
  const keyOffset = keyHeaderOffset + 4;
  const dataOffset = keyOffset + keySize;
  const sched = scheduleKey(aesKey());
  const enc = spk.subarray(dataOffset);
  const parts = [];
  const stride = K.SPK_BLOCK_SIZE + K.SPK_PADDING_SIZE;
  for (let i = 0; i < enc.length; i += stride) {
    const chunk = enc.subarray(i, Math.min(i + stride, enc.length));
    parts.push(unpadBlock(ecbDecrypt(sched, chunk)));
  }
  return concat(...parts);
}
