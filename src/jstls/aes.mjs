/**
 * 纯 JS AES（128/192/256）+ CBC/ECB 辅助。
 *
 * 为什么必须自己写（实测结论，见 tests/tls/README.md #9）：
 *   WebCrypto 的 AES-CBC **自带 PKCS#7 补填充**，没有关掉的开关；而 TLS 的填充是
 *   「padding_length 个值为 padding_length 的字节 + 1 个长度字节」，padding_length 还可以是 0
 *   ⇒ 借它的填充会在某些记录上直接报错。更关键的是 WebCrypto 只给 AES **加密方向**的原语
 *   （CTR/GCM 内部都是盖密码流），**没有 AES 解密方向**的裸接口，而解相机发来的记录必须用它。
 *
 * 实现走 FIPS-197 的直白结构（SubBytes/ShiftRows/MixColumns/AddRoundKey + 逆过程），
 * S-box 与各乘法表都在加载时算出来 —— 不硬编码 256 字节的表，省得抄错一位。
 * 实测速度够用：2.9 MB 的 spk 加解密在几十毫秒到几百毫秒量级，USB 传输才是瓶颈。
 *
 * 正确性：crypto-test.mjs 里对着 Node 的 crypto 逐字节比（ECB 单块、CBC 多块、128/256 位密钥）。
 */

// ---------------------------------------------------------------- GF(2^8)
function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function mulTable(n) {
  const t = new Uint8Array(256);
  for (let a = 0; a < 256; a++) t[a] = gmul(a, n);
  return t;
}

const M2 = mulTable(2);
const M3 = mulTable(3);
const M9 = mulTable(9);
const M11 = mulTable(11);
const M13 = mulTable(13);
const M14 = mulTable(14);

function rotl8(x, n) {
  return ((x << n) | (x >>> (8 - n))) & 0xff;
}

// S-box / 逆 S-box：由「GF(2^8) 乘法逆 + 仿射变换」直接算出来
const SBOX = new Uint8Array(256);
const RSBOX = new Uint8Array(256);
{
  const inv = new Uint8Array(256);
  for (let a = 1; a < 256; a++) {
    for (let b = 1; b < 256; b++) {
      if (gmul(a, b) === 1) {
        inv[a] = b;
        break;
      }
    }
  }
  for (let a = 0; a < 256; a++) {
    const x = inv[a];
    const s = (x ^ rotl8(x, 1) ^ rotl8(x, 2) ^ rotl8(x, 3) ^ rotl8(x, 4) ^ 0x63) & 0xff;
    SBOX[a] = s;
    RSBOX[s] = a;
  }
}

// ---------------------------------------------------------------- 密钥扩展
function expandKey(key) {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`AES key length must be 16/24/32 bytes, got ${key.length}`);
  }
  const nk = key.length / 4;
  const nr = nk + 6;
  const w = new Uint8Array(16 * (nr + 1));
  w.set(key);
  let rcon = 1;
  for (let i = nk; i < 4 * (nr + 1); i++) {
    let t0 = w[4 * (i - 1)];
    let t1 = w[4 * (i - 1) + 1];
    let t2 = w[4 * (i - 1) + 2];
    let t3 = w[4 * (i - 1) + 3];
    if (i % nk === 0) {
      const tmp = t0;
      t0 = SBOX[t1] ^ rcon;
      t1 = SBOX[t2];
      t2 = SBOX[t3];
      t3 = SBOX[tmp];
      rcon = gmul(rcon, 2);
    } else if (nk > 6 && i % nk === 4) {
      t0 = SBOX[t0];
      t1 = SBOX[t1];
      t2 = SBOX[t2];
      t3 = SBOX[t3];
    }
    w[4 * i] = w[4 * (i - nk)] ^ t0;
    w[4 * i + 1] = w[4 * (i - nk) + 1] ^ t1;
    w[4 * i + 2] = w[4 * (i - nk) + 2] ^ t2;
    w[4 * i + 3] = w[4 * (i - nk) + 3] ^ t3;
  }
  return { w, nr };
}

function subBytes(s, box) {
  for (let i = 0; i < 16; i++) s[i] = box[s[i]];
}

function addRoundKey(s, w, round) {
  for (let i = 0; i < 16; i++) s[i] ^= w[16 * round + i];
}

function shiftRows(s) {
  let t = s[1];
  s[1] = s[5];
  s[5] = s[9];
  s[9] = s[13];
  s[13] = t;
  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;
  // 第 3 行要左移 3（= 右移 1）—— 写成左移 1 会跟 InvShiftRows 一起错成"自洽的另¬—种算法"，
  // 往返测试看不出来，只有官方向量能发现
  t = s[15];
  s[15] = s[11];
  s[11] = s[7];
  s[7] = s[3];
  s[3] = t;
}

function invShiftRows(s) {
  let t = s[13];
  s[13] = s[9];
  s[9] = s[5];
  s[5] = s[1];
  s[1] = t;
  t = s[14];
  s[14] = s[6];
  s[6] = t;
  t = s[10];
  s[10] = s[2];
  s[2] = t;
  t = s[3];
  s[3] = s[7];
  s[7] = s[11];
  s[11] = s[15];
  s[15] = t;
}

function mixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const i = 4 * c;
    const a0 = s[i];
    const a1 = s[i + 1];
    const a2 = s[i + 2];
    const a3 = s[i + 3];
    s[i] = M2[a0] ^ M3[a1] ^ a2 ^ a3;
    s[i + 1] = a0 ^ M2[a1] ^ M3[a2] ^ a3;
    s[i + 2] = a0 ^ a1 ^ M2[a2] ^ M3[a3];
    s[i + 3] = M3[a0] ^ a1 ^ a2 ^ M2[a3];
  }
}

function invMixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const i = 4 * c;
    const a0 = s[i];
    const a1 = s[i + 1];
    const a2 = s[i + 2];
    const a3 = s[i + 3];
    s[i] = M14[a0] ^ M11[a1] ^ M13[a2] ^ M9[a3];
    s[i + 1] = M9[a0] ^ M14[a1] ^ M11[a2] ^ M13[a3];
    s[i + 2] = M13[a0] ^ M9[a1] ^ M14[a2] ^ M11[a3];
    s[i + 3] = M11[a0] ^ M13[a1] ^ M9[a2] ^ M14[a3];
  }
}

// ---------------------------------------------------------------- 单块加解密
/** 加密一个 16 字节块（输入/输出都是 16 字节）。 */
export function encryptBlock(key, block) {
  const ks = key.w ? key : expandKey(key);
  const s = new Uint8Array(block);
  addRoundKey(s, ks.w, 0);
  for (let r = 1; r < ks.nr; r++) {
    subBytes(s, SBOX);
    shiftRows(s);
    mixColumns(s);
    addRoundKey(s, ks.w, r);
  }
  subBytes(s, SBOX);
  shiftRows(s);
    addRoundKey(s, ks.w, ks.nr);
  return s;
}

/** 解密一个 16 字节块。 */
export function decryptBlock(key, block) {
  const ks = key.w ? key : expandKey(key);
  const s = new Uint8Array(block);
  addRoundKey(s, ks.w, ks.nr);
  for (let r = ks.nr - 1; r >= 1; r--) {
    invShiftRows(s);
    subBytes(s, RSBOX);
    addRoundKey(s, ks.w, r);
    invMixColumns(s);
  }
  invShiftRows(s);
  subBytes(s, RSBOX);
  addRoundKey(s, ks.w, 0);
  return s;
}

/** 预先把密钥排好（重复加密时省一次扩展）。 */
export function scheduleKey(key) {
  return expandKey(key instanceof Uint8Array ? key : new Uint8Array(key));
}

// ---------------------------------------------------------------- 模式
/** ECB 加密（按 16 字节块；spk 就是这么用的）。 */
export function ecbEncrypt(sched, data) {
  if (data.length % 16 !== 0) throw new Error('ECB data length must be a multiple of 16');
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 16) out.set(encryptBlock(sched, data.subarray(i, i + 16)), i);
  return out;
}

export function ecbDecrypt(sched, data) {
  if (data.length % 16 !== 0) throw new Error('ECB data length must be a multiple of 16');
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 16) out.set(decryptBlock(sched, data.subarray(i, i + 16)), i);
  return out;
}

/**
 * CBC 加密（**裸**：不补填充，调用方保证长度是 16 的倍数）。
 * TLS 的填充由记录层按自己的口径加上去。
 */
export function cbcEncrypt(sched, iv, data) {
  if (data.length % 16 !== 0) throw new Error('CBC data length must be a multiple of 16');
  let prev = iv;
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 16) {
    const blk = new Uint8Array(16);
    for (let k = 0; k < 16; k++) blk[k] = data[i + k] ^ prev[k];
    const enc = encryptBlock(sched, blk);
    out.set(enc, i);
    prev = enc;
  }
  return out;
}

/** CBC 解密（裸，不碰填充）。 */
export function cbcDecrypt(sched, iv, data) {
  if (data.length % 16 !== 0) throw new Error('CBC data length must be a multiple of 16');
  let prev = iv;
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 16) {
    const ct = data.subarray(i, i + 16);
    const dec = decryptBlock(sched, ct);
    for (let k = 0; k < 16; k++) out[i + k] = dec[k] ^ prev[k];
    prev = ct;
  }
  return out;
}
