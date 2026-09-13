/**
 * 字节工具：打包/解包，口径对齐 PMCA 的 `pmca/util/__init__.py`。
 *
 * 关键约定（照抄上游，别按「直觉」改）：
 *   - PMCA 的 `Struct` **默认小端**（`LITTLE_ENDIAN` 是默认参数）。
 *     协议里显式标了大端的才用大端：CommonMsgHeader / TcpMsgHeader / RestMsgHeader /
 *     ProxyConnectMsgHeader / SslDataMsgHeader / ProtocolMsgHeader / ThreeValueMsg。
 *   - `Struct.STR % n`（struct 格式 `ns`）：短了补 `\0`，长了截断。
 *   - 文本一律按 latin1（逐字节）处理；只有 PTP 字符串是 UTF-16LE。
 */

export function concat(...chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export function u8(v) {
  return new Uint8Array([v & 0xff]);
}

export function u16le(v) {
  return new Uint8Array([v & 0xff, (v >>> 8) & 0xff]);
}

export function u16be(v) {
  return new Uint8Array([(v >>> 8) & 0xff, v & 0xff]);
}

export function u32le(v) {
  return new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]);
}

export function u32be(v) {
  return new Uint8Array([
    (v >>> 24) & 0xff,
    (v >>> 16) & 0xff,
    (v >>> 8) & 0xff,
    v & 0xff,
  ]);
}

/** 把 (字符串 | Uint8Array | number[]) 转成 Uint8Array。字符串按 latin1（每字符一字节）。 */
export function asBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return new Uint8Array(v);
  if (typeof v === 'number') return new Uint8Array([v & 0xff]);
  const s = String(v);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export function readU8(b, o) {
  return b[o];
}

export function readU16le(b, o) {
  return b[o] | (b[o + 1] << 8);
}

export function readU16be(b, o) {
  return (b[o] << 8) | b[o + 1];
}

export function readU32le(b, o) {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

export function readU32be(b, o) {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}

/** latin1 解码（逐字节 → 字符），对应 Python 的 .decode('latin1') */
export function latin1(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

/**
 * UTF-8 解码。用于 JSON 正文：JSON 标准就是 UTF-8，而 PMCA 那边用 latin1 解，
 * 遇到中文会花屏（它只是打印一下所以无所谓，我们是要显示给人看的）。
 * 纯 ASCII 场景下与 latin1 等价，所以对现有流程没有行为变化。
 */
export function utf8(bytes) {
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder('utf-8').decode(bytes);
  }
  return decodeURIComponent(escape(latin1(bytes)));
}

/** PTP/MTP 字符串：长度前缀（字符数）×2 个字节 UTF-16LE，去尾部 NUL。 */
export function decodePtpString(bytes) {
  let s = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const c = bytes[i] | (bytes[i + 1] << 8);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(hex) {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function toBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * PMCA 的 `Struct` 等价物。
 * fields: [[名字, 类型], [null, 填充字节数], ...]
 * 类型：'u8' | 'u16' | 'u32' | 's4'（定长字符串，pmca 的 Struct.STR % n）
 */
export class Struct {
  constructor(name, fields, endian = 'little') {
    this.name = name;
    this.endian = endian;
    this.fields = [];
    this.size = 0;
    for (const [fname, ftype] of fields) {
      if (typeof ftype === 'number') {
        this.fields.push({ name: null, type: null, offset: this.size, size: ftype });
        this.size += ftype;
      } else {
        // 'u16'/'u32' = 位宽/8；'s4'/'s16' = 定长字符串的字节数（PMCA 的 Struct.STR % n）
        const size = ftype[0] === 's' ? parseInt(ftype.slice(1), 10) : Number(ftype.slice(1)) / 8;
        this.fields.push({ name: fname, type: ftype, offset: this.size, size });
        this.size += size;
      }
    }
  }

  pack(obj = {}) {
    const out = new Uint8Array(this.size);
    const dv = new DataView(out.buffer);
    const le = this.endian === 'little';
    for (const f of this.fields) {
      if (!f.type || !(f.name in obj)) continue; // 填充或未给值 → 全 0
      const v = obj[f.name];
      if (f.type === 'u8') dv.setUint8(f.offset, v);
      else if (f.type === 'u16') dv.setUint16(f.offset, v, le);
      else if (f.type === 'u32') dv.setUint32(f.offset, v, le);
      else if (f.type[0] === 's') {
        const src = asBytes(v);
        out.set(src.subarray(0, f.size), f.offset); // 短了就是 0 填充，长了截断
      }
    }
    return out;
  }

  unpack(bytes, offset = 0) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const le = this.endian === 'little';
    const out = {};
    for (const f of this.fields) {
      if (!f.type) continue;
      const o = offset + f.offset;
      if (f.type === 'u8') out[f.name] = dv.getUint8(o);
      else if (f.type === 'u16') out[f.name] = dv.getUint16(o, le);
      else if (f.type === 'u32') out[f.name] = dv.getUint32(o, le);
      else if (f.type[0] === 's') out[f.name] = bytes.subarray(o, o + f.size);
    }
    return out;
  }
}
