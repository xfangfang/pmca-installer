/**
 * apk.mjs —— 纯 JS 的 apk 静态分析（对应 backend/apk.py，逐条口径照抄）。
 *
 * 界面上显示「包名 / 版本 / minSdk / 签名文件」要用它；搬进浏览器后就彻底不需要后端了。
 * 只读、永不抛给调用方（分析不出来只影响提示，不影响装包 —— 真正装包的是相机）。
 *
 * 解压（AndroidManifest.xml 是 deflate 的）：inflateRaw 由外面注入 ——
 * 浏览器里用 `DecompressionStream('deflate-raw')`（Chrome 103+），Node 里用 zlib。
 */

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

const RES_STRING_POOL = 0x0001;
const RES_XML_START_ELEMENT = 0x0102;

const TYPE_STRING = 0x03;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_BOOLEAN = 0x12;

const PKG_RE = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;

function u16(d, o) {
  return d[o] | (d[o + 1] << 8);
}
function u32(d, o) {
  return (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)) >>> 0;
}
function latin1(d, start, len) {
  let s = '';
  for (let i = 0; i < len; i++) s += String.fromCharCode(d[start + i]);
  return s;
}
function utf8Decode(bytes) {
  if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}
function utf16leDecode(bytes) {
  let s = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const c = bytes[i] | (bytes[i + 1] << 8);
    if (c !== 0) s += String.fromCharCode(c);
  }
  return s;
}

/** 把 zip 的中央目录读成 [{name, method, compressed, uncompressed, offset}]。 */
export function readCentralDirectory(data) {
  const minEocd = 22;
  const scanFrom = Math.max(0, data.length - 65557);
  let eocd = -1;
  for (let i = data.length - minEocd; i >= scanFrom; i--) {
    if (u32(data, i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a valid zip/apk (no EOCD found)');
  const count = u16(data, eocd + 10);
  const cdOffset = u32(data, eocd + 16);
  const out = [];
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (u32(data, p) !== CD_SIG) throw new Error(`bad signature on central directory entry ${i}`);
    const method = u16(data, p + 10);
    const compressed = u32(data, p + 20);
    const uncompressed = u32(data, p + 24);
    const nameLen = u16(data, p + 28);
    const extraLen = u16(data, p + 30);
    const commentLen = u16(data, p + 32);
    const offset = u32(data, p + 42);
    out.push({
      name: latin1(data, p + 46, nameLen),
      method,
      compressed,
      uncompressed,
      offset,
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/** 读出某个条目的原始数据（store 直接切，deflate 交给注入的 inflateRaw）。 */
export async function readEntry(data, entry, inflateRaw) {
  if (u32(data, entry.offset) !== LOCAL_SIG) throw new Error(`bad local header signature: ${entry.name}`);
  const nameLen = u16(data, entry.offset + 26);
  const extraLen = u16(data, entry.offset + 28);
  const start = entry.offset + 30 + nameLen + extraLen;
  const raw = data.subarray(start, start + entry.compressed);
  if (entry.method === 0) return raw;
  if (entry.method !== 8) throw new Error(`unsupported compression method ${entry.method}`);
  return await inflateRaw(raw);
}

// ---------------------------------------------------------------- AXML
function parseStringPool(data, off) {
  const headerSize = u16(data, off + 2);
  const size = u32(data, off + 4);
  const count = u32(data, off + 8);
  const flags = u32(data, off + 16);
  const stringsStart = u32(data, off + 20);
  if (count <= 0 || count > 0x100000) throw new Error('unexpected string pool entry count');
  const utf = (flags & 0x100) !== 0;
  const base = off + stringsStart;
  const strings = [];
  for (let i = 0; i < count; i++) {
    let p = base + u32(data, off + headerSize + 4 * i);
    try {
      if (utf) {
        let n = data[p++];
        if (n & 0x80) {
          n = ((n & 0x7f) << 8) | data[p++];
        }
        let bn = data[p++];
        if (bn & 0x80) {
          bn = ((bn & 0x7f) << 8) | data[p++];
        }
        strings.push(utf8Decode(data.subarray(p, p + bn)));
      } else {
        let n = u16(data, p);
        p += 2;
        if (n & 0x8000) {
          n = ((n & 0x7fff) << 16) | u16(data, p);
          p += 2;
        }
        strings.push(utf16leDecode(data.subarray(p, p + 2 * n)));
      }
    } catch (e) {
      strings.push('');
    }
  }
  return { strings, size };
}

/** 扫描所有起始元素 → { 元素名: { 属性名: 值 } }。 */
export function parseAxml(data) {
  if (u16(data, 0) !== 0x0003) throw new Error('not AXML');
  const total = u32(data, 4);
  let off = 8;
  let strings = null;
  const elements = {};
  while (off + 8 <= Math.min(total, data.length)) {
    const ctype = u16(data, off);
    const headerSize = u16(data, off + 2);
    const csize = u32(data, off + 4);
    if (csize <= 0) break;
    if (ctype === RES_STRING_POOL) {
      strings = parseStringPool(data, off).strings;
    } else if (ctype === RES_XML_START_ELEMENT && strings) {
      // ResXMLTree_attrExt：ns(4) name(4) attributeStart(2) attributeSize(2)
      //   attributeCount(2) idIndex(2) classIndex(2) styleIndex(2)
      // ⚠️ attributeCount 在 +12（不是 +14 的 idIndex —— 曾经读错，属性数恒为 0）
      const p = off + headerSize;
      const nameIdx = u32(data, p + 4);
      const attrStart = u16(data, p + 8);
      const attrCount = u16(data, p + 12);
      const attrs = {};
      const ap = off + headerSize + attrStart;
      for (let i = 0; i < attrCount; i++) {
        const a = ap + i * 20;
        const nIdx = u32(data, a + 4);
        const rawIdx = u32(data, a + 8);
        const dtype = data[a + 15];
        const dval = u32(data, a + 16);
        const key = nIdx < strings.length ? strings[nIdx] : '';
        let val;
        if (dtype === TYPE_STRING && dval < strings.length) val = strings[dval];
        else if (dtype === TYPE_INT_DEC || dtype === TYPE_INT_HEX) val = dval;
        else if (dtype === TYPE_BOOLEAN) val = dval !== 0;
        else if (rawIdx < strings.length) val = strings[rawIdx];
        else val = dval;
        attrs[key] = val;
      }
      const ename = nameIdx < strings.length ? strings[nameIdx] : '';
      if (ename && elements[ename] === undefined) elements[ename] = attrs;
    }
    off += csize;
  }
  return elements;
}

// ---------------------------------------------------------------- 入口
/**
 * 分析 apk 字节（永不抛错，失败写进 notes）。
 * @param {Uint8Array} data
 * @param {string} name
 * @param {object} opts { inflateRaw } —— 同步或异步都行
 */
export async function analyzeApk(data, name, opts = {}) {
  const inflateRaw = opts.inflateRaw;
  const info = {
    name: name || '',
    size: data.length,
    entries: null,
    uncompressed: null,
    has_manifest: null,
    has_dex: null,
    package: null,
    version_name: null,
    version_code: null,
    min_sdk: null,
    cert_files: [],
    notes: [],
  };
  try {
    const entries = readCentralDirectory(data);
    info.entries = entries.length;
    info.uncompressed = entries.reduce((n, e) => n + e.uncompressed, 0);
    const names = entries.map((e) => e.name);
    info.has_manifest = names.indexOf('AndroidManifest.xml') >= 0;
    info.has_dex = names.some((n) => n.startsWith('classes') && n.endsWith('.dex'));
    info.cert_files = names
      .filter((n) => n.startsWith('META-INF/') && ['RSA', 'DSA', 'EC'].indexOf(ext(n)) >= 0)
      .sort();
    if (info.has_manifest) {
      try {
        if (typeof inflateRaw !== 'function') throw new Error('no inflate function available');
        const entry = entries.filter((e) => e.name === 'AndroidManifest.xml')[0];
        const xml = await readEntry(data, entry, inflateRaw);
        const elements = parseAxml(xml);
        const manifest = elements.manifest || {};
        if (PKG_RE.test(String(manifest.package || ''))) info.package = manifest.package;
        info.version_name = manifest.versionName === undefined ? null : String(manifest.versionName);
        info.version_code = manifest.versionCode === undefined ? null : String(manifest.versionCode);
        const usesSdk = elements['uses-sdk'] || {};
        info.min_sdk = usesSdk.minSdkVersion === undefined ? null : String(usesSdk.minSdkVersion);
      } catch (e) {
        info.notes.push(`manifest parsing failed: ${e && e.message ? e.message : e}`);
      }
    }
  } catch (e) {
    info.notes.push(`analysis failed: ${e && e.message ? e.message : e}`);
  }

  if (info.min_sdk === null || info.min_sdk === undefined) {
    info.notes.push('minSdkVersion unknown (the camera is API 10 / Android 2.3.7; anything >10 may not install)');
  } else if (/^\d+$/.test(info.min_sdk) && Number(info.min_sdk) > 10) {
    info.notes.push(`minSdkVersion = ${info.min_sdk} > 10: may not work on this camera`);
  }
  if (!info.cert_files.length) {
    info.notes.push('no META-INF/*.RSA|DSA|EC found — the apk may be unsigned');
  }
  return info;
}

function ext(name) {
  const i = name.lastIndexOf('.');
  return i < 0 ? '' : name.slice(i + 1).toUpperCase();
}
