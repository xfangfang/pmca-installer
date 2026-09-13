/**
 * xpd.mjs —— 纯 JS 签发 xpd 票据（与 backend/xpd.py 逐字节等价）。
 *
 * xpd 是「把相机指向哪个门户」的票，内容是个 ini：
 *     [DrmTCD]
 *     TCD = <门户地址>
 *     TKN = 0
 *     CIC = HMAC-SHA256(cicKey, TCD) 的 hexdigest
 * 相机拿 TCD 去连那个域名；而真正的 TCP 连接它会通过 USB 交给我们 —— 所以我们不必改域名。
 *
 * 格式必须与 Python 的 ConfigParser 输出**逐字节**一致（行序、` = ` 空格、结尾空行），
 * 否则相机可能不认；验收见 server-test.mjs（对着 tests/fixtures.mjs 里 Python 生成的那份比）。
 */

import { latin1Bytes, toHex } from './bytes.mjs';
import { hmacSha256 } from './sha256.mjs';
import * as K from './sony-keys.mjs';

export const SECTION = 'DrmTCD';
export const MIME_TYPE = 'application/x-psn-dstartup2';
export const PORTAL_URL = 'https://www.playmemoriescameraapps.com/';

/** CIC 字段：HMAC-SHA256(key=cicKey, msg=url) 的 hexdigest。 */
export function calculateChecksum(url) {
  return toHex(hmacSha256(K.XPD_CIC_KEY, latin1Bytes(url)));
}

export function dump(items) {
  const lines = ['[' + SECTION + ']'];
  for (const key of Object.keys(items)) lines.push(key + ' = ' + items[key]);
  return latin1Bytes(lines.join('\n') + '\n\n');
}

export function parse(data) {
  const out = {};
  const text = Array.prototype.map
    .call(data, (b) => String.fromCharCode(b))
    .join('');
  for (const line of text.split('\n')) {
    const i = line.indexOf(' = ');
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 3);
  }
  return out;
}

export function build(correlation = '0', portalUrl = PORTAL_URL) {
  return dump({
    TCD: portalUrl,
    TKN: correlation,
    CIC: calculateChecksum(portalUrl),
  });
}
