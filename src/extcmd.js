/**
 * Sony 外部命令（SonyExtCmdCamera）：把「插件号 + 命令号」包成 ExtCmdHeader 再发。
 *
 * 对应 PMCA `pmca/usb/sony.py: SonyExtCmdCamera`。本工具只用到其中两条：
 *   (5, 2) NotifyScalarDlmode  —— 切到 app 安装模式
 *   (1, 1) GetModelInfo        —— 打印机型（可选的信息展示）
 *
 * 传输无关：只要 dev 提供 `sendSonyExtCommand(cmd, data, bufferSize)` 即可
 * （MSC 侧是 MscBbbDevice，PTP 侧是 SonyMtpExtCmdDevice）。
 */

import { Struct, concat, latin1 } from './bytes.js';

const ExtCmdHeader = new Struct('ExtCmdHeader', [
  ['dataSize', 'u32'],
  ['cmd', 'u16'],
  ['direction', 'u16'],
  [null, 8],
]);

const WRITE_BUFFER_SIZE = 0x2000;
const READ_BUFFER_SIZE = 0x2000;

export const CMD_DevInfoSender_GetModelInfo = [1, 1];
export const CMD_ScalarExtCmdPlugIn_NotifyScalarDlmode = [5, 2];

function padTo(bytes, size) {
  if (bytes.length >= size) return bytes;
  const out = new Uint8Array(size);
  out.set(bytes);
  return out;
}

export class SonyExtCmdCamera {
  constructor(dev) {
    this.dev = dev;
  }

  async _sendCommand(cmd, data = new Uint8Array(0), writeBufferSize = WRITE_BUFFER_SIZE, readBufferSize = READ_BUFFER_SIZE) {
    const payload = padTo(
      concat(ExtCmdHeader.pack({ dataSize: data.length, cmd: cmd[1], direction: 0 }), data),
      writeBufferSize
    );
    const out = await this.dev.sendSonyExtCommand(cmd[0], payload, readBufferSize);
    if (readBufferSize === 0 || out.length < ExtCmdHeader.size) return new Uint8Array(0);
    const header = ExtCmdHeader.unpack(out);
    return out.subarray(ExtCmdHeader.size, ExtCmdHeader.size + header.dataSize);
  }

  /** 让相机切进 app 安装模式（写完就不管回包：readBufferSize=0）。 */
  async switchToAppInstaller() {
    await this._sendCommand(CMD_ScalarExtCmdPlugIn_NotifyScalarDlmode, new Uint8Array(0), WRITE_BUFFER_SIZE, 0);
  }

  /**
   * 机型信息。PMCA 的布局（plist 后跟机型/型号代码/序列号）：
   *   u32 plistSize | plist | u32 | u8 modelSize | model | 5 字节 modelCode | 4 字节 serial
   * 这里只取「机型」，够在界面上确认连对了相机。
   */
  async getCameraInfo() {
    const data = await this._sendCommand(CMD_DevInfoSender_GetModelInfo);
    if (data.length < 5) return { modelName: null };
    const plistSize = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    let off = 4 + plistSize + 4;
    if (off >= data.length) return { modelName: null };
    const modelSize = data[off];
    off += 1;
    return { modelName: latin1(data.subarray(off, off + modelSize)) };
  }
}
