/**
 * PTP/MTP 侧：容器封装 + DeviceInfo + Sony 的「代理消息」私有操作。
 *
 * 对应 PMCA：
 *   pmca/usb/driver/__init__.py : MtpDriver（PTP 容器收发）
 *   pmca/usb/__init__.py        : MtpDevice（openSession / getDeviceInfo）
 *   pmca/usb/sony.py            : SonyMtpAppInstallDevice
 *
 * 一个反直觉但很关键的点：**这个协议是轮询式的**。
 * 相机没有东西要送时，`GetProxyMessage` 会回一个长度为 0 的 DATA 容器 + 响应码
 * `PTP_RC_NoData`，于是 `receiveMessage()` 返回 (null, null)，上层 `continue` 去检查
 * 代理 socket 有没有数据要送给相机。所以「读」不会一直阻塞，别写成「等到有数据为止」。
 *
 * 布局（PTP 容器，小端）：
 *   PtpHeader = size(u32, 含头) + type(u16) + code(u16) + transaction(u32)  = 12 字节
 */

import { Struct, concat, decodePtpString } from './bytes.js';
import { UsbError } from './usb.js';
import { tr } from './i18n.js';

const MAX_PKG_LEN = 512;

const TYPE_COMMAND = 1;
const TYPE_DATA = 2;
const TYPE_RESPONSE = 3;

const PtpHeader = new Struct('PtpHeader', [
  ['size', 'u32'],
  ['type', 'u16'],
  ['code', 'u16'],
  ['transaction', 'u32'],
]);

const MsgHeader = new Struct('MsgHeader', [['type', 'u16']], 'big');

const InfoMsgHeader = new Struct('InfoMsgHeader', [
  [null, 4],
  ['magic', 'u16'],
  [null, 2],
  ['dataSize', 'u32'],
  [null, 2],
  [null, 42],
]);

export class MtpError extends UsbError {}
export class MtpInvalidCommand extends MtpError {}

export const PTP_RC_OK = 0x2001;
export const PTP_RC_SessionNotOpen = 0x2003;
export const PTP_RC_ParameterNotSupported = 0x2006;
export const PTP_RC_DeviceBusy = 0x2019;
export const PTP_RC_SessionAlreadyOpened = 0x201e;

// libInfraMtpServer.so 里的索尼厂商外部命令（**普通 MTP 模式**用它）
// （0xa489 的 PTP_RC_SonyDeviceBusy 上面已经导出过，两边都用它）
export const PTP_OC_SonyDiExtCmd_write = 0x9280;
export const PTP_OC_SonyDiExtCmd_read = 0x9281;

const PTP_OC_GetDeviceInfo = 0x1001;
const PTP_OC_OpenSession = 0x1002;
const PTP_OC_CloseSession = 0x1003;

// libUsbAppDlSvr.so 里的私有操作（app 安装模式专用）
export const PTP_OC_GetProxyMessageInfo = 0x9488;
export const PTP_OC_GetProxyMessage = 0x9489;
export const PTP_OC_SendProxyMessageInfo = 0x948c;
export const PTP_OC_SendProxyMessage = 0x948d;
export const PTP_RC_NoData = 0xa488;
export const PTP_RC_SonyDeviceBusy = 0xa489;

export const SONY_MANUFACTURER = 'Sony Corporation';
const INFO_MAGIC = 0xb481;

export class MtpDevice {
  constructor(usb, log = () => {}) {
    this.usb = usb;
    this.log = log;
    this.transaction = 0;
    this.timeout = 20000;
  }

  // ---------------- 传输层（PMCA 的 MtpDriver）
  async _writePtp(type, code, transaction, data = new Uint8Array(0)) {
    const header = PtpHeader.pack({
      size: PtpHeader.size + data.length,
      type,
      code,
      transaction,
    });
    await this.usb.write(concat(header, data));
  }

  async _readPtp() {
    let data = new Uint8Array(0);
    let guard = 0;
    while (data.length === 0) {
      data = await this.usb.readUpTo(MAX_PKG_LEN, 0, this.timeout);
      if (data.length === 0 && ++guard > 8) throw new MtpError('USB returned empty packets back to back');
    }
    // 至少要凑够一个头，才能知道这一包有多长
    while (data.length < PtpHeader.size) {
      data = concat(data, await this.usb.readUpTo(PtpHeader.size - data.length, 0, this.timeout));
    }
    const header = PtpHeader.unpack(data);
    if (header.size > data.length) {
      data = concat(data, await this.usb.readExactly(header.size - data.length, 0, this.timeout));
    }
    return {
      type: header.type,
      code: header.code,
      transaction: header.transaction,
      data: data.subarray(PtpHeader.size, PtpHeader.size + header.size),
    };
  }

  async _readData() {
    const msg = await this._readPtp();
    if (msg.type !== TYPE_DATA) throw new MtpError(`expected a DATA container but got type=0x${msg.type.toString(16)}`);
    return msg.data;
  }

  async _readResponse() {
    const msg = await this._readPtp();
    if (msg.type !== TYPE_RESPONSE) {
      throw new MtpError(`expected a RESPONSE container but got type=0x${msg.type.toString(16)}`);
    }
    return msg.code;
  }

  _checkResponse(code, accepted = []) {
    if (code === PTP_RC_OK || accepted.includes(code)) return;
    const msg = `MTP error 0x${code.toString(16)}`;
    if (code === PTP_RC_ParameterNotSupported) throw new MtpInvalidCommand(msg);
    throw new MtpError(msg);
  }

  /**
   * 发起一个命令。transaction id 先自增再使用 ⇒ 第一条命令的 id = 1
   * （对齐 PMCA `_writeInitialCommand`：`self.transaction += 1` 在写之前）。
   */
  async _writeInitialCommand(code, args) {
    this.transaction += 1;
    const payload = new Uint8Array(4 * args.length);
    const dv = new DataView(payload.buffer);
    args.forEach((a, i) => dv.setUint32(i * 4, a >>> 0, true));
    await this._writePtp(TYPE_COMMAND, code, this.transaction, payload);
  }

  /** 无数据阶段的命令。 */
  async sendCommand(code, args) {
    await this._writeInitialCommand(code, args);
    return await this._readResponse();
  }

  /** 写数据阶段的命令。 */
  async sendWriteCommand(code, args, data) {
    await this._writeInitialCommand(code, args);
    // DATA 容器用与 COMMAND 相同的 transaction id（PMCA: self.transaction）
    await this._writePtp(TYPE_DATA, code, this.transaction, data);
    return await this._readResponse();
  }

  /** 读数据阶段的命令 → {code, data}。 */
  async sendReadCommand(code, args) {
    await this._writeInitialCommand(code, args);
    const data = await this._readData();
    return { code: await this._readResponse(), data };
  }

  // ---------------- 会话（PMCA 的 MtpDevice）
  /**
   * 打开设备：清 halt → **先问 DeviceInfo（不开会话）** → 再开会话。
   *
   * 顺序有意与 PMCA 略不同（它是 OpenSession 优先）：DeviceInfo 在 PTP 里本来就允许
   * 在会话之外问（libmtp 等主流实现也是这个顺序），而且这样能把失败**分层**：
   * DeviceInfo 拿到了 ⇒ 传输层没问题；拿不到 ⇒ 是传输层/驱动/占用的问题。
   *
   * ⚠️ 会话必须拿到：硬件实测（ILCE-5100 普通 MTP 模式）**厂商命令 0x9280 要求会话
   * 已打开**，没会话时相机会直接 STALL 掉数据阶段。所以这里不会「失败也继续」。
   */
  async open() {
    await this.usb.reset(); // PMCA 里是 detach 内核驱动，WebUSB 下为 no-op
    this.info = null;
    if (this.usb.clearHaltBoth) {
      const eps = await this.usb.clearHaltBoth();
      this.log(`cleared halt on: ${eps.join(', ')}`);
    }

    try {
      this.info = await this.getDeviceInfo();
      this.log('✓ got DeviceInfo without opening a session (the transport layer is fine)', 'ok');
    } catch (e) {
      this.log(`DeviceInfo without a session failed: ${String(e.message).split('\n')[0]}`, 'warn');
    }

    await this._openSessionWithRecovery();
    return this;
  }

  /**
   * 开会话；被 STALL 时按**硬件实测过的顺序**自救：
   *   清 halt → CloseSession（收尾残留会话，回 SessionNotOpen 也算正常）→ OpenSession 再来
   * 实测依据：探针里先 CloseSession 再 OpenSession 就成功了，而直接 OpenSession 会 STALL
   * （相机端残留着上一次没收干净的会话）。
   */
  async _openSessionWithRecovery() {
    try {
      await this.openSession(1);
      return;
    } catch (e) {
      if (!e.stalled) throw e;
      this.log('OpenSession stalled → cleared the halt and closed the leftover session, retrying once', 'warn');
      if (this.usb.clearHaltBoth) await this.usb.clearHaltBoth();
      try {
        await this.closeSession(); // 本来就没会话时会回 SessionNotOpen，正常
      } catch (err) {
        /* 忽略：收尾失败不影响重试 */
      }
      await this.openSession(1);
      this.log('session established (via the self-recovery path)', 'ok');
    }
  }

  /**
   * 索尼外部命令通道（**MTP 版**）。对应 PMCA `SonyMtpExtCmdDevice.sendSonyExtCommand`：
   * 同一个「插件号」先写后读，响应码 SonyDeviceBusy 时整条重试。
   *
   * 为什么重要：PMCA 切进 app 安装模式有两条路 —— 大容量存储模式下用 SCSI 0x7a，
   * 普通 MTP 模式下就用这里的 0x9280/0x9281。而在 macOS 上 Chrome 抢不到大容量存储
   * 接口（无法 detach 内核驱动），所以对「相机设成 MTP 模式」的用户，**这是唯一的路**。
   * 有了它，extcmd.js 的 SonyExtCmdCamera 就能当传输无关的包装层复用。
   *
   * 被 STALL 时不直接放弃：清 halt + 重开会话再发一次。
   * （本工具只用它发 NotifyScalarDlmode 与 GetModelInfo，两者幂等，重发安全。）
   */
  async sendSonyExtCommand(cmd, data, bufferSize) {
    try {
      return await this._sendSonyExtCommand(cmd, data, bufferSize);
    } catch (e) {
      if (!e.stalled) throw e;
      this.log('vendor command stalled → cleared the halt, reopened the session and sent it again', 'warn');
      if (this.usb.clearHaltBoth) await this.usb.clearHaltBoth();
      try {
        await this.closeSession();
      } catch (err) {
        /* ignore */
      }
      await this.openSession(1);
      return await this._sendSonyExtCommand(cmd, data, bufferSize);
    }
  }

  async _sendSonyExtCommand(cmd, data, bufferSize) {
    let response = await this._busyRetry(
      () => this.sendWriteCommand(PTP_OC_SonyDiExtCmd_write, [cmd], data),
      `vendor command 0x9280, write phase (plugin ${cmd})`
    );
    this._checkResponse(response);

    if (bufferSize === 0) return new Uint8Array(0);

    let out = new Uint8Array(0);
    response = await this._busyRetry(async () => {
      const res = await this.sendReadCommand(PTP_OC_SonyDiExtCmd_read, [cmd]);
      out = res.data;
      return res.code;
    }, `vendor command 0x9281, read phase (plugin ${cmd})`);
    this._checkResponse(response);
    return out;
  }

  /**
   * 一直重发直到不再是「忙」。
   *
   * 关键：**两种忙码都要认** —— 上游 PMCA 只重试索尼私有忙码 `0xa489`，但实测（ILCE-5100，
   * app 安装模式）相机会回**标准 PTP 忙码 `0x2019`**，只认前者就会直接报「MTP 错误 0x2019」。
   * 加上次数上限，避免相机一直忙时无限循环（上游是无上限的）。
   */
  async _busyRetry(fn, label, maxTries = 100) {
    let code;
    for (let i = 1; ; i++) {
      code = await fn();
      if (code !== PTP_RC_DeviceBusy && code !== PTP_RC_SonyDeviceBusy) return code;
      if (i >= maxTries) {
        throw new MtpError(`${label} keeps reporting busy (retried ${maxTries} times)`);
      }
      if (i === 1 || i % 20 === 0) this.log(`${label}: camera reports busy (0x${code.toString(16)}), retrying…`);
    }
  }

  async openSession(id = 1) {
    const code = await this.sendCommand(PTP_OC_OpenSession, [id]);
    this._checkResponse(code, [PTP_RC_SessionAlreadyOpened]);
  }

  async closeSession() {
    const code = await this.sendCommand(PTP_OC_CloseSession, []);
    this._checkResponse(code, [PTP_RC_SessionNotOpen]);
  }

  _parseString(data, offset) {
    const length = data[offset];
    offset += 1;
    const end = offset + 2 * length;
    return [end, decodePtpString(data.subarray(offset, end))];
  }

  _parseIntArray(data, offset) {
    const length =
      data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
    offset += 4;
    const end = offset + 2 * length;
    const out = [];
    for (let o = offset; o < end; o += 2) out.push(data[o] | (data[o + 1] << 8));
    return [end, out];
  }

  _parseDeviceInfo(data) {
    let offset = 8; // DeviceInfo 头部
    let vendorExtension;
    [offset, vendorExtension] = this._parseString(data, offset);
    offset += 2; // FunctionalMode
    let operationsSupported, eventsSupported, devicePropertiesSupported, captureFormats, imageFormats;
    [offset, operationsSupported] = this._parseIntArray(data, offset);
    [offset, eventsSupported] = this._parseIntArray(data, offset);
    [offset, devicePropertiesSupported] = this._parseIntArray(data, offset);
    [offset, captureFormats] = this._parseIntArray(data, offset);
    [offset, imageFormats] = this._parseIntArray(data, offset);
    let manufacturer, model, version, serial;
    [offset, manufacturer] = this._parseString(data, offset);
    [offset, model] = this._parseString(data, offset);
    [offset, version] = this._parseString(data, offset);
    [offset, serial] = this._parseString(data, offset);
    return {
      manufacturer,
      model,
      version,
      serialNumber: serial,
      operationsSupported: new Set(operationsSupported),
      vendorExtension,
    };
  }

  async getDeviceInfo() {
    const { code, data } = await this.sendReadCommand(PTP_OC_GetDeviceInfo, []);
    this._checkResponse(code);
    return this._parseDeviceInfo(data);
  }
}

/** 判断「这是不是一台处于 app 安装模式的索尼相机」（PMCA 同款三条判断）。 */
export function isSonyMtpAppInstallCamera(info) {
  const required = [
    PTP_OC_GetProxyMessageInfo,
    PTP_OC_GetProxyMessage,
    PTP_OC_SendProxyMessageInfo,
    PTP_OC_SendProxyMessage,
  ];
  return (
    info.manufacturer === SONY_MANUFACTURER &&
    (info.vendorExtension || '').includes('sony.net/SEN_PRXY_MSG:') &&
    required.every((op) => info.operationsSupported.has(op))
  );
}

/** 普通 MTP 模式（用于提示用户「你现在连的是 MTP，不是安装模式」）。 */
export function isSonyMtpCamera(info) {
  const required = [0x9280, 0x9281, 0x9282];
  return (
    info.manufacturer === SONY_MANUFACTURER &&
    !info.vendorExtension &&
    required.every((op) => info.operationsSupported.has(op))
  );
}

/**
 * app 安装模式的设备：把一条「代理消息」通过两个 PTP 私有操作搬进/搬出相机。
 * 消息体是 SonyAppInstallCamera 的协议（见 appinstall.js）。
 */
export class SonyMtpAppInstallDevice extends MtpDevice {
  async _write(data) {
    const info = InfoMsgHeader.pack({ magic: INFO_MAGIC, dataSize: data.length });
    // 「忙」要重试（两种忙码都认，见 _busyRetry）
    let response = await this._busyRetry(
      () => this.sendWriteCommand(PTP_OC_SendProxyMessageInfo, [], info),
      'proxy message length report (0x948c)'
    );
    this._checkResponse(response);

    response = await this._busyRetry(
      () => this.sendWriteCommand(PTP_OC_SendProxyMessage, [], data),
      'proxy message send (0x948d)'
    );
    this._checkResponse(response);
  }

  async _read() {
    // 两次查询都可能是「忙」：相机没话说时会回 dataSize=0 + PTP_RC_NoData(0xa488)，
    // 而繁忙时回 0x2019/0xa489 —— 后者要重试，前者是正常的轮询结果。
    const infoRes = await this._busyRetry(
      () => this.sendReadCommand(PTP_OC_GetProxyMessageInfo, [0]),
      'proxy message length query (0x9488)'
    );
    this._checkResponse(infoRes.code);
    const info = InfoMsgHeader.unpack(infoRes.data);
    if (info.magic !== INFO_MAGIC) {
      throw new MtpError(`bad proxy message magic: 0x${info.magic.toString(16)}`);
    }
    const res = await this._busyRetry(
      () => this.sendReadCommand(PTP_OC_GetProxyMessage, [0]),
      'proxy message read (0x9489)'
    );
    this._checkResponse(res.code, [PTP_RC_NoData]);
    return res.data.subarray(0, info.dataSize);
  }

  async sendMessage(type, data) {
    await this._write(concat(MsgHeader.pack({ type }), data));
  }

  /** 返回 [type, data]；相机没话要说时返回 [null, null]。 */
  async receiveMessage() {
    const data = await this._read();
    if (data.length === 0) return [null, null];
    const type = MsgHeader.unpack(data).type;
    return [type, data.subarray(MsgHeader.size)];
  }
}
