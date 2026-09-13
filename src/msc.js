/**
 * 大容量存储（MSC）侧：Bulk-Only Transport + SCSI + Sony 外部命令。
 *
 * 这里只为一件事服务：把相机从「大容量存储」切进「app 安装模式」
 * （`NotifyScalarDlmode` = 命令 (5, 2)）。对应 PMCA：
 *   pmca/usb/driver/__init__.py : MscBbbDriver
 *   pmca/usb/sony.py            : MscDevice / _BaseSonyMscExtCmdDevice / SonyExtCmdCamera
 *
 * 两个必须照抄的行为：
 *   1. 数据阶段**只读一次**（`readUpTo`），不能 readExactly：
 *      CBW 的 dataTransferLength 只是「我准备接多少」，设备完全可以少发
 *      （ext cmd 的读回就是典型：我们申请 0x2000，它只发 header.dataSize 那么多）。
 *      多要一次就会挂在那里等一个永远不来的包。
 *   2. DeviceBusy（sense 0x9/0x81/0x81）要**重试同一条命令**，不是错误。
 */

import { Struct, concat, u8, u32le, latin1 } from './bytes.js';
import { UsbError } from './usb.js';

const MSC_OC_INQUIRY = 0x12;
const MSC_OC_REQUEST_SENSE = 0x03;
const MSC_OC_EXT_CMD = 0x7a;

export const MSC_SENSE_OK = [0, 0, 0];
const MSC_SENSE_ERROR_UNKNOWN = [0x2, 0xff, 0xff];
const MSC_SENSE_INVALID_COMMAND_OPERATION_CODE = [0x5, 0x20, 0x0];
const MSC_SENSE_DEVICE_BUSY = [0x9, 0x81, 0x81];

const DIRECTION_WRITE = 0;
const DIRECTION_READ = 0x80;

const Cbw = new Struct('MscCommandBlockWrapper', [
  ['signature', 's4'], // 'USBC'
  ['tag', 'u32'],
  ['dataTransferLength', 'u32'],
  ['flags', 'u8'],
  ['lun', 'u8'],
  ['commandLength', 'u8'],
  ['command', 's16'], // commandLength 之后的其余字节都补 0（PMCA: struct 's' 自动补齐）
]);

const Csw = new Struct('MscCommandStatusWrapper', [
  ['signature', 's4'], // 'USBS'
  ['tag', 'u32'],
  ['dataResidue', 'u32'],
  ['status', 'u8'],
]);

const ExtCmdHeader = new Struct('ExtCmdHeader', [
  ['dataSize', 'u32'],
  ['cmd', 'u16'],
  ['direction', 'u16'],
  [null, 8],
]);

export class MscError extends UsbError {}

export class MscInvalidCommand extends MscError {}

function padTo(bytes, size) {
  if (bytes.length >= size) return bytes;
  const out = new Uint8Array(size);
  out.set(bytes);
  return out;
}

function sameSense(a, b) {
  return a[0] === b[0] && a[1] === b[1] && a[2] === b[2];
}

/** SCSI sense 三元组（PMCA 的 parseMscSense）。 */
export function parseMscSense(buf) {
  return [buf[2] & 0x0f, buf[12], buf[13]];
}

export class MscBbbDevice {
  constructor(usb, log = () => {}) {
    this.usb = usb;
    this.log = log;
    this.lastSense = MSC_SENSE_OK; // 最近一条 SCSI 命令的 sense（DeviceBusy 要重试）
  }

  /** MscDevice.__init__：先发一条 6 字节全 0 的命令（TEST UNIT READY 类）。 */
  async open() {
    await this.usb.reset();
    await this.sendCommand(new Uint8Array(6));
    return this;
  }

  _checkResponse(sense) {
    if (sameSense(sense, MSC_SENSE_OK)) return;
    const msg = `mass storage error: sense 0x${sense[0].toString(16)} 0x${sense[1].toString(16)} 0x${sense[2].toString(16)}`;
    if (sameSense(sense, MSC_SENSE_INVALID_COMMAND_OPERATION_CODE)) throw new MscInvalidCommand(msg);
    if (sameSense(sense, MSC_SENSE_ERROR_UNKNOWN)) throw new MscError(msg);
    throw new MscError(msg);
  }

  async _writeCommand(direction, command, dataSize, tag = 0, lun = 0) {
    await this.usb.write(
      Cbw.pack({
        signature: 'USBC',
        tag,
        dataTransferLength: dataSize,
        flags: direction,
        lun,
        commandLength: command.length,
        command,
      })
    );
  }

  async _readCsw(failOnError = false) {
    const buf = await this.usb.readUpTo(Csw.size);
    if (buf.length < Csw.size) throw new MscError(`CSW was only ${buf.length} bytes`);
    const csw = Csw.unpack(buf);
    if (latin1(csw.signature) !== 'USBS') throw new MscError('the CSW signature is not USBS');
    if (csw.status !== 0) {
      if (failOnError) throw new MscError('mass storage error (failOnError)');
      return await this.requestSense();
    }
    return MSC_SENSE_OK;
  }

  /** REQUEST SENSE，18 字节。 */
  async requestSense() {
    const cdb = concat(u8(MSC_OC_REQUEST_SENSE), new Uint8Array(3), u8(18), new Uint8Array(1));
    const data = await this.sendReadCommand(cdb, 18, true);
    return parseMscSense(data);
  }

  async sendCommand(command, failOnError = false) {
    await this._writeCommand(DIRECTION_WRITE, command, 0);
    this.lastSense = await this._readCsw(failOnError);
    return this.lastSense;
  }

  async sendWriteCommand(command, data, failOnError = false) {
    await this._writeCommand(DIRECTION_WRITE, command, data.length);
    let stalled = false;
    try {
      await this.usb.write(data);
    } catch (e) {
      stalled = true;
      await this.usb.clearHalt(0); // epOut
    }
    const sense = await this._readCsw(failOnError);
    if (stalled && sameSense(sense, MSC_SENSE_OK)) throw new MscError('mass storage write error');
    this.lastSense = sense;
    return sense;
  }

  async sendReadCommand(command, size, failOnError = false) {
    await this._writeCommand(DIRECTION_READ, command, size);
    let stalled = false;
    let data = new Uint8Array(0);
    try {
      data = await this.usb.readUpTo(size); // 只读一次，见文件头说明
    } catch (e) {
      stalled = true;
      await this.usb.clearHalt(0);
    }
    const sense = await this._readCsw(failOnError);
    if (stalled && sameSense(sense, MSC_SENSE_OK)) throw new MscError('mass storage read error');
    if (size > 0 && data.length < size) {
      // 不改成 readExactly：CBW 里的长度只是「准备接多少」，设备少发是常态
      // （Sony 外部命令尤其如此），多读一次会挂在等一个不会来的包上。
      // 但对 SCSI 数据阶段来说短包意味着要少算，所以至少要把话说明白。
      this.log(`⚠ MSC data phase only delivered ${data.length}/${size} bytes (treating it as a short packet)`);
    }
    this.lastSense = sense;
    return data;
  }

  /** SCSI INQUIRY → (manufacturer, model)，PMCA 用它们判「这是不是索尼相机」。 */
  async getDeviceInfo() {
    const head = await this.sendReadCommand(concat(u8(MSC_OC_INQUIRY), new Uint8Array(3), u8(5), u8(0)), 5);
    const length = 5 + head[4];
    const data = await this.sendReadCommand(
      concat(u8(MSC_OC_INQUIRY), new Uint8Array(3), u8(length), u8(0)),
      length
    );
    const trim = (s) => s.replace(/[ \u0000]+$/, '');
    return {
      manufacturer: trim(latin1(data.subarray(8, 16))),
      model: trim(latin1(data.subarray(16, 32))),
    };
  }

  /**
   * Sony 外部命令通道（MSC 版入口）。
   * PMCA: _BaseSonyMscExtCmdDevice.sendSonyExtCommand —— 同一条 12 字节 CDB 先写后读，
   * sense == DeviceBusy 时整条重试。
   */
  async sendSonyExtCommand(cmd, data, bufferSize) {
    const command = concat(u8(MSC_OC_EXT_CMD), u32le(cmd), new Uint8Array(7));
    let sense = MSC_SENSE_DEVICE_BUSY;
    while (sameSense(sense, MSC_SENSE_DEVICE_BUSY)) {
      sense = await this.sendWriteCommand(command, data);
    }
    this._checkResponse(sense);

    if (bufferSize === 0) return new Uint8Array(0);

    let out = new Uint8Array(0);
    sense = MSC_SENSE_DEVICE_BUSY;
    while (sameSense(sense, MSC_SENSE_DEVICE_BUSY)) {
      out = await this.sendReadCommand(command, bufferSize);
      sense = this.lastSense;
    }
    this._checkResponse(sense);
    return out;
  }
}

export const SONY_MSC_MODELS = ['DSC', 'Camcorder'];

/**
 * 上游原口径：INQUIRY 的产品串必须**正好等于** 'DSC' 或 'Camcorder'。
 * 保留它，是为了「与 PMCA 行为一致」这个可验证的基准。
 */
export function isSonyMscCamera(info) {
  return info.manufacturer === 'Sony' && SONY_MSC_MODELS.includes(info.model);
}

/**
 * 宽松口径：厂商是 Sony 且产品串以 DSC / Camcorder 开头（兼容 "DSC-HX99" 这种带型号的）。
 * 上游的严格等值判定在真实机型上可能过不了（那样 pmca-console 自己也认不出相机），
 * 所以界面用这一层做最终判定 —— 它接受的是上游的超集，不会拒绝上游接受的东西。
 */
export function looksLikeSonyMscCamera(info) {
  return info.manufacturer === 'Sony' && /^(DSC|Camcorder)/.test(info.model || '');
}
