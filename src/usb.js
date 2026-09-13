/**
 * WebUSB 传输层：给上层提供和 PMCA `pmca/usb/driver/generic`+`libusb.py` 同形的接口。
 *
 * 与 libusb 版的差异（都是刻意的）：
 *   1. `reset()` 不做任何事。PMCA 的 `UsbBackend.reset()` 只做「有内核驱动就 detach」，
 *      **不是** USB 端口复位；WebUSB 没有 detachKernelDriver（Chrome 已移除），
 *      而用 `device.reset()` 会真的复位设备、把相机踢掉，所以这里保持 no-op。
 *   2. 读用 `readUpTo`（单次 transfer）与 `readExactly`（循环补齐）区分开：
 *      USB 短包是正常的，PMCA 靠 libusb 一次给够，这里必须自己补齐。
 *   3. 单次 transfer 长度封顶 16 KiB（Chrome 侧过大长度不保证），大块自动分片 ——
 *      libusb 内部也是这么分的，设备不受影响。
 */

import { concat, sleep } from './bytes.js';

export const SONY_VENDOR_ID = 0x054c;
export const USB_CLASS_PTP = 6;
export const USB_CLASS_MSC = 8;

const MAX_XFER = 16384;

export class UsbError extends Error {}

export class UsbTimeout extends UsbError {}

/**
 * 端点被 STALL 时抛的错。
 *
 * 关键理解：**STALL 是设备「功能性拒绝」，不是「没数据」** —— 没数据会是超时（NAK）。
 * 所以出现 STALL 意味着「设备不认这条请求」，而不是「相机没回话」。
 * 见过的高频成因：上一个没结束干净的会话把端点留在 halted 状态
 * （表现就是「新开一次，第一条命令的读回就 STALL」），clearHalt 后重试即好。
 */
function stallError(dir, ep, dirName) {
  const e = new UsbError(
    `USB ${dir} stalled (endpoint 0x${ep.toString(16)}, ${dirName}; the halt was cleared and the request retried)
  · STALL = the device refused this round of requests (this is NOT "no data"; no data shows up as a timeout)
  · Usual causes: the previous session was not closed cleanly / a leftover halted endpoint / a command that does not match the camera state
  · First try: unplug and replug the camera (re-enumeration resets the endpoints), then run ③ Diagnostics again
  · If it always stalls on the first read: paste the full ③ Diagnostics output — it tells the transport layer and the session layer apart`
  );
  e.stalled = true;
  e.endpoint = ep;
  return e;
}

function isTimeout(e) {
  return e && (e.name === 'NetworkError' || /timeout/i.test(e.message || ''));
}

/** 从 USBConfiguration 里挑一个「像我们要的」接口（优先 PTP/MSC）。 */
function pickInterface(configuration) {
  const ifaces = [...(configuration.interfaces || [])];
  const score = (i) => {
    const cls = i.alternates[0].interfaceClass;
    if (cls === USB_CLASS_PTP) return 0;
    if (cls === USB_CLASS_MSC) return 1;
    return 2;
  };
  ifaces.sort((a, b) => score(a) - score(b) || a.interfaceNumber - b.interfaceNumber);
  return ifaces[0];
}

export class WebUsbTransport {
  constructor(device, log = () => {}) {
    this.device = device;
    this.log = log;
    this.epIn = null;
    this.epOut = null;
    this.iface = null;
    this.gone = false;
    this.stalls = 0;
    this._onDisconnect = (e) => {
      if (e.device === this.device) {
        this.gone = true;
        this.log('⚠ device was unplugged from USB / re-enumerated');
      }
    };
  }

  static isSupported() {
    return typeof navigator !== 'undefined' && !!navigator.usb;
  }

  /** 弹选择框（必须由用户手势触发）。filters 只按厂商过滤，避免漏掉模式切换后的新设备。 */
  static async request() {
    if (!WebUsbTransport.isSupported()) {
      throw new UsbError('this browser has no WebUSB (use Chrome or Edge)');
    }
    return navigator.usb.requestDevice({ filters: [{ vendorId: SONY_VENDOR_ID }] });
  }

  static async alreadyGranted() {
    if (!WebUsbTransport.isSupported()) return [];
    const devices = await navigator.usb.getDevices();
    return devices.filter((d) => d.vendorId === SONY_VENDOR_ID);
  }

  /**
   * 探测一台设备**现在**还能不能用：真的 `open()` 一次。
   *
   * 为什么不能只看 `rankDevice()`：设备被拔掉 / 重新枚举（切模式就会）之后，Chrome 手里那个
   * USBDevice 对象上**依然读得到**厂商号、产品名和描述符缓存 —— 那些是枚举时抄下来的，
   * 所以「描述符看着挺正常」完全不代表它还连在总线上。
   * 真机踩过的坑：切完模式回头 `open()` 直接抛
   * `Failed to execute 'open' on 'USBDevice': The device was disconnected.`
   *
   * 唯一可靠的判据就是 `open()` 成不成。成功时**保持打开**（调用方接着就要用它），
   * 失败时把错误原样交回去（含 SecurityError 等，别把真正的权限问题说成「设备没了」）。
   */
  static async tryOpen(device) {
    if (device.opened) return { ok: true };
    try {
      await device.open();
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e };
    }
  }

  /** 一台设备的一行描述（静态版，给「还没打开设备」的场景用）。 */
  static describeDevice(d) {
    const vid = d.vendorId.toString(16).padStart(4, '0');
    const pid = d.productId.toString(16).padStart(4, '0');
    return `Sony ${vid}:${pid} ${d.productName || ''}`.trim();
  }

  /**
   * 给一台设备打分：**数字越小越能用**。
   *
   * 用途：浏览器里可能同时有好几台「已授权」的索尼设备（比如切模式前那台 MTP 的、切模式后
   * 安装模式那台，旧的记录不一定马上消失）。以前只看「已授权的恰好只有一台」才复用，于是
   * 两台并存时每次点②都会白弹一次选择框 —— 这个打分就是为了从里面挑出对的那台。
   *
   *   0   = PTP(class 6) 且有成对 bulk 端点（app 安装模式 / 普通 MTP）
   *   10  = 其它 class 但有成对 bulk 端点
   *   20  = 大容量存储（macOS 上 Chrome 抢不到接口，只当备选）
   *   900 = 没有可用的 bulk 端点
   *   999 = 连描述符都读不到（多半已经拔了/重新枚举过）
   */
  static rankDevice(d) {
    let best = 900;
    try {
      for (const cfg of d.configurations) {
        for (const iface of cfg.interfaces) {
          for (const alt of iface.alternates) {
            const eps = alt.endpoints || [];
            const hasIn = eps.some((e) => e.type === 'bulk' && e.direction === 'in');
            const hasOut = eps.some((e) => e.type === 'bulk' && e.direction === 'out');
            if (!hasIn || !hasOut) continue;
            const score =
              alt.interfaceClass === USB_CLASS_PTP ? 0 : alt.interfaceClass === USB_CLASS_MSC ? 20 : 10;
            if (score < best) best = score;
          }
        }
      }
    } catch (e) {
      return 999;
    }
    return best;
  }

  describe() {
    return WebUsbTransport.describeDevice(this.device);
  }

  async open() {
    navigator.usb.addEventListener('disconnect', this._onDisconnect);
    // acquireUsb() 是「先 open 探活、再交回来」的，所以到这里可能已经开着；
    // 对已打开的设备再 open() 会抛 InvalidStateError，所以先看一眼。
    if (!this.device.opened) await this.device.open();
    if (!this.device.configuration) {
      const configs = [...this.device.configurations];
      let chosen = null;
      for (const c of configs) {
        const i = pickInterface(c);
        if (i) {
          chosen = c;
          break;
        }
      }
      if (!chosen) throw new UsbError('this device has no usable configuration');
      await this.device.selectConfiguration(chosen.configurationValue);
    }
    this.iface = pickInterface(this.device.configuration);
    if (!this.iface) throw new UsbError('no usable interface found');
    try {
      await this.device.claimInterface(this.iface.interfaceNumber);
    } catch (e) {
      throw new UsbError(
        `claimInterface(${this.iface.interfaceNumber}) failed: ${e.message}
  · macOS: the interface is held by a system driver, so WebUSB cannot take it over (a Chrome limitation, not a camera problem)
  · Windows: use Zadig to switch that interface to the libusb/WinUSB driver first
  · Linux: usually works as is; if needed, unload usb-storage first: sudo modprobe -r usb_storage`
      );
    }
    const alt = this.iface.alternates[0];
    const eps = alt.endpoints || [];
    const bulkIn = eps.find((e) => e.type === 'bulk' && e.direction === 'in');
    const bulkOut = eps.find((e) => e.type === 'bulk' && e.direction === 'out');
    if (!bulkIn || !bulkOut) throw new UsbError('the interface has no paired bulk IN/OUT endpoints');
    this.epIn = bulkIn.endpointNumber;
    this.epOut = bulkOut.endpointNumber;
    this.log(
      `claimed interface ${this.iface.interfaceNumber} (class ${alt.interfaceClass}), IN=0x${this.epIn.toString(16)} OUT=0x${this.epOut.toString(16)}`
    );
    return this;
  }

  async close() {
    navigator.usb.removeEventListener('disconnect', this._onDisconnect);
    try {
      if (this.iface) await this.device.releaseInterface(this.iface.interfaceNumber);
    } catch (e) {
      /* 设备可能已经重新枚举，忽略 */
    }
    try {
      await this.device.close();
    } catch (e) {
      /* 同上 */
    }
  }

  _assertAlive() {
    if (this.gone) throw new UsbError('device is gone');
  }

  /** PMCA 的 backend.reset() 语义：只 detach 内核驱动；WebUSB 无从做，故 no-op。 */
  reset() {}

  async clearHalt(epNumber) {
    try {
      await this.device.clearHalt(epNumber);
    } catch (e) {
      /* 有些平台不支持，忽略 */
    }
  }

  /**
   * 单次 bulk IN，最多 MAX_XFER 字节；超时抛 UsbTimeout。
   * epIndex 与 PMCA 的 `driver.read(len, ep=n)` 对齐（默认第 0 个 bulk IN）。
   *
   * 被 STALL 时会 clearHalt 并重试（默认 2 次）—— 这是 MTP 主机的标准做法：
   * 上一个会话没收干净时，端点往往还是 halted 的，第一条命令就会 STALL。
   */
  async readUpTo(length, epIndex = 0, timeoutMs = 20000, retries = 3) {
    this._assertAlive();
    if (epIndex !== 0) throw new UsbError('only bulk IN endpoint #0 is supported');
    const n = Math.max(1, Math.min(length, MAX_XFER));
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        res = await this.device.transferIn(this.epIn, n, timeoutMs);
      } catch (e) {
        if (isTimeout(e)) throw new UsbTimeout(`USB read timed out (${timeoutMs} ms)`);
        throw new UsbError(`USB read failed: ${e.message}`);
      }
      if (res.status === 'stall') {
        this.stalls++;
        await this.clearHalt(this.epIn);
        if (attempt < retries) {
          this.log(`IN endpoint stalled → cleared the halt, retrying the read (${attempt + 1}/${retries})`);
          // 间隔略长一点：刚切完模式时相机可能还没就绪
          await sleep(150);
          continue;
        }
        throw stallError('read', this.epIn, 'IN');
      }
      if (res.status !== 'ok' || !res.data) return new Uint8Array(0);
      return new Uint8Array(res.data.buffer, res.data.byteOffset, res.data.byteLength);
    }
  }

  /** 一直读到凑满 n 字节（USB 短包是常态，必须自己补齐）。 */
  async readExactly(n, epIndex = 0, timeoutMs = 20000) {
    const chunks = [];
    let got = 0;
    while (got < n) {
      const part = await this.readUpTo(n - got, epIndex, timeoutMs);
      if (part.length === 0) throw new UsbError(`got an empty packet but ${n - got} more bytes are needed`);
      chunks.push(part);
      got += part.length;
    }
    return chunks.length === 1 ? chunks[0] : concat(...chunks);
  }

  async write(data, epIndex = 0, retries = 3) {
    this._assertAlive();
    if (epIndex !== 0) throw new UsbError('only bulk OUT endpoint #0 is supported');
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    for (let off = 0; off < bytes.length; off += MAX_XFER) {
      const slice = bytes.subarray(off, Math.min(off + MAX_XFER, bytes.length));
      for (let attempt = 0; ; attempt++) {
        let res;
        try {
          res = await this.device.transferOut(this.epOut, slice);
        } catch (e) {
          throw new UsbError(`USB write failed: ${e.message}`);
        }
        if (res.status === 'stall') {
          this.stalls++;
          await this.clearHalt(this.epOut);
          if (attempt < retries) {
            this.log(`OUT endpoint stalled → cleared the halt, retrying the write (${attempt + 1}/${retries})`);
            await sleep(150);
            continue;
          }
          throw stallError('write', this.epOut, 'OUT');
        }
        if (res.status !== 'ok') throw new UsbError(`unexpected USB write status: ${res.status}`);
        break;
      }
    }
  }

  /** 把 IN/OUT 两个端点都 clearHalt。开新会话前先做一次，成本几乎为零。 */
  async clearHaltBoth() {
    const done = [];
    for (const ep of [this.epIn, this.epOut]) {
      try {
        await this.device.clearHalt(ep);
        done.push(`0x${ep.toString(16)}`);
      } catch (e) {
        done.push(`0x${ep.toString(16)}(failed)`);
      }
    }
    return done;
  }

  /** 采集传输层实况，用于排查（配置号/接口类/alt/端点号/包大小）。 */
  transportInfo() {
    const iface = this.iface;
    const alt = iface.alternates[0];
    const eps = alt.endpoints || [];
    const find = (num) => eps.find((e) => e.endpointNumber === num) || {};
    return {
      configuration: this.device.configuration ? this.device.configuration.configurationValue : null,
      interfaceNumber: iface.interfaceNumber,
      interfaceClass: alt.interfaceClass,
      interfaceSubclass: alt.interfaceSubclass,
      interfaceProtocol: alt.interfaceProtocol,
      alternate: iface.alternate ? iface.alternate.alternateSetting : 0,
      epIn: this.epIn,
      epInMaxPacket: find(this.epIn).packetSize,
      epOut: this.epOut,
      epOutMaxPacket: find(this.epOut).packetSize,
      stalls: this.stalls,
    };
  }

  /** MscCbiDriver 用的 class 接口请求（BBB 用不到，留着对齐 PMCA 的能力面）。 */
  async classInterfaceRequestOut(request, value, index, data = new Uint8Array(0)) {
    await this.device.controlTransferOut(
      { requestType: 'class', recipient: 'interface', request, value, index },
      data
    );
  }

  /** SonySenserAuthDevice 用的 vendor 请求（本工具不用，但保持一致）。 */
  async vendorRequestOut(request, value, index, data = new Uint8Array(0)) {
    await this.device.controlTransferOut(
      { requestType: 'vendor', recipient: 'other', request, value, index },
      data
    );
  }
}
