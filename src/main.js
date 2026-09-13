/**
 * 界面编排：三步走 —— ①（可选）把相机切进安装模式 ② 选 apk ③ 装。
 *
 * **纯静态**：没有后端、不连网。假索尼商店（连 TLS 终结、spk 打包、xpd 签发）整份跑在
 * 这个页面里（src/jstls/），相机交上来的 TLS 字节就地处理，不经过任何网络。
 * 把 webinstaller/ 整个目录挂到 https（或 http://localhost）就能用。
 */

import { WebUsbTransport, UsbError, USB_CLASS_MSC, USB_CLASS_PTP } from './usb.js';
import { MscBbbDevice, isSonyMscCamera, looksLikeSonyMscCamera, MscInvalidCommand } from './msc.js';
import { SonyExtCmdCamera } from './extcmd.js';
import { SonyMtpAppInstallDevice, isSonyMtpAppInstallCamera, isSonyMtpCamera } from './mtp.js';
import { SonyAppInstallCamera } from './appinstall.js';
import { runInstall, describeCameraRefusal } from './installer.js';
import { purePrimitives } from './jstls/pure-primitives.mjs';
import { LocalMarketStore } from './jstls/local-store.mjs';
import { analyzeApk } from './jstls/apk.mjs';
import { tr, onLangChange, boot as bootI18n } from './i18n.js';

const $ = (id) => document.getElementById(id);

let apkBytes = null;
let apkInfo = null;
let lastInfo = null;
let busy = false;

// ---------------------------------------------------------------- 界面小工具
function log(text, kind = 'info') {
  const el = $('log');
  const line = document.createElement('div');
  line.className = `line ${kind}`;
  const t = new Date().toTimeString().slice(0, 8);
  line.textContent = `[${t}] ${text}`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
  console.log(`[${kind}] ${text}`);
}

function setStatus(text, kind = '') {
  const el = $('status');
  // 一旦有了运行期状态，这个元素就不再是「静态文案」了：摘掉 data-i18n，
  // 免得切语言时把当前状态刷回默认的「就绪」（见 i18n.js 的 applyDom）。
  if (el.hasAttribute('data-i18n')) el.removeAttribute('data-i18n');
  el.textContent = text;
  el.className = `status ${kind}`;
}

/** 写诊断面板。同上：写入内容后就不再是静态占位词，摘掉 data-i18n。 */
function setDeviceInfo(text) {
  const el = $('device-info');
  if (el.hasAttribute('data-i18n')) el.removeAttribute('data-i18n');
  el.textContent = text;
}

function setProgress(percent, label) {
  $('progress-bar').style.width = `${Math.max(0, Math.min(100, percent || 0))}%`;
  $('progress-text').textContent = label || '';
}

function humanSize(n) {
  if (n == null) return '?';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(2)} MiB`;
}

function setBusy(value) {
  busy = value;
  for (const id of ['step1-btn', 'step2-install', 'repick-btn', 'probe-btn']) $(id).disabled = value;
}

// ---------------------------------------------------------------- apk 读取
/** 浏览器里解 deflate（AndroidManifest.xml 是压缩存的）。 */
async function inflateRawBrowser(bytes) {
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('this browser has no DecompressionStream("deflate-raw"), so the manifest cannot be parsed (installing still works)');
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** 取那张相机唯一认的证书（静态托管时把它跟页面放在一起就行）。 */
async function loadCertPem() {
  // 证书就在本页旁边：dist/certs/localtest.me.pem。第二个候选是给「把 dist/ 里的
  // 东西摊到站点根去发布」留的后路。
  const candidates = ['certs/localtest.me.pem', '../certs/localtest.me.pem'];
  for (const p of candidates) {
    try {
      const res = await fetch(p);
      if (res.ok) return await res.text();
    } catch (e) {
      /* 换下一个路径 */
    }
  }
  throw new Error(
    'cannot fetch certs/localtest.me.pem — when hosting this statically, publish dist/index.html together with dist/certs/'
  );
}

async function uploadApk(file) {
  setStatus(tr`正在读取 ${file.name}…`);
  apkBytes = new Uint8Array(await file.arrayBuffer());
  apkInfo = await analyzeApk(apkBytes, file.name, { inflateRaw: inflateRawBrowser });
  renderApkInfo();
  log(`apk selected: ${file.name} (${humanSize(apkInfo.size)}, ${apkInfo.entries} entries)`, 'ok');
  for (const note of apkInfo.notes || []) log(`  note: ${note}`, 'warn');
  log('(the apk stays in your browser; nothing is uploaded anywhere)');
  setStatus(tr('apk 就绪，可以安装了'), 'ok');
  $('step2-install').disabled = false;
}

function renderApkInfo() {
  const i = apkInfo;
  if (!i) return;
  const rows = [
    [tr('文件'), i.name],
    [tr('大小'), tr`${humanSize(i.size)}（解压后 ${humanSize(i.uncompressed)}）`],
    [tr('包名'), i.package || tr('（没解析出来）')],
    [tr('版本'), [i.version_name, i.version_code && `code ${i.version_code}`].filter(Boolean).join(' / ') || '?'],
    ['minSdk', i.min_sdk || '?'],
    [tr('签名文件'), (i.cert_files || []).join(', ') || tr('（没有）')],
  ];
  $('apk-info').innerHTML = rows
    .map(([k, v]) => `<div class="row"><span class="k">${k}</span><span class="v">${v}</span></div>`)
    .join('');
}

// ---------------------------------------------------------------- 重置 / 换设备
/**
 * 右上角「换一台设备 / 重置」：
 *   ① 清空本页已选的数据（apk、诊断面板、进度、状态）与日志；
 *   ② 忘掉刚才记住的那台相机，下一次会**重新弹选择框**。
 *
 * 为什么把「重置数据」和「换设备」绑在一起：换设备通常意味着「刚才那台不合适/上一次试砸了」，
 * 这时候把上一轮的 apk 与日志一起清掉，比留着让人误以为是新一次的结果要清楚。
 */
function resetPage() {
  if (busy) {
    setStatus(tr('正在忙，等当前操作结束再重置'), 'warn');
    return;
  }
  forcePickOnce = true;
  lastDevice = null;

  apkBytes = null;
  apkInfo = null;
  const pick = $('apk-file');
  if (pick) pick.value = '';
  $('apk-info').innerHTML = '';
  $('step2-install').disabled = true;
  setDeviceInfo(tr('（还没读）'));
  $('log').innerHTML = '';
  setProgress(0, '');
  setStatus(tr('已重置：请重新选 apk；下一次安装会弹出设备选择框'), 'warn');
  log('page data cleared: apk, diagnostics panel, log and progress are all reset');
  log('the next Install press will show the device dialog again — select the camera there');
}

// ---------------------------------------------------------------- 设备获取
/**
 * 拿一台能用的相机。**默认不再弹选择框**，只有真的没得用时才弹。
 *
 * 顺序（每一台都要**真的 open() 一次**才算数，见 `WebUsbTransport.tryOpen`）：
 *   1. 刚才用过的那台；
 *   2. 浏览器里已授权过的索尼设备，按 `rankDevice()` 从「最像能用」往下排；
 *   3. 都不行 → 弹选择框。
 *
 * ⚠️ 为什么必须真开一次：相机切模式（NotifyScalarDlmode）会在 USB 上**重新枚举成另一个设备**
 * （PID 变），旧句柄随即失效，但它上面**仍然读得到**产品名/描述符（枚举时抄的缓存）。
 * 真机就栽在这里：日志里写着「继续用刚才那台相机（Sony 054c:08e7 ILCE-5100）」，
 * 紧接着 `open()` 报 `The device was disconnected.` —— 描述符探活是假阳性，open 才是真判据。
 *
 * 另外：切模式 / 拔线时用 `forgetDevice()` 把这个缓存清掉，别让下一次拿旧句柄去撞。
 */
let lastDevice = null;
let forcePickOnce = false;

/** 忘掉记住的那台设备（切模式 / 拔线 / 断开时调用）。 */
function forgetDevice(why) {
  if (!lastDevice) return;
  const name = WebUsbTransport.describeDevice(lastDevice);
  lastDevice = null;
  log(`${why}: forgot ${name}`);
}

async function acquireUsb() {
  if (forcePickOnce) {
    forcePickOnce = false;
    lastDevice = null;
  }

  // 候选：先刚才那台，再其余已授权的（按打分排序，分小的先试）
  const rest = [];
  for (const d of await WebUsbTransport.alreadyGranted()) {
    if (d !== lastDevice) rest.push(d);
  }
  rest.sort((a, b) => WebUsbTransport.rankDevice(a) - WebUsbTransport.rankDevice(b));
  const candidates = [];
  if (lastDevice) candidates.push({ d: lastDevice, reuse: true });
  for (const d of rest) candidates.push({ d, reuse: false });

  const dead = [];
  for (const { d, reuse } of candidates) {
    const r = await WebUsbTransport.tryOpen(d);
    if (r.ok) {
      lastDevice = d;
      const name = WebUsbTransport.describeDevice(d);
      for (const note of dead) log(`…skipping ${note}`, 'warn');
      if (dead.length) {
        log('(after a mode switch the camera re-enumerates as a new device and the old one shows up as "disconnected" — this is normal)', 'warn');
      }
      log(`${reuse ? 'continuing with the same camera' : 'reusing an already authorized camera'} (${name})`);
      return d;
    }
    dead.push(`${WebUsbTransport.describeDevice(d)}: ${firstLine(r.error.message || r.error)}`);
  }

  if (dead.length) {
    for (const note of dead) log(`✗ authorized device could not be opened → ${note}`, 'warn');
    log('(most likely it re-enumerated after a mode switch or a replug, so the old handle is dead) — pick it from the dialog instead', 'warn');
  }
  log('Select the camera in the dialog…');
  lastDevice = await WebUsbTransport.request();
  return lastDevice;
}

// ---------------------------------------------------------------- 通用展示
function deviceInfoLines(info) {
  return [
    `manufacturer : ${info.manufacturer}`,
    `model        : ${info.model}`,
    `serial       : ${info.serialNumber}`,
    `firmware     : ${info.version}`,
    `vendorExt    : ${JSON.stringify(info.vendorExtension)}`,
    `Private ops  : 0x9488=${info.operationsSupported.has(0x9488)} 0x9489=${info.operationsSupported.has(0x9489)} ` +
      `0x948c=${info.operationsSupported.has(0x948c)} 0x948d=${info.operationsSupported.has(0x948d)}`,
    `Vendor cmd   : 0x9280=${info.operationsSupported.has(0x9280)} (MTP-side external command, needed to switch modes)`,
    `App install  : ${isSonyMtpAppInstallCamera(info) ? 'yes' : 'no'}`,
    `Plain MTP    : ${isSonyMtpCamera(info) ? 'yes' : 'no'}`,
  ];
}

function printDeviceInfo(info) {
  lastInfo = info;
  const lines = paintDeviceInfo(info);
  for (const l of lines) log(l);
  return lines;
}

/** 只画面板不打日志（切语言重绘时用）。 */
function paintDeviceInfo(info) {
  const lines = deviceInfoLines(info);
  setDeviceInfo(lines.join('\n'));
  return lines;
}

/** 机型信息：best-effort —— 个别机型不认这条外部命令，失败不影响后面的流程。 */
async function bestEffortModelName(ext) {
  try {
    const camInfo = await ext.getCameraInfo();
    if (camInfo.modelName) log(`camera reports model: ${camInfo.modelName}`, 'ok');
  } catch (e) {
    log(`model query failed (ignored): ${String(e.message).split('\n')[0]}`, 'warn');
  }
}

// ---------------------------------------------------------------- ① 切模式
/**
 * 把相机切进 app 安装模式。**有两条路**（PMCA 也是两条）：
 *
 *   · 大容量存储模式（接口 class 8）→ SCSI 0x7a 带 Sony 外部命令
 *     （PMCA: SonyMscExtCmdDevice）
 *   · 普通 MTP 模式（接口 class 6）→ PTP 私有操作 0x9280/0x9281 带**同一条**外部命令
 *     （PMCA: SonyMtpExtCmdDevice）
 *
 * 为什么两条都要：macOS 上 Chrome 抢不到大容量存储接口（无法 detach 内核驱动），
 * 所以「相机设成 MTP + 走 MTP 这条路」对 macOS 用户才是唯一可行的组合。
 */
async function switchToAppInstaller() {
  setBusy(true);
  setProgress(0, '');
  let usb = null;
  try {
    const device = await acquireUsb();
    usb = new WebUsbTransport(device, log);
    await usb.open();
    const t = usb.transportInfo();
    log(
      `interface ${t.interfaceNumber}: class ${t.interfaceClass} subclass ${t.interfaceSubclass} ` +
        `protocol ${t.interfaceProtocol}, alt ${t.alternate}`
    );
    log(`endpoints IN=0x${t.epIn.toString(16)} OUT=0x${t.epOut.toString(16)} (maxPacket ${t.epInMaxPacket})`);

    if (t.interfaceClass === USB_CLASS_MSC) {
      await switchViaMsc(usb);
    } else if (t.interfaceClass === USB_CLASS_PTP) {
      await switchViaMtp(usb);
    } else {
      throw new Error(
        `interface class = ${t.interfaceClass}: neither mass storage (8) nor PTP (6). Set the camera's USB connection mode to "MTP" or "Mass Storage" and try again.`
      );
    }
    // 相机切模式会在 USB 上重新枚举成**另一个设备**（PID 变），手里这个句柄随即作废。
    // 必须在这里就忘掉它，否则下一步会拿着「已断开」的旧句柄去 open
    //（真机报错：Failed to execute 'open' on 'USBDevice': The device was disconnected.）。
    // 刻意**不**强制弹选择框：新设备若以前授权过，会被自动复用。
    forgetDevice('camera re-enumerated on USB after the mode switch');
    setStatus(tr('切换命令已发出。等相机 USB 重新枚举完成后，点「② 选择相机并安装」。'), 'ok');
  } catch (e) {
    reportError(e);
  } finally {
    // 无论如何都要释放设备：否则报错后接口一直被这个页面占着，
    // 重试、或其它程序（pmca/adb/ImageCapture）都会抢不到。
    if (usb) await usb.close();
    setBusy(false);
  }
}

/** 路一：大容量存储 → SCSI 0x7a。Linux/Windows 上可用，macOS 上 Chrome 通常抢不到这个接口。 */
async function switchViaMsc(usb) {
  log('camera is in "Mass Storage" mode → taking the SCSI path (PMCA: SonyMscExtCmdDevice)');
  const msc = new MscBbbDevice(usb, log);
  await msc.open();
  const info = await msc.getDeviceInfo();
  log(`SCSI INQUIRY: manufacturer="${info.manufacturer}" model="${info.model}"`);
  if (isSonyMscCamera(info)) {
    log('recognized as a Sony camera by upstream\'s strict rule (model is exactly DSC/Camcorder)');
  } else if (looksLikeSonyMscCamera(info)) {
    log(
      `upstream's strict rule would reject "${info.model}" (it only accepts exactly "DSC"/"Camcorder"); we relax it to a prefix match and let it through. If a later SCSI command fails, please include this log line too.`,
      'warn'
    );
  } else {
    throw new Error(
      `this device does not look like a Sony camera (needs manufacturer="Sony" and a model starting with "DSC"/"Camcorder"). Make sure the camera is in "Mass Storage" mode and properly recognized by the system.`
    );
  }
  const ext = new SonyExtCmdCamera(msc);
  await bestEffortModelName(ext);
  try {
    await ext.switchToAppInstaller();
  } catch (e) {
    if (e instanceof MscInvalidCommand) {
      throw new Error('the camera rejected this SCSI command → this model does not support PlayMemories Camera Apps');
    }
    throw e;
  }
  log('NotifyScalarDlmode sent over SCSI (command 5,2)', 'ok');
}

/** 路二：普通 MTP → PTP 0x9280/0x9281。macOS 上通常只有这条路能走通。 */
async function switchViaMtp(usb) {
  log('camera is in "MTP" mode → taking the PTP path (PMCA: SonyMtpExtCmdDevice)');
  const dev = new SonyMtpAppInstallDevice(usb, log);
  await dev.open();
  const info = dev.info || (await dev.getDeviceInfo());
  printDeviceInfo(info);

  if (isSonyMtpAppInstallCamera(info)) {
    log('the camera is already in app install mode → no switch needed, just press ② Pick a camera and install', 'ok');
    return;
  }
  if (!isSonyMtpCamera(info)) {
    throw new Error(
      `the camera is neither in app install mode nor offering the Sony vendor external commands (0x9280/0x9281) → this path cannot switch modes. Check the camera's USB connection mode (MTP / Mass Storage).${MTP_MODEL_HINT(info)}`
    );
  }
  const ext = new SonyExtCmdCamera(dev);
  await bestEffortModelName(ext);
  await ext.switchToAppInstaller();
  log('NotifyScalarDlmode sent over PTP (command 5,2)', 'ok');
}

function MTP_MODEL_HINT(info) {
  return /ILCE|NEX|DSC|HDR|FDR/.test(info.model || '')
    ? ` (model recognized as ${info.model}, which should be on the PMCA support list)`
    : '';
}

// ---------------------------------------------------------------- ② 装
async function installApk() {
  if (!apkBytes) {
    setStatus(tr('先选一个 apk 文件'), 'warn');
    return;
  }
  setBusy(true);
  setProgress(0, '');
  let bridge = null;
  let usb = null;
  try {
    const device = await acquireUsb();
    usb = new WebUsbTransport(device, log);
    await usb.open();
    // 上次没收干净的会话常把端点留在 halted：开新会话前先清一遍
    log(`cleared halt on endpoints: ${(await usb.clearHaltBoth()).join(', ')}`);

    const dev = new SonyMtpAppInstallDevice(usb, log);
    await dev.open();
    // open() 已经顺带取过一次 DeviceInfo（这正是它能把失败分层的原因），有就复用
    const info = dev.info || (await dev.getDeviceInfo());
    printDeviceInfo(info);

    if (!isSonyMtpAppInstallCamera(info)) {
      if (isSonyMtpCamera(info)) {
        throw new Error(
          `the camera is in plain MTP mode (no sony.net/SEN_PRXY_MSG:) → run ① Switch to install mode first, then press this button.`
        );
      }
      throw new Error(
        `the camera is not in app install mode: vendorExtension has no "sony.net/SEN_PRXY_MSG:", or the four private operations 0x9488/0x9489/0x948c/0x948d are missing.`
      );
    }
    log('✓ camera is in app install mode', 'ok');

    // 假商店就在这一页里（src/jstls/）：TLS 在页面内终结，spk/xpd 也在页面内算
    const prim = purePrimitives();
    const certPem = await loadCertPem();
    const store = new LocalMarketStore({
      prim,
      certPem,
      apk: apkBytes,
      appName: 'app',
      onLog: (m) => log(m),
      onEvent: handleStoreEvent,
    });
    bridge = store;
    const xpdBytes = await store.startTask();
    log('fake store ready: it lives in this page (the camera\'s TLS bytes terminate here, no network involved)');
    log(`xpd signed (the HMAC-SHA256 CIC is computed in this page too, ${xpdBytes.length} bytes)`);
    log('starting the official install flow: submit the xpd → the camera reaches the fake store over the USB tunnel → download the spk → install');

    setStatus(tr('安装中…（不要拔线、不要在相机上做别的操作）'));
    const cam = new SonyAppInstallCamera(dev, log);
    const result = await runInstall({
      dev: cam,
      bridge,
      xpdBytes,
      onLog: (m) => log(m),
      onStatus: (s) => {
        setProgress(s.percent, `${s.message} ${s.percent}%`);
        log(`progress: ${s.message} ${s.percent}% (${humanSize(s.totalSize)})`);
      },
    });

    if (result.code === 0) {
      setProgress(100, tr('完成'));
      setStatus(tr`安装完成：${result.message}`, 'ok');
      log(`✓ camera reports the task succeeded: ${result.message}`, 'ok');
      log('tip: unplug USB and power-cycle the camera; the app should show up in the camera menu.', 'ok');
    } else {
      throw new Error(describeCameraRefusal(result));
    }
  } catch (e) {
    reportError(e);
  } finally {
    if (bridge && typeof bridge.shutdown === 'function') bridge.shutdown();
    if (usb) await usb.close();
    setBusy(false);
  }
}

/** 页面内假商店的事件（上报/结果/spk 下发）。 */
function handleStoreEvent(kind, payload) {
  if (kind === 'camera-report' || kind === 'camera-result') {
    let summary = `(${payload.length} bytes)`;
    try {
      const report = JSON.parse(utf8Text(payload));
      const d = report.deviceinfo || {};
      summary = `${d.name || '?'} (${d.productcode || '?'}, serial ${d.deviceid || '?'}, firmware ${d.fwversion || '?'}, battery ${d.battery || '?'})`;
      if (report.applications) summary += `, ${report.applications.length} apps installed`;
    } catch (e) {
      /* 解析不了就只报字节数 */
    }
    if (kind === 'camera-report') {
      log(`camera report: ${summary}`, 'ok');
      setDeviceInfo(summary);
    } else {
      log(`camera final report: ${summary}`, 'ok');
    }
    return;
  }
  if (kind === 'spk-served') {
    log(`handed the spk (${humanSize(payload)}) to the camera`, 'ok');
  }
}

function utf8Text(bytes) {
  if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

// ---------------------------------------------------------------- ③ 诊断
/**
 * 把「能不能装」拆成可分辨的几步，卡在哪一环一目了然。
 * 顺序刻意做成「不开会话也能做的先做」：PTP 的 GetDeviceInfo 不要求会话，
 * 所以它能成功就说明**传输层没问题**，问题出在会话状态。
 */
async function probeDevice() {
  setBusy(true);
  setDeviceInfo('');
  let usb = null;
  try {
    const device = await acquireUsb();
    usb = new WebUsbTransport(device, log);
    await usb.open();
    const t = usb.transportInfo();
    log(
      `configuration ${t.configuration} / interface ${t.interfaceNumber} (class ${t.interfaceClass} ` +
        `subclass ${t.interfaceSubclass} protocol ${t.interfaceProtocol}, alt ${t.alternate})`
    );
    log(
      `endpoint IN=0x${t.epIn.toString(16)} (maxPacket ${t.epInMaxPacket})` +
        ` OUT=0x${t.epOut.toString(16)} (maxPacket ${t.epOutMaxPacket})`
    );
    if (t.interfaceClass !== 6) {
      log(`interface class = ${t.interfaceClass} (anything but 6 means it is not PTP/MTP) → the camera is not in app install mode; run ① Switch to install mode first`, 'warn');
    }

    const dev = new SonyMtpAppInstallDevice(usb, log);
    const cleared = await usb.clearHaltBoth();
    log(`① cleared halt on endpoints: ${cleared.join(', ')}`);

    let info = null;
    let how = '';
    try {
      info = await dev.getDeviceInfo();
      how = 'without a session';
    } catch (e) {
      log(`② DeviceInfo without a session failed: ${firstLine(e.message)}`, 'warn');
      try {
        await dev.openSession(1);
        log('   openSession(1) succeeded', 'ok');
        info = await dev.getDeviceInfo();
        how = 'after opening a session';
      } catch (e2) {
        log(`   openSession(1) failed too: ${firstLine(e2.message)}`, 'err');
        throw e2;
      }
    }
    log(`② DeviceInfo retrieved (${how})`, 'ok');

    const lines = deviceInfoLines(info);
    lines.push(`Endpoint stalls: ${usb.stalls}`);
    setDeviceInfo(lines.join('\n'));
    for (const l of lines) log(l);
    if (isSonyMtpAppInstallCamera(info)) {
      log('✓ transport and session are both fine → you can press ② Pick a camera and install', 'ok');
    } else if (isSonyMtpCamera(info)) {
      log('the camera is in plain MTP mode (0x9280/0x9281 present) → just press ① Switch to install mode (it will use the MTP-side command)', 'warn');
    } else {
      log('the camera is neither in app install mode nor offering the Sony vendor commands 0x9280/0x9281 → try a different USB connection mode', 'warn');
    }
  } catch (e) {
    reportError(e);
  } finally {
    if (usb) await usb.close();
    setBusy(false);
  }
}

function firstLine(text) {
  return String(text).split('\n')[0];
}

function reportError(e) {
  const msg = explainUsbError(e && e.message ? e.message : String(e));
  log(`✗ ${msg}`, 'err');
  setStatus(msg.split('\n')[0], 'err');
  if (!(e instanceof UsbError)) console.error(e);
}

/**
 * 把 Chrome 那句干巴巴的 USB 报错翻成人话 + 下一步做什么。
 *
 * 最常见的两条：
 *   · `The device was disconnected.` —— 手里那个句柄已经作废（切模式/拔线后重新枚举）。
 *     这不是「相机坏了」，重试一次会自动重新找到新那台设备。
 *   · `No device selected.` —— 选择框被关掉了。
 */
function explainUsbError(msg) {
  if (/device was disconnected|not connected|no such device/i.test(msg)) {
    return (
      `${msg}\n` +
      '  · Meaning: this USB handle is stale (the camera re-enumerated, e.g. right after a mode switch or a replug)\n' +
      '  · Next: just press ② Pick a camera and install again — it will look for the new device and ask once if needed\n' +
      '  · Camera missing from the dialog: unplug and replug USB, wait for it to enumerate, then try again'
    );
  }
  if (/no device selected|user cancelled/i.test(msg)) {
    return `${msg}\n  · The dialog was dismissed: press the button again and make sure to select the camera (the row usually reads Sony Camera / ILCE-xxxx)`;
  }
  if (/user gesture|user activation/i.test(msg)) {
    return (
      `${msg}\n` +
      '  · The browser requires the dialog to be triggered directly by a button press — the previous step took too long and the gesture expired\n' +
      '  · Next: press ② Pick a camera and install again, and do not click anywhere else in between'
    );
  }
  return msg;
}

// ---------------------------------------------------------------- 事件绑定
function init() {
  // 语言：优先浏览器偏好，右上角菜单可覆盖。（index.html 会在加载本模块前先调一次，
  // 这里再调一次是为了「只发布 dist/ 打包版」的部署也能切换语言；重复调用无副作用。）
  bootI18n();

  if (!WebUsbTransport.isSupported()) {
    $('usb-warn').style.display = 'block';
    setBusy(true);
  } else {
    // 相机一旦从总线上断开（拔线、切模式重新枚举），立刻把记住的那台删掉 ——
    // 免得下一次点「② 安装」拿旧句柄去 open。
    navigator.usb.addEventListener('disconnect', (e) => {
      if (e.device === lastDevice) forgetDevice('camera disconnected from USB');
    });
  }
  $('step1-btn').onclick = switchToAppInstaller;
  $('step2-install').onclick = installApk;
  $('repick-btn').onclick = resetPage;
  $('probe-btn').onclick = probeDevice;
  $('log-clear').onclick = () => ($('log').innerHTML = '');

  const pick = $('apk-file');
  $('apk-pick-btn').onclick = () => pick.click();
  pick.onchange = async () => {
    if (!pick.files || !pick.files[0]) return;
    setBusy(true);
    try {
      await uploadApk(pick.files[0]);
    } catch (e) {
      reportError(e);
    } finally {
      setBusy(false);
    }
  };

  const drop = $('apk-drop');
  drop.ondragover = (e) => {
    e.preventDefault();
    drop.classList.add('over');
  };
  drop.ondragleave = () => drop.classList.remove('over');
  drop.ondrop = async (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (!file) return;
    setBusy(true);
    try {
      await uploadApk(file);
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(false);
    }
  };

  // 语言切换后：能从状态重建的面板重画一遍（日志里已经打出去的历史不动）
  onLangChange(() => {
    renderApkInfo();
    if (lastInfo) paintDeviceInfo(lastInfo);
  });

  log('UI ready. Suggested order: ① switch to install mode → pick an apk → ② install.');
  log('Note: if the camera is already in app install mode (usually the case once an app is installed), you can skip ①.');
}

init();
