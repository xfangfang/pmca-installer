/**
 * 英文词条 —— dist/index.html 的静态文案。
 * key = 元素上的 data-i18n / data-i18n-html / data-i18n-title 属性值；
 * 带 -html 的可以把标签原样写进来。中文原文留在 HTML 里，不在这里重复。
 *
 * 改 index.html 的文案/结构时记得同步这里：删掉不再用的 key，改掉文案变了的 value。
 * 查漏：node /tmp/check-i18n.mjs
 */
export const EN_SHELL = {
  'title.repick': 'Pick another camera and clear the data and log collected on this page',
  'btn.repick': 'Another camera / reset',

  sub1:
    "Replays Sony's own <i>App Installer</i> flow through Chrome's <b>WebUSB</b>, to install apk apps " +
    'onto the camera.',
  'usb-warn':
    'This browser has no <code>navigator.usb</code>. Use desktop <b>Chrome</b> or <b>Edge</b> and open ' +
    'this page over <code>https://</code> or <code>http://localhost</code> (WebUSB requires a secure context).',

  'step1.title': 'Set the camera to MTP mode, then connect it over USB',
  'btn.step1': 'Switch to install mode',
  'step2.title': 'Pick an apk and install',
  'apk.drop': 'Drop a <code>.apk</code> here, or',
  'btn.pick': 'Choose file…',
  'btn.install': 'Install',
  'step3.title': 'Diagnostics',
  'btn.probe': 'Print camera DeviceInfo',
  'deviceinfo.none': '(not read yet)',

  'log.title': 'Log',
  'btn.clear': 'Clear',

  // #status 的初始文案（main.js 第一次写状态时会摘掉它的 data-i18n，见 setStatus）
  'status.ready': 'Ready',
};
