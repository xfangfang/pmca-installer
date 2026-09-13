/**
 * 英文词条 —— 界面上会跟着语言变的那几处动态文案（src/main.js）。
 *
 * 只有「页面文字」在这里：状态栏、进度条文字、apk 信息表的表头/占位词。
 * **日志与报错一律直接写英文**（源码里就是英文，不查表、不跟着切换），所以不在这里。
 *
 * key = 源码里 tr`…` 的各段用 \u0000 连起来（或 tr('整句') 的整句）；
 * 值里也要有同样个数的 \u0000，顺序一一对应。
 */
export const EN_UI = {
  // 状态栏 / 进度（#status 的初始文案不在这里，它在 i18n-en-shell.js 的 status.ready）
  '正在读取 \u0000…': 'Reading \u0000…',
  'apk 就绪，可以安装了': 'apk ready — you can install now',
  '正在忙，等当前操作结束再重置': 'Busy — wait for the current operation to finish before resetting',
  '已重置：请重新选 apk；下一次安装会弹出设备选择框':
    'Reset: pick an apk again; the next install will show the device dialog',
  '先选一个 apk 文件': 'Pick an apk file first',
  '切换命令已发出。等相机 USB 重新枚举完成后，点「② 选择相机并安装」。':
    'Switch command sent. Once the camera has re-enumerated on USB, press ② Pick a camera and install.',
  '安装中…（不要拔线、不要在相机上做别的操作）':
    'Installing… (do not unplug, do not do anything else on the camera)',
  '安装完成：\u0000': 'Install finished: \u0000',
  '完成': 'Done',

  // apk 信息表 / DeviceInfo 面板的占位词
  '文件': 'File',
  '大小': 'Size',
  '\u0000（解压后 \u0000）': '\u0000 (\u0000 uncompressed)',
  '包名': 'Package',
  '（没解析出来）': '(not parsed)',
  '版本': 'Version',
  '签名文件': 'Signer',
  '（没有）': '(none)',
  '（还没读）': '(not read yet)',
};
