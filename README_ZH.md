# Sony PMCA Installer

在浏览器里把 APK 装进索尼相机。

[English README](README.md)

支持的设备：https://openmemories.readthedocs.io/devices.html

## 在线使用

访问：https://xfangfang.github.io/pmca-installer

## 本地使用

```bash
node serve.js
```

然后打开 `http://127.0.0.1:8765/dist/`


## 遇到这些不用慌

- 提示设备已断开：切模式时相机重新枚举了，再点一次安装就行。
- 日志里出现等待相机、忙碌重试：相机在写存储，属于正常过程。
- 进度停在某个百分比十几秒不动：相机在自己装包，等一会儿。
- 提示 `Start not accepted`：相机里还留着上一次被中断的任务，这个状态不会自己恢复，把 USB 线拔掉再插上，重新切一次安装模式再选文件装。
- 提示签名冲突（`resultCode 100`）：同一个包名的旧版本还在相机里，先卸掉再装。
- macOS 上建议先执行 `killall icdd`，系统自带的图像捕捉服务会占用相机。

## 致谢

安装流程与协议参考了 ma1co 的 [Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE)（MIT 许可）。

