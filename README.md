# Sony PMCA Installer

Install apps onto Sony cameras from your browser.

[中文说明](README_ZH.md)

Supported devices: https://openmemories.readthedocs.io/devices.html

## Use it online

Open https://xfangfang.github.io/pmca-installer

## Run it locally

```bash
node serve.js
```

Then open `http://127.0.0.1:8765/dist/`

## Things that look wrong but aren't

- "The device was disconnected": the camera re-enumerated while switching modes, just click install again.
- Waiting for the camera, or busy retries in the log: the camera is writing to storage, this is expected.
- Progress sitting at some percentage for ten-odd seconds: the camera is installing the package, give it a moment.
- `Start not accepted`: the camera still holds a task from a previous run that was interrupted. It won't clear by
  itself — unplug the USB cable, plug it back in, then switch to install mode and pick the file again.
- Signature conflict (`resultCode 100`): an older build with the same package name is still on the camera.
  Uninstall it first.
- On macOS, run `killall icdd` first — the system image capture service grabs the camera.

## Credits

The install flow and protocol work are based on ma1co's [Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) (MIT).
