/**
 * 相机在 app 安装模式下与主机对话的应用层协议。
 * 对应 PMCA `pmca/usb/sony.py: SonyAppInstallCamera`。
 *
 * 消息分两个通道（都是「PTP 代理消息」里的 payload）：
 *   Common (0)：start(0x400)/hello(0x401)/bye(0x402) —— 握手与收尾
 *   帧头  = version(u16) + type(u32) + size(u32) + 6 字节填充    ← 注意**大端**
 *   Tcp (1)：proxyConnect(0x501)/proxyDisconnect(0x502)/proxyData(0x503)/proxyEnd(0x504)
 *   相机把要发给某个 host:port 的 **TLS 裸字节**塞在这里交给主机
 *   Rest (2)：in(0)/out(2) —— 一个极简 HTTP 封装，只有 /task/start、/task/progress、
 *   /task/complete 三个端点，格式 `POST <url> REST/1.0\r\n...`
 *
 * `header.size` 是**逻辑消息总长**（含 16 字节帧头），所以 payload = data[16:size]。
 */

import { Struct, concat, latin1, sleep } from './bytes.js';

export const SONY_MSG_COMMON = 0;
export const SONY_MSG_TCP = 1;
export const SONY_MSG_REST = 2;

const SONY_MSG_Common_Start = 0x400;
const SONY_MSG_Common_Hello = 0x401;
const SONY_MSG_Common_Bye = 0x402;

const SONY_MSG_Tcp_ProxyConnect = 0x501;
const SONY_MSG_Tcp_ProxyDisconnect = 0x502;
const SONY_MSG_Tcp_ProxyData = 0x503;
const SONY_MSG_Tcp_ProxyEnd = 0x504;

const SONY_MSG_Rest_In = 0;
const SONY_MSG_Rest_Out = 2;

export const COMMON_MSG_VERSION = 1;

const CommonMsgHeader = new Struct(
  'CommonMsgHeader',
  [
    ['version', 'u16'],
    ['type', 'u32'],
    ['size', 'u32'],
    [null, 6],
  ],
  'big'
);

const TcpMsgHeader = new Struct('TcpMsgHeader', [['socketFd', 'u32']], 'big');
const RestMsgHeader = new Struct('RestMsgHeader', [['type', 'u16'], ['size', 'u16']], 'big');
const ProxyConnectMsgHeader = new Struct(
  'ProxyConnectMsgHeader',
  [
    ['port', 'u16'],
    ['hostSize', 'u32'],
  ],
  'big'
);
const SslDataMsgHeader = new Struct('SslDataMsgHeader', [['size', 'u32']], 'big');
const ProtocolMsgHeader = new Struct('ProtocolMsgHeader', [['numProtocols', 'u32']], 'big');
const ProtocolMsgProto = new Struct(
  'ProtocolMsgProto',
  [
    ['name', 's4'],
    ['id', 'u16'],
  ],
  'big'
);
const ThreeValueMsg = new Struct(
  'ThreeValueMsg',
  [
    ['a', 'u16'],
    ['b', 'u32'],
    ['c', 'u32'],
  ],
  'big'
);

/** 相机要跟主机谈的两个协议：TCPT（TCP 隧道）与 REST。 */
export const PROTOCOLS = [
  ['TCPT', 0x01],
  ['REST', 0x100],
];

export class SonyAppInstallCamera {
  constructor(dev, log = () => {}) {
    this.dev = dev;
    this.log = log;
  }

  /**
   * 收一条消息并解析。返回 null 表示「相机暂时没话说」（正常轮询结果），
   * 上层应当去检查代理 socket 有没有数据要送给相机。
   */
  async receive() {
    const [type, data] = await this.dev.receiveMessage();
    if (type === null) return null;

    if (type === SONY_MSG_COMMON) {
      const header = CommonMsgHeader.unpack(data);
      const body = data.subarray(CommonMsgHeader.size, header.size);
      if (header.type === SONY_MSG_Common_Hello) {
        const n = ProtocolMsgHeader.unpack(body).numProtocols;
        const protocols = [];
        for (let i = 0; i < n; i++) {
          const p = ProtocolMsgProto.unpack(body, ProtocolMsgHeader.size + i * ProtocolMsgProto.size);
          protocols.push([latin1(p.name), p.id]);
        }
        return { kind: 'init', protocols };
      }
      if (header.type === SONY_MSG_Common_Bye) throw new Error('the camera sent Bye');
      throw new Error(`unknown Common message 0x${header.type.toString(16)}`);
    }

    if (type === SONY_MSG_TCP) {
      const header = CommonMsgHeader.unpack(data);
      const body = data.subarray(CommonMsgHeader.size, header.size);
      const tcp = TcpMsgHeader.unpack(body);
      const rest = body.subarray(TcpMsgHeader.size);
      if (header.type === SONY_MSG_Tcp_ProxyConnect) {
        const proxy = ProxyConnectMsgHeader.unpack(rest);
        const host = latin1(rest.subarray(ProxyConnectMsgHeader.size, ProxyConnectMsgHeader.size + proxy.hostSize));
        return { kind: 'sslStart', connectionId: tcp.socketFd, host, port: proxy.port };
      }
      if (header.type === SONY_MSG_Tcp_ProxyDisconnect) {
        return { kind: 'sslEnd', connectionId: tcp.socketFd };
      }
      if (header.type === SONY_MSG_Tcp_ProxyData) {
        const size = SslDataMsgHeader.unpack(rest).size;
        return {
          kind: 'sslData',
          connectionId: tcp.socketFd,
          data: rest.subarray(SslDataMsgHeader.size, SslDataMsgHeader.size + size),
        };
      }
      throw new Error(`unknown TCP message 0x${header.type.toString(16)}`);
    }

    if (type === SONY_MSG_REST) {
      const header = RestMsgHeader.unpack(data);
      const body = data.subarray(RestMsgHeader.size, RestMsgHeader.size + header.size);
      if (header.type === SONY_MSG_Rest_Out) return { kind: 'response', data: body };
      if (header.type === SONY_MSG_Rest_In) return { kind: 'request', data: body };
      throw new Error(`unknown REST message 0x${header.type.toString(16)}`);
    }

    throw new Error(`unknown message type 0x${type.toString(16)}`);
  }

  async _receiveResponse(kind) {
    for (;;) {
      const msg = await this.receive();
      if (msg === null) continue;
      if (msg.kind !== kind) throw new Error(`expected ${kind} but got ${msg.kind}`);
      return msg;
    }
  }

  /** 把相机缓冲区里积压的消息读干净（开始新任务前必做）。
   *
   * 比上游的 `emptyBuffer()`（读到「无数据」就停）多一个安静窗口：相机里的下载 app
   * 是独立线程，上一次任务被半路丢下时它的消息可能姗姗来迟 ⇒ 连续 quietMs 没有新消息
   * 才算干净。quietMs=0 即上游语义（收到一条空就停），测试用它保持剧本可控。
   */
  async emptyBuffer(quietMs = 150) {
    let n = 0;
    let deadline = Date.now() + quietMs;
    for (;;) {
      const msg = await this.receive();
      if (msg) {
        n++;
        if (n > 1000) return n;
        deadline = Date.now() + quietMs;
        continue;
      }
      if (Date.now() >= deadline) return n;
      await sleep(5);
    }
  }

  async _sendCommonMessage(subType, data, type = SONY_MSG_COMMON) {
    await this.dev.sendMessage(
      type,
      concat(
        CommonMsgHeader.pack({
          version: COMMON_MSG_VERSION,
          type: subType,
          size: CommonMsgHeader.size + data.length,
        }),
        data
      )
    );
  }

  async _sendTcpMessage(subType, socketFd, data) {
    await this._sendCommonMessage(
      subType,
      concat(TcpMsgHeader.pack({ socketFd }), data),
      SONY_MSG_TCP
    );
  }

  async _sendRestMessage(subType, data) {
    await this.dev.sendMessage(
      SONY_MSG_REST,
      concat(RestMsgHeader.pack({ type: subType, size: data.length }), data)
    );
  }

  /** 握手：宣告我们支持 TCPT + REST。 */
  async sendInit(protocols = PROTOCOLS) {
    const parts = [ProtocolMsgHeader.pack({ numProtocols: protocols.length })];
    for (const [name, id] of protocols) parts.push(ProtocolMsgProto.pack({ name, id }));
    await this._sendCommonMessage(SONY_MSG_Common_Start, concat(...parts));
    const msg = await this._receiveResponse('init');
    return msg.protocols;
  }

  /** 把一条 REST 请求投给相机（投 xpd、启动任务）。**不等**回应 —— 回应可能不是紧接着的那一条，
   * 所以由 installer.js 的主循环按状态机来认（见那里的注释）。 */
  async sendStartRequest(data) {
    await this._sendRestMessage(SONY_MSG_Rest_Out, data);
  }

  /** 把从代理 socket 读到的字节回灌给相机（相机自己用它做 TLS）。 */
  async sendSslData(req, data) {
    await this._sendTcpMessage(
      SONY_MSG_Tcp_ProxyData,
      req,
      concat(SslDataMsgHeader.pack({ size: data.length }), data)
    );
  }

  async sendSslEnd(req) {
    await this._sendTcpMessage(
      SONY_MSG_Tcp_ProxyEnd,
      req,
      ThreeValueMsg.pack({ a: 1, b: 1, c: 0 })
    );
  }

  async sendEnd() {
    await this._sendCommonMessage(SONY_MSG_Common_Bye, ThreeValueMsg.pack({ a: 0, b: 0, c: 0 }));
  }
}
