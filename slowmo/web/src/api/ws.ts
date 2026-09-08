/**
 * WebSocket 传输层 —— 对接后端 TenetWSService (uWebSockets + FlatBuffers)。
 *
 * 协议契约（见 src/ws/schema/tenet_ws.fbs）：
 *  - 每个二进制帧 = 一个 **非 size-prefixed** 的 Envelope FlatBuffer。
 *  - Envelope { msg_id: uint32, type: MessageType(uint16), payload: [ubyte] }
 *    payload 内嵌一个具体消息（同样 **非 size-prefixed**），由调用方手动解析。
 *  - 请求 msg_id 自增；服务端响应回显同一 msg_id。
 *  - 服务端主动推送事件用 msg_id = 0。
 *
 * 本层只负责：连接/重连、Envelope 编解码、请求-响应配对、事件分发。
 * 具体消息的 build/parse 由 ws-api.ts 提供。
 */
import * as flatbuffers from 'flatbuffers';
import { isTauri } from '@/lib/env';
import { Envelope, ErrorResponse, MessageType } from './ws-gen/tenet/ws';

/** 默认端口，与后端 TenetWSService::start(9090) 对齐 */
const DEFAULT_WS_PORT = 9090;

/** 动态 WS 端口——由 appStore.openTrace() 设置，Tauri 模式下覆盖默认值 */
let dynamicWsPort: number | null = null;

/** 供 appStore 调用：后端启动后设置实际的 WS 端口 */
export function setWsPort(port: number): void {
  dynamicWsPort = port;
}

/**
 * 当前动态 WS 端口（未设置时为 null）。
 * 供弹出面板窗口（openPanelWindow）把它写进子窗口 URL——子窗口是独立的
 * JS 上下文，不共享本模块的 dynamicWsPort，没有这个参数就会错误地连到
 * 默认 9090（多 trace 并行时后端实际分配在 9090+n）。
 */
export function getWsPort(): number | null {
  return dynamicWsPort;
}

/**
 * 运行环境自适应的 WS 地址：
 *  - Tauri webview：直连后端绝对地址（无 dev proxy），webview 允许跨源 WS。
 *  - 浏览器 dev：走 Vite proxy 的 /ws（避免混合内容/跨源问题）。
 *  - 浏览器生产（同源部署）：也走 /ws，交给反向代理转发。
 */
function resolveWsUrl(): string {
  if (isTauri()) {
    const port = dynamicWsPort ?? DEFAULT_WS_PORT;
    return `ws://127.0.0.1:${port}`;
  }
  const proto = typeof location !== 'undefined' && location.protocol === 'https:' ? 'wss' : 'ws';
  const host = typeof location !== 'undefined' ? location.host : `127.0.0.1:${DEFAULT_WS_PORT}`;
  return `${proto}://${host}/ws`;
}

/** 解析后的一条响应：type + payload（内嵌消息的原始字节，非 size-prefixed） */
export interface WsResponse {
  type: MessageType;
  /** 内嵌消息字节，可直接 new ByteBuffer(...) + getRootAsXxx 解析 */
  payload: Uint8Array;
}

type Resolver = {
  resolve: (r: WsResponse) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

/** 事件监听回调：收到服务端推送（msg_id=0）时调用 */
export type WsEventListener = (type: MessageType, payload: Uint8Array) => void;

export type WsConnState = 'connecting' | 'open' | 'closed';

const REQUEST_TIMEOUT_MS = 15_000;
const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 8_000;

class WsTransport {
  private ws: WebSocket | null = null;
  private url: string;
  private nextMsgId = 1;
  private pending = new Map<number, Resolver>();
  private eventListeners = new Set<WsEventListener>();
  private stateListeners = new Set<(s: WsConnState) => void>();
  private state: WsConnState = 'closed';
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private connectPromise: Promise<void> | null = null;
  private manualClose = false;
  /** 一旦成功握手过一次，视为“后端存在”，允许自动重连 */
  private everConnected = false;

  constructor(url: string) {
    this.url = url;
  }

  getState(): WsConnState {
    return this.state;
  }

  isEverConnected(): boolean {
    return this.everConnected;
  }

  onEvent(fn: WsEventListener): () => void {
    this.eventListeners.add(fn);
    return () => this.eventListeners.delete(fn);
  }

  onStateChange(fn: (s: WsConnState) => void): () => void {
    this.stateListeners.add(fn);
    return () => this.stateListeners.delete(fn);
  }

  private setState(s: WsConnState) {
    if (this.state === s) return;
    this.state = s;
    for (const fn of this.stateListeners) fn(s);
  }

  /** 确保已连接；重复调用共享同一次连接过程 */
  connect(): Promise<void> {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return Promise.resolve();
    if (this.connectPromise) return this.connectPromise;

    this.manualClose = false;
    this.setState('connecting');
    this.connectPromise = new Promise<void>((resolve, reject) => {
      let settled = false;
      let ws: WebSocket;
      try {
        ws = new WebSocket(this.url);
      } catch (e) {
        this.connectPromise = null;
        this.setState('closed');
        reject(e instanceof Error ? e : new Error(String(e)));
        return;
      }
      ws.binaryType = 'arraybuffer';
      this.ws = ws;

      ws.onopen = () => {
        settled = true;
        this.everConnected = true;
        this.reconnectAttempts = 0;
        this.connectPromise = null;
        this.setState('open');
        resolve();
      };

      ws.onmessage = (ev) => this.onMessage(ev);

      ws.onerror = () => {
        if (!settled) {
          settled = true;
          this.connectPromise = null;
          this.setState('closed');
          reject(new Error('WebSocket connection error'));
        }
      };

      ws.onclose = () => {
        this.ws = null;
        this.setState('closed');
        // 挂起请求全部失败
        for (const [, r] of this.pending) {
          clearTimeout(r.timer);
          r.reject(new Error('WebSocket closed'));
        }
        this.pending.clear();
        if (!settled) {
          settled = true;
          this.connectPromise = null;
          reject(new Error('WebSocket closed before open'));
        }
        // 仅在曾连接成功且非手动关闭时自动重连
        if (!this.manualClose && this.everConnected) {
          this.scheduleReconnect();
        }
      };
    });
    return this.connectPromise;
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) return;
    const delay = Math.min(
      RECONNECT_BASE_MS * 2 ** this.reconnectAttempts,
      RECONNECT_MAX_MS,
    );
    this.reconnectAttempts++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect().catch(() => {
        /* 失败会再次触发 onclose → 再排程 */
      });
    }, delay);
  }

  close() {
    this.manualClose = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
    this.setState('closed');
  }

  private onMessage(ev: MessageEvent) {
    if (!(ev.data instanceof ArrayBuffer)) return; // 只处理二进制帧
    const bytes = new Uint8Array(ev.data);
    const bb = new flatbuffers.ByteBuffer(bytes);
    const env = Envelope.getRootAsEnvelope(bb);
    const msgId = env.msgId();
    const type = env.type();
    const payload = env.payloadArray() ?? new Uint8Array(0);

    if (msgId === 0) {
      // 服务端主动推送事件
      for (const fn of this.eventListeners) fn(type, payload);
      return;
    }

    const resolver = this.pending.get(msgId);
    if (!resolver) return; // 迟到/未知响应，忽略
    this.pending.delete(msgId);
    clearTimeout(resolver.timer);

    if (type === MessageType.ErrorResp) {
      const ebb = new flatbuffers.ByteBuffer(payload);
      const err = ErrorResponse.getRootAsErrorResponse(ebb);
      resolver.reject(new Error(`WS error ${err.code()}: ${err.message() ?? ''}`));
      return;
    }
    resolver.resolve({ type, payload });
  }

  /**
   * 发送一个请求并等待响应。
   * @param reqType   请求 MessageType
   * @param buildPayload  在给定 builder 上构造内嵌消息，返回其 offset
   */
  async request(
    reqType: MessageType,
    buildPayload: (b: flatbuffers.Builder) => flatbuffers.Offset,
  ): Promise<WsResponse> {
    await this.connect();
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not open');
    }

    // 1) 构造内嵌 payload（独立 builder，得到非 size-prefixed 字节）
    const pb = new flatbuffers.Builder(256);
    const off = buildPayload(pb);
    pb.finish(off);
    const payloadBytes = pb.asUint8Array();

    // 2) 构造 Envelope，把 payload 作为 [ubyte] 向量嵌入
    const eb = new flatbuffers.Builder(256 + payloadBytes.length);
    const msgId = this.nextMsgId++;
    if (this.nextMsgId > 0xffff_fffe) this.nextMsgId = 1;
    const payloadVec = Envelope.createPayloadVector(eb, payloadBytes);
    const envOff = Envelope.createEnvelope(eb, msgId, reqType, payloadVec);
    eb.finish(envOff);
    const frame = eb.asUint8Array();

    // 3) 注册 pending + 发送
    return new Promise<WsResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(msgId);
        reject(new Error(`WS request timeout (type=${reqType})`));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(msgId, { resolve, reject, timer });
      try {
        // slice 防止底层 buffer 被复用
        ws.send(frame.slice().buffer);
      } catch (e) {
        this.pending.delete(msgId);
        clearTimeout(timer);
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }
}

/** 单例传输实例——初始化时用默认 URL，重连时用最新 URL */
let wsTransportInstance: WsTransport | null = null;

function getWsTransport(): WsTransport {
  if (!wsTransportInstance) {
    wsTransportInstance = new WsTransport(resolveWsUrl());
  }
  return wsTransportInstance;
}

export { getWsTransport as wsTransport };

/**
 * 重置 WS 连接（端口变更后调用）。
 * 关闭旧连接，下次访问时自动用新 URL 创建。
 */
export function resetWsTransport(): void {
  wsTransportInstance?.close();
  wsTransportInstance = new WsTransport(resolveWsUrl());
}

/** 便捷导出：发送请求 */
export function wsRequest(
  reqType: MessageType,
  buildPayload: (b: flatbuffers.Builder) => flatbuffers.Offset,
): Promise<WsResponse> {
  return getWsTransport().request(reqType, buildPayload);
}

/** 便捷导出：探测 WS 是否可连接（用于混合路由决策） */
export async function probeWs(): Promise<boolean> {
  try {
    await getWsTransport().connect();
    return getWsTransport().getState() === 'open';
  } catch {
    return false;
  }
}
