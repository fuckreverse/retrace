/**
 * 高频跳转：跟踪调用 / 跟踪返回 —— 补齐 GUI 的 follow call / follow return 能力。
 *
 *   followCall(instId)   ：当前指令为 bl（直接调用）时，从操作数解析目标地址，
 *                          xref 取被调函数首次执行点并跳转；blr 为寄存器间接
 *                          调用，静态无法解析目标，返回 false。
 *   followReturn(instId) ：当前指令为 ret 时，取调用栈倒数第二帧（调用者）的
 *                          call_inst_id，跳到其下一条指令（即返回落点）。
 *
 * 两个函数都先取当前行校验 mnemonic，条件不满足时返回 false，由调用方决定提示。
 */
import { api } from '@/api/service';
import { useTraceStore } from '@/store/traceStore';

async function rowOf(instId: number) {
  return (await api.disasm(instId, 1)).rows[0];
}

/** 跟踪调用：从 bl 指令跳到被调函数首次执行点。 */
export async function followCall(instId: number): Promise<boolean> {
  const row = await rowOf(instId);
  if (!row || !/^bl\b/.test(row.mnemonic ?? '')) return false;
  // bl 直接寻址：操作数即目标函数地址（形如 "0x1000045c0"）
  const m = /0x[0-9a-fA-F]+/.exec(row.operands ?? '');
  if (!m) return false;
  const x = await api.xref(m[0]);
  const first = x.inst_ids?.[0];
  if (first == null) return false;
  useTraceStore.getState().navigateTo(first);
  return true;
}

/** 跟踪返回：从 ret 指令跳回调用点下一条指令。 */
export async function followReturn(instId: number): Promise<boolean> {
  const row = await rowOf(instId);
  if (!row || !/^ret\b/.test(row.mnemonic ?? '')) return false;
  const frames = await api.callStack(instId);
  if (frames.length < 2) return false;
  // 栈底帧（最后一项）是当前函数；倒数第二帧的 call_inst_id 是进入当前函数的调用点
  const caller = frames[frames.length - 2];
  useTraceStore.getState().navigateTo(caller.call_inst_id + 1);
  return true;
}
