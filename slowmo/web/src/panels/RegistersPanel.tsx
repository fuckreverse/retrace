/**
 * Registers 面板 —— 当前指令执行前的寄存器状态，高亮读/写/变化。
 */
import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import * as ContextMenu from '@radix-ui/react-context-menu';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { RegsResult } from '@/types/tenet';
import './registers.css';

const GPR_ORDER = [
  'x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14',
  'x15','x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28',
];
const SPECIAL = ['fp', 'lr', 'sp', 'pc'];

export function RegistersPanel() {
  const cur = useTraceStore((s) => s.currentInst);
  const setHexAddr = useTraceStore((s) => s.setHexAddr);
  const [regs, setRegs] = useState<RegsResult | null>(null);
  const [prev, setPrev] = useState<RegsResult | null>(null);
  const [written, setWritten] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.regs(cur), api.regs(Math.max(0, cur - 1)), api.disasm(cur, 1)]).then(
      ([r, p, dis]) => {
        if (cancelled) return;
        setRegs(r);
        setPrev(p);
        const w = new Set<string>();
        dis.rows[0]?.reg_diffs?.forEach((d) => w.add(d.reg));
        setWritten(w);
      },
    );
    return () => { cancelled = true; };
  }, [cur]);

  if (!regs) return <div className="reg-panel" />;

  const cell = (name: string) => {
    const val = regs.regs[name] ?? '0x0';
    const changed = prev && prev.regs[name] !== val;
    const isWrite = written.has(name);
    return (
      <ContextMenu.Root key={name}>
        <ContextMenu.Trigger asChild>
          <div className={clsx('reg-cell', isWrite && 'reg-write', changed && !isWrite && 'reg-changed')}>
            <span className="reg-name">{name}</span>
            <span className="reg-val mono">{val}</span>
          </div>
        </ContextMenu.Trigger>
        <ContextMenu.Portal>
          <ContextMenu.Content className="ctx-menu">
            <ContextMenu.Item className="ctx-item" onSelect={() => setHexAddr(val)}>
              Open Value in Hex Dump
            </ContextMenu.Item>
            <ContextMenu.Item className="ctx-item" onSelect={() => navigator.clipboard?.writeText(val)}>
              Copy Value
            </ContextMenu.Item>
            <ContextMenu.Item className="ctx-item">Trace Producer Chain</ContextMenu.Item>
          </ContextMenu.Content>
        </ContextMenu.Portal>
      </ContextMenu.Root>
    );
  };

  const nzcv = parseInt(regs.regs['nzcv'] ?? '0x0', 16);
  const flags = [
    ['N', (nzcv >> 31) & 1],
    ['Z', (nzcv >> 30) & 1],
    ['C', (nzcv >> 29) & 1],
    ['V', (nzcv >> 28) & 1],
  ] as const;

  return (
    <div className="reg-panel">
      <div className="reg-legend">
        <span className="lg lg-w">W 写</span>
        <span className="lg lg-c">△ 变化</span>
        <span className="dim">inst #{cur}</span>
      </div>
      <div className="reg-grid">{GPR_ORDER.map(cell)}</div>
      <div className="reg-sep" />
      <div className="reg-grid">{SPECIAL.map(cell)}</div>
      <div className="reg-sep" />
      <div className="reg-nzcv">
        <span className="reg-name">nzcv</span>
        {flags.map(([f, v]) => (
          <span key={f} className={clsx('flag', v && 'flag-on')}>{f}</span>
        ))}
        <span className="reg-val mono">{regs.regs['nzcv']}</span>
      </div>
    </div>
  );
}
