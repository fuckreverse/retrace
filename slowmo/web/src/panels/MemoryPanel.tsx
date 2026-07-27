/**
 * Memory Accesses 面板 —— 当前指令的读/写访问。
 */
import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import * as ContextMenu from '@radix-ui/react-context-menu';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { MemAccess } from '@/types/tenet';
import { Empty } from '@/components/ui';
import './memory.css';

export function MemoryPanel() {
  const cur = useTraceStore((s) => s.currentInst);
  const setHexAddr = useTraceStore((s) => s.setHexAddr);
  const [accesses, setAccesses] = useState<MemAccess[]>([]);

  useEffect(() => {
    let cancelled = false;
    api.disasm(cur, 1).then((r) => {
      if (!cancelled) setAccesses(r.rows[0]?.mem_accesses ?? []);
    });
    return () => { cancelled = true; };
  }, [cur]);

  if (accesses.length === 0) {
    return <Empty>当前指令无内存访问</Empty>;
  }

  return (
    <div className="mem-panel">
      {accesses.map((a, i) => (
        <ContextMenu.Root key={i}>
          <ContextMenu.Trigger asChild>
            <div className="mem-row" onDoubleClick={() => setHexAddr(a.addr)}>
              <span className={clsx('mem-type', a.type === 'READ' ? 'mem-read' : 'mem-write')}>
                {a.type}
              </span>
              <span className="mem-field">
                addr <span className="mono mem-addr" onClick={() => setHexAddr(a.addr)}>{a.addr}</span>
              </span>
              <span className="mem-field">size <span className="mono">{a.size}</span></span>
              <span className="mem-field">val <span className="mono mem-valcol">{a.value}</span></span>
              <button className="mem-hex-btn" onClick={() => setHexAddr(a.addr)}>Hex</button>
            </div>
          </ContextMenu.Trigger>
          <ContextMenu.Portal>
            <ContextMenu.Content className="ctx-menu">
              <ContextMenu.Item className="ctx-item" onSelect={() => navigator.clipboard?.writeText(a.addr)}>
                Copy Address
              </ContextMenu.Item>
              <ContextMenu.Item className="ctx-item" onSelect={() => navigator.clipboard?.writeText(a.value)}>
                Copy Value
              </ContextMenu.Item>
              <ContextMenu.Separator className="ctx-sep" />
              <ContextMenu.Item className="ctx-item" onSelect={() => setHexAddr(a.addr)}>
                Open in Hex Dump
              </ContextMenu.Item>
            </ContextMenu.Content>
          </ContextMenu.Portal>
        </ContextMenu.Root>
      ))}
    </div>
  );
}
