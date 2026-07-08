/**
 * Call Stack 面板 —— 当前指令的调用栈，帧间导航。
 */
import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { CallFrame } from '@/types/tenet';
import { Empty } from '@/components/ui';
import './lists.css';

export function CallStackPanel() {
  const cur = useTraceStore((s) => s.currentInst);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const [frames, setFrames] = useState<CallFrame[]>([]);

  useEffect(() => {
    let cancelled = false;
    api.callStack(cur).then((f) => { if (!cancelled) setFrames(f); });
    return () => { cancelled = true; };
  }, [cur]);

  if (frames.length === 0) return <Empty>无调用栈信息</Empty>;

  return (
    <div className="list-panel">
      <div className="callstack">
        {frames.map((f, i) => (
          <div
            key={i}
            className={clsx('frame', i === frames.length - 1 && 'frame-top')}
            style={{ paddingLeft: 8 + f.depth * 14 }}
            onClick={() => navigateTo(f.call_inst_id)}
            title="单击跳转到 call site"
          >
            <span className="frame-marker">{i === frames.length - 1 ? '▸' : '·'}</span>
            <span className={clsx('frame-name mono', f.func_name.startsWith('-[') && 'objc-name')}>{f.func_name}</span>
            <span className="frame-at dim mono">@{f.call_inst_id}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
