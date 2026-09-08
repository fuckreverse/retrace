/**
 * Functions 面板 —— 函数列表 + 排序 + 过滤。
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { clsx } from 'clsx';
import * as ContextMenu from '@radix-ui/react-context-menu';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { FunctionEntry } from '@/types/tenet';
import { copyText } from '@/lib/clipboard';
import { openInHexDump } from '@/lib/hexLink';
import { Input } from '@/components/ui';
import './lists.css';

type SortKey = 'name' | 'calls' | 'insts';

export function FunctionsPanel() {
  const [funcs, setFuncs] = useState<FunctionEntry[]>([]);
  const [filter, setFilter] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('calls');
  const [asc, setAsc] = useState(false);
  // 点击选中的函数（仅本地视图状态，用于行高亮）
  const [selectedPc, setSelectedPc] = useState<string | null>(null);
  // 当前指令所在函数（栈底帧），由 cur 反向联动得出
  const [currentFuncPc, setCurrentFuncPc] = useState<string | null>(null);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const cur = useTraceStore((s) => s.currentInst);
  const tbodyRef = useRef<HTMLTableSectionElement | null>(null);

  useEffect(() => {
    api.functions().then(setFuncs);
  }, []);

  // 反向联动：cur 变化时查调用栈，取栈底帧的 func_pc 作为"当前所在函数"
  useEffect(() => {
    let cancelled = false;
    api.callStack(cur)
      .then((frames) => {
        if (cancelled) return;
        // 栈底帧（最后一项）即当前正在执行的函数
        const top = frames.length > 0 ? frames[frames.length - 1] : undefined;
        setCurrentFuncPc(top ? top.func_pc : null);
      })
      .catch(() => {
        if (!cancelled) setCurrentFuncPc(null);
      });
    return () => { cancelled = true; };
  }, [cur]);

  const rows = useMemo(() => {
    let r = funcs.filter((f) => f.name.toLowerCase().includes(filter.toLowerCase()));
    r = [...r].sort((a, b) => {
      let d = 0;
      if (sortKey === 'name') d = a.name.localeCompare(b.name);
      else d = a[sortKey] - b[sortKey];
      return asc ? d : -d;
    });
    return r;
  }, [funcs, filter, sortKey, asc]);

  // 当前所在函数行变化时滚动到可视区，避免手动翻找
  // （放在 rows 之后声明：依赖数组在渲染期求值，且过滤/排序变化后行可能重建）
  useEffect(() => {
    if (!currentFuncPc || !tbodyRef.current) return;
    const el = tbodyRef.current.querySelector<HTMLTableRowElement>(
      `tr[data-pc="${CSS.escape(currentFuncPc)}"]`,
    );
    el?.scrollIntoView({ block: 'nearest' });
  }, [currentFuncPc, rows]);

  const toggleSort = (k: SortKey) => {
    if (k === sortKey) setAsc(!asc);
    else { setSortKey(k); setAsc(k === 'name'); }
  };

  const gotoFunc = async (pc: string) => {
    const xref = await api.xref(pc);
    if (xref.inst_ids.length > 0) navigateTo(xref.inst_ids[0]);
  };

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">已识别 {funcs.length} 个函数</span>
        <Input placeholder="过滤…" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 160, marginLeft: 'auto' }} />
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th className="sortable" onClick={() => toggleSort('name')}>Name {sortKey === 'name' && (asc ? '▲' : '▼')}</th>
              <th className="sortable" style={{ width: 60, textAlign: 'right' }} onClick={() => toggleSort('calls')}>Calls {sortKey === 'calls' && (asc ? '▲' : '▼')}</th>
              <th className="sortable" style={{ width: 64, textAlign: 'right' }} onClick={() => toggleSort('insts')}>Insts {sortKey === 'insts' && (asc ? '▲' : '▼')}</th>
            </tr>
          </thead>
          <tbody ref={tbodyRef}>
            {rows.map((f) => (
              <ContextMenu.Root key={f.pc}>
                <ContextMenu.Trigger asChild>
                  <tr
                    data-pc={f.pc}
                    className={clsx(f.pc === selectedPc && 'row-selected', f.pc === currentFuncPc && 'row-current')}
                    onClick={() => { setSelectedPc(f.pc); void gotoFunc(f.pc); }}
                    onDoubleClick={() => openInHexDump(f.pc)}
                  >
                    <td className={clsx('mono', f.name.startsWith('-[') && 'objc-name')}>{f.name}</td>
                    <td className="mono num">{f.calls}</td>
                    <td className="mono num dim">{f.insts}</td>
                  </tr>
                </ContextMenu.Trigger>
                <ContextMenu.Portal>
                  <ContextMenu.Content className="ctx-menu">
                    <ContextMenu.Item className="ctx-item" onSelect={() => void gotoFunc(f.pc)}>
                      跳转到函数
                    </ContextMenu.Item>
                    <ContextMenu.Item className="ctx-item" onSelect={() => openInHexDump(f.pc)}>
                      在 Hex Dump 打开
                    </ContextMenu.Item>
                    <ContextMenu.Separator className="ctx-sep" />
                    <ContextMenu.Item className="ctx-item" onSelect={() => void copyText(f.name, '函数名')}>
                      复制函数名
                    </ContextMenu.Item>
                    <ContextMenu.Item className="ctx-item" onSelect={() => void copyText(f.pc, '地址')}>
                      复制地址
                    </ContextMenu.Item>
                  </ContextMenu.Content>
                </ContextMenu.Portal>
              </ContextMenu.Root>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
