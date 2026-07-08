/**
 * Functions 面板 —— 函数列表 + 排序 + 过滤。
 */
import { useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { FunctionEntry } from '@/types/tenet';
import { Input } from '@/components/ui';
import './lists.css';

type SortKey = 'name' | 'calls' | 'insts';

export function FunctionsPanel() {
  const [funcs, setFuncs] = useState<FunctionEntry[]>([]);
  const [filter, setFilter] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('calls');
  const [asc, setAsc] = useState(false);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const setHexAddr = useTraceStore((s) => s.setHexAddr);

  useEffect(() => {
    api.functions().then(setFuncs);
  }, []);

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

  const toggleSort = (k: SortKey) => {
    if (k === sortKey) setAsc(!asc);
    else { setSortKey(k); setAsc(k === 'name'); }
  };

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">Discovered {funcs.length} functions</span>
        <Input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 160, marginLeft: 'auto' }} />
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
          <tbody>
            {rows.map((f) => (
              <tr key={f.pc} onClick={() => navigateTo(0)} onDoubleClick={() => setHexAddr(f.pc)}>
                <td className={clsx('mono', f.name.startsWith('-[') && 'objc-name')}>{f.name}</td>
                <td className="mono num">{f.calls}</td>
                <td className="mono num dim">{f.insts}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
