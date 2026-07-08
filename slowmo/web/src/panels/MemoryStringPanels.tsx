/**
 * Memory-String 类面板 —— Memory Search / Memory Strings / Entropy / YARA。
 */
import { useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { EntropyBlock, MemSearchHit, MemStringEntry, YaraMatch } from '@/types/tenet';
import { Chip, Input } from '@/components/ui';
import { Icon } from '@/components/icons';
import './lists.css';

/* ---------- Memory Search ---------- */
export function MemorySearchPanel() {
  const [query, setQuery] = useState('');
  const [hits, setHits] = useState<MemSearchHit[] | null>(null);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const setHexAddr = useTraceStore((s) => s.setHexAddr);

  const run = () => {
    const q = query.trim();
    if (!q) { setHits(null); return; }
    api.memSearch(q).then(setHits);
  };

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="mem-search-icon"><Icon.Search /></span>
        <Input
          placeholder="搜索内存值 / 十六进制字节 (如 deadbeef)…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && run()}
          style={{ width: 300 }}
        />
        {hits && <span className="list-count" style={{ marginLeft: 'auto' }}>{hits.length} hits</span>}
      </div>
      <div className="list-scroll">
        {!hits ? (
          <div className="empty-state">输入内存值或字节序列后回车搜索</div>
        ) : (
          <table className="data-table">
            <thead><tr><th style={{ width: 130 }}>Address</th><th style={{ width: 70 }}>Type</th><th>Value</th><th>Context</th><th style={{ width: 60 }}>Inst</th></tr></thead>
            <tbody>
              {hits.map((h, i) => (
                <tr key={i} onClick={() => { navigateTo(h.inst_id); setHexAddr(h.addr); }}>
                  <td className="mono dim">{h.addr}</td>
                  <td><span className={clsx('cat-tag', h.match_type === 'write' ? 'cat-warning' : 'cat-accent')}>{h.match_type}</span></td>
                  <td className="mono str-val">{h.value}</td>
                  <td className="mono dim">{h.context}</td>
                  <td className="mono link">#{h.inst_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

/* ---------- Memory Strings ---------- */
export function MemoryStringsPanel() {
  const [rows, setRows] = useState<MemStringEntry[]>([]);
  const [region, setRegion] = useState('All');
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const setHexAddr = useTraceStore((s) => s.setHexAddr);

  useEffect(() => { api.memStrings().then(setRows); }, []);
  const regions = useMemo(() => ['All', ...Array.from(new Set(rows.map((r) => r.region)))], [rows]);
  const filtered = rows.filter((r) => region === 'All' || r.region === region);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        {regions.map((r) => <Chip key={r} active={region === r} onClick={() => setRegion(r)}>{r}</Chip>)}
        <span className="list-count" style={{ marginLeft: 'auto' }}>{filtered.length} runtime strings</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 130 }}>Address</th><th style={{ width: 70 }}>Region</th><th>String</th><th style={{ width: 50 }}>Len</th><th style={{ width: 60 }}>Inst</th></tr></thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr key={i} onClick={() => { navigateTo(r.inst_id); setHexAddr(r.addr); }}>
                <td className="mono dim">{r.addr}</td>
                <td><span className="cat-tag cat-default">{r.region}</span></td>
                <td className="mono str-val">"{r.value}"</td>
                <td className="mono num dim">{r.length}</td>
                <td className="mono link">#{r.inst_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Entropy ---------- */
function entropyColor(e: number): string {
  // 0..8 → 蓝(低) → 橙 → 红(高)
  if (e > 7.2) return 'var(--danger)';
  if (e > 5.5) return 'var(--hl-imm)';
  if (e > 3.5) return 'var(--accent)';
  return 'var(--text-tertiary)';
}
export function EntropyPanel() {
  const [rows, setRows] = useState<EntropyBlock[]>([]);
  const setHexAddr = useTraceStore((s) => s.setHexAddr);

  useEffect(() => { api.entropy().then(setRows); }, []);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">{rows.length} blocks · 256 B/block · Shannon 熵</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 140 }}>Address</th><th style={{ width: 70 }}>Size</th><th style={{ width: 220 }}>Entropy</th><th>Classification</th></tr></thead>
          <tbody>
            {rows.map((b, i) => (
              <tr key={i} onClick={() => setHexAddr(b.addr)}>
                <td className="mono dim">{b.addr}</td>
                <td className="mono num dim">{b.size}</td>
                <td>
                  <div className="ent-bar">
                    <div className="ent-fill" style={{ width: `${(b.entropy / 8) * 100}%`, background: entropyColor(b.entropy) }} />
                    <span className="ent-label mono">{b.entropy.toFixed(2)}</span>
                  </div>
                </td>
                <td className={clsx('dim', b.entropy > 7.2 && 'ent-high')}>{b.classification}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- YARA ---------- */
export function YaraPanel() {
  const [rows, setRows] = useState<YaraMatch[]>([]);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  useEffect(() => { api.yara().then(setRows); }, []);

  return (
    <div className="list-panel">
      <div className="list-toolbar">
        <span className="list-count">{rows.length} YARA rule matches</span>
      </div>
      <div className="list-scroll">
        <table className="data-table">
          <thead><tr><th style={{ width: 180 }}>Rule</th><th style={{ width: 110 }}>Namespace</th><th>Tags</th><th style={{ width: 90 }}>Strings</th><th style={{ width: 60 }}>Inst</th></tr></thead>
          <tbody>
            {rows.map((m, i) => (
              <tr key={i} onClick={() => navigateTo(m.inst_id)}>
                <td className="mono objc-name">{m.rule}</td>
                <td className="dim">{m.namespace}</td>
                <td>
                  {m.tags.map((t) => <span key={t} className="cat-tag cat-accent" style={{ marginRight: 4 }}>{t}</span>)}
                </td>
                <td className="mono num dim">{m.strings_matched}</td>
                <td className="mono link">#{m.inst_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
