/**
 * Memory-String 类面板 —— Memory Search / Memory Strings / Entropy / YARA。
 */
import { useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { EntropyBlock, MemSearchHit, MemStringEntry, YaraMatch } from '@/types/tenet';
import { Button, Chip, Input } from '@/components/ui';
import { Icon } from '@/components/icons';
import './lists.css';

/* ---------- Memory Search ---------- */
type MemSearchMode = 'pattern' | 'exact';

export function MemorySearchPanel() {
  const [mode, setMode] = useState<MemSearchMode>('pattern');
  const [query, setQuery] = useState('');
  const [isText, setIsText] = useState(false);
  const [searchRegisters, setSearchRegisters] = useState(false);
  const [searchImmediates, setSearchImmediates] = useState(false);
  const [hits, setHits] = useState<MemSearchHit[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigateTo = useTraceStore((s) => s.navigateTo);
  const setHexAddr = useTraceStore((s) => s.setHexAddr);

  const run = async () => {
    const q = query.trim();
    if (!q) { setHits(null); setError(null); return; }
    setBusy(true);
    setError(null);
    try {
      const result = await api.memSearch({
        mode,
        pattern: mode === 'pattern' ? q : undefined,
        isText: mode === 'pattern' ? isText : undefined,
        exactValue: mode === 'exact' ? q : undefined,
        searchRegisters,
        searchImmediates,
      });
      setHits(result);
    } catch {
      setError('搜索失败（后端 mem_search 调用出错）');
      setHits(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="list-panel">
      <div className="list-toolbar" style={{ flexWrap: 'wrap', rowGap: 6 }}>
        <span className="mem-search-icon"><Icon.Search /></span>
        <Chip active={mode === 'pattern'} onClick={() => setMode('pattern')}>字节模式</Chip>
        <Chip active={mode === 'exact'} onClick={() => setMode('exact')}>精确值</Chip>
        <Input
          placeholder={mode === 'pattern'
            ? (isText ? '搜索 ASCII 子串（如 password）…' : '空格分隔十六进制字节，?? 为通配符（如 DE AD ?? EF）…')
            : '精确标量值（十六进制 0x... 或十进制），如 crypto IV / 指针…'}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void run()}
          style={{ width: 320 }}
        />
        {mode === 'pattern' && (
          <label className="mem-search-toggle">
            <input type="checkbox" checked={isText} onChange={(e) => setIsText(e.target.checked)} />
            <span>文本 (text)</span>
          </label>
        )}
        <label className="mem-search-toggle">
          <input type="checkbox" checked={searchRegisters} onChange={(e) => setSearchRegisters(e.target.checked)} />
          <span>寄存器 (reg)</span>
        </label>
        {mode === 'exact' && (
          <label className="mem-search-toggle">
            <input type="checkbox" checked={searchImmediates} onChange={(e) => setSearchImmediates(e.target.checked)} />
            <span>立即数 (imm)</span>
          </label>
        )}
        <Button variant="primary" size="sm" onClick={() => void run()} disabled={busy || !query.trim()}>
          {busy ? '搜索中…' : '搜索'}
        </Button>
        {hits && <span className="list-count" style={{ marginLeft: 'auto' }}>{hits.length} hits</span>}
      </div>
      <div className="list-scroll">
        {error ? (
          <div className="empty-state">{error}</div>
        ) : !hits ? (
          <div className="empty-state">
            选择"字节模式"（内存写入的字节序列，支持 ?? 通配符/文本子串）或"精确值"（标量值/指针/IV，
            可选同时扫描寄存器差异或 MOVZ/MOVK 立即数），输入后回车搜索
          </div>
        ) : (
          <table className="data-table">
            <thead><tr><th style={{ width: 130 }}>Address</th><th style={{ width: 90 }}>Source</th><th>Value</th><th>Context</th><th style={{ width: 60 }}>Inst</th></tr></thead>
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
  const [rows, setRows] = useState<YaraMatch[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigateTo = useTraceStore((s) => s.navigateTo);

  // 对齐后端 yara_mem_scan 可选参数（见 mcp_tools_analysis.cpp register_search_tools）
  const [rulesDir, setRulesDir] = useState('');
  const [minEntropy, setMinEntropy] = useState('0');
  const [scanCode, setScanCode] = useState(false);
  const [minWritesPerPage, setMinWritesPerPage] = useState('1');

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.yara({
        rulesDir: rulesDir.trim() || undefined,
        minEntropy: Number(minEntropy) || 0,
        scanCode,
        minWritesPerPage: Number(minWritesPerPage) || 1,
      });
      setRows(result);
    } catch {
      setError('扫描失败（后端 yara_mem_scan 调用出错，可能未启用 TENET_ENABLE_YARA）');
      setRows(null);
    } finally {
      setBusy(false);
    }
  };

  // 首次挂载即用默认参数跑一次（对齐旧行为：一进面板就有结果），后续可调参重新扫描
  useEffect(() => { void run(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, []);

  return (
    <div className="list-panel">
      <div className="list-toolbar" style={{ flexWrap: 'wrap', rowGap: 6 }}>
        <input
          className="input mono"
          style={{ width: 160 }}
          value={rulesDir}
          onChange={(e) => setRulesDir(e.target.value)}
          placeholder="额外规则目录（可选 .yar）"
        />
        <label className="mem-search-toggle">
          <span>min entropy</span>
          <input
            className="input mono diff-range-input"
            value={minEntropy}
            onChange={(e) => setMinEntropy(e.target.value)}
            style={{ width: 56 }}
          />
        </label>
        <label className="mem-search-toggle">
          <span>min writes/page</span>
          <input
            className="input mono diff-range-input"
            value={minWritesPerPage}
            onChange={(e) => setMinWritesPerPage(e.target.value)}
            style={{ width: 48 }}
          />
        </label>
        <label className="mem-search-toggle">
          <input type="checkbox" checked={scanCode} onChange={(e) => setScanCode(e.target.checked)} />
          <span>扫描代码段</span>
        </label>
        <Button variant="primary" size="sm" onClick={() => void run()} disabled={busy}>
          {busy ? '扫描中…' : '重新扫描'}
        </Button>
        {rows && <span className="list-count" style={{ marginLeft: 'auto' }}>{rows.length} YARA rule matches</span>}
      </div>
      <div className="list-scroll">
        {error ? (
          <div className="empty-state">{error}</div>
        ) : !rows || rows.length === 0 ? (
          <div className="empty-state">{busy ? '扫描中…' : '未发现匹配（内置规则库：AES S-Box / SHA-256 IV / anti-debug 字符串 / DER 证书等）'}</div>
        ) : (
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
        )}
      </div>
    </div>
  );
}
