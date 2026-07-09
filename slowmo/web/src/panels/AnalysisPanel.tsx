/**
 * Analysis 控制台 —— 按类别分组的 pass 列表 + 运行控制。
 *
 * 真实驱动：Run/Rerun 调用 api.runPass(name) → 后端 RunPassReq（在事件循环上
 * 同步执行，响应返回时 pass 已完成或失败），完成后重新拉取 api.passes()
 * 刷新真实状态与摘要。没有本地伪造的进度条——运行期间只显示"运行中"占位，
 * 因为协议是阻塞式的，没有中途进度事件可订阅。
 */
import { useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { api } from '@/api/service';
import type { PassInfo, PassState } from '@/types/tenet';
import { Button } from '@/components/ui';
import { Icon } from '@/components/icons';
import './analysis.css';

const CATEGORY_ORDER = [
  'Structure', 'Taint', 'Crypto-Pattern', 'Memory-String',
  'ObjC-Platform', 'Profile-Trace', 'Misc',
];

const STATE_ICON: Record<PassState, string> = {
  not_run: '·',
  running: '▶',
  completed: '✓',
  failed: '✕',
};

export function AnalysisPanel() {
  const [passes, setPasses] = useState<PassInfo[]>([]);
  const [inFlight, setInFlight] = useState<Set<string>>(new Set());

  const refresh = () => { api.passes().then(setPasses); };
  useEffect(() => { refresh(); }, []);

  const grouped = useMemo(() => {
    const m = new Map<string, PassInfo[]>();
    for (const p of passes) {
      if (!m.has(p.category)) m.set(p.category, []);
      m.get(p.category)!.push(p);
    }
    return m;
  }, [passes]);

  const running = inFlight.size > 0;

  const runPass = async (name: string) => {
    setInFlight((prev) => new Set(prev).add(name));
    setPasses((prev) => prev.map((p) => (p.name === name ? { ...p, state: 'running' } : p)));
    try {
      const res = await api.runPass(name);
      setPasses((prev) => prev.map((p) => (p.name === name
        ? { ...p, state: res.ok ? 'completed' : 'failed', summary: res.ok ? undefined : res.message }
        : p)));
    } finally {
      setInFlight((prev) => {
        const next = new Set(prev);
        next.delete(name);
        return next;
      });
      // 拉取真实摘要（GetPassCatalog 目前不带 summary，交由 wsRunAnalysis 类
      // 面板各自展示；这里至少刷新最新 state）。
      refresh();
    }
  };

  const stopAll = () => {
    // 协议是同步阻塞式的，没有取消语义；此处仅清空本地"运行中"标记。
    setInFlight(new Set());
  };

  const clearAll = () => {
    void api.clearAnalysis();
    refresh();
  };

  return (
    <div className="analysis-panel">
      <div className={clsx('analysis-banner', running && 'running')}>
        {running ? (
          <>
            <div className="mini-spinner" />
            <span>分析进行中… ({inFlight.size})</span>
            <Button size="sm" variant="danger" style={{ marginLeft: 'auto' }} onClick={stopAll}>Stop All</Button>
          </>
        ) : (
          <>
            <Icon.Dot style={{ color: 'var(--success)', width: 14 }} />
            <span>就绪 · {passes.filter((p) => p.state === 'completed').length}/{passes.length} 已完成</span>
            <Button size="sm" variant="ghost" style={{ marginLeft: 'auto' }} onClick={clearAll}>Clear All</Button>
          </>
        )}
      </div>

      <div className="analysis-scroll">
        {CATEGORY_ORDER.filter((c) => grouped.has(c)).map((cat) => (
          <div key={cat} className="pass-group">
            <div className="pass-group-title">{cat}</div>
            {grouped.get(cat)!.map((p) => {
              const busy = inFlight.has(p.name);
              return (
                <div key={p.name} className={clsx('pass-row', `state-${p.state}`)}>
                  <span className={clsx('pass-icon', `pi-${p.state}`)}>{STATE_ICON[p.state]}</span>
                  <div className="pass-main">
                    <div className="pass-name">{p.display_name}</div>
                    {busy ? (
                      <div className="pass-progress">
                        <div className="pass-progress-fill pass-progress-indeterminate" />
                      </div>
                    ) : (
                      <div className="pass-summary dim">{p.summary ?? (p.state === 'not_run' ? '未运行' : p.state === 'failed' ? '运行失败' : '')}</div>
                    )}
                  </div>
                  <div className="pass-ctrl">
                    {!busy && p.state === 'not_run' && <button className="pass-btn" onClick={() => runPass(p.name)}><Icon.Play /></button>}
                    {!busy && p.state === 'completed' && <button className="pass-btn" onClick={() => runPass(p.name)}><Icon.Refresh /></button>}
                    {!busy && p.state === 'failed' && <button className="pass-btn" onClick={() => runPass(p.name)}><Icon.Play /></button>}
                    {busy && <span className="dim mono">运行中…</span>}
                  </div>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}
