/**
 * Analysis 控制台 —— 按类别分组的 pass 列表 + 运行控制。
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

  useEffect(() => {
    api.passes().then(setPasses);
  }, []);

  const grouped = useMemo(() => {
    const m = new Map<string, PassInfo[]>();
    for (const p of passes) {
      if (!m.has(p.category)) m.set(p.category, []);
      m.get(p.category)!.push(p);
    }
    return m;
  }, [passes]);

  const running = passes.some((p) => p.state === 'running');

  const runPass = (name: string) => {
    setPasses((prev) => prev.map((p) => (p.name === name ? { ...p, state: 'running', progress: 0 } : p)));
    // 模拟进度
    let prog = 0;
    const timer = setInterval(() => {
      prog += 0.15 + Math.random() * 0.2;
      if (prog >= 1) {
        clearInterval(timer);
        setPasses((prev) => prev.map((p) => (p.name === name ? { ...p, state: 'completed', progress: 1, summary: p.summary ?? 'done' } : p)));
      } else {
        setPasses((prev) => prev.map((p) => (p.name === name ? { ...p, progress: prog } : p)));
      }
    }, 200);
  };

  return (
    <div className="analysis-panel">
      <div className={clsx('analysis-banner', running && 'running')}>
        {running ? (
          <>
            <div className="mini-spinner" />
            <span>分析进行中…</span>
            <Button size="sm" variant="danger" style={{ marginLeft: 'auto' }}>Stop All</Button>
          </>
        ) : (
          <>
            <Icon.Dot style={{ color: 'var(--success)', width: 14 }} />
            <span>就绪 · {passes.filter((p) => p.state === 'completed').length}/{passes.length} 已完成</span>
            <Button size="sm" variant="ghost" style={{ marginLeft: 'auto' }}>Clear All</Button>
          </>
        )}
      </div>

      <div className="analysis-scroll">
        {CATEGORY_ORDER.filter((c) => grouped.has(c)).map((cat) => (
          <div key={cat} className="pass-group">
            <div className="pass-group-title">{cat}</div>
            {grouped.get(cat)!.map((p) => (
              <div key={p.name} className={clsx('pass-row', `state-${p.state}`)}>
                <span className={clsx('pass-icon', `pi-${p.state}`)}>{STATE_ICON[p.state]}</span>
                <div className="pass-main">
                  <div className="pass-name">{p.display_name}</div>
                  {p.state === 'running' ? (
                    <div className="pass-progress">
                      <div className="pass-progress-fill" style={{ width: `${(p.progress ?? 0) * 100}%` }} />
                    </div>
                  ) : (
                    <div className="pass-summary dim">{p.summary ?? (p.state === 'not_run' ? '未运行' : '')}</div>
                  )}
                </div>
                <div className="pass-ctrl">
                  {p.state === 'not_run' && <button className="pass-btn" onClick={() => runPass(p.name)}><Icon.Play /></button>}
                  {p.state === 'completed' && <button className="pass-btn" onClick={() => runPass(p.name)}><Icon.Refresh /></button>}
                  {p.state === 'failed' && <button className="pass-btn" onClick={() => runPass(p.name)}><Icon.Play /></button>}
                  {p.state === 'running' && <span className="dim mono">{((p.progress ?? 0) * 100).toFixed(0)}%</span>}
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
