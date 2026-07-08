/**
 * Pass 预设选择对话框 — 首次打开 trace 文件时弹出，
 * 让用户选择分析深度(Minimal/Standard/Full/Custom)。
 */
import { useCallback } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { clsx } from 'clsx';
import {
  useAppStore,
  PASS_CATALOG,
  PASS_CATEGORIES,
  type PassPreset,
} from '@/store/appStore';
import './pass-preset.css';

/* ------------------------------------------------------------------ */
/*  Preset definitions                                                 */
/* ------------------------------------------------------------------ */

interface PresetDef {
  key: PassPreset;
  label: string;
  labelCN: string;
  desc: string;
}

const PRESETS: PresetDef[] = [
  {
    key: 'minimal',
    label: 'Minimal',
    labelCN: '\u6700\u5c11',
    desc: 'xref + cfg only \u2014 fastest startup, basic navigation',
  },
  {
    key: 'standard',
    label: 'Standard',
    labelCN: '\u5e38\u7528',
    desc: 'Functions, CFG, patterns, strings, loops \u2014 the default analysis set',
  },
  {
    key: 'full',
    label: 'Full',
    labelCN: '\u5b8c\u6574',
    desc: 'Every analysis pass including taint, ObjC, profiling, etc.',
  },
  {
    key: 'custom',
    label: 'Custom',
    labelCN: '\u81ea\u5b9a\u4e49',
    desc: 'Pick individual passes from the catalog',
  },
];

/* ------------------------------------------------------------------ */
/*  Check icon (inline SVG)                                            */
/* ------------------------------------------------------------------ */

function CheckIcon() {
  return (
    <svg className="pp-check-icon" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 5.5l2 2 4-4.5" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export function PassPresetDialog() {
  const open = useAppStore((s) => s.showPassPresetDialog);
  const preset = useAppStore((s) => s.passPreset);
  const customPasses = useAppStore((s) => s.customPasses);
  const setPreset = useAppStore((s) => s.setPassPreset);
  const setCustom = useAppStore((s) => s.setCustomPasses);
  const cancel = useAppStore((s) => s.cancelOpen);
  const confirmAndOpen = useAppStore((s) => s.confirmAndOpen);

  const togglePass = useCallback(
    (name: string) => {
      const next = customPasses.includes(name)
        ? customPasses.filter((p) => p !== name)
        : [...customPasses, name];
      setCustom(next);
    },
    [customPasses, setCustom],
  );

  const passesByCategory = PASS_CATEGORIES.map((cat) => ({
    category: cat,
    passes: PASS_CATALOG.filter((p) => p.category === cat),
  }));

  return (
    <Dialog.Root open={open} onOpenChange={(v) => { if (!v) cancel(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="pp-overlay" />
        <Dialog.Content className="pp-dialog" aria-describedby={undefined}>
          {/* Header */}
          <div className="pp-header">
            <Dialog.Title className="pp-title">Choose Analysis Passes</Dialog.Title>
            <Dialog.Close className="pp-close" aria-label="Close">
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
                <path d="M1 1l12 12M13 1L1 13" />
              </svg>
            </Dialog.Close>
          </div>

          {/* Body */}
          <div className="pp-body">
            {PRESETS.map((p) => (
              <div key={p.key}>
                <button
                  className={clsx('pp-option', preset === p.key && 'selected')}
                  onClick={() => setPreset(p.key)}
                  type="button"
                >
                  <span className="pp-radio">
                    <span className="pp-radio-dot" />
                  </span>
                  <span className="pp-option-text">
                    <span className="pp-option-label">
                      {p.label} ({p.labelCN})
                    </span>
                    <span className="pp-option-desc">{p.desc}</span>
                  </span>
                </button>

                {/* Custom checklist — shown only when custom is selected */}
                {p.key === 'custom' && preset === 'custom' && (
                  <div className="pp-custom-section">
                    {passesByCategory.map((group) => (
                      <div key={group.category}>
                        <div className="pp-category-title">{group.category}</div>
                        <div className="pp-category-passes">
                          {group.passes.map((pass) => {
                            const checked = customPasses.includes(pass.name);
                            return (
                              <button
                                key={pass.name}
                                className={clsx('pp-pass', checked && 'checked')}
                                onClick={() => togglePass(pass.name)}
                                type="button"
                              >
                                <span className="pp-checkbox">
                                  <CheckIcon />
                                </span>
                                {pass.display}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Footer */}
          <div className="pp-footer">
            <button className="pp-btn-cancel" onClick={cancel} type="button">
              Cancel
            </button>
            <button className="pp-btn-start" onClick={confirmAndOpen} type="button">
              Start Analysis
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
