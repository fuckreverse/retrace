/**
 * Hex Dump 面板 —— 以地址为中心的内存 16x16 hex 浏览 + 写龄热力。
 */
import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import type { MemReadResult } from '@/types/tenet';
import { Button, Input } from '@/components/ui';
import './hexdump.css';

const BYTES = 256; // 16 x 16

export function HexDumpPanel() {
  const cur = useTraceStore((s) => s.currentInst);
  const hexAddr = useTraceStore((s) => s.hexAddr);
  const setHexAddr = useTraceStore((s) => s.setHexAddr);
  const [addrInput, setAddrInput] = useState('0x16D000000');
  const [data, setData] = useState<MemReadResult | null>(null);

  const activeAddr = hexAddr ?? addrInput;

  useEffect(() => {
    if (hexAddr) setAddrInput(hexAddr);
  }, [hexAddr]);

  useEffect(() => {
    let cancelled = false;
    let addr = activeAddr;
    try {
      // 对齐到 16
      const b = BigInt(activeAddr) & ~0xfn;
      addr = '0x' + b.toString(16).toUpperCase();
    } catch { /* keep */ }
    api.memRead(addr, BYTES, cur).then((r) => {
      if (!cancelled) setData({ ...r, addr });
    });
    return () => { cancelled = true; };
  }, [activeAddr, cur]);

  const baseAddr = data ? BigInt(data.addr) : 0n;

  return (
    <div className="hex-panel">
      <div className="hex-toolbar">
        <Input
          value={addrInput}
          onChange={(e) => setAddrInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setHexAddr(addrInput)}
          className="mono"
          style={{ width: 160 }}
        />
        <Button size="sm" onClick={() => setHexAddr(addrInput)}>Go</Button>
        <Button size="sm" variant="ghost" onClick={() => { setHexAddr(null); setAddrInput('0x16D000000'); }}>
          From Inst
        </Button>
        <span className="dim hex-known">
          {data ? `${data.known_count}/${data.size} known` : ''}
        </span>
      </div>
      <div className="hex-body mono">
        {data &&
          Array.from({ length: 16 }).map((_, row) => {
            const rowAddr = baseAddr + BigInt(row * 16);
            return (
              <div className="hex-line" key={row}>
                <span className="hex-off">{('0x' + rowAddr.toString(16).toUpperCase()).slice(0, 12)}</span>
                <span className="hex-bytes">
                  {Array.from({ length: 16 }).map((_, col) => {
                    const idx = row * 16 + col;
                    const known = data.known?.[idx] ?? false;
                    const val = data.data?.[idx] ?? 0;
                    return (
                      <span
                        key={col}
                        className={clsx('hex-byte', !known && 'hex-unknown', known && val !== 0 && 'hex-hot')}
                      >
                        {known ? val.toString(16).padStart(2, '0') : '··'}
                      </span>
                    );
                  })}
                </span>
                <span className="hex-ascii">
                  {Array.from({ length: 16 }).map((_, col) => {
                    const idx = row * 16 + col;
                    const known = data.known?.[idx] ?? false;
                    const val = data.data?.[idx] ?? 0;
                    const ch = known && val >= 32 && val < 127 ? String.fromCharCode(val) : '.';
                    return <span key={col} className={clsx(!known && 'hex-unknown')}>{ch}</span>;
                  })}
                </span>
              </div>
            );
          })}
      </div>
    </div>
  );
}
