/**
 * Hex Dump 面板 —— 以地址为中心的内存 hex 浏览 + 写龄热力，行宽可选 8/16/32 字节。
 */
import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import * as ContextMenu from '@radix-ui/react-context-menu';
import { useTraceStore } from '@/store/traceStore';
import { api } from '@/api/service';
import { copyText } from '@/lib/clipboard';
import type { MemReadResult } from '@/types/tenet';
import { Button, Input } from '@/components/ui';
import './hexdump.css';

const BYTES = 256; // 总字节数固定 256，行宽可调（8/16/32 → 32/16/8 行）

const ROW_LEN_OPTIONS = [8, 16, 32] as const;
type RowLen = (typeof ROW_LEN_OPTIONS)[number];

export function HexDumpPanel() {
  const cur = useTraceStore((s) => s.currentInst);
  const hexAddr = useTraceStore((s) => s.hexAddr);
  const setHexAddr = useTraceStore((s) => s.setHexAddr);
  const [addrInput, setAddrInput] = useState('0x16D000000');
  const [rowLen, setRowLen] = useState<RowLen>(16);
  const [data, setData] = useState<MemReadResult | null>(null);

  const activeAddr = hexAddr ?? addrInput;

  useEffect(() => {
    if (hexAddr) setAddrInput(hexAddr);
  }, [hexAddr]);

  useEffect(() => {
    let cancelled = false;
    let addr = activeAddr;
    try {
      // 对齐到 rowLen（行起始地址），行宽变化时重新对齐
      const b = BigInt(activeAddr) & ~BigInt(rowLen - 1);
      addr = '0x' + b.toString(16).toUpperCase();
    } catch { /* keep */ }
    api.memRead(addr, BYTES, cur).then((r) => {
      if (!cancelled) setData({ ...r, addr });
    });
    return () => { cancelled = true; };
  }, [activeAddr, cur, rowLen]);

  const baseAddr = data ? BigInt(data.addr) : 0n;
  const nRows = BYTES / rowLen;

  const gotoCurrentInst = async () => {
    const dis = await api.disasm(cur, 1);
    const pc = dis.rows[0]?.pc;
    setHexAddr(pc ?? '0x16D000000');
  };

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
        <Button size="sm" onClick={() => setHexAddr(addrInput)}>跳转</Button>
        <Button size="sm" variant="ghost" onClick={() => void gotoCurrentInst()}>
          从当前指令
        </Button>
        {/* 行宽选择：每行字节数，切换后按 rowLen 重新对齐并渲染 */}
        <select
          className="settings-select mono"
          value={rowLen}
          onChange={(e) => setRowLen(Number(e.target.value) as RowLen)}
          title="每行字节数"
          style={{ width: 92 }}
        >
          {ROW_LEN_OPTIONS.map((n) => (
            <option key={n} value={n}>{n} 字节/行</option>
          ))}
        </select>
        <span className="dim hex-known">
          {data ? `${data.known_count}/${data.size} 已知` : ''}
        </span>
      </div>
      <div className="hex-body mono">
        {data &&
          Array.from({ length: nRows }).map((_, row) => {
            const rowAddr = baseAddr + BigInt(row * rowLen);
            return (
              <div className="hex-line" key={row}>
                <span className="hex-off">{('0x' + rowAddr.toString(16).toUpperCase()).slice(0, 12)}</span>
                <span className="hex-bytes">
                  {Array.from({ length: rowLen }).map((_, col) => {
                    const idx = row * rowLen + col;
                    const known = data.known?.[idx] ?? false;
                    const val = data.data?.[idx] ?? 0;
                    const byteAddr = '0x' + (rowAddr + BigInt(col)).toString(16).toUpperCase();
                    return (
                      <ContextMenu.Root key={col}>
                        <ContextMenu.Trigger asChild>
                          <span
                            className={clsx('hex-byte', !known && 'hex-unknown', known && val !== 0 && 'hex-hot')}
                            title={known ? byteAddr : `${byteAddr}（未知：trace 中未被写入或超出快照范围）`}
                            onClick={() => setHexAddr(byteAddr)}
                          >
                            {known ? val.toString(16).padStart(2, '0') : '··'}
                          </span>
                        </ContextMenu.Trigger>
                        <ContextMenu.Portal>
                          <ContextMenu.Content className="ctx-menu">
                            <ContextMenu.Item
                              className="ctx-item"
                              onSelect={() => void copyText(`0x${val.toString(16).padStart(2, '0').toUpperCase()}`, '字节值')}
                            >
复制字节值
</ContextMenu.Item>
                            <ContextMenu.Item
                              className="ctx-item"
                              onSelect={() => void copyText(byteAddr, '地址')}
                            >
复制地址
</ContextMenu.Item>
                            <ContextMenu.Separator className="ctx-sep" />
                            {/* 面板内部跳转：只更新地址，不重复切 tab */}
                            <ContextMenu.Item className="ctx-item" onSelect={() => setHexAddr(byteAddr)}>
在 Hex Dump 跳转到该地址
</ContextMenu.Item>
                          </ContextMenu.Content>
                        </ContextMenu.Portal>
                      </ContextMenu.Root>
                    );
                  })}
                </span>
                <span className="hex-ascii">
                  {Array.from({ length: rowLen }).map((_, col) => {
                    const idx = row * rowLen + col;
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
