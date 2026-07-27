import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { readFileSync } from 'node:fs';

// 从 package.json 读取版本号，通过 define 注入为编译时常量 __APP_VERSION__，
// 避免在 WelcomePage 等处硬编码版本号导致与 package.json 失同步。
const pkg = JSON.parse(readFileSync(path.resolve(__dirname, 'package.json'), 'utf-8')) as { version: string };

// Tenet WS server default: 127.0.0.1:9090 (binary FlatBuffers, /ws → /*)。
// 前端已不再使用 MCP HTTP 通道（MCP 现仅供 AI agent），故移除 /mcp 代理。
export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5210,
    proxy: {
      // WebSocket 代理：浏览器 dev 下把 /ws 转发到 TenetWSService。
      // 后端监听 '/*'，故这里 rewrite 去掉 /ws 前缀。
      '/ws': {
        target: 'ws://127.0.0.1:9090',
        ws: true,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/ws/, ''),
      },
    },
  },
});
