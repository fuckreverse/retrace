import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// Tenet WS server default: 127.0.0.1:9090 (binary FlatBuffers, /ws → /*)。
// 前端已不再使用 MCP HTTP 通道（MCP 现仅供 AI agent），故移除 /mcp 代理。
export default defineConfig({
  plugins: [react()],
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
