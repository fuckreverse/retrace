# Tenet Website

`website/` 是 Tenet 的 Astro 静态官网与双语文档站，使用 pnpm 管理依赖，构建产物输出到 `dist/`。

## 常用命令

从 `website/` 目录执行：

```bash
pnpm dev
pnpm test
pnpm build
```

发布前必须依次通过 `pnpm test` 和 `pnpm build`。不要手工修改 `dist/`，它由 Astro 重新生成。

## 目录与配置

- `src/pages/`：官网页面
- `src/content/docs/`：中英文文档内容
- `public/`：原样复制到站点的静态资源
- `astro.config.mjs`：Astro、Starlight、站点 URL 与 sitemap 配置
- `wrangler.toml`：Cloudflare Pages 配置，输出目录为 `dist/`

## Cloudflare Pages 发布

- Pages 项目：`tenet-website`
- 生产分支：`dev-next`
- 生产地址：<https://tenet-website-b24.pages.dev/>

Wrangler 完成 Cloudflare OAuth 登录后，执行：

```bash
pnpm test
pnpm build
npx wrangler pages deploy dist --project-name tenet-website --branch dev-next
```

发布后至少验证首页、`/en/`、`/zh-CN/`、图片资源和 Pagefind 搜索资源。Cloudflare 凭据、Token 和 Cookie 禁止写入仓库。网站使用 Pages 托管；R2 仅用于安装包等对象文件，不用于托管本站。
