import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './store/themeStore'; // 提前初始化主题(设置 <html data-theme>)
import './styles/global.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
