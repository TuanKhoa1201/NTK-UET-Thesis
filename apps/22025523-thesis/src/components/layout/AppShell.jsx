import {useEffect, useState} from 'react';
import {NavLink, Outlet, useLocation} from 'react-router-dom';
import {Icon} from '../common/Ui';
import UETLogo from '../common/UETLogo';
import {navGroups} from '../../data/research';

export default function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [backend, setBackend] = useState({status: 'CHECKING', health: null});
  const connected = backend.status === 'CONNECTED';
  const location = useLocation();
  const current = navGroups.flatMap((group) => group.items).find(([path]) => path === location.pathname);

  useEffect(() => {
    const controller = new AbortController();
    let timedOut = false;
    const timeout = window.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 5000);
    const baseUrl = (import.meta.env.VITE_API_BASE_URL || 'https://admin-pc.tail856d55.ts.net').replace(/\/$/, '');

    fetch(`${baseUrl}/api/health`, {signal: controller.signal})
      .then((response) => response.ok ? response.json() : Promise.reject(new Error('Backend không phản hồi')))
      .then((health) => {
        if (!controller.signal.aborted) {
          setBackend(health?.status === 'OK'
            ? {status: 'CONNECTED', health}
            : {status: 'ERROR', health});
        }
      })
      .catch(() => {
        if (!controller.signal.aborted || timedOut) {
          setBackend({status: 'ERROR', health: null});
        }
      })
      .finally(() => window.clearTimeout(timeout));
    return () => {
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, []);

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''}`}>
      <aside className="sidebar">
        <NavLink to="/" className="brand">
          <UETLogo />
          {!collapsed && <span><b>22025523</b><small>SECURITY RESEARCH</small></span>}
        </NavLink>
        <div className="sidebar-nav">
          {navGroups.map((group) => (
            <div className="nav-group" key={group.title}>
              {!collapsed && <div className="nav-group-title">{group.title}</div>}
              {group.items.map(([path, label, icon]) => (
                <NavLink end={path === '/'} to={path} key={path} title={collapsed ? label : undefined} className={({isActive}) => `nav-item ${isActive ? 'active' : ''}`}>
                  <Icon name={icon} /><span>{label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </div>
        <div className="sidebar-bottom">
          <div className="sidebar-status">
            <span className={`status-dot ${connected ? 'online' : ''}`} />
            {!collapsed && <span>{backend.status === 'CHECKING' ? 'Đang kiểm tra backend' : connected ? 'Backend đã kết nối' : 'Backend chưa kết nối'}</span>}
          </div>
          <button className="collapse-button" onClick={() => setCollapsed(!collapsed)}>
            <Icon name={collapsed ? 'PanelLeftOpen' : 'PanelLeftClose'} />
            <span>{!collapsed && 'Thu gọn menu'}</span>
          </button>
        </div>
      </aside>
      <div className="main-area">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>22025523</span><Icon name="ChevronRight" />
            <strong>{current?.[1] || 'Tổng quan'}</strong>
          </div>
          <div className="topbar-actions">
            <span className={`connection-pill ${connected ? 'connected' : ''}`}>
              <i />{backend.status === 'CHECKING' ? 'ĐANG KIỂM TRA API' : connected ? 'KẾT NỐI THỰC' : 'API KHÔNG KHẢ DỤNG'}
            </span>
          </div>
        </header>
        <main className="content-area">
          <Outlet context={{backend}} />
          <footer className="footer">
            <span>22025523 <b>·</b> Nền tảng nghiên cứu phân tích mã nguồn</span>
            <NavLink to="/about">Thông tin đề tài <Icon name="ArrowUpRight" /></NavLink>
          </footer>
        </main>
      </div>
    </div>
  );
}