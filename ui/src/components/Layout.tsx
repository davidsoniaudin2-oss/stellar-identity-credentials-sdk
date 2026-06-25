import React, { useState } from 'react';

export interface NavItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
}

export interface LayoutProps {
  navItems?: NavItem[];
  activeItem?: string;
  onNavChange?: (id: string) => void;
  header?: React.ReactNode;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  navItems = [],
  activeItem,
  onNavChange,
  header,
  children,
}) => {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div style={{
      display: 'flex',
      minHeight: '100vh',
      fontFamily: 'var(--font-family)',
      backgroundColor: 'var(--color-bg-secondary)',
      color: 'var(--color-text)',
    }}>
      {/* Sidebar */}
      <aside style={{
        width: sidebarOpen ? 'var(--sidebar-width)' : 'var(--sidebar-width-collapsed)',
        backgroundColor: 'var(--color-bg)',
        borderRight: '1px solid var(--color-border)',
        display: 'flex',
        flexDirection: 'column',
        transition: 'width var(--transition-slow)',
        flexShrink: 0,
        position: 'fixed',
        top: 0,
        left: 0,
        bottom: 0,
        zIndex: 40,
      }}>
        {/* Sidebar Header */}
        <div style={{
          height: 'var(--header-height)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 var(--space-4)',
          borderBottom: '1px solid var(--color-border)',
        }}>
          {sidebarOpen && (
            <span style={{
              fontSize: 'var(--font-size-lg)',
              fontWeight: 'var(--font-weight-bold)' as any,
              color: 'var(--color-primary-600)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
            }}>
              Stellar ID
            </span>
          )}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              padding: 'var(--space-2)',
              color: 'var(--color-text-secondary)',
              fontSize: 'var(--font-size-lg)',
            }}
          >
            {sidebarOpen ? '←' : '→'}
          </button>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, padding: 'var(--space-2)', overflowY: 'auto' }}>
          {navItems.map((item) => {
            const isActive = activeItem === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavChange?.(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-3)',
                  width: '100%',
                  padding: 'var(--space-3) var(--space-3)',
                  borderRadius: 'var(--radius-md)',
                  border: 'none',
                  backgroundColor: isActive ? 'var(--color-primary-50)' : 'transparent',
                  color: isActive ? 'var(--color-primary-700)' : 'var(--color-text-secondary)',
                  fontWeight: isActive ? 'var(--font-weight-medium)' as any : 'var(--font-weight-normal)' as any,
                  fontSize: 'var(--font-size-sm)',
                  fontFamily: 'var(--font-family)',
                  cursor: 'pointer',
                  marginBottom: 'var(--space-1)',
                  textAlign: 'left',
                  transition: 'all var(--transition-fast)',
                }}
              >
                {item.icon && <span style={{ flexShrink: 0 }}>{item.icon}</span>}
                {sidebarOpen && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>
      </aside>

      {/* Main Content */}
      <div style={{
        flex: 1,
        marginLeft: sidebarOpen ? 'var(--sidebar-width)' : 'var(--sidebar-width-collapsed)',
        transition: 'margin-left var(--transition-slow)',
        display: 'flex',
        flexDirection: 'column',
        minWidth: 0,
      }}>
        {/* Header */}
        {header && (
          <header style={{
            height: 'var(--header-height)',
            backgroundColor: 'var(--color-bg)',
            borderBottom: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            padding: '0 var(--space-6)',
            position: 'sticky',
            top: 0,
            zIndex: 30,
          }}>
            {header}
          </header>
        )}

        {/* Page Content */}
        <main style={{
          flex: 1,
          padding: 'var(--space-6)',
          maxWidth: 'var(--content-max-width)',
          width: '100%',
          margin: '0 auto',
          boxSizing: 'border-box',
        }}>
          {children}
        </main>
      </div>

      {/* Mobile sidebar overlay */}
      <style>{`
        @media (max-width: 768px) {
          aside {
            transform: ${sidebarOpen ? 'translateX(0)' : 'translateX(-100%)'} !important;
            width: var(--sidebar-width) !important;
          }
          div[style*="margin-left"] {
            margin-left: 0 !important;
          }
        }
        @media (min-width: 769px) and (max-width: 1024px) {
          aside {
            width: var(--sidebar-width-collapsed) !important;
          }
          div[style*="margin-left"] {
            margin-left: var(--sidebar-width-collapsed) !important;
          }
        }
      `}</style>
    </div>
  );
};
