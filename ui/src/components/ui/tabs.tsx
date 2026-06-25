import React, { useState } from 'react';

const TabsContext = React.createContext<{
  value: string;
  onValueChange: (value: string) => void;
}>({ value: '', onValueChange: () => {} });

export interface TabsProps extends React.HTMLAttributes<HTMLDivElement> {
  defaultValue?: string;
  value?: string;
  onValueChange?: (value: string) => void;
}

export const Tabs: React.FC<TabsProps> = ({ defaultValue = '', value: controlledValue, onValueChange, children, ...props }) => {
  const [internalValue, setInternalValue] = useState(defaultValue);
  const value = controlledValue ?? internalValue;
  const handleChange = onValueChange ?? setInternalValue;

  return (
    <TabsContext.Provider value={{ value, onValueChange: handleChange }}>
      <div {...props}>{children}</div>
    </TabsContext.Provider>
  );
};

export const TabsList = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ style, children, ...props }, ref) => (
    <div
      ref={ref}
      role="tablist"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        backgroundColor: 'var(--color-bg-tertiary)',
        borderRadius: 'var(--radius-md)',
        padding: 'var(--space-1)',
        gap: 'var(--space-1)',
        ...style,
      }}
      {...props}
    >
      {children}
    </div>
  )
);
TabsList.displayName = 'TabsList';

export interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string;
}

export const TabsTrigger = React.forwardRef<HTMLButtonElement, TabsTriggerProps>(
  ({ value: tabValue, style, children, ...props }, ref) => {
    const { value, onValueChange } = React.useContext(TabsContext);
    const isActive = value === tabValue;

    return (
      <button
        ref={ref}
        role="tab"
        type="button"
        aria-selected={isActive}
        onClick={() => onValueChange(tabValue)}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 'var(--space-2) var(--space-3)',
          borderRadius: 'var(--radius-sm)',
          border: 'none',
          fontSize: 'var(--font-size-sm)',
          fontWeight: 'var(--font-weight-medium)' as any,
          fontFamily: 'var(--font-family)',
          cursor: 'pointer',
          backgroundColor: isActive ? 'var(--color-bg)' : 'transparent',
          color: isActive ? 'var(--color-text)' : 'var(--color-text-secondary)',
          boxShadow: isActive ? 'var(--shadow-sm)' : 'none',
          transition: 'all var(--transition-fast)',
          ...style,
        }}
        {...props}
      >
        {children}
      </button>
    );
  }
);
TabsTrigger.displayName = 'TabsTrigger';

export interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
}

export const TabsContent = React.forwardRef<HTMLDivElement, TabsContentProps>(
  ({ value: tabValue, style, children, ...props }, ref) => {
    const { value } = React.useContext(TabsContext);
    if (value !== tabValue) return null;

    return (
      <div
        ref={ref}
        role="tabpanel"
        style={{
          marginTop: 'var(--space-4)',
          ...style,
        }}
        {...props}
      >
        {children}
      </div>
    );
  }
);
TabsContent.displayName = 'TabsContent';
