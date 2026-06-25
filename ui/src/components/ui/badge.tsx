import React from 'react';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'secondary' | 'destructive' | 'outline';
}

const variantStyles: Record<string, React.CSSProperties> = {
  default: {
    backgroundColor: 'var(--color-primary-600)',
    color: '#ffffff',
    border: '1px solid transparent',
  },
  secondary: {
    backgroundColor: 'var(--color-bg-tertiary)',
    color: 'var(--color-text-secondary)',
    border: '1px solid transparent',
  },
  destructive: {
    backgroundColor: 'var(--color-danger-600)',
    color: '#ffffff',
    border: '1px solid transparent',
  },
  outline: {
    backgroundColor: 'transparent',
    color: 'var(--color-text)',
    border: '1px solid var(--color-border)',
  },
};

export const Badge = React.forwardRef<HTMLSpanElement, BadgeProps>(
  ({ variant = 'default', style, children, ...props }, ref) => (
    <span
      ref={ref}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        borderRadius: 'var(--radius-full)',
        padding: '2px var(--space-3)',
        fontSize: 'var(--font-size-xs)',
        fontWeight: 'var(--font-weight-medium)' as any,
        fontFamily: 'var(--font-family)',
        lineHeight: 'var(--line-height-normal)',
        whiteSpace: 'nowrap',
        ...variantStyles[variant],
        ...style,
      }}
      {...props}
    >
      {children}
    </span>
  )
);
Badge.displayName = 'Badge';
