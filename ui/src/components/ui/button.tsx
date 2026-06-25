import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  asChild?: boolean;
}

const variantStyles: Record<string, React.CSSProperties> = {
  default: {
    backgroundColor: 'var(--color-primary-600)',
    color: '#ffffff',
    border: 'none',
  },
  destructive: {
    backgroundColor: 'var(--color-danger-600)',
    color: '#ffffff',
    border: 'none',
  },
  outline: {
    backgroundColor: 'transparent',
    color: 'var(--color-text)',
    border: '1px solid var(--color-border)',
  },
  secondary: {
    backgroundColor: 'var(--color-bg-tertiary)',
    color: 'var(--color-text)',
    border: 'none',
  },
  ghost: {
    backgroundColor: 'transparent',
    color: 'var(--color-text)',
    border: 'none',
  },
  link: {
    backgroundColor: 'transparent',
    color: 'var(--color-primary-600)',
    border: 'none',
    textDecoration: 'underline',
  },
};

const sizeStyles: Record<string, React.CSSProperties> = {
  default: { padding: 'var(--space-2) var(--space-4)', fontSize: 'var(--font-size-sm)', height: '40px' },
  sm: { padding: 'var(--space-1) var(--space-3)', fontSize: 'var(--font-size-xs)', height: '32px' },
  lg: { padding: 'var(--space-3) var(--space-8)', fontSize: 'var(--font-size-base)', height: '48px' },
  icon: { padding: 'var(--space-2)', width: '40px', height: '40px' },
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'default', size = 'default', style, className, disabled, children, ...props }, ref) => {
    const baseStyle: React.CSSProperties = {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 'var(--space-2)',
      borderRadius: 'var(--radius-md)',
      fontFamily: 'var(--font-family)',
      fontWeight: 'var(--font-weight-medium)' as any,
      cursor: disabled ? 'not-allowed' : 'pointer',
      opacity: disabled ? 0.5 : 1,
      transition: 'background-color var(--transition-fast), opacity var(--transition-fast)',
      whiteSpace: 'nowrap',
      ...variantStyles[variant],
      ...sizeStyles[size],
      ...style,
    };

    return (
      <button
        ref={ref}
        className={className}
        style={baseStyle}
        disabled={disabled}
        {...props}
      >
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';
