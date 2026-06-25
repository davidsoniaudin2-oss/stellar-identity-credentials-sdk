import React from 'react';

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'destructive';
}

export const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
  ({ variant = 'default', style, children, ...props }, ref) => {
    const borderColor = variant === 'destructive'
      ? 'var(--color-danger-500)'
      : 'var(--color-border)';
    const bgColor = variant === 'destructive'
      ? 'var(--color-danger-50)'
      : 'var(--color-bg-secondary)';

    return (
      <div
        ref={ref}
        role="alert"
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 'var(--space-3)',
          borderRadius: 'var(--radius-lg)',
          border: `1px solid ${borderColor}`,
          backgroundColor: bgColor,
          padding: 'var(--space-4)',
          fontSize: 'var(--font-size-sm)',
          fontFamily: 'var(--font-family)',
          ...style,
        }}
        {...props}
      >
        {children}
      </div>
    );
  }
);
Alert.displayName = 'Alert';

export const AlertDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
  ({ style, children, ...props }, ref) => (
    <p
      ref={ref}
      style={{
        fontSize: 'var(--font-size-sm)',
        color: 'var(--color-text-secondary)',
        margin: 0,
        lineHeight: 'var(--line-height-normal)',
        ...style,
      }}
      {...props}
    >
      {children}
    </p>
  )
);
AlertDescription.displayName = 'AlertDescription';
