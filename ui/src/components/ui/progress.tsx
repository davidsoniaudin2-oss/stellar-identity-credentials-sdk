import React from 'react';

export interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number;
  max?: number;
}

export const Progress = React.forwardRef<HTMLDivElement, ProgressProps>(
  ({ value = 0, max = 100, style, ...props }, ref) => {
    const percentage = Math.min(100, Math.max(0, (value / max) * 100));

    return (
      <div
        ref={ref}
        role="progressbar"
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={max}
        style={{
          height: '8px',
          width: '100%',
          borderRadius: 'var(--radius-full)',
          backgroundColor: 'var(--color-bg-tertiary)',
          overflow: 'hidden',
          ...style,
        }}
        {...props}
      >
        <div
          style={{
            height: '100%',
            width: `${percentage}%`,
            backgroundColor: 'var(--color-primary-600)',
            borderRadius: 'var(--radius-full)',
            transition: 'width var(--transition-slow)',
          }}
        />
      </div>
    );
  }
);
Progress.displayName = 'Progress';
