import React from 'react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ style, ...props }, ref) => (
    <input
      ref={ref}
      style={{
        display: 'flex',
        width: '100%',
        height: '40px',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--color-border)',
        backgroundColor: 'var(--color-bg)',
        padding: 'var(--space-2) var(--space-3)',
        fontSize: 'var(--font-size-sm)',
        fontFamily: 'var(--font-family)',
        color: 'var(--color-text)',
        outline: 'none',
        transition: 'border-color var(--transition-fast)',
        boxSizing: 'border-box',
        ...style,
      }}
      {...props}
    />
  )
);
Input.displayName = 'Input';

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {}

export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ style, ...props }, ref) => (
    <textarea
      ref={ref}
      style={{
        display: 'flex',
        width: '100%',
        minHeight: '80px',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--color-border)',
        backgroundColor: 'var(--color-bg)',
        padding: 'var(--space-2) var(--space-3)',
        fontSize: 'var(--font-size-sm)',
        fontFamily: 'var(--font-family)',
        color: 'var(--color-text)',
        outline: 'none',
        resize: 'vertical',
        boxSizing: 'border-box',
        ...style,
      }}
      {...props}
    />
  )
);
Textarea.displayName = 'Textarea';

export interface LabelProps extends React.LabelHTMLAttributes<HTMLLabelElement> {}

export const Label = React.forwardRef<HTMLLabelElement, LabelProps>(
  ({ style, children, ...props }, ref) => (
    <label
      ref={ref}
      style={{
        fontSize: 'var(--font-size-sm)',
        fontWeight: 'var(--font-weight-medium)' as any,
        fontFamily: 'var(--font-family)',
        color: 'var(--color-text)',
        ...style,
      }}
      {...props}
    >
      {children}
    </label>
  )
);
Label.displayName = 'Label';
