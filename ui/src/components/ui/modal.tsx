import React, { useEffect, useRef, useCallback } from 'react';

export interface DialogProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  children: React.ReactNode;
}

export const Dialog: React.FC<DialogProps> = ({ open, onOpenChange, children }) => {
  if (!open) {
    return <>{React.Children.toArray(children).filter(
      (child) => React.isValidElement(child) && (child as React.ReactElement<any>).type === DialogTrigger
    )}</>;
  }
  return <>{children}</>;
};

export interface DialogTriggerProps {
  asChild?: boolean;
  children: React.ReactNode;
}

export const DialogTrigger: React.FC<DialogTriggerProps> = ({ children }) => {
  return <>{children}</>;
};

export interface DialogContentProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export const DialogContent = React.forwardRef<HTMLDivElement, DialogContentProps>(
  ({ style, children, ...props }, ref) => {
    const overlayRef = useRef<HTMLDivElement>(null);

    const handleOverlayClick = useCallback((e: React.MouseEvent) => {
      if (e.target === overlayRef.current) {
        const dialog = overlayRef.current?.closest('[data-dialog]');
        if (dialog) {
          const event = new CustomEvent('dialog-close');
          dialog.dispatchEvent(event);
        }
      }
    }, []);

    useEffect(() => {
      const handleEscape = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          const event = new CustomEvent('dialog-close');
          overlayRef.current?.dispatchEvent(event);
        }
      };
      document.addEventListener('keydown', handleEscape);
      return () => document.removeEventListener('keydown', handleEscape);
    }, []);

    return (
      <div
        ref={overlayRef}
        onClick={handleOverlayClick}
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 50,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
        }}
        role="dialog"
        aria-modal="true"
      >
        <div
          ref={ref}
          style={{
            backgroundColor: 'var(--color-bg)',
            borderRadius: 'var(--radius-lg)',
            boxShadow: 'var(--shadow-xl)',
            padding: 'var(--space-6)',
            width: '100%',
            maxWidth: '32rem',
            maxHeight: '85vh',
            overflowY: 'auto',
            margin: 'var(--space-4)',
            ...style,
          }}
          {...props}
        >
          {children}
        </div>
      </div>
    );
  }
);
DialogContent.displayName = 'DialogContent';

export const DialogHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ style, children, ...props }) => (
  <div
    style={{
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--space-2)',
      marginBottom: 'var(--space-4)',
      ...style,
    }}
    {...props}
  >
    {children}
  </div>
);

export const DialogTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ style, children, ...props }) => (
  <h2
    style={{
      fontSize: 'var(--font-size-lg)',
      fontWeight: 'var(--font-weight-semibold)' as any,
      color: 'var(--color-text)',
      margin: 0,
      ...style,
    }}
    {...props}
  >
    {children}
  </h2>
);
