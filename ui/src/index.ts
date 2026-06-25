// Design System Base Components
export { Button } from './components/ui/button';
export type { ButtonProps } from './components/ui/button';

export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from './components/ui/card';
export type { CardProps } from './components/ui/card';

export { Badge } from './components/ui/badge';
export type { BadgeProps } from './components/ui/badge';

export { Input, Textarea, Label } from './components/ui/input';
export type { InputProps, TextareaProps, LabelProps } from './components/ui/input';

export { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from './components/ui/select';
export type { SelectProps, SelectItemProps } from './components/ui/select';

export { Dialog, DialogTrigger, DialogContent, DialogHeader, DialogTitle } from './components/ui/modal';
export type { DialogProps } from './components/ui/modal';

export { Alert, AlertDescription } from './components/ui/alert';
export type { AlertProps } from './components/ui/alert';

export { Progress } from './components/ui/progress';
export type { ProgressProps } from './components/ui/progress';

export { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
export type { TabsProps, TabsTriggerProps, TabsContentProps } from './components/ui/tabs';

// Layout
export { Layout } from './components/Layout';
export type { LayoutProps, NavItem } from './components/Layout';

// Feature Components
export { DIDManager, ConnectedDIDManager } from './components/DIDManager';
export { CredentialWallet } from './components/CredentialWallet';
export { ReputationBadge } from './components/ReputationBadge';
export { ProofRequest } from './components/ProofRequest';
export { ComplianceCheck } from './components/ComplianceCheck';

// Hooks
export {
  useStellarIdentity,
  useDID,
  useCredentials,
  useReputation,
  useCompliance,
} from './hooks/useStellarIdentity';
