import React, { useState, useEffect } from 'react';
import { 
  Card, 
  CardHeader, 
  CardTitle, 
  CardContent 
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogTrigger 
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DIDClient } from '@stellar-identity/sdk';
import { VerificationMethod, Service, DIDDocument, StellarIdentityConfig } from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import { Copy, Plus, Trash2, Edit, CheckCircle, AlertCircle } from 'lucide-react';
import { useStellarIdentity } from '../hooks/useStellarIdentity';

interface DIDManagerProps {
  sdk: any;
  address: string;
  keypair: Keypair;
}

export const DIDManager: React.FC<DIDManagerProps> = ({ sdk, address, keypair }) => {
  const [didDocument, setDidDocument] = useState<DIDDocument | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  // Form states
  const [verificationMethods, setVerificationMethods] = useState<VerificationMethod[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [newVerificationMethod, setNewVerificationMethod] = useState<VerificationMethod>({
    id: '',
    type: 'Ed25519VerificationKey2018',
    controller: address,
    publicKey: ''
  });
  const [newService, setNewService] = useState<Service>({
    id: '',
    type: '',
    endpoint: ''
  });

  useEffect(() => {
    loadDIDDocument();
  }, [address]);

  const loadDIDDocument = async () => {
    try {
      setLoading(true);
      const did = sdk.did.generateDID(address);
      const result = await sdk.did.resolveDID(did);
      setDidDocument(result.didDocument);
      setVerificationMethods(result.didDocument.verificationMethod);
      setServices(result.didDocument.service);
    } catch (error) {
      // DID might not exist yet
      setDidDocument(null);
    } finally {
      setLoading(false);
    }
  };

  const createDID = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const did = await sdk.did.createDID(keypair, {
        verificationMethods,
        services
      });
      
      setSuccess(`DID created successfully: ${did}`);
      setShowCreateDialog(false);
      await loadDIDDocument();
    } catch (error: any) {
      setError(error.message || 'Failed to create DID');
    } finally {
      setLoading(false);
    }
  };

  const updateDID = async () => {
    try {
      setLoading(true);
      setError(null);
      
      await sdk.did.updateDID(keypair, verificationMethods, services);
      setSuccess('DID updated successfully');
      await loadDIDDocument();
    } catch (error: any) {
      setError(error.message || 'Failed to update DID');
    } finally {
      setLoading(false);
    }
  };

  const deactivateDID = async () => {
    if (!confirm('Are you sure you want to deactivate this DID? This action cannot be undone.')) {
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      await sdk.did.deactivateDID(keypair);
      setSuccess('DID deactivated successfully');
      setDidDocument(null);
    } catch (error: any) {
      setError(error.message || 'Failed to deactivate DID');
    } finally {
      setLoading(false);
    }
  };

  const addVerificationMethod = () => {
    if (!newVerificationMethod.id || !newVerificationMethod.publicKey) {
      setError('Please fill in all verification method fields');
      return;
    }
    setVerificationMethods([...verificationMethods, { ...newVerificationMethod }]);
    setNewVerificationMethod({
      id: '',
      type: 'Ed25519VerificationKey2018',
      controller: address,
      publicKey: ''
    });
  };

  const removeVerificationMethod = (index: number) => {
    setVerificationMethods(verificationMethods.filter((_, i) => i !== index));
  };

  const addService = () => {
    if (!newService.id || !newService.type || !newService.endpoint) {
      setError('Please fill in all service fields');
      return;
    }
    setServices([...services, { ...newService }]);
    setNewService({ id: '', type: '', endpoint: '' });
  };

  const removeService = (index: number) => {
    setServices(services.filter((_, i) => i !== index));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccess('Copied to clipboard!');
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2">Loading DID information...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      
      {success && (
        <Alert variant="default" className="bg-green-50 border-green-200">
          <CheckCircle className="h-4 w-4 text-green-600" />
          <AlertDescription className="text-green-800">{success}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <CardTitle>Decentralized Identity (DID)</CardTitle>
            <div className="space-x-2">
              {!didDocument ? (
                <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
                  <DialogTrigger asChild>
                    <Button>
                      <Plus className="h-4 w-4 mr-2" />
                      Create DID
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                    <DialogHeader>
                      <DialogTitle>Create New DID</DialogTitle>
                    </DialogHeader>
                    <CreateDIDForm
                      verificationMethods={verificationMethods}
                      services={services}
                      newVerificationMethod={newVerificationMethod}
                      newService={newService}
                      onVerificationMethodChange={setNewVerificationMethod}
                      onServiceChange={setNewService}
                      onAddVerificationMethod={addVerificationMethod}
                      onRemoveVerificationMethod={removeVerificationMethod}
                      onAddService={addService}
                      onRemoveService={removeService}
                      onCreate={createDID}
                      loading={loading}
                    />
                  </DialogContent>
                </Dialog>
              ) : (
                <div className="space-x-2">
                  <Button variant="outline" onClick={updateDID}>
                    <Edit className="h-4 w-4 mr-2" />
                    Update
                  </Button>
                  <Button variant="destructive" onClick={deactivateDID}>
                    <Trash2 className="h-4 w-4 mr-2" />
                    Deactivate
                  </Button>
                </div>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {didDocument ? (
            <DIDDocumentDisplay 
              didDocument={didDocument} 
              onCopy={copyToClipboard}
            />
          ) : (
            <div className="text-center py-8 text-gray-500">
              <AlertCircle className="h-12 w-12 mx-auto mb-4 text-gray-400" />
              <p>No DID found for this address</p>
              <p className="text-sm">Create a DID to start managing your decentralized identity</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

interface CreateDIDFormProps {
  verificationMethods: VerificationMethod[];
  services: Service[];
  newVerificationMethod: VerificationMethod;
  newService: Service;
  onVerificationMethodChange: (method: VerificationMethod) => void;
  onServiceChange: (service: Service) => void;
  onAddVerificationMethod: () => void;
  onRemoveVerificationMethod: (index: number) => void;
  onAddService: () => void;
  onRemoveService: (index: number) => void;
  onCreate: () => void;
  loading: boolean;
}

const CreateDIDForm: React.FC<CreateDIDFormProps> = ({
  verificationMethods,
  services,
  newVerificationMethod,
  newService,
  onVerificationMethodChange,
  onServiceChange,
  onAddVerificationMethod,
  onRemoveVerificationMethod,
  onAddService,
  onRemoveService,
  onCreate,
  loading
}) => {
  return (
    <Tabs defaultValue="verification" className="w-full">
      <TabsList className="grid w-full grid-cols-2">
        <TabsTrigger value="verification">Verification Methods</TabsTrigger>
        <TabsTrigger value="services">Services</TabsTrigger>
      </TabsList>
      
      <TabsContent value="verification" className="space-y-4">
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Verification Methods</h3>
          
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="vm-id">ID</Label>
              <Input
                id="vm-id"
                value={newVerificationMethod.id}
                onChange={(e) => onVerificationMethodChange({
                  ...newVerificationMethod,
                  id: e.target.value
                })}
                placeholder="e.g., #key-1"
              />
            </div>
            <div>
              <Label htmlFor="vm-publicKey">Public Key</Label>
              <Input
                id="vm-publicKey"
                value={newVerificationMethod.publicKey}
                onChange={(e) => onVerificationMethodChange({
                  ...newVerificationMethod,
                  publicKey: e.target.value
                })}
                placeholder="Stellar public key"
              />
            </div>
          </div>
          
          <Button onClick={onAddVerificationMethod} className="w-full">
            <Plus className="h-4 w-4 mr-2" />
            Add Verification Method
          </Button>
          
          {verificationMethods.length > 0 && (
            <div className="space-y-2">
              <h4 className="font-medium">Current Methods:</h4>
              {verificationMethods.map((method, index) => (
                <div key={index} className="flex items-center justify-between p-3 border rounded">
                  <div>
                    <p className="font-medium">{method.id}</p>
                    <p className="text-sm text-gray-600">{method.type}</p>
                  </div>
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => onRemoveVerificationMethod(index)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </TabsContent>
      
      <TabsContent value="services" className="space-y-4">
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Services</h3>
          
          <div className="grid grid-cols-3 gap-4">
            <div>
              <Label htmlFor="service-id">ID</Label>
              <Input
                id="service-id"
                value={newService.id}
                onChange={(e) => onServiceChange({
                  ...newService,
                  id: e.target.value
                })}
                placeholder="e.g., #hub"
              />
            </div>
            <div>
              <Label htmlFor="service-type">Type</Label>
              <Input
                id="service-type"
                value={newService.type}
                onChange={(e) => onServiceChange({
                  ...newService,
                  type: e.target.value
                })}
                placeholder="e.g., IdentityHub"
              />
            </div>
            <div>
              <Label htmlFor="service-endpoint">Endpoint</Label>
              <Input
                id="service-endpoint"
                value={newService.endpoint}
                onChange={(e) => onServiceChange({
                  ...newService,
                  endpoint: e.target.value
                })}
                placeholder="https://example.com/hub"
              />
            </div>
          </div>
          
          <Button onClick={onAddService} className="w-full">
            <Plus className="h-4 w-4 mr-2" />
            Add Service
          </Button>
          
          {services.length > 0 && (
            <div className="space-y-2">
              <h4 className="font-medium">Current Services:</h4>
              {services.map((service, index) => (
                <div key={index} className="flex items-center justify-between p-3 border rounded">
                  <div>
                    <p className="font-medium">{service.id}</p>
                    <p className="text-sm text-gray-600">{service.type}</p>
                    <p className="text-xs text-gray-500">{service.endpoint}</p>
                  </div>
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => onRemoveService(index)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </TabsContent>
      
      <div className="flex justify-end space-x-2 pt-4">
        <Button onClick={onCreate} disabled={loading}>
          {loading ? 'Creating...' : 'Create DID'}
        </Button>
      </div>
    </Tabs>
  );
};

interface DIDDocumentDisplayProps {
  didDocument: DIDDocument;
  onCopy: (text: string) => void;
}

const DIDDocumentDisplay: React.FC<DIDDocumentDisplayProps> = ({ didDocument, onCopy }) => {
  return (
    <div className="space-y-6">
      <div>
        <Label className="text-sm font-medium">DID</Label>
        <div className="flex items-center space-x-2 mt-1">
          <code className="bg-gray-100 px-3 py-2 rounded text-sm flex-1">{didDocument.id}</code>
          <Button variant="outline" size="sm" onClick={() => onCopy(didDocument.id)}>
            <Copy className="h-4 w-4" />
          </Button>
        </div>
      </div>
      
      <div>
        <Label className="text-sm font-medium">Controller</Label>
        <div className="flex items-center space-x-2 mt-1">
          <code className="bg-gray-100 px-3 py-2 rounded text-sm flex-1">{didDocument.controller}</code>
          <Button variant="outline" size="sm" onClick={() => onCopy(didDocument.controller)}>
            <Copy className="h-4 w-4" />
          </Button>
        </div>
      </div>
      
      <div>
        <Label className="text-sm font-medium">Created</Label>
        <p className="text-sm text-gray-600 mt-1">
          {new Date(didDocument.created).toLocaleString()}
        </p>
      </div>
      
      <div>
        <Label className="text-sm font-medium">Last Updated</Label>
        <p className="text-sm text-gray-600 mt-1">
          {new Date(didDocument.updated).toLocaleString()}
        </p>
      </div>
      
      {didDocument.verificationMethod.length > 0 && (
        <div>
          <Label className="text-sm font-medium">Verification Methods</Label>
          <div className="space-y-2 mt-2">
            {didDocument.verificationMethod.map((method, index) => (
              <Card key={index}>
                <CardContent className="p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="font-medium">{method.id}</p>
                      <p className="text-sm text-gray-600">{method.type}</p>
                      <p className="text-xs text-gray-500 mt-1">Controller: {method.controller}</p>
                    </div>
                    <Button variant="outline" size="sm" onClick={() => onCopy(method.publicKey)}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="mt-2">
                    <Label className="text-xs">Public Key</Label>
                    <code className="block bg-gray-100 px-2 py-1 rounded text-xs mt-1 break-all">
                      {method.publicKey}
                    </code>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
      
      {didDocument.service.length > 0 && (
        <div>
          <Label className="text-sm font-medium">Services</Label>
          <div className="space-y-2 mt-2">
            {didDocument.service.map((service, index) => (
              <Card key={index}>
                <CardContent className="p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="font-medium">{service.id}</p>
                      <p className="text-sm text-gray-600">{service.type}</p>
                      <p className="text-xs text-gray-500 mt-1">{service.endpoint}</p>
                    </div>
                    <Button variant="outline" size="sm" onClick={() => onCopy(service.endpoint)}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

interface ConnectedDIDManagerProps {
  config: StellarIdentityConfig;
  autoConnect?: boolean;
}

export const ConnectedDIDManager: React.FC<ConnectedDIDManagerProps> = ({
  config,
  autoConnect = false,
}) => {
  const { sdk, address, keypair, isLoading, error } = useStellarIdentity({
    config,
    autoConnect,
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2">Connecting to Stellar network...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  if (!sdk || !address || !keypair) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="text-center py-8 text-gray-500">
            <AlertCircle className="h-12 w-12 mx-auto mb-4 text-gray-400" />
            <p>Not connected to Stellar network</p>
            <p className="text-sm">Use the connect function to establish a connection</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return <DIDManager sdk={sdk} address={address} keypair={keypair} />;
};
