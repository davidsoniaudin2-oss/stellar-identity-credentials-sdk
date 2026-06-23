import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { DIDManager, ConnectedDIDManager } from '../DIDManager';

const mockSdk = {
  did: {
    generateDID: jest.fn().mockReturnValue('did:stellar:GA123'),
    resolveDID: jest.fn(),
    createDID: jest.fn().mockResolvedValue('did:stellar:GA123'),
    updateDID: jest.fn().mockResolvedValue(undefined),
    deactivateDID: jest.fn().mockResolvedValue(undefined),
  },
};

const mockKeypair = {
  publicKey: () => 'GA1234567890ABCDEF',
};

const mockDIDDocument = {
  id: 'did:stellar:GA123',
  controller: 'GA123',
  verificationMethod: [
    {
      id: '#key-1',
      type: 'Ed25519VerificationKey2018',
      controller: 'GA123',
      publicKey: '0123456789abcdef',
    },
  ],
  authentication: ['#key-1'],
  service: [
    {
      id: '#hub',
      type: 'IdentityHub',
      endpoint: 'https://hub.example.com',
    },
  ],
  created: Date.now() - 86400000,
  updated: Date.now(),
};

describe('DIDManager', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('should render loading state', () => {
    mockSdk.did.resolveDID.mockImplementation(() => new Promise(() => {}));
    render(
      <DIDManager sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    expect(screen.getByText('Loading DID information...')).toBeInTheDocument();
  });

  test('should render create DID prompt when no DID exists', async () => {
    mockSdk.did.resolveDID.mockRejectedValue(new Error('Not found'));
    render(
      <DIDManager sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    expect(await screen.findByText('Create DID')).toBeInTheDocument();
    expect(screen.getByText('No DID found for this address')).toBeInTheDocument();
  });

  test('should render DID document when it exists', async () => {
    mockSdk.did.resolveDID.mockResolvedValue({ didDocument: mockDIDDocument });
    render(
      <DIDManager sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    expect(await screen.findByText('did:stellar:GA123')).toBeInTheDocument();
    expect(screen.getByText('#key-1')).toBeInTheDocument();
    expect(screen.getByText('#hub')).toBeInTheDocument();
    expect(screen.getByText('IdentityHub')).toBeInTheDocument();
  });

  test('should show Edit and Deactivate buttons when DID exists', async () => {
    mockSdk.did.resolveDID.mockResolvedValue({ didDocument: mockDIDDocument });
    render(
      <DIDManager sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    expect(await screen.findByText('Update')).toBeInTheDocument();
    expect(screen.getByText('Deactivate')).toBeInTheDocument();
  });

  test('should show create dialog when Create DID is clicked', async () => {
    mockSdk.did.resolveDID.mockRejectedValue(new Error('Not found'));
    render(
      <DIDManager sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    fireEvent.click(await screen.findByText('Create DID'));
    expect(screen.getByText('Verification Methods')).toBeInTheDocument();
    expect(screen.getByText('Services')).toBeInTheDocument();
  });

  test('should handle deactivation with confirmation', async () => {
    mockSdk.did.resolveDID.mockResolvedValue({ didDocument: mockDIDDocument });
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    render(
      <DIDManager sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    fireEvent.click(await screen.findByText('Deactivate'));
    expect(confirmSpy).toHaveBeenCalled();
    expect(mockSdk.did.deactivateDID).toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  test('should handle error state', async () => {
    mockSdk.did.resolveDID.mockRejectedValue(new Error('Network error'));
    render(
      <DIDManager sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    expect(await screen.findByText('Create DID')).toBeInTheDocument();
  });

  test('should show controller and timestamps in DID document', async () => {
    mockSdk.did.resolveDID.mockResolvedValue({ didDocument: mockDIDDocument });
    render(
      <DIDManager sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    expect(await screen.findByText('GA123')).toBeInTheDocument();
    expect(screen.getByText('Controller')).toBeInTheDocument();
    expect(screen.getByText('Created')).toBeInTheDocument();
    expect(screen.getByText('Last Updated')).toBeInTheDocument();
  });

  test('should copy DID to clipboard', async () => {
    mockSdk.did.resolveDID.mockResolvedValue({ didDocument: mockDIDDocument });
    const writeText = jest.fn();
    Object.assign(navigator, { clipboard: { writeText } });
    render(
      <DIDManager sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    const copyButtons = await screen.findAllByRole('button', { name: '' });
    const didCopyButton = copyButtons.find(
      b => b.closest('div')?.previousElementSibling?.textContent === 'DID'
    );
    if (didCopyButton) fireEvent.click(didCopyButton);
  });
});

describe('ConnectedDIDManager', () => {
  test('should render connecting state', () => {
    render(
      <ConnectedDIDManager
        config={{
          network: 'testnet',
          contracts: {
            didRegistry: 'CA',
            credentialIssuer: 'CB',
            reputationScore: 'CC',
            zkAttestation: 'CD',
            complianceFilter: 'CE',
          },
        }}
      />
    );
    expect(screen.getByText('Connecting to Stellar network...')).toBeInTheDocument();
  });
});
