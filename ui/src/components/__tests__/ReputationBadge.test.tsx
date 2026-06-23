import React from 'react';
import { render, screen } from '@testing-library/react';
import { ReputationBadge } from '../ReputationBadge';

const mockSdk = {
  reputation: {
    getReputationAnalysis: jest.fn(),
    calculateReputationTrend: jest.fn().mockReturnValue({
      trend: 'up',
      change: 5.2,
      percentage: 8.3,
    }),
  },
};

const mockKeypair = {
  publicKey: () => 'GABC123456789',
};

describe('ReputationBadge', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('should render loading skeleton while fetching', () => {
    mockSdk.reputation.getReputationAnalysis.mockImplementation(
      () => new Promise(() => {})
    );
    render(
      <ReputationBadge sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );
    expect(screen.getByText('Reputation Score')).toBeInTheDocument();
  });

  test('should display reputation score and tier', async () => {
    mockSdk.reputation.getReputationAnalysis.mockResolvedValue({
      score: 85,
      percentile: 72,
      factors: { transactionCount: 150, successRate: 0.95, credentialCount: 12 },
      history: [70, 75, 80, 82, 85],
      lastUpdated: Date.now(),
    });

    render(
      <ReputationBadge sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );

    expect(await screen.findByText('85')).toBeInTheDocument();
    expect(screen.getByText('72%')).toBeInTheDocument();
  });

  test('should render with Bronze tier for low scores', async () => {
    mockSdk.reputation.getReputationAnalysis.mockResolvedValue({
      score: 30,
      percentile: 15,
      factors: { transactionCount: 3 },
      history: [20, 25, 30],
      lastUpdated: Date.now(),
    });

    render(
      <ReputationBadge sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );

    expect(await screen.findByText('Bronze')).toBeInTheDocument();
  });

  test('should render with Silver tier for medium scores', async () => {
    mockSdk.reputation.getReputationAnalysis.mockResolvedValue({
      score: 60,
      percentile: 45,
      factors: { transactionCount: 80 },
      history: [50, 55, 60],
      lastUpdated: Date.now(),
    });

    render(
      <ReputationBadge sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );

    expect(await screen.findByText('Silver')).toBeInTheDocument();
  });

  test('should render with Gold tier for high scores', async () => {
    mockSdk.reputation.getReputationAnalysis.mockResolvedValue({
      score: 80,
      percentile: 65,
      factors: { transactionCount: 200 },
      history: [70, 75, 80],
      lastUpdated: Date.now(),
    });

    render(
      <ReputationBadge sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );

    expect(await screen.findByText('Gold')).toBeInTheDocument();
  });

  test('should render with Platinum tier for excellent scores', async () => {
    mockSdk.reputation.getReputationAnalysis.mockResolvedValue({
      score: 95,
      percentile: 99,
      factors: { transactionCount: 500 },
      history: [85, 90, 95],
      lastUpdated: Date.now(),
    });

    render(
      <ReputationBadge sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );

    expect(await screen.findByText('Platinum')).toBeInTheDocument();
  });

  test('should render error state on failure', async () => {
    mockSdk.reputation.getReputationAnalysis.mockRejectedValue(
      new Error('Failed to load')
    );

    render(
      <ReputationBadge sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );

    expect(await screen.findByText('Failed to load')).toBeInTheDocument();
  });

  test('should render fallback for missing data', () => {
    mockSdk.reputation.getReputationAnalysis.mockResolvedValue(null);

    render(
      <ReputationBadge sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );

    expect(screen.getByText('No reputation data available')).toBeInTheDocument();
  });

  test('should apply small size styles', () => {
    mockSdk.reputation.getReputationAnalysis.mockResolvedValue({
      score: 75,
      percentile: 50,
      factors: {},
      history: [75],
      lastUpdated: Date.now(),
    });

    render(
      <ReputationBadge size="sm" sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );

    expect(screen.getByText('Reputation Score')).toBeInTheDocument();
  });

  test('should apply large size styles', () => {
    mockSdk.reputation.getReputationAnalysis.mockResolvedValue({
      score: 75,
      percentile: 50,
      factors: {},
      history: [75],
      lastUpdated: Date.now(),
    });

    render(
      <ReputationBadge size="lg" sdk={mockSdk} address="GABC123" keypair={mockKeypair as any} />
    );

    expect(screen.getByText('Reputation Score')).toBeInTheDocument();
  });
});
