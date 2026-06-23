import React, { useState, useEffect, useMemo } from 'react';
import { 
  Card, 
  CardHeader, 
  CardTitle, 
  CardContent 
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { 
  ReputationClient, 
  ReputationScoreResult 
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import { 
  TrendingUp, 
  TrendingDown, 
  Minus, 
  Star, 
  Medal,
  Award,
  AlertCircle,
  CheckCircle,
  BarChart3,
  Target,
  Activity,
  Info,
  Gem,
  Shield,
} from 'lucide-react';

type BadgeSize = 'sm' | 'md' | 'lg';

interface TierConfig {
  name: string;
  minScore: number;
  color: string;
  textColor: string;
  bgColor: string;
  borderColor: string;
  icon: React.ReactNode;
}

interface ReputationBadgeProps {
  sdk: any;
  address: string;
  keypair: Keypair;
  size?: BadgeSize;
}

const TIERS: TierConfig[] = [
  {
    name: 'Platinum',
    minScore: 90,
    color: 'bg-gradient-to-r from-purple-500 via-pink-500 to-amber-400',
    textColor: 'text-purple-700',
    bgColor: 'bg-purple-50',
    borderColor: 'border-purple-300',
    icon: <Gem className="h-5 w-5 text-purple-600" />,
  },
  {
    name: 'Gold',
    minScore: 75,
    color: 'bg-amber-500',
    textColor: 'text-amber-700',
    bgColor: 'bg-amber-50',
    borderColor: 'border-amber-300',
    icon: <Award className="h-5 w-5 text-amber-600" />,
  },
  {
    name: 'Silver',
    minScore: 50,
    color: 'bg-gray-400',
    textColor: 'text-gray-700',
    bgColor: 'bg-gray-50',
    borderColor: 'border-gray-300',
    icon: <Medal className="h-5 w-5 text-gray-500" />,
  },
  {
    name: 'Bronze',
    minScore: 25,
    color: 'bg-amber-700',
    textColor: 'text-amber-800',
    bgColor: 'bg-amber-50',
    borderColor: 'border-amber-500',
    icon: <Shield className="h-5 w-5 text-amber-700" />,
  },
  {
    name: 'Unranked',
    minScore: 0,
    color: 'bg-gray-300',
    textColor: 'text-gray-600',
    bgColor: 'bg-gray-50',
    borderColor: 'border-gray-200',
    icon: <BarChart3 className="h-5 w-5 text-gray-400" />,
  },
];

const sizeConfig = {
  sm: {
    cardPadding: 'p-3',
    scoreText: 'text-2xl',
    titleSize: 'text-sm',
    iconSize: 'h-4 w-4',
    badgeSize: 'text-xs',
    gap: 'gap-2',
  },
  md: {
    cardPadding: 'p-4',
    scoreText: 'text-3xl',
    titleSize: 'text-base',
    iconSize: 'h-5 w-5',
    badgeSize: 'text-sm',
    gap: 'gap-3',
  },
  lg: {
    cardPadding: 'p-6',
    scoreText: 'text-5xl',
    titleSize: 'text-lg',
    iconSize: 'h-6 w-6',
    badgeSize: 'text-base',
    gap: 'gap-4',
  },
};

const LoadingSkeleton: React.FC<{ size: BadgeSize }> = ({ size }) => {
  const cfg = sizeConfig[size];
  return (
    <Card>
      <CardContent className={cfg.cardPadding}>
        <div className="space-y-4 animate-pulse">
          <div className={`flex items-center justify-between ${cfg.gap}`}>
            <div className="h-4 bg-gray-200 rounded w-1/3"></div>
            <div className="h-6 bg-gray-200 rounded w-16"></div>
          </div>
          <div className="flex justify-center">
            <div className="h-12 bg-gray-200 rounded w-20"></div>
          </div>
          <div className="h-3 bg-gray-200 rounded w-full"></div>
          <div className="grid grid-cols-2 gap-2">
            <div className="h-4 bg-gray-200 rounded"></div>
            <div className="h-4 bg-gray-200 rounded"></div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export const ReputationBadge: React.FC<ReputationBadgeProps> = ({
  sdk,
  address,
  keypair,
  size = 'md',
}) => {
  const [reputationData, setReputationData] = useState<ReputationScoreResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showTooltip, setShowTooltip] = useState(false);
  const [prevScore, setPrevScore] = useState<number | null>(null);
  const [scoreChanged, setScoreChanged] = useState(false);

  const cfg = sizeConfig[size];

  useEffect(() => {
    loadReputationData();
  }, [address]);

  useEffect(() => {
    if (prevScore !== null && reputationData && reputationData.score !== prevScore) {
      setScoreChanged(true);
      const timer = setTimeout(() => setScoreChanged(false), 1000);
      return () => clearTimeout(timer);
    }
    if (reputationData) {
      setPrevScore(reputationData.score);
    }
  }, [reputationData?.score]);

  const loadReputationData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const data = await sdk.reputation.getReputationAnalysis(address);
      setReputationData(data);
    } catch (error: any) {
      setError(error.message || 'Failed to load reputation data');
    } finally {
      setLoading(false);
    }
  };

  const getTier = (score: number): TierConfig => {
    return TIERS.find(t => score >= t.minScore) || TIERS[TIERS.length - 1];
  };

  const getTrendIcon = (trend: 'up' | 'down' | 'stable') => {
    switch (trend) {
      case 'up':
        return <TrendingUp className="h-4 w-4 text-green-500" />;
      case 'down':
        return <TrendingDown className="h-4 w-4 text-red-500" />;
      default:
        return <Minus className="h-4 w-4 text-gray-500" />;
    }
  };

  const getScoreWithinTier = (score: number, tier: TierConfig): number => {
    const tierIndex = TIERS.indexOf(tier);
    if (tierIndex === 0) return 100;
    const nextTierMin = TIERS[tierIndex - 1].minScore;
    const range = nextTierMin - tier.minScore;
    return ((score - tier.minScore) / range) * 100;
  };

  if (loading) {
    return <LoadingSkeleton size={size} />;
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  if (!reputationData) {
    return (
      <Card>
        <CardContent className={cfg.cardPadding}>
          <div className="text-center text-gray-500">
            <BarChart3 className="h-12 w-12 mx-auto mb-4 text-gray-400" />
            <p>No reputation data available</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const tier = getTier(reputationData.score);
  const trend = sdk.reputation.calculateReputationTrend(reputationData.history);
  const progressInTier = getScoreWithinTier(reputationData.score, tier);

  return (
    <div className="space-y-6">
      <Card
        className={`${tier.bgColor} ${tier.borderColor} border-2 transition-all duration-500 ${
          scoreChanged ? 'scale-105 shadow-lg' : 'scale-100'
        }`}
      >
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className={`flex items-center space-x-2 ${cfg.titleSize}`}>
              {React.cloneElement(tier.icon as React.ReactElement, {
                className: `${cfg.iconSize} ${tier.textColor}`,
              })}
              <span className={tier.textColor}>Reputation Score</span>
            </CardTitle>
            <div className="relative">
              <Badge
                className={`${tier.color} text-white ${cfg.badgeSize} cursor-help`}
                onMouseEnter={() => setShowTooltip(true)}
                onMouseLeave={() => setShowTooltip(false)}
                onClick={() => setShowTooltip(!showTooltip)}
              >
                {tier.name}
              </Badge>
              {showTooltip && reputationData && (
                <div className="absolute top-full right-0 mt-2 w-72 bg-white border rounded-lg shadow-xl z-50 p-4">
                  <div className="space-y-3">
                    <div className="flex items-center space-x-2 border-b pb-2">
                      {tier.icon}
                      <span className="font-semibold">{tier.name} Tier</span>
                    </div>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-600">Score Range</span>
                        <span className="font-medium">
                          {tier.minScore} - {tier.name === 'Platinum' ? '100' : TIERS[TIERS.indexOf(tier) - 1]?.minScore ?? 100}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Total Transactions</span>
                        <span className="font-medium">{reputationData.factors?.transactionCount || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Success Rate</span>
                        <span className="font-medium">
                          {reputationData.factors?.successRate
                            ? `${(reputationData.factors.successRate * 100).toFixed(1)}%`
                            : 'N/A'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Credential Count</span>
                        <span className="font-medium">{reputationData.factors?.credentialCount || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Percentile</span>
                        <span className="font-medium">{reputationData.percentile}%</span>
                      </div>
                    </div>
                    <div className="border-t pt-2 text-xs text-gray-500">
                      <p>Next tier: {
                        TIERS[TIERS.indexOf(tier) - 1]?.name || 'Maximum'
                      } at {
                        TIERS[TIERS.indexOf(tier) - 1]?.minScore || reputationData.score
                      } points</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className={`space-y-4 ${cfg.gap}`}>
            <div className="text-center">
              <div
                className={`${cfg.scoreText} font-bold mb-2 transition-all duration-700 ${
                  scoreChanged ? 'text-green-500' : tier.textColor
                }`}
              >
                {reputationData.score}
              </div>
              <div className="flex items-center justify-center space-x-2">
                {getTrendIcon(trend.trend)}
                <span className="text-sm text-gray-600">
                  {trend.trend === 'up' ? '+' : ''}{trend.change?.toFixed(1) || '0.0'} ({trend.percentage?.toFixed(1) || '0.0'}%)
                </span>
              </div>
            </div>
            
            <div className="relative">
              <Progress
                value={reputationData.score}
                className={`w-full transition-all duration-1000 ${tier.color}`}
              />
              <div className="flex justify-between text-xs text-gray-400 mt-1">
                <span>0</span>
                <span>25</span>
                <span>50</span>
                <span>75</span>
                <span>100</span>
              </div>
            </div>

            <div className={`grid grid-cols-2 gap-4 text-sm ${size === 'lg' ? '' : 'text-xs'}`}>
              <div>
                <span className="text-gray-600">Percentile:</span>
                <span className="ml-2 font-medium">{reputationData.percentile}%</span>
              </div>
              <div>
                <span className="text-gray-600">Tier Progress:</span>
                <span className="ml-2 font-medium">{Math.round(progressInTier)}%</span>
              </div>
              <div>
                <span className="text-gray-600">Last Updated:</span>
                <span className="ml-2 font-medium">
                  {new Date(reputationData.lastUpdated).toLocaleDateString()}
                </span>
              </div>
              <div>
                <span className="text-gray-600">Tier:</span>
                <span className={`ml-2 font-medium ${tier.textColor}`}>{tier.name}</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center text-lg">
              <Target className="h-5 w-5 mr-2" />
              Reputation Factors
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(reputationData.factors || {}).map(([factor, count]) => (
                <div key={factor} className="flex justify-between items-center">
                  <span className="text-sm font-medium capitalize">
                    {factor.replace(/_/g, ' ')}
                  </span>
                  <Badge variant="outline">{String(count)}</Badge>
                </div>
              ))}
              {(!reputationData.factors || Object.keys(reputationData.factors).length === 0) && (
                <p className="text-sm text-gray-400">No factor data available</p>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center text-lg">
              <Activity className="h-5 w-5 mr-2" />
              Recent Activity
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(reputationData.history || []).slice(-5).reverse().map((score, index) => (
                <div key={index} className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">
                    {index === 0 ? 'Current' : `${index} updates ago`}
                  </span>
                  <span className="font-medium">{score}</span>
                </div>
              ))}
              {(!reputationData.history || reputationData.history.length === 0) && (
                <p className="text-sm text-gray-400">No history available</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className={cfg.titleSize}>Reputation Insights</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className={`${cfg.scoreText} font-bold text-blue-600`}>
                  {reputationData.score}
                </div>
                <div className="text-sm text-gray-600">Current Score</div>
              </div>
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className={`${size === 'lg' ? 'text-2xl' : 'text-xl'} font-bold text-green-600`}>
                  {reputationData.percentile}%
                </div>
                <div className="text-sm text-gray-600">Percentile Rank</div>
              </div>
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className={`${size === 'lg' ? 'text-2xl' : 'text-xl'} font-bold text-purple-600`}>
                  {Object.keys(reputationData.factors || {}).length}
                </div>
                <div className="text-sm text-gray-600">Active Factors</div>
              </div>
            </div>
            
            <div className="space-y-2">
              <h4 className="font-medium">Recommendations:</h4>
              <ul className="text-sm text-gray-600 space-y-1">
                {reputationData.score < 60 && (
                  <li>• Focus on successful transactions to improve your score</li>
                )}
                {Object.keys(reputationData.factors || {}).length < 3 && (
                  <li>• Obtain more verifiable credentials to strengthen your reputation</li>
                )}
                {trend.trend === 'down' && (
                  <li>• Recent activity shows a declining trend - consider reviewing recent transactions</li>
                )}
                {reputationData.score >= 80 && (
                  <li>• Excellent reputation! Maintain your current activity level</li>
                )}
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
