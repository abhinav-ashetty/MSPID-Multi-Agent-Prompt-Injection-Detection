import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { useEffect, useState } from 'react';
import { securityApi } from '../../services/api';
import { RiskDistributionItem } from '../../types/security';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';

/**
 * Risk distribution chart component.
 * Displays risk score distribution.
 */
export const RiskDistribution = () => {
  const [data, setData] = useState<RiskDistributionItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const riskData = await securityApi.getRiskDistribution();
        setData(riskData);
        setError(null);
      } catch (err) {
        console.error('Failed to fetch risk distribution data:', err);
        setError('Failed to load risk distribution data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return <LoadingState />;
  }

  if (error) {
    return <ErrorState message={error} onRetry={() => { /* trigger refetch */ setLoading(true); }} />;
  }

  if (data.length === 0) {
    return (
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Distribution</h3>
        <p className="text-gray-500">No risk distribution data available</p>
      </div>
    );
  }

  // Format data for Recharts
  const chartData = data.map(item => ({
    range: item.range,
    count: item.count
  }));

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Distribution</h3>
      <ResponsiveContainer width="100%" height={250}>
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="range" tick={{ fontSize: 12 }} />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip 
            wrapperStyle={{ borderRadius: 4, padding: 8 }}
            contentStyle={{ backgroundColor: 'white', border: '1px solid #e5e7eb' }}
            labelStyle={{ fontSize: 12, fontWeight: 600 }}
            itemStyle={{ fontSize: 12 }}
          />
          <Legend verticalAlign="top" height={36} />
          <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
