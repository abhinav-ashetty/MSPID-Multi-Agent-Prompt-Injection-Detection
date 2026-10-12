import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { useEffect, useState } from 'react';
import { securityApi } from '../../services/api';
import { AttackAnalyticsItem } from '../../types/security';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';

/**
 * Attack categories chart component.
 * Displays attack type distribution.
 */
export const AttackCategories = () => {
  const [data, setData] = useState<AttackAnalyticsItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const attackData = await securityApi.getAttacks();
        setData(attackData);
        setError(null);
      } catch (err) {
        console.error('Failed to fetch attack data:', err);
        setError('Failed to load attack data');
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
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Attack Categories</h3>
        <p className="text-gray-500">No attack data available</p>
      </div>
    );
  }

  // Format data for Recharts
  const chartData = data.map(item => ({
    attackType: item.attack_type,
    count: item.count
  }));

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Attack Categories</h3>
      <ResponsiveContainer width="100%" height={250}>
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="attackType" tick={{ fontSize: 12 }} />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip 
            wrapperStyle={{ borderRadius: 4, padding: 8 }}
            contentStyle={{ backgroundColor: 'white', border: '1px solid #e5e7eb' }}
            labelStyle={{ fontSize: 12, fontWeight: 600 }}
            itemStyle={{ fontSize: 12 }}
          />
          <Legend verticalAlign="top" height={36} />
          <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
