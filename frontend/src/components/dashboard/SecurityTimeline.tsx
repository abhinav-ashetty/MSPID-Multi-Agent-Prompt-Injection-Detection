import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { useEffect, useState } from 'react';
import { securityApi } from '../../services/api';
import { TimelineItem } from '../../types/security';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';

/**
 * Security timeline chart component.
 * Displays assessment counts over time.
 */
export const SecurityTimeline = () => {
  const [data, setData] = useState<TimelineItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const timelineData = await securityApi.getTimeline('day');
        setData(timelineData);
        setError(null);
      } catch (err) {
        console.error('Failed to fetch timeline data:', err);
        setError('Failed to load timeline data');
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
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Activity Timeline</h3>
        <p className="text-gray-500">No timeline data available</p>
      </div>
    );
  }

  // Format data for Recharts: ensure date is string and values are numbers
  const chartData = data.map(item => ({
    date: item.date,
    total: item.total,
    allowed: item.allowed,
    sanitized: item.sanitized,
    blocked: item.blocked
  }));

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Activity Timeline</h3>
      <ResponsiveContainer width="100%" height={250}>
        <LineChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="date" tick={{ fontSize: 12 }} />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip 
            wrapperStyle={{ borderRadius: 4, padding: 8 }}
            contentStyle={{ backgroundColor: 'white', border: '1px solid #e5e7eb' }}
            labelStyle={{ fontSize: 12, fontWeight: 600 }}
            itemStyle={{ fontSize: 12 }}
          />
          <Legend verticalAlign="top" height={36} />
          <Line type="monotone" dataKey="allowed" stroke="#10b981" strokeWidth={2} dot={{ r: 4 }} />
          <Line type="monotone" dataKey="sanitized" stroke="#f59e0b" strokeWidth={2} dot={{ r: 4 }} />
          <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} dot={{ r: 4 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};
