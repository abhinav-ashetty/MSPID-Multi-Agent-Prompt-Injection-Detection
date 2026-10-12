import { useEffect, useState } from 'react';
import { securityApi } from '../../services/api';
import { AssessmentItem } from '../../types/security';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import { EmptyState } from '../common/EmptyState';

/**
 * Recent assessments table component.
 */
export const RecentAssessments = () => {
  const [assessments, setAssessments] = useState<AssessmentItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const response = await securityApi.getAssessments(10, 0); // Get first 10
        setAssessments(response.items);
        setError(null);
      } catch (err) {
        console.error('Failed to fetch assessments:', err);
        setError('Failed to load assessments');
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

  if (assessments.length === 0) {
    return (
      <EmptyState
        title="No assessments yet"
        description="No security assessments have been recorded. Start by analyzing a prompt."
        actionText="Analyze Prompt"
        onAction={() => {
          // Navigate to analyze page
          window.location.href = '/analyze';
        }}
      />
    );
  }

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Recent Security Assessments</h3>
        <div className="flex items-center space-x-2">
          <button 
            className="px-3 py-1 bg-blue-500 text-white rounded-md text-sm hover:bg-blue-600"
            onClick={() => {
              window.location.href = '/assessments';
            }}
          >
            View All
          </button>
        </div>
      </div>
      
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left text-gray-500">
          <thead className="text-xs text-gray-700 uppercase bg-gray-50">
            <tr>
              <th scope="col" className="px-4 py-2">Time</th>
              <th scope="col" className="px-4 py-2">Risk</th>
              <th scope="col" className="px-4 py-2">Decision</th>
              <th scope="col" className="px-4 py-2">Attack Type</th>
              <th scope="col" className="px-4 py-2">Confidence</th>
            </tr>
          </thead>
          <tbody>
            {assessments.map((item) => (
              <tr key={item.id} className="border-b border-gray-100 hover:bg-gray-50">
                <td className="px-4 py-3">
                  <div className="flex items-center space-x-2">
                    <time dateTime={item.timestamp}>
                      {new Date(item.timestamp).toLocaleString()}
                    </time>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center">
                    <div 
                      className={`w-2 h-2 rounded-full 
                        ${item.final_risk_score >= 70 ? 'bg-red-500' 
                          : item.final_risk_score >= 40 ? 'bg-yellow-500' 
                          : 'bg-green-500'}`}
                    />
                    <span className="ml-2 text-xs font-medium">{item.final_risk_score}</span>
                  </div>
              </td>
                <td className="px-4 py-3">
                  <span 
                    className={`px-2 py-1 text-xs font-semibold 
                      ${item.decision === 'ALLOW' ? 'bg-green-100 text-green-800' 
                        : item.decision === 'SANITIZE' ? 'bg-yellow-100 text-yellow-800' 
                        : 'bg-red-100 text-red-800'}`}
                  >
                    {item.decision}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs">{item.attack_type}</span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs font-medium">
                    {(item.confidence * 100).toFixed(0)}%
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
