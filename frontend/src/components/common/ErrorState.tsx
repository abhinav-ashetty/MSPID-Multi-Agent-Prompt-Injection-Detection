import { RefreshCw } from 'lucide-react';

/**
 * Error state component.
 */
interface ErrorStateProps {
  /** Error message to display. */
  message: string;
  /** Optional retry callback. */
  onRetry?: () => void;
  /** Optional custom class name. */
  className?: string;
}

export const ErrorState = ({ 
  message, 
  onRetry, 
  className = '' 
}: ErrorStateProps) => {
  return (
    <div className={`flex flex-col items-center justify-center py-12 text-center ${className}`}>
      <div className="w-12 h-12 flex items-center justify-center rounded-full bg-red-100 text-red-500 mb-4">
        <RefreshCw className="w-5 h-5" />
      </div>
      <h3 className="text-lg font-semibold text-gray-900 mb-2">
        Something went wrong
      </h3>
      <p className="text-gray-600 mb-6">
        {message}
      </p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="btn btn-primary"
        >
          Try again
        </button>
      )}
    </div>
  );
};
