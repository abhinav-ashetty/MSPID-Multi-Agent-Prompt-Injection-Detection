import axios from 'axios';
import type {
  SecurityAnalysisRequest,
  SecurityAnalysisResponse,
  AssessmentsResponse,
  StatisticsResponse,
  AttackAnalyticsItem,
  RiskDistributionItem,
  TimelineItem
} from '../types/security';
import type {
  SimulationHistoryResponse,
  SimulationRequest,
  SimulationRunRecord,
  SimulationStatistics,
} from '../types/simulation';

/**
 * Axios instance configured with relative base URL.
 * Requests go through Vite proxy (configured in vite.config.ts) to reach FastAPI backend.
 * Vite proxy forwards /api/* to http://localhost:8000
 */
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 120000, // LLM analysis can take longer than a typical API request
});

/**
 * Health check API calls.
 */
export const healthApi = {
  /**
   * Check backend health status.
   * @returns Promise resolving to health response
   */
  check: async () => {
    const response = await api.get<{ status: string }>('/api/v1/health');
    return response.data;
  },
};

/**
 * Security API calls.
 */
export const securityApi = {
  /**
   * Analyze a prompt for security threats.
   * @param request - The prompt to analyze
   * @returns Promise resolving to the security analysis response
   */
  analyzePrompt: async (request: SecurityAnalysisRequest): Promise<SecurityAnalysisResponse> => {
    const response = await api.post<SecurityAnalysisResponse>('/api/v1/security/analyze', request);
    return response.data;
  },

  /**
   * Get a specific assessment by ID.
   * @param id - The assessment ID
   * @returns Promise resolving to the security analysis response
   */
  getAssessment: async (id: number): Promise<SecurityAnalysisResponse> => {
    const response = await api.get<SecurityAnalysisResponse>(`/api/v1/security/assessments/${id}`);
    return response.data;
  },

  /**
   * Get recent assessments with pagination.
   * @param limit - Number of items to return (default: 100)
   * @param offset - Number of items to skip (default: 0)
   * @returns Promise resolving to the assessments response
   */
  getAssessments: async (limit: number = 100, offset: number = 0): Promise<AssessmentsResponse> => {
    const response = await api.get<AssessmentsResponse>('/api/v1/security/assessments', {
      params: { limit, offset }
    });
    return response.data;
  },

  /**
   * Get dashboard statistics.
   * @returns Promise resolving to the statistics response
   */
  getStatistics: async (): Promise<StatisticsResponse> => {
    const response = await api.get<StatisticsResponse>('/api/v1/security/statistics');
    return response.data;
  },

  /**
   * Get attack category statistics.
   * @returns Promise resolving to the attack analytics items
   */
  getAttacks: async (): Promise<AttackAnalyticsItem[]> => {
    const response = await api.get<AttackAnalyticsItem[]>('/api/v1/security/attacks');
    return response.data;
  },

  /**
   * Get risk distribution data.
   * @returns Promise resolving to the risk distribution items
   */
  getRiskDistribution: async (): Promise<RiskDistributionItem[]> => {
    const response = await api.get<RiskDistributionItem[]>('/api/v1/security/risk-distribution');
    return response.data;
  },

  /**
   * Get assessment counts over time.
   * @param period - Grouping period: 'day' or 'week' (default: 'day')
   * @returns Promise resolving to the timeline items
   */
  getTimeline: async (period: string = 'day'): Promise<TimelineItem[]> => {
    const response = await api.get<TimelineItem[]>('/api/v1/security/timeline', {
      params: { period }
    });
    return response.data;
  },
};

/** Simulation API calls for the Attacker → Defender → Target workflow. */
export const simulationApi = {
  run: async (request: SimulationRequest): Promise<SimulationRunRecord> => {
    const response = await api.post<SimulationRunRecord>('/api/v1/simulations/run', request);
    return response.data;
  },

  get: async (simulationId: string): Promise<SimulationRunRecord> => {
    const response = await api.get<SimulationRunRecord>(`/api/v1/simulations/${encodeURIComponent(simulationId)}`);
    return response.data;
  },

  list: async (limit: number = 20, offset: number = 0): Promise<SimulationHistoryResponse> => {
    const response = await api.get<SimulationHistoryResponse>('/api/v1/simulations', {
      params: { limit, offset },
    });
    return response.data;
  },

  statistics: async (): Promise<SimulationStatistics> => {
    const response = await api.get<SimulationStatistics>('/api/v1/simulations/statistics');
    return response.data;
  },
};
