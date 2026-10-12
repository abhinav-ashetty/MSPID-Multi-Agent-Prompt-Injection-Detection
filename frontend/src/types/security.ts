/**
 * TypeScript interfaces for AIShield security API responses.
 * These must match the backend Pydantic models.
 */

export interface Decision {
  ALLOW: 'ALLOW';
  SANITIZE: 'SANITIZE';
  BLOCK: 'BLOCK';
}

/**
 * Attack types as defined in the backend.
 */
export type AttackType = 'NONE' | 'PROMPT_INJECTION' | 'OTHER';

/**
 * Request model for security analysis.
 */
export interface SecurityAnalysisRequest {
  prompt: string;
}

/**
 * Response model for security analysis (POST /analyze and GET /assessments/{id}).
 */
export interface SecurityAnalysisResponse {
  id: number;
  timestamp: string; // ISO datetime string
  prompt: string;
  decision: 'ALLOW' | 'SANITIZE' | 'BLOCK';
  final_risk_score: number; // 0-100
  rule_score: number; // 0-100
  ml_probability: number; // 0.0-1.0
  gemini_risk_score: number; // 0-100
  attack_type: AttackType;
  confidence: number; // 0.0-1.0
  reason: string;
}

/**
 * Individual assessment item for lists (GET /assessments).
 */
export interface AssessmentItem {
  id: number;
  timestamp: string; // ISO datetime string
  prompt: string;
  decision: 'ALLOW' | 'SANITIZE' | 'BLOCK';
  final_risk_score: number; // 0-100
  attack_type: AttackType;
  confidence: number; // 0.0-1.0
  reason: string;
}

/**
 * Response model for paginated assessments (GET /assessments).
 */
export interface AssessmentsResponse {
  items: AssessmentItem[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * Response model for security statistics (GET /statistics).
 */
export interface StatisticsResponse {
  total_assessments: number;
  decisions: {
    ALLOW: number;
    SANITIZE: number;
    BLOCK: number;
  };
  average_risk_score: number;
  high_risk_count: number;
  attack_types: {
    NONE: number;
    PROMPT_INJECTION: number;
    OTHER: number;
  };
}

/**
 * Attack analytics item (GET /attacks).
 */
export interface AttackAnalyticsItem {
  attack_type: AttackType;
  count: number;
  percentage: number;
}

/**
 * Risk distribution item (GET /risk-distribution).
 */
export interface RiskDistributionItem {
  range: string; // e.g., "0-19", "20-39", etc.
  count: number;
}

/**
 * Timeline item for assessments over time (GET /timeline).
 */
export interface TimelineItem {
  date: string; // YYYY-MM-DD format
  total: number;
  allowed: number;
  sanitized: number;
  blocked: number;
}
