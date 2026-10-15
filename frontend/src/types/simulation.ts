export type AttackCategory =
  | 'BENIGN'
  | 'PROMPT_INJECTION'
  | 'INSTRUCTION_CONFLICT'
  | 'ROLE_MANIPULATION'
  | 'SYSTEM_PROMPT_EXTRACTION'
  | 'SENSITIVE_INFORMATION_REQUEST';

export type SimulationOutcome = 'PREVENTED' | 'LEAKED' | 'NO_LEAK' | 'TARGET_ERROR';
export type SuccessCriterion = 'PROTECTED_CANARY_MATCH';
export type Decision = 'ALLOW' | 'SANITIZE' | 'BLOCK';

export interface SimulationRequest {
  attack_category: AttackCategory;
  protected_canaries: string[];
  success_criterion?: SuccessCriterion;
}

export interface AttackTestCase {
  attack_id: string;
  category: AttackCategory;
  prompt: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  description: string;
}

export interface HybridAssessmentSummary {
  decision: Decision;
  final_risk_score: number;
  rule_score: number;
  ml_probability: number;
  gemini_risk_score: number;
  attack_type: 'NONE' | 'PROMPT_INJECTION' | 'OTHER';
  confidence: number;
  reason: string;
}

export interface TargetResponse {
  response: string;
  target_name: string;
  completed: boolean;
  error: string | null;
  metadata: Record<string, string>;
}

export interface LeakageMatch {
  canary: string;
  match_type: 'EXACT' | 'NORMALIZED';
}

export interface SimulationResult {
  simulation_id: string;
  outcome: SimulationOutcome;
  ai_mode: 'GEMINI' | 'LOCAL_FALLBACK';
  fallback_reason: 'RATE_LIMITED' | 'UNAVAILABLE' | null;
  attack: AttackTestCase | null;
  defender_assessment: HybridAssessmentSummary | null;
  defender_decision: Decision | null;
  target_called: boolean;
  target_received_original_prompt: boolean;
  target_response: TargetResponse | null;
  leakage_matches: LeakageMatch[];
  attack_success: boolean;
  success_criterion: SuccessCriterion;
  sanitization_status: 'NOT_APPLICABLE' | 'NOT_IMPLEMENTED';
  failed_stage: 'attacker' | 'defender' | 'target' | null;
  error: string | null;
}

export interface SimulationRunRecord {
  id: number;
  created_at: string;
  result: SimulationResult;
}

export interface SimulationHistoryItem {
  id: number;
  simulation_id: string;
  created_at: string;
  attack_category: AttackCategory;
  prompt: string | null;
  defender_decision: Decision | null;
  target_called: boolean;
  target_received_original_prompt: boolean;
  leakage_matches: LeakageMatch[];
  attack_success: boolean;
  outcome: SimulationOutcome;
  success_criterion: SuccessCriterion;
  sanitization_status: 'NOT_APPLICABLE' | 'NOT_IMPLEMENTED';
  failed_stage: 'attacker' | 'defender' | 'target' | null;
  error: string | null;
}

export interface SimulationHistoryResponse {
  items: SimulationHistoryItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface SimulationStatistics {
  total_simulations: number;
  successful_attacks: number;
  outcomes: Record<SimulationOutcome, number>;
}
