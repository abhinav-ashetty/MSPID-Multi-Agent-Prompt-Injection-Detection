import type { SimulationOutcome } from '../../types/simulation';

export const outcomePresentation: Record<SimulationOutcome, { label: string; classes: string }> = {
  PREVENTED: { label: 'Prevented', classes: 'bg-blue-100 text-blue-800' },
  LEAKED: { label: 'Leak detected', classes: 'bg-red-100 text-red-800' },
  NO_LEAK: { label: 'No leak detected', classes: 'bg-green-100 text-green-800' },
  TARGET_ERROR: { label: 'Component error (TARGET_ERROR)', classes: 'bg-amber-100 text-amber-900' },
};
