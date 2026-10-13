import { describe, expect, it } from 'vitest';
import { outcomePresentation } from './outcomePresentation';

describe('simulation outcome presentation', () => {
  it('assigns a distinct readable label and style to every outcome', () => {
    expect(outcomePresentation.PREVENTED.label).toBe('Prevented');
    expect(outcomePresentation.LEAKED.label).toBe('Leak detected');
    expect(outcomePresentation.NO_LEAK.label).toBe('No leak detected');
    expect(outcomePresentation.TARGET_ERROR.label).toBe('Component error (TARGET_ERROR)');
    expect(new Set(Object.values(outcomePresentation).map(value => value.classes)).size).toBe(4);
  });
});
