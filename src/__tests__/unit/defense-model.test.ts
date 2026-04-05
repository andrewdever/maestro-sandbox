import { describe, it, expect } from 'vitest';
import {
  DEFENSE_CONTROLS,
  SAFETY_INVARIANT,
  OWASP_LLM_TOP_10,
  validateDefenseModel,
  validateOwaspCoverage,
} from '../../defense-model.js';

describe('DefenseModel', () => {
  describe('DEFENSE_CONTROLS', () => {
    it('contains both structural and heuristic controls', () => {
      const structural = DEFENSE_CONTROLS.filter(c => c.type === 'structural');
      const heuristic = DEFENSE_CONTROLS.filter(c => c.type === 'heuristic');

      expect(structural.length).toBeGreaterThan(0);
      expect(heuristic.length).toBeGreaterThan(0);
    });

    it('every heuristic control has a structural backup', () => {
      const heuristics = DEFENSE_CONTROLS.filter(c => c.type === 'heuristic');
      for (const control of heuristics) {
        expect(control.structuralBackup, `${control.name} missing backup`).toBeTruthy();
      }
    });

    it('every control has a spec section reference', () => {
      for (const control of DEFENSE_CONTROLS) {
        expect(control.specSection).toBeTruthy();
      }
    });

    it('all controls have unique names', () => {
      const names = DEFENSE_CONTROLS.map(c => c.name);
      expect(new Set(names).size).toBe(names.length);
    });
  });

  describe('validateDefenseModel', () => {
    it('returns no violations for the current model', () => {
      expect(validateDefenseModel()).toEqual([]);
    });
  });

  describe('SAFETY_INVARIANT', () => {
    it('documents 4 guarantees', () => {
      expect(SAFETY_INVARIANT.guarantees).toHaveLength(4);
    });

    it('counts match actual controls', () => {
      const structural = DEFENSE_CONTROLS.filter(c => c.type === 'structural').length;
      const heuristic = DEFENSE_CONTROLS.filter(c => c.type === 'heuristic').length;

      expect(SAFETY_INVARIANT.structuralControlCount).toBe(structural);
      expect(SAFETY_INVARIANT.heuristicControlCount).toBe(heuristic);
    });
  });

  describe('OWASP LLM Top 10 mapping', () => {
    it('covers all 10 OWASP categories', () => {
      expect(OWASP_LLM_TOP_10).toHaveLength(10);
      const ids = OWASP_LLM_TOP_10.map(e => e.id);
      for (let i = 1; i <= 10; i++) {
        expect(ids).toContain(`LLM${String(i).padStart(2, '0')}`);
      }
    });

    it('every in-scope category has 2+ defense layers', () => {
      for (const entry of OWASP_LLM_TOP_10) {
        if (entry.notes?.includes('Out of scope')) continue;
        expect(entry.layers.length, `${entry.id} (${entry.name})`).toBeGreaterThanOrEqual(2);
        expect(entry.meetsTarget).toBe(true);
      }
    });

    it('validateOwaspCoverage returns no violations', () => {
      expect(validateOwaspCoverage()).toEqual([]);
    });

    it('LLM09 (Overreliance) is explicitly out of scope', () => {
      const llm09 = OWASP_LLM_TOP_10.find(e => e.id === 'LLM09');
      expect(llm09).toBeDefined();
      expect(llm09!.meetsTarget).toBe(false);
      expect(llm09!.notes).toContain('Out of scope');
    });

    it('LLM01 (Prompt Injection) has 4+ layers', () => {
      const llm01 = OWASP_LLM_TOP_10.find(e => e.id === 'LLM01');
      expect(llm01!.layers.length).toBeGreaterThanOrEqual(4);
    });

    it('LLM03 (Training Data) and LLM10 (Model Theft) each have 2+ layers', () => {
      const llm03 = OWASP_LLM_TOP_10.find(e => e.id === 'LLM03');
      const llm10 = OWASP_LLM_TOP_10.find(e => e.id === 'LLM10');
      expect(llm03!.layers.length).toBeGreaterThanOrEqual(2);
      expect(llm10!.layers.length).toBeGreaterThanOrEqual(2);
    });
  });
});
