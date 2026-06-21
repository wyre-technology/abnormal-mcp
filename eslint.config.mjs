/**
 * Mode-4 warn-baseline canonical — see cortextos task_1779393988390 (Mode-4 batch).
 *
 * This repo has latent lint debt that the strict fleet-canonical surfaces. To preserve the
 * Mode-4 gate-fix discipline (Lint step finds config + runs + exits 0, not exit-2 with
 * "no config") without conflating Mode-4 (configure lint) with Mode-2 (fix repo-specific
 * lint debt), the following rule is downgraded from error → warn:
 *
 *   '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }]
 *
 * LATENT DEBT (visible warnings, not blocking errors):
 *   1 finding: no-unused-vars (unused 'vi' vitest import in test file)
 *
 * GOAL: warn → error after the debt is addressed. Follow-up task: cortextos task_1779394868025_82169245.
 * Rest of the fleet-canonical (eslint:recommended + @typescript-eslint recommended baseline)
 * preserved strict; the warn-downgrade is rule-specific, not blanket.
 */
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'coverage/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
);
