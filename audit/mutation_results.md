# Mutation Testing Audit Results (`audit/mutation_results.md`)

**Summary**: Total: 1 | **KILLED**: 1 | **SURVIVED**: 0 | **BASELINE FAILS**: 0 | **N/A**: 0

| ID | File | Description | Result | Output / Failure Line | Test that Should Catch |
|---|---|---|---|---|---|
| M8 | `ips/models/evt.py` | Off-by-one in split-conformal quantile index | KILLED | `1 failed in 3.12s` | `tests/test_models.py::test_split_conformal_regime_and_alpha_budget` |
