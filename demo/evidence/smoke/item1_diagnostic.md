# Prompt 9 Item 1 Diagnostic — Smoke ROC Inversion & Mock Closed-Loop False DROP

> **Evidence Type**: `SYNTHETIC SMOKE (pipeline demonstration only — NOT A RESULT)` + `UNIT TEST`

## 1a. Pre-Fix Smoke Test Split Score Table (`p8-demo`, commit `31da19b`, `epochs=8`, unnormalised `log_iat`)

Label convention in `ips/models/eval_offline.py` (`roc_auc_score(y_true, scores)` with `y=1` attack) is **correct**. The model genuinely assigned **higher** reconstruction MSE to benign flows than to attack flows:

| Model | Precision | Masked MSE (`build_valid_mask_matrix`) | Benign Mean (Median) | Attack Mean (Median) | Masked AUROC | Unmasked AUROC |
|---|---|---|---|---|---|---|
| `ckpt_4` | FP32 / INT8 | Yes / No | `3.8010` (`4.0958`) | `2.7350` (`2.3112`) | `0.3009` / `0.3017` | `0.3009` / `0.3017` |
| `ckpt_8` | FP32 / INT8 | Yes | `7.9355` (`8.5567`) | `5.4491` (`4.2943`) | `0.2455` / `0.2449` | `0.2581` / `0.2576` |
| `ckpt_16` | FP32 / INT8 | Yes | `6.5789` (`7.1819`) | `4.6673` (`3.5504`) | `0.2921` / `0.2922` | `0.3302` / `0.3303` |
| `global_16` | FP32 / INT8 | Yes | `4.8648` (`5.3198`) | `3.4092` (`2.7126`) | `0.2969` / `0.2964` | `0.3219` / `0.3213` |

## 1b & 1c. Diagnosed Root Causes

1. **Under-training + unnormalised `log_iat` dominance (`[0, ~7.5]`)**: `demo/run_smoke_pipeline.py` ran `epochs=8` with `batch_size=64, lr=0.002` on `n_train=204` (**32 gradient updates total**). Decoder outputs on `log_iat` stayed near initialization (`~2.54–2.96`). Because slow benign IoT sensors/plugs had `log_iat ~ 6.0–6.48` while fast attacks (`A1_flood=3.27`, `A4_exfil=3.95`, `A5_bruteforce=5.38`) lay closer to `~2.7`, `log_iat` squared error was **`14.95` on benign vs `10.85` on attack** (`44x` larger than `sizes` `0.34`), inverting ROC.
2. **Code bug in `ips/models/eval_offline.py::score_onnx_model`**: Computed unmasked `np.mean((X - out)**2, axis=1)` without applying `build_valid_mask_matrix(X)`, diverging from `EarlyFlowAutoencoder.get_reconstruction_error` and `IPSEngine.score_vector` on short flows (`valid_len < early_n`).
3. **Smoke-data design flaw in `ips/smoke/synth.py` (`A3_c2`)**: `A3_c2` used alternating `dirs=[0,1,0,1]`, `sizes ~ N(80, 5)`, `iats ~ 5–30 s`, strictly inside the convex hull of benign `sensor` (`64B, 10s`), `thermostat` (`140B, 15s`), and `plug` (`50B, 30s`). Updated `A3_c2` (deterministic `seed=42`) to model periodic `52B` check-ins followed by 3-packet `920B` downlink tasking bursts (`4 ms` intra-burst IATs).

## 1e. Why `benign_sensor_1` Received `DROP` (`score=2.525898`) in `mock_closed_loop.json`

It was a **triple bug** (not an intended false-positive demo):
1. `IPSEngine._load_model_and_thresholds` (`ips/engine/engine.py`) hard-coded `models/model_card.json` instead of reading `config["engine"]["model_card"]`, AND `handle_early_flow_event` checked `if self.threshold == 0.25:` (bypassing `self.ckpt_thresholds` whenever a model card updated `self.threshold`).
2. `demo/run_smoke_pipeline.py` assigned `engine.checkpoint_thresholds` (typo for `engine.ckpt_thresholds`).
3. `demo/run_smoke_pipeline.py` simulated `benign_sensor_1` with `dir = pkt_i % 2` for `pkt_i=1..19` (`[1,0,1,0,...]`, inverted relative to client-first `[0,1,0,1,...]`) and `500 ms` IAT instead of `10 s` sensor IAT.

## 1f. Post-Fix Smoke Scores (`epochs=50`, `seed=42`, Determinism `10/10 IDENTICAL`)

- `offline_int8_auroc`: **`0.3213` -> `1.0000`** (`SYNTHETIC SMOKE — NOT A RESULT`; Item 2 further normalises `log_iat` by `/ 7.0`).
- Per-checkpoint INT8 AUROC (flows reaching `k`): `k=4: 0.9455`, `k=8: 0.9628`, `k=16: 0.9999`.
- `mock_closed_loop.json`: `attack_exfil_1` -> `DROP` at `pkt=4` (`sticky_drop_verdict=DROP_STICKY`, `15` packets dropped); `benign_sensor_1` -> `CONTINUE` (`k=4, 8`) -> `BYPASS` (`k=16`, `score=0.006777`, `3` packets bypassed).
