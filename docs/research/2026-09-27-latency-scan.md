# Latency scan for M4 plan 4

**Date:** 2026-09-27
**Status:** Research notes feeding M4 spec §16.12 and plan 4. Measurements were taken on an Apple M4 (4P+6E) while another build loaded the machine (load average 8–12): single-thread numbers were stable, 4-thread numbers varied up to 1.5×, so compare ratios within a run. x86 statements come from source analysis unless marked measured.
**Reproduction:** the scripts in `2026-09-27-latency/` (Python, build-time only; `onnx`, `onnxruntime` 1.30, `numpy`). A Rust harness used `ort =2.0.0-rc.13` (ORT 1.28).

This complements `2026-09-27-prior-art.md` §3, which lists the ideas already in spec §16.12.

## 1. Inference-level findings (measured)

### 1.1 GLiNER's span head is half its runtime; an exact rewrite removes most of it

- An ONNX Runtime node profile of gliner-x-small (`t_nodes.py`) puts `span_rep_layer/out_project` at 29.9 % + 17.4 % of runtime. It is an MLP over every candidate span (277 words × `max_width` 12 = 3324 spans): [3324,1536]×[1536,3072] then ×[3072,768], about 47 GFLOP per chunk against about 17 GFLOP for the whole mT5 encoder.
- GLiNER's markerV0 head computes `out = W2·relu(W1·relu([s_i; e_j]) + b1) + b2` and `logit_c = out·p_c`. Because `relu` is elementwise and `W1·[s;e] = W1a·s + W1b·e`, this equals `relu(A_i + B_j)·(W2ᵀ p_c) + b2·p_c` with `A = relu(S)·W1a` and `B = relu(E)·W1b + b1` computed once per word, not once per span.
- `rewrite_head.py` performs this as ONNX graph surgery; inputs and outputs are unchanged, so `crates/inumaki-models/src/gliner.rs` needs no change.
- Accuracy: fp32 original versus fp32 rewritten, max |Δlogit| 4e-5. Against the shipped int8 model (whose head was int8), max 0.064; entities identical at thresholds 0.3 and 0.5 over 48 chunks (1225/1225) (`t_fasthead.py`).
- Speed, 5 KB input (4 chunks), ORT 1.28 on M4: 1 thread 727 → 323 ms (2.25×); 4 threads 255 → 147 ms (1.7×). On compute-bound x86 cores the gain should approach the FLOP ratio (about 70 → 25 GFLOP per chunk); not measured.

### 1.2 The shipped GLiNER int8 model uses the slowest int8 kernel

- Its `MatMulInteger` weights are uint8, asymmetric, per-tensor (zero points 88–123); the mBERT verifier's are int8, symmetric, per-channel.
- ONNX Runtime's MLAS picks kernels by type (`onnxruntime/core/mlas/lib/platform.cpp`): U8U8 gets a VNNI kernel only with AVX-VNNI-INT8 (lines 674–686), which Intel N100 (Gracemont) lacks; U8S8 uses the AVX-VNNI kernel (lines 598–614), which N100 has.
- Micro-GEMM [512×768]×[768×3072], M4, 1 thread: U8U8 5.5 ms, U8S8 1.2 ms, fp32 1.5 ms.
- Accuracy against fp32 with the same dequantized weights: shipped u8, mean |Δlogit| 1.28, max 9.9 (per-tensor u8 activation quantization); S8 per-channel on the M4 SME path, mean 0.087, max 0.70. Crude recall on 12 synthetic texts: names 374/377 (u8), 377/377 (fp32), 377/377 (S8); streets 144/157, 149/157, 151/157.
- `requant_s8.py` re-encodes the weights as int8 symmetric per-channel. Re-encoding from the u8 weights changed about 20 % of spans on M4; requantizing from the fp32 export is preferable. Either way this needs the eval gate.

### 1.3 On SME Macs (M4 and later), fp32 is fastest

- ONNX Runtime's KleidiAI integration sends fp32 GEMM to SME. fp32 fast-head GLiNER (built from `onnx/model.onnx`, 689 MB): 5 KB in 182 ms at 1 thread (4× the current 727 ms), 136–177 ms at 4 threads. mBERT fp32 364 ms versus int8 436 ms at 1 thread, about equal at 4.
- KleidiAI's dynamic-int8 path runs only with SME (`qgemm.cpp:206-210`) and needs a symmetric zero point (`matmul_integer_base.h:181`). M1–M3 use NEON sdot/udot, where int8 still wins, so variants must be chosen per CPU class.
- Output hashes were bit-identical at 1, 2, and 4 threads for every variant, so the eval's thread-determinism rule holds. Kernel choice differs per platform, so baselines stay per platform variant.

### 1.4 Threads and sessions on M4

SME units are shared per cluster. mBERT int8: 1 thread 436 ms, 4 threads 240 ms at best; 4 processes × 1 thread about 312 ms per pass of throughput; 2 sessions × 2 threads was worse than 1 × 4. Spec §7's `sessions > 1` must be measured on M4 specifically. Turning ORT spinning off changed nothing in latency (436 versus 437 ms) and saves idle CPU.

### 1.5 Smaller items

- Pre-optimized model (`with_optimized_model_path`): load 250 → 190 ms per model, identical outputs; the `.ort` format gave nothing more.
- One pre-tokenized encode call with `word_ids` instead of per-word encoding: 2.9 → 2.1 ms per 5 KB (0.7 ms with a word cache). Low value.
- CoreML EP: dynamic shapes 820–1300 ms (slower); static 512 MLProgram 182–236 ms but 114–152 s compile at load and fp16 outputs that differ from CPU. Avoid.
- XNNPACK EP: fp32 MatMul/Gemm only, no dynamic int8, not in prebuilt binaries. OpenVINO EP: custom ORT build, no published N100 numbers. Candle and tract: much slower than ORT for encoders (Manticore reports about 14× for embeddings). Avoid.
- Jasper Lake/Gemini Lake Celerons (N5105, J4125) have no AVX2 and fall back to SSE kernels: best effort only.

## 2. How similar privacy projects handle latency (source-level)

Only radianceteam/pii-shield shows measured latency engineering. CloakPipe's "3.2 ms" benchmark runs with NER disabled (`crates/cloakpipe-core/examples/pii_benchmark.rs:317`, `config.rs:160`).

| Project | Technique | Evidence | Numbers | Recall impact |
|---|---|---|---|---|
| radianceteam/pii-shield | Cross-turn findings cache keyed by policy, model, and NER availability; offsets and kinds only; large results not cached | `src/pii_shield/shield.py:370-450` | turn 5 of a growing session 2.69 → 0.61 s | none if the key is complete |
| radianceteam/pii-shield | Profiled non-model code: quadratic dedup was a fifth of detection time | README 424-462 | 199 KB: 7.19 → 2.90 s | none |
| radianceteam/pii-shield | Ask NER only for entities the policy acts on | `shield.py:353-395` | 1.34× | none |
| radianceteam/pii-shield | Threads over blank-line blocks, only ≥ 32 KB; batching alone gave nothing | `shield.py:50,297-345` | 392 KB: 6.85 → 2.04 s at 8 threads | ~0 |
| ort issue #402 | `run(&mut self)` since rc.10; transmuting to share a session is undefined behaviour; intra-op threads past physical cores fall off a cliff | github.com/pykeio/ort/issues/402 | 5 threads 1.19 s, 6 threads 1.94 s | — |
| Kiji | Fixed [1,512] tensors, batch 1; shared bound tensors without a lock; full history re-masked every turn; one AVX-512-VNNI int8 build for all platforms | `onnx_model_detector.go:714-790, 842-887` | — | data race can return another request's spans |
| CloakPipe | Mutex per session; GLiNER truncates at 512 with a warning | `detector/gliner.rs:79,188,270-279` | — | silent truncation |
| PII-Shield (gregmos) | 2500-char chunks; larger chunks raised GLiNER scores; quint8 GLiNER found zero entities; NER only on the first 8000 characters | `pii-engine.ts:27-42`, `ner-backend.ts:653-667, 2025-2028` | ~1 s per chunk | fail-open truncation |
| GLiNER (Python) docs | Overlap ≥ `max_width − 1` words guarantees span containment; stock DeBERTa loses accuracy under int8 | `docs/usage.md:365-455` | int8 about 1.6× | — |
| gliner npm 0.0.19 | 512-word blocks with no overlap | `model.ts:84-120` | — | boundary splits |
| LLM Guard | Lazy load, no warm-up; head/tail truncation | `transformers_helpers.py:43-65` | Anonymize 317 chars: 177 ms, 129 ms ONNX (m5.xlarge) | truncation |
| Presidio | Quadratic dedup (#2280: 27 s for 20k results); character chunker cannot split whitespace-free text | `chunkers/base_chunker.py:83` | — | oversized chunks |
| LiteLLM Presidio guardrail | Gather serialized by a lock, no cross-turn cache, fails open | `presidio.py:317-322, 1411-1491` | — | fail-open |
| mcp-server-conceal | Whole-text cache in SQLite storing originals, unkeyed hash, no config in key | `mapping.rs:72-80, 240-265` | — | stale results, stored originals |

## 3. What this adds to plan 4

In addition to spec §16.12:

1. **Span-head rewrite** of GLiNER at model-build time (§1.1). Largest single win; exact in fp32.
2. **Per-CPU-class model variants**: fp32 on SME Macs, S8 symmetric per-channel int8 elsewhere (§1.2–1.3), selected at startup from CPU features, each with its own baseline.
3. **Profile Rust stages as well as ORT** and remove quadratic work (span decode, overlap dedup, merge, collapse, resolve).
4. **Skip the sanitizer's NER where it cannot change the output**: every NER label preserved by policy, or a slot fully covered by a deterministic detector. The verifier still runs.
5. **Warm-up** of every pooled session with the largest shape before the daemon reports ready; pre-optimized model files for load time.
6. **Threads**: intra-op threads at or below physical cores, 1–2 on SME Macs pending measurement; spinning off; measure batching and parallel sessions separately with a size threshold.
7. **Chunk geometry**: fewer, larger chunks with overlap ≥ `max_width − 1` words, chosen by a recall-gated sweep.
8. **Cache key completeness**: model manifest hash, label and floor-threshold fingerprint, policy version, pipeline-health flag, and a size cap per entry.

Anti-patterns plan 4 tests against: silent truncation, overlap below `max_width`, whitespace-free text forming one oversized chunk, failing open under load or timeout, shared mutable inference state, quantization without per-platform DACH exact-span parity, caches holding originals or incomplete keys, benchmarks that hide which stages ran, and head/tail or last-message-only speed modes.

Watch list, not plan 4: GLiNER StreamingSpan (causal KV-cache append, `knowledgator/gliner-stream-pii-v1.0`) and banded-attention privacy-filter kernels.
