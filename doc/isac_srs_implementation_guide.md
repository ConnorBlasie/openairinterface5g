# Implementing the GPU SRS estimator: a step-by-step guide

This is the workshop walkthrough for the task described in [isac_srs_demo.md](isac_srs_demo.md):
replace the stub in `srs_est_cuda.cu` with a CUDA estimator that beats the gNB's fixed-point SRS
channel estimator, then prove it at three levels (unit test, link-level sim, end-to-end rfsim walk)
and plot the result. Read `isac_srs_demo.md` first for the "why"; this doc is the "do, in order."

[[_TOC_]]

## 0. Before you start

- A CUDA-capable machine (the reference target is a GB10, `sm_121`). Adjust
  `CMAKE_CUDA_ARCHITECTURES` to your GPU if different. Check both before you start, not after a
  build failure:
  ```bash
  nvidia-smi                    # an actual GPU must show up here
  nvcc --list-gpu-arch | tail   # the toolkit must list your target's compute capability
  ```
  A machine with no GPU at all (`nvidia-smi` can't talk to a driver) can still be used to read and
  write the `.cu` source, but can't compile or run any of it — `-DCMAKE_CUDA_ARCHITECTURES` needs a
  real device to target, and every verification step from §6 onward (`test_srs_est`, `nr_srssim`,
  the end-to-end rfsim walk) needs the module to actually execute. A toolkit that predates your
  target architecture fails even earlier, at compile time: e.g. CUDA 11.5 only goes up to `sm_87`
  and doesn't know `sm_121` (Blackwell/GB10) exists, so `cmake`/`nvcc` will reject that architecture
  flag outright. You need a real GPU and a CUDA toolkit new enough to target it.
  - If `nvcc` isn't found even though `nvidia-smi` works, the toolkit is probably installed but not
    on `PATH` (the driver and the toolkit are separate installs) — check
    `ls /usr/local/cuda*/bin/nvcc` and `export PATH=/usr/local/cuda/bin:$PATH` (that path is usually
    a symlink to whichever version is "current").
  - **Match `CMAKE_CUDA_ARCHITECTURES` to the GPU you're actually on, not to the doc's GB10
    default.** The workshop machines are easy to mix up:

    | Machine | GPU | Compute capability | `CMAKE_CUDA_ARCHITECTURES` |
    |---|---|---|---|
    | GB10 (the doc's reference target) | Blackwell | `sm_121` | `121` (needs CUDA 12.8+) |
    | GH200 Machine | GH200 (Grace Hopper) | `sm_90` | `90` |
    | A100 machine | A100 (Ampere) | `sm_80` | `80` |

    Confirm with `nvidia-smi --query-gpu=name,compute_cap --format=csv` — don't assume from the
    machine name alone.
- This repo (`oai_isac_demo`) and `../raytracing-channel-emulator`, sibling directories, both
  present. The emulator repo must be on branch `isac-demo` (it generates the CIR database; the gNB
  and UE don't need it at runtime, only the `.bin`/`.yaml` files it produces).
- Increase socket buffers once per machine, before running the rfsim pair (32 streams of
  122.88 Msps will deadlock the default kernel buffers otherwise):
  ```bash
  sudo sysctl -w net.core.wmem_max=100000000 net.core.rmem_max=100000000
  # already set on the pod devices
  ```

## 1. Generate the CIR database

The gNB/UE link replays a ray-traced channel instead of a statistical model. Generate it once; it's
reused by every rfsim run afterward.

```bash
git clone https://gitlab.eurecom.fr/oai/raytracing-channel-emulator.git -b isac-demo
cd raytracing-channel-emulator
git status   # confirm you're on isac-demo
cd server/isac
python3 scene_street.py --out out_full          # writes scene/, scene_topview.png
python3 generate_isac_cirdb.py --out out_full \
    --static 5.0 --motion 30.0 --dt 0.01        # writes cir_db.bin, isac.yaml, truth.npz, array.json
```

- `scene_street.py` builds the Sionna-RT street canyon: 8 buildings, one metal pillar, one metal
  vehicle driving through at 8 m/s, a 4x8 UPA gNB at 10 m, a 2x2 UE walking at 1.4 m/s.
- `generate_isac_cirdb.py` ray-traces it (pass 1) and synthesizes 128-tap, 122.88 Msps CIRs every
  10 ms (pass 2), self-checking each snapshot against the exact multipath response
  (`out_full/selfcheck.json`, target -50 dB NMSE — if this fails, don't bother debugging the GPU
  estimator yet, the database itself is broken). It takes a while; use `--quick` (200 snapshots) for
  a fast sanity pass while iterating on the scene, and the full `--static 5.0 --motion 30.0` run for
  the actual demo (5 s static attach phase + 30 s of UE/vehicle motion).
- A pre-generated `server/isac/out_full/` may already exist in that repo — check before
  regenerating; it's slow (ray tracing + tap synthesis).

Set `DB=$(pwd)/out_full` (or wherever you generated it) — every gNB/UE invocation below points
`--rfsimulator.[0].cirdb_yaml`/`cirdb_file` there.

## 2. Build OAI with the CUDA SRS module

Per repo convention, the build directory is `cmake_targets/ran_build/build` (the default `build_oai`
uses), not a `build/` at the repo root. Build with the `build_oai` wrapper; `--cmake-opt` passes
options straight through to `cmake`. Pick the invocation matching your GPU (see the table in §0):

```bash
git clone https://github.com/ConnorBlasie/openairinterface5g.git -b isac-task
cd openairinterface5g/cmake_targets
./build_oai -I   # once per machine, to install system dependencies

# GH200 machine (sm_90)
./build_oai --gNB --nrUE -w SIMU -P --ninja \
    --cmake-opt "-DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_CHANNEL_SIM_CUDA=ON -DENABLE_SRS_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=90 -DENABLE_TESTS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_CUDA_FLAGS=\"-Xcompiler -fPIC\"" \
    && cmake --build ran_build/build --target srs_est_cuda test_srs_est ldpc

# A100 machine (sm_80, x86)
./build_oai --gNB --nrUE -w SIMU -P --ninja \
    --cmake-opt "-DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_CHANNEL_SIM_CUDA=ON -DENABLE_SRS_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=80 -DENABLE_TESTS=ON -DCUDAToolkit_ROOT=/usr/local/cuda/targets/x86_64-linux -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_CUDA_FLAGS=\"-Xcompiler -fPIC\"" \
    && cmake --build ran_build/build --target srs_est_cuda test_srs_est ldpc
```

On an x86 host, CMake may need `-DCUDAToolkit_ROOT=/usr/local/cuda/targets/x86_64-linux` to find the
toolkit (already included in the A100 invocation above), or set it at the top of the root
`CMakeLists.txt`. 

`srs_est_cuda` and `ldpc` are both `MODULE` targets (loaded with `dlopen` at runtime as
`.so`s), so their object code must be position-independent. `CMAKE_POSITION_INDEPENDENT_CODE`
covers the C/C++ side; `nvcc` doesn't always honor it for its own compiles, so `-Xcompiler -fPIC`
forwards `-fPIC` to the underlying host compiler explicitly for `.cu` sources.

`ENABLE_SRS_CUDA` is declared in `openair1/PHY/NR_ESTIMATION/srs_est/CMakeLists.txt`, not the root
`CMakeLists.txt` — it's what turns on `add_library(srs_est_cuda MODULE srs_est_cuda.cu)`, producing
`libsrs_est_cuda.so` in this same build directory. The loader code (`srs_est_load.c`) is always
built in; without `--loader.srs_est.shlibversion _cuda` on the command line, nothing changes — the
gNB uses the fixed-point estimator exactly as it does today.

The rest of this guide invokes binaries the way the existing OAI docs do: `cd cmake_targets`, then
run `./ran_build/build/<binary>` with conf/data paths given relative to `cmake_targets` (i.e. one
`..` to reach the repo root) rather than `cd`-ing into the build directory itself — except for the
unit test and `nr_srssim`, which are self-contained and run directly from the build directory.

`-P` (`--phy_simulators`) is what gets you `nr_srssim`. Since `ENABLE_SRS_CUDA` makes `nr-softmodem`
and `nr_srssim` both depend on `srs_est_cuda` (see the root `CMakeLists.txt`), this one invocation
builds the CUDA module too. Two things it does *not* pull in, though, so build them directly against
the directory `build_oai` just populated:
- `srs_est_cuda` is the only target with that dependency wired in; `test_srs_est` has no such link
  and isn't behind any `build_oai` flag either.
- `ldpc` (the channel-coding module `nr-softmodem`/`nr-uesoftmodem` load at runtime) also isn't
  behind any flag: `build_oai` always appends `coding` to whatever you ask for (see below), but
  `coding`, `ldpc_orig` and `ldpc` are three separate MODULE targets in
  `openair1/PHY/CODING/CMakeLists.txt`, and only `coding` is in that auto-added list — `ldpc` itself
  is missing unless you ask for it. (`--build-lib` doesn't cover it either: that flag only knows the
  *offload* variants, `ldpc_aal`/`ldpc_cuda`/`ldpc_ors`, not plain `ldpc`.)

From here on, every command in this guide that says "build directory" means
`cmake_targets/ran_build/build`.

Separately: whenever `build_oai` is given any target at all, it silently also appends
`params_libconfig coding rfsimulator dfts params_yaml vrtsim rf_emulator` to the list
(`cmake_targets/build_oai:423`) — so `rfsimulator`, `params_libconfig` and `dfts` are already
covered by `-w SIMU` plus that auto-add; nothing extra to ask for there.

`ENABLE_CHANNEL_SIM_CUDA` is unrelated to your estimator; it's what accelerates the CIR-DB
convolution the rfsimulator itself does on each end. Needed for a 32x32 real-time-ish run, not for
`test_srs_est` or `nr_srssim`.

## 3. Where the fixed-point reference lives (read this before writing CUDA)

Your estimator replaces this, so read it first — it's the baseline you're told to beat, and the
signal layout it consumes is the same one your module receives.

| What | Where |
|---|---|
| Per-RE LS estimate (conjugate correlation against the reference sequence, CDM-combined over ports sharing a comb RE) | `nr_srs_ls_channel_estimation()`, `openair1/PHY/NR_ESTIMATION/nr_ul_channel_estimation.c:635` |
| Noise power from guard REs | `nr_srs_noise_power_estimation()`, same file, line 729 |
| LS estimate -> time domain (oversampled IDFT, for TA / PDP) | `nr_srs_freq_to_time()`, same file, line 773 |
| Fixed FIR interpolation from comb REs to every subcarrier (8-tap for comb-2, 16-tap for comb-4), after a phase-ramp delay correction | `nr_srs_channel_interpolation()`, same file, line 798 |

This is "LS + short FIR interpolator," all in `c16_t` fixed point — not MMSE, no exploitation of the
channel's delay sparsity beyond a single coarse delay correction. That's why it floors around
-20 to -30 dB NMSE depending on SNR (reference numbers for 32 rx / 4 ports / 273 PRB / TDL-A:
-4.1 dB @ 0 dB SNR, -23.8 dB @ 20 dB, -32.9 dB @ 40 dB — see `isac_srs_demo.md`). A sparse-delay-domain
method (truncate to a plausible excess-delay window, LMMSE or thresholded LS in the delay domain,
transform back) is what gets you below that floor.

## 4. Measure the fixed-point baseline first (no CUDA needed)

Before writing a line of the GPU estimator, get a number for what you're trying to beat — this
needs none of your own code, just the existing fixed-point path.

- **`nr_srssim` gives you this directly.** Run it with no `--loader.srs_est.shlibversion` flag at
  all and it uses the fixed-point estimator (`legacy_est()` in `openair1/SIMULATION/NR_PHY/srssim.c`)
  and reports its NMSE the same way it would for your module:
  ```bash
  cd ran_build/build
  
  ./nr_srssim -R 273 -z 32 -y 4 -g A,l,0 -s 0 -S 40 -N 0 -n 3 --loader.srs_est.shlibversion _cuda #fairly slow

  ctest -R nr_srssim.module --output-on-failure


  ```
  This is exactly the "fixed point (the default)" column of the target table in `isac_srs_demo.md`
  (e.g. -25 dB for module3's 51 PRB/8 rx/4 port/TDL-A/20 dB case) — reproduce it yourself here before
  trusting the doc's numbers or comparing your own module's improvement against them. It works
  for any PRB/antenna/port/channel-model combination you want to probe, not just the five fixed
  `ctest` scenarios.
- **`test_srs_est` cannot do this** — it `dlopen`s `libsrs_est_cuda.so` specifically and has no path
  to the fixed-point code at all; it's module-only by construction.
- **The end-to-end `--isac.dump_file` export cannot do this either**, and this one's worth
  understanding precisely because it's not obvious from the CLI: in
  `openair1/SCHED_NR/phy_procedures_nr_gNB.c`, `gNB->srs_est_last.valid` (the flag that gates both
  the `isac_dump_record()` call around line 1163 and the export check at line 1203) is only ever set
  `true` inside `srs_module_estimation()`, on a successful GPU-module call. The fixed-point branch
  (the `else if (*srs_est >= 0)` a few lines below it, which calls
  `nr_srs_ls_channel_estimation()`/`nr_srs_channel_interpolation()`) never touches `srs_est_last` at
  all. So with no module loaded, the rfsim demo runs fine and SRS works, but `isac.bin` stays empty
  — `--isac.dump_file`/`nmse_vs_truth.py` only ever scores your GPU module, never the fixed-point
  baseline, no matter how you invoke the gNB.

In short: use `nr_srssim` for the fixed-point number at whatever scale you care about (including the full
32x32/273 PRB config from §8, if you want the true 20 dB SNR comparison point:
`./nr_srssim -R 273 -z 32 -y 4 -g A,l,0 -s 20 -S 20 -n 10`), and treat that as your "before" — there's
no way to get a fixed-point "before" number out of the unit test or the end-to-end walk.

## 5. Where your GPU implementation goes

**File:** `openair1/PHY/NR_ESTIMATION/srs_est/srs_est_cuda.cu` — three functions, currently stubs:

```c
extern "C" int32_t srs_est_init(int max_rx, int max_ports, int max_M, int max_K_TC);
extern "C" int32_t srs_est_run(const srs_est_in_t *in, srs_est_out_t *out);
extern "C" void    srs_est_shutdown(void);
```

- `srs_est_init()`: allocate device buffers sized off the `max_*` arguments (worst case this run will
  ever ask for — 32 rx, 4 ports, `M` up to 1632 comb REs, `K_TC` up to 4), create your FFT plans
  (`cuFFT`, already linked) and/or solver handles (`cuSOLVER`, already linked) once, here — not per
  call. A `cudaStream_t` is already created for you.
- `srs_est_run()`: do the actual estimation. Currently calls `check_input()` (bounds checks) and then
  returns -1 unconditionally, which is why the gNB always falls back today.
- `srs_est_shutdown()`: free what `srs_est_init()` allocated.

**Interface contract:** `openair1/PHY/NR_ESTIMATION/srs_est/srs_est_interface.h`. The signal model it
documents is what you're inverting:

```
Y_p[a][l][k] = sum_q H_q[a][k] * rbar[l][k] * exp(j 2*pi*n_cs_q*k / n_cs_max) + noise
```
(sum over every port `q` sharing port `p`'s comb; `a` = gNB antenna, `l` = SRS symbol, `k` = comb RE
index 0..M-1).

Inputs (`srs_est_in_t`): `nb_rx`, `n_ports`, `n_symb`, `M`, `K_TC`, `n_cs_max`, per-port `n_cs[]`/
`comb[]`, `y` (received REs, `[port][antenna][symbol][M]`, `c16_t`), `rbar` (unit-modulus base
sequence with no cyclic shift applied, `[symbol][M]`, `cf_t`), `method` (`SRS_EST_LMMSE` or
`SRS_EST_DFT`), `win_pre`/`win_post` (delay search window in M-point bins, before/after n=0 —
`win_post` in particular has to cover the street's excess delay, up to ~1 µs with paths 40 dB down),
`oversampling`, `scs_hz`, `pdp_threshold`.

Outputs (`srs_est_out_t`): `h_comb` (`[port][antenna][M]`, your estimate at the comb REs),
`h_full` (`[port][antenna][K_TC*M]`, interpolated to every subcarrier — this is what gets converted
back to `c16_t` and feeds the rest of L1), `noise_var` (per RE), `signal_power` (mean `|h_comb|^2`),
`timing_offset_s` (informational).

Keep in mind while designing the kernel(s):
- Ports on the same comb are told apart only by cyclic shift — you cannot separate them per-RE
  without using the CS structure (that's what the `exp(j*2*pi*n_cs_q*k/n_cs_max)` term is for).
- The UE's timing advance moves in ~0.26 µs steps, so the channel's dominant tap is not at delay 0 —
  don't assume it is when windowing or truncating in the delay domain.
- `win_post` needs to be wide enough for 1 µs+ multipath, but a too-wide window just integrates more
  noise into `h_full` — this is the main accuracy/robustness knob.
- One SRS is 32 ant x 4 ports x 1632 comb REs, arriving every 10 ms — that's also your throughput
  budget (see the timing target below).

**You do not need to touch** the glue (`srs_module_estimation()` /
`nr_srs_rx_procedures()` in `openair1/SCHED_NR/phy_procedures_nr_gNB.c`) or the loader
(`srs_est_load.c`) — they already build `srs_est_in_t`, call your `run()`, convert `h_full` back to
`c16_t` (scaled by `c16_scale = sqrt(N_ap)` to match the fixed-point gain convention) so TA/SNR/
SRS.indication/MAC are unaffected, and export `h_comb` via `isac_dump_record()` when
`--isac.dump_file` is set.

## 6. Unit test: exact synthetic channel

Fastest feedback loop — no rfsim, no core network, just your module against a known channel.

Continue to build and prototype your implementation.

You can drop the following from the section 4 testing in order to run the GPU variant:
--loader.srs_est.shlibversion _cuda

`openair1/PHY/NR_ESTIMATION/srs_est/tests/test_srs_est.cpp` `dlopen`s `libsrs_est_cuda.so` directly
and drives it with a synthetic 5-tap channel (delays out to ~1 µs, powers down to -20 dB, independent
random phase per antenna/port — i.e. a rich, off-grid multipath scenario, not a toy single-tap one),
computing NMSE against the exact noiseless channel. It sweeps 8 rx / 1-4 ports / comb-2 and comb-4 /
single- and multi-symbol-averaged / with and without UE timing offset, gated per case from -18 dB
(the simpler DFT method, off-grid) up to -70 dB (no noise, LMMSE). See `isac_srs_demo.md`'s target
table for the full gate list. All cases must pass before moving on — this is where you'll spend most
of your debugging time, with the fastest iteration.

## 7. Link-level simulator: realistic channel models, sweepable SNR

```bash
cd ran_build/build
./nr_srssim -R 273 -z 32 -y 4 -g A,l,0 -s 0 -S 40 -N 0 -n 3 --loader.srs_est.shlibversion _cuda
ctest -R nr_srssim.module --output-on-failure
```

`-N <dB>` is the pass/fail gate (exit nonzero if NMSE doesn't clear it); without
`--loader.srs_est.shlibversion _cuda` you get the fixed-point estimator's number instead, which is
the right way to sanity-check the harness itself before trusting a GPU result (§4).
`ctest -R nr_srssim.module` runs the five fixed scenarios wired up in
`openair1/SIMULATION/tests/CMakeLists.txt` (51-273 PRB, TDL-A/C/AWGN, comb-2/4, 1-4 ports) against
the per-scenario gates in the target table. These exercise realistic 3GPP channel models (not just
the unit test's synthetic taps) and a PRB count that matches the real 32x32 demo.

## 8. End-to-end: core network, gNB, UE over the ray-traced channel

### With the 5G core

**Core network** (everything except gNB/UE, which run on the host):

```bash
cd ci-scripts/yaml_files/5g_rfsimulator
docker compose up -d mysql oai-amf oai-smf oai-upf oai-ext-dn
```

The config expects the gNB reachable at `192.168.71.129` on the host.

**gNB and UE**, `DB` pointing at the directory with `isac.yaml`/`cir_db.bin` from step 1. Run from
`cmake_targets` (binaries at `ran_build/build/`, conf/data paths relative to the repo root, same as
the rest of the OAI docs) — `isac.bin` lands in `cmake_targets/` too. Set `DB` and `CH` in both
terminals:

```bash
cd cmake_targets
DB=/home/blasie/oai_nc_state_demo/raytracing-channel-emulator/server/isac/out_full
CH="--rfsimulator.[0].cirdb_yaml $DB/isac.yaml --rfsimulator.[0].cirdb_file $DB/cir_db.bin --channelmod.noise_power_dBFS -63"

# Terminal 1: gNB
sudo ./ran_build/build/nr-softmodem -O ../ci-scripts/conf_files/gnb.sa.band78.273prb.rfsim.32x32.isac.conf --rfsim $CH \
     --loader.srs_est.shlibversion _cuda --isac.dump_file isac.bin 2>&1 | tee gnb.log

# Terminal 2: UE
sudo ./ran_build/build/nr-uesoftmodem -O ../ci-scripts/conf_files/nrue.uicc.conf -C 3450720000 -r 273 --numerology 1 \
     --band 78 --ssb 1518 --rfsim --rfsimulator.[0].serveraddr 127.0.0.1 \
     --ue-nb-ant-tx 4 --ue-nb-ant-rx 4 \
     --uecap_file ../targets/PROJECTS/GENERIC-NR-5GC/CONF/uecap_ports4.xml $CH
```

### Without the 5G core (`--phy-test`)

Same channel, no core network or RRC attach. The gNB still logs
`[NR_MAC] Invalid timing advance offset for RNTI 1234` in this mode.

```bash
cd cmake_targets
DB=/home/jovyan/raytracing-channel-emulator/server/isac/out_full
CH="--rfsimulator.[0].cirdb_yaml $DB/isac.yaml --rfsimulator.[0].cirdb_file $DB/cir_db.bin --channelmod.noise_power_dBFS -63"

# Terminal 1: gNB
sudo ./ran_build/build/nr-softmodem -O ../ci-scripts/conf_files/gnb.sa.band78.273prb.rfsim.32x32.isac.conf --rfsim --phy-test \
     --uecap_file ../targets/PROJECTS/GENERIC-NR-5GC/CONF/uecap_ports4.xml $CH \
     --loader.srs_est.shlibversion _cuda --isac.dump_file isac.bin 2>&1 | tee gnb.log

# Terminal 2: UE
sudo ./ran_build/build/nr-uesoftmodem --phy-test -C 3450720000 -r 273 --numerology 1 --band 78 --ssb 1518 \
     --rfsim --rfsimulator.[0].serveraddr 127.0.0.1 --ue-nb-ant-tx 4 --ue-nb-ant-rx 4 $CH
```

### Notes

- `uecap_ports4.xml` is what makes the UE advertise 4 SRS ports — without it you'll silently get a
  single-port SRS and a much less interesting (and less representative) test.
- Without `--loader.srs_est.shlibversion _cuda` the same setup runs fine on the fixed-point
  estimator (attach works, SRS works) but nothing is exported — useful as a baseline sanity check if
  the demo with the CUDA module doesn't come up.
- With the stub as shipped, the gNB logs that the module failed and falls back to fixed point for
  every SRS — that's expected until step 5 is actually implemented.
- The `tee gnb.log` above is what makes `--gnb-log gnb.log` in the plotting step work — the launch
  command doesn't save its output anywhere on its own, and `nmse_vs_truth.py` needs that file (it
  greps it for the line below). Without the `tee`, pass `--t0 <N>` instead, read directly off
  whatever terminal/log already has the gNB's output.
- Watch the gNB log for `"CIR DB: snapshot 0 starts at timestamp <N>"` — that timestamp is `t0`,
  needed for the plotting step below if you don't pass `--gnb-log` directly.
- The database has 5 s of a static scene (for attach) then 30 s of motion, replayed ~60x slower than
  real time on a GB10 — budget ~40 minutes for the full walk. Use `--isac.min_interval_ms` and
  `--isac.max_records` to thin/bound the export while iterating.
- Known gotcha (see `isac_srs_demo.md` Limits): the UE's MAC has crashed
  (`get_pucch_start_symbol_length()` on a NULL PUCCH resource) on RRC re-establishment when 4 DL
  layers are allowed in a ray-traced street with rank-3 reported; the shipped `.conf` already pins
  `maxMIMO_layers = 1`, which has held for the full run — don't raise it without re-testing.

## 9. Plotting / scoring the result

**NMSE against the true channel** (fits and removes the UE's unknown TX gain/phase and the link's
absolute timing per record, since neither matters for sensing but both would otherwise dominate a
naive NMSE):

```bash
cd tools/isac
python3 nmse_vs_truth.py --dump ../../cmake_targets/isac.bin --cirdb $DB --gnb-log ../../cmake_targets/gnb.log --out nmse.json --gate-db -30
```
`nmse.json` has a `summary` block (`nmse_db_median`/`p10`/`p90`/`worst`, `snr_db_median`,
`records`/`records_without_srs`, snapshot range covered) and a per-record list
(`frame`/`slot`/`snapshot`/`nmse_db`/`gain_db`/`delay_ns`/`snr_db`). `--gate-db -30` matches the
end-to-end target in `isac_srs_demo.md` (median NMSE over the walk below -30 dB) and exits nonzero
if it isn't met — wire this into the same place you'd wire a CI gate.

**Reading the rest of `summary`, beyond the pass/fail gate:**
- `nmse_db_p10`/`nmse_db_p90` — the best and worst 10% of records. A healthy run has these fairly
  close together (a few dB either side of the median); a wide spread, especially a `p90` well above
  the `-30` dB gate even when the median clears it, usually means the estimator does fine most of
  the time but struggles during specific stretches of the walk — check which records those are
  (sorted by `nmse_db` in the per-record list) and what the UE/vehicle were doing then (near a
  building corner, the vehicle passing close by, a moment of weak SRS SNR).
- `nmse_db_worst` — the single worst record. One or two outliers (e.g. right at attach, or right
  after an RRC re-establishment) are normal; if `worst` is dramatically bad (think -5 dB, not -20)
  and isn't an isolated blip, that's worth a closer look rather than averaging over.
- `snr_db_median` — the estimator's own view of its SNR (`signal_power`/`noise_var` from the
  exported header, not a comparison against truth). It should roughly track
  `--channelmod.noise_power_dBFS` from the run; if it's much lower than you'd expect from that
  setting, the estimator's noise/signal-power bookkeeping is probably off even if NMSE itself looks
  fine, since noise_var/signal_power aren't part of what the NMSE gate checks.
- `records_without_srs` — records where `signal_power == 0` (no SRS found that occasion), filtered
  out before scoring. A handful near the very start (before the UE attaches) is expected; a nonzero
  count scattered throughout the motion phase suggests the SRS detection itself (not your estimator)
  is dropping out — cross-check against `[NR_PHY] No SRS signal` in the gNB log.
- `gain_db`/`delay_ns` per record (the fitted nuisance parameters `fit_gain_delay` removes before
  scoring) — not gated, but worth a sanity glance: `delay_ns` should drift smoothly as the UE/vehicle
  move, not jump erratically record to record, and `gain_db` should stay roughly flat if the UE's
  transmit power is constant. Either one jumping around is a sign something's unstable in the fit
  (or in the estimate it's fitting to) even if the final `nmse_db` still happens to pass.

**Visualizing the sensing result** — reconstructing the street from the estimated multipath (what
the reference demo output looks like): take the per-port `h_comb`/`h_full` estimates
(`tools/isac/isac_io.py`'s `read_srs_dump()` gives you `SrsRecord.h[port][antenna][M]` plus
subcarrier/timestamp helpers), run a delay-domain transform per antenna pair to pull out resolvable
paths above the noise floor, and triangulate each path as a point on a bistatic ellipse (gNB and UE
positions from `array.json`/the known UE track, or from `truth.npz` while validating). The reference
visualization plots one square per detected reflection (sized by wavelength, colored by delay/power
relative to the strongest path, down to a -30 dB floor), the estimated LOS and reflected rays,
building geometry, and the Sionna ray-tracer's ground-truth rays and UE track side by side for
comparison — use `truth.npz` (loaded via `isac_io.load_truth()`) for that comparison layer while
you're developing, then drop it for a live/blind run. This part is open-ended; `nmse_vs_truth.py`
only scores raw channel accuracy; turning that into a street reconstruction is the sensing
application on top and is where you have room to build whatever's useful for the workshop's goals
(a single static plot per snapshot, or an interactive 3D view like the reference).

## 10. Timing target

Once correctness gates (unit test, `nr_srssim.module1-5`) pass, check throughput: one SRS worth of
work (32 antennas x 4 ports x 273 PRB, i.e. the full comb grid) has to run "well under" the 10 ms SRS
period on the target GPU (the doc gives the GB10 as reference) — profile `srs_est_run()` alone
(`nvprof`/`nsys`, or simple `cudaEventRecord` timers around it) before worrying about end-to-end wall
clock, since the rfsim motion replay itself is intentionally slowed down and not representative of
real-time throughput.

## 11. Suggested order of work

1. Read §3 (fixed-point reference) and §5 (interface) fully before writing any CUDA.
2. Build (§2), confirm the stub builds and the gNB logs the fallback message over rfsim — proves the
   plumbing works before you touch the kernel.
3. Get the fixed-point baseline number (§4) via `nr_srssim` with no `--loader` flag, at whatever
   scale you'll ultimately be judged on — you need a "before" to know if your "after" is real.
4. Implement against the unit test (§6) first — fastest loop, exact known channel, catches basic
   algorithm bugs (CS separation, delay windowing, comb interpolation) before SNR and realistic
   channel models are in the mix.
5. Move to `nr_srssim` (§7) once the unit test gates pass — this is where TDL-A/B/C and the realistic
   273-PRB/32-antenna scale show up, and where you compare directly against the §4 baseline.
6. Only then run the full end-to-end rfsim + core network walk (§8) and score it (§9) — it's the
   slowest loop (tens of minutes) and the hardest to debug blind, so leave it for validation, not
   development.
