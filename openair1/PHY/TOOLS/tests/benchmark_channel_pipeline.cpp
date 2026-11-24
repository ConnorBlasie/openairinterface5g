/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <time.h>
#include <getopt.h>
#include "oai_cuda.h"
#include "common/config/config_userapi.h"
#include <memory>
#include <chrono>
#include <cstring>
#include <sys/mman.h>
#include "benchmark/benchmark.h"
#include "test_channel_pipeline_tools.h"
#include "channel_pipeline.h"
extern "C" {
#include "openair1/SIMULATION/TOOLS/sim.h"
}
configmodule_interface_t *uniqCfg = NULL;

extern "C" void exit_function(const char *file, const char *function, const int line, const char *s, const int assert)
{
  fprintf(stderr, "FATAL: %s at %s:%s:%d\n", s, file, function, line);
  exit(EXIT_FAILURE);
}

#define MAX_SAMPLE_LENGTH (65536)

#ifdef CHANNEL_SIM_CUDA
static void BM_channel_convolution_gpu(benchmark::State &state)
{
  int nb_rx = state.range(0);
  int nb_tx = state.range(1);
  int num_samples = state.range(2);
  int channel_length = state.range(3);

  // nb_tx=64 and nb_rx>4 are outside the currently supported GPU pipeline configuration;
  // Support all lesser link level configs and skip unsupported configs
  if (nb_tx * nb_rx > (64 * 4)) {
    state.SkipWithMessage("nb_tx=64 with nb_rx > 4  is not currently supported");
    return;
  }
  // Skip any configs where RX is larger than TX as this is not a realistic case
  if (nb_tx < nb_rx) {
    state.SkipWithMessage("No configs where RX antenna count is > TX antenna count");
    return;
  }

  size_t num_input_samples = num_samples + channel_length - 1;
  std::vector<c16_t *> input(nb_tx);
  for (int i = 0; i < nb_tx; ++i) {
    input[i] = new c16_t[num_input_samples];
  }

  std::vector<c16_t *> output(nb_rx);
  for (int i = 0; i < nb_rx; ++i) {
    output[i] = new c16_t[num_samples];
  }

  std::vector<cf_t *> channel(nb_rx * nb_tx);
  for (int i = 0; i < nb_rx * nb_tx; ++i) {
    channel[i] = new cf_t[channel_length];
  }

  for (int i = 0; i < nb_rx * nb_tx; ++i) {
    generate_random_signal_float(channel[i], channel_length);
  }

  void *gpu_context = cuda_channel_pipeline_init(MAX_SAMPLE_LENGTH, nb_tx, nb_rx, channel_length);

  for (int aatx = 0; aatx < nb_tx; aatx++) {
    generate_random_signal(input[aatx], num_input_samples);
  }

  size_t total_samples = 0;
  for (auto _ : state) {
    cuda_channel_pipeline(gpu_context,
                          (const cf_t **)channel.data(),
                          (const c16_t **)input.data(),
                          nullptr,
                          num_input_samples,
                          output.data(),
                          nullptr,
                          num_samples,
                          num_samples,
                          channel_length,
                          nb_tx,
                          nb_rx,
                          0.0f);
    total_samples += num_samples;
  }
  state.counters["MSPS"] = benchmark::Counter(total_samples / 1000000.f, benchmark::Counter::kIsRate);

  cuda_channel_pipeline_shutdown(gpu_context);
}

// One call as vrtsim makes it: context sized for 1 ms at 61.44 Msps, TX split into history and new samples,
// same taps on every call (the CIR changes about once per second).
static void BM_channel_pipeline_gpu_vrtsim(benchmark::State &state)
{
  const int nb_tx = state.range(0);
  const int nb_rx = state.range(1);
  const int num_samples = state.range(2);
  const int channel_length = state.range(3);
  const int hist = channel_length - 1;

  std::vector<std::vector<c16_t>> tx0(nb_tx, std::vector<c16_t>(hist)), tx1(nb_tx, std::vector<c16_t>(num_samples));
  std::vector<const c16_t *> tx0_p(nb_tx), tx1_p(nb_tx);
  for (int a = 0; a < nb_tx; a++) {
    generate_random_signal(tx0[a].data(), hist);
    generate_random_signal(tx1[a].data(), num_samples);
    tx0_p[a] = tx0[a].data();
    tx1_p[a] = tx1[a].data();
  }
  std::vector<std::vector<c16_t>> out(nb_rx, std::vector<c16_t>(num_samples));
  std::vector<c16_t *> out_p(nb_rx);
  for (int r = 0; r < nb_rx; r++)
    out_p[r] = out[r].data();
  std::vector<std::vector<cf_t>> taps(nb_tx * nb_rx, std::vector<cf_t>(channel_length));
  std::vector<const cf_t *> chan_p(nb_tx * nb_rx);
  for (int l = 0; l < nb_tx * nb_rx; l++) {
    generate_random_signal_float(taps[l].data(), channel_length);
    chan_p[l] = taps[l].data();
  }

  void *gpu_context = cuda_channel_pipeline_init(61440, nb_tx, nb_rx, channel_length);
  for (auto _ : state) {
    cuda_channel_pipeline(gpu_context,
                          chan_p.data(),
                          tx0_p.data(),
                          tx1_p.data(),
                          hist,
                          out_p.data(),
                          nullptr,
                          num_samples,
                          num_samples,
                          channel_length,
                          nb_tx,
                          nb_rx,
                          0.0f);
  }
  cuda_channel_pipeline_shutdown(gpu_context);
}

// Host-memory side of a vrtsim call. mode 0: CPU never touches the buffers. mode 1: as vrtsim_write_with_chanmod, the CPU
// writes the TX input, then copies each RX output into a MAP_SHARED ring (shm_td_iq_channel_tx); gpu_us and copy_us are
// timed separately. mode 2: the GPU writes straight into a rotating ring, so each call touches new pages.
static void BM_channel_pipeline_gpu_vrtsim_io(benchmark::State &state)
{
  const int nb_tx = state.range(0);
  const int nb_rx = state.range(1);
  const int num_samples = state.range(2);
  const int channel_length = state.range(3);
  const int mode = state.range(4);
  const int hist = channel_length - 1;
  const size_t ring_len = 30720 * 20; // CIRCULAR_BUFFER_SIZE in shm_td_iq_channel.c

  std::vector<std::vector<c16_t>> tx0(nb_tx, std::vector<c16_t>(hist)), tx1(nb_tx, std::vector<c16_t>(num_samples)),
      src(nb_tx, std::vector<c16_t>(num_samples));
  std::vector<const c16_t *> tx0_p(nb_tx), tx1_p(nb_tx);
  for (int a = 0; a < nb_tx; a++) {
    generate_random_signal(tx0[a].data(), hist);
    generate_random_signal(src[a].data(), num_samples);
    tx1[a] = src[a];
    tx0_p[a] = tx0[a].data();
    tx1_p[a] = tx1[a].data();
  }
  std::vector<std::vector<c16_t>> out(nb_rx, std::vector<c16_t>(num_samples));
  const size_t ring_bytes = sizeof(c16_t) * ring_len * nb_rx;
  c16_t *ring = (c16_t *)mmap(NULL, ring_bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (ring == MAP_FAILED) {
    state.SkipWithError("mmap failed");
    return;
  }
  memset(ring, 0, ring_bytes);
  std::vector<c16_t *> out_p(nb_rx);
  std::vector<std::vector<cf_t>> taps(nb_tx * nb_rx, std::vector<cf_t>(channel_length));
  std::vector<const cf_t *> chan_p(nb_tx * nb_rx);
  for (int l = 0; l < nb_tx * nb_rx; l++) {
    generate_random_signal_float(taps[l].data(), channel_length);
    chan_p[l] = taps[l].data();
  }

  void *gpu_context = cuda_channel_pipeline_init(61440, nb_tx, nb_rx, channel_length);
  size_t pos = 0;
  double gpu_us = 0, copy_us = 0;
  for (auto _ : state) {
    if (mode == 1)
      for (int a = 0; a < nb_tx; a++)
        memcpy(tx1[a].data(), src[a].data(), sizeof(c16_t) * num_samples);
    for (int r = 0; r < nb_rx; r++)
      out_p[r] = mode == 2 ? ring + r * ring_len + pos : out[r].data();
    auto t0 = std::chrono::steady_clock::now();
    cuda_channel_pipeline(gpu_context,
                          chan_p.data(),
                          tx0_p.data(),
                          tx1_p.data(),
                          hist,
                          out_p.data(),
                          nullptr,
                          num_samples,
                          num_samples,
                          channel_length,
                          nb_tx,
                          nb_rx,
                          0.0f);
    auto t1 = std::chrono::steady_clock::now();
    if (mode == 1)
      for (int r = 0; r < nb_rx; r++)
        memcpy(ring + r * ring_len + pos, out[r].data(), sizeof(c16_t) * num_samples);
    auto t2 = std::chrono::steady_clock::now();
    gpu_us += std::chrono::duration<double, std::micro>(t1 - t0).count();
    copy_us += std::chrono::duration<double, std::micro>(t2 - t1).count();
    pos = (pos + num_samples) % ring_len;
  }
  state.counters["gpu_us"] = benchmark::Counter(gpu_us, benchmark::Counter::kAvgIterations);
  state.counters["copy_us"] = benchmark::Counter(copy_us, benchmark::Counter::kAvgIterations);
  cuda_channel_pipeline_shutdown(gpu_context);
  munmap(ring, ring_bytes);
}

#endif

static void BM_channel_convolution_cpu(benchmark::State &state)
{
  int nb_rx = state.range(0);
  int nb_tx = state.range(1);
  int num_samples = state.range(2);
  int channel_length = state.range(3);

  size_t num_input_samples = num_samples + channel_length - 1;
  std::vector<c16_t *> input(nb_tx);
  for (int i = 0; i < nb_tx; ++i) {
    input[i] = new c16_t[num_input_samples];
  }

  std::vector<c16_t *> output(nb_rx);
  for (int i = 0; i < nb_rx; ++i) {
    output[i] = new c16_t[num_samples];
  }

  std::vector<cf_t *> channel(nb_rx * nb_tx);
  for (int i = 0; i < nb_rx * nb_tx; ++i) {
    channel[i] = new cf_t[channel_length];
  }

  for (int i = 0; i < nb_rx * nb_tx; ++i) {
    generate_random_signal_float(channel[i], channel_length);
  }
  for (int aatx = 0; aatx < nb_tx; aatx++) {
    generate_random_signal(input[aatx], num_input_samples);
  }

  size_t total_samples = 0;
  for (auto _ : state) {
    channel_convolution_cpu((const cf_t **)channel.data(),
                            (const c16_t **)input.data(),
                            nullptr,
                            num_input_samples,
                            output.data(),
                            nullptr,
                            num_samples,
                            num_samples,
                            channel_length,
                            nb_tx,
                            nb_rx);
    total_samples += num_samples;
  }
  state.counters["MSPS"] = benchmark::Counter(total_samples / 1000000.0f, benchmark::Counter::kIsRate);

  for (int i = 0; i < nb_tx; ++i)
    delete[] input[i];
  for (int i = 0; i < nb_rx * nb_tx; ++i)
    delete[] channel[i];
  for (int i = 0; i < nb_rx; ++i) {
    delete[] output[i];
  }
}

static void BM_channel_convolution_tpool(benchmark::State &state)
{
  int nb_rx = state.range(0);
  int nb_tx = state.range(1);
  int num_samples = state.range(2);
  int channel_length = state.range(3);

  size_t num_input_samples = num_samples + channel_length - 1;
  std::vector<c16_t *> input(nb_tx);
  for (int i = 0; i < nb_tx; ++i) {
    input[i] = new c16_t[num_input_samples];
  }

  std::vector<c16_t *> output(nb_rx);
  for (int i = 0; i < nb_rx; ++i) {
    output[i] = new c16_t[num_samples];
  }

  std::vector<cf_t *> channel(nb_rx * nb_tx);
  for (int i = 0; i < nb_rx * nb_tx; ++i) {
    channel[i] = new cf_t[channel_length];
  }

  for (int i = 0; i < nb_rx * nb_tx; ++i) {
    generate_random_signal_float(channel[i], channel_length);
  }
  for (int aatx = 0; aatx < nb_tx; aatx++) {
    generate_random_signal(input[aatx], num_input_samples);
  }

  void *tpool = init_tpool(16);
  channel_pipeline_init(0.0f);

  size_t total_samples = 0;
  for (auto _ : state) {
    channel_pipeline(tpool,
                     (const cf_t **)channel.data(),
                     (const c16_t **)input.data(),
                     nullptr,
                     num_input_samples,
                     output.data(),
                     nullptr,
                     num_samples,
                     num_samples,
                     channel_length,
                     nb_tx,
                     nb_rx,
                     0.0f);
    total_samples += num_samples;
  }
  state.counters["MSPS"] = benchmark::Counter(total_samples / 1000000.f, benchmark::Counter::kIsRate);

  channel_pipeline_shutdown();

  destroy_tpool(tpool);

  for (int i = 0; i < nb_tx; ++i)
    delete[] input[i];
  for (int i = 0; i < nb_rx * nb_tx; ++i)
    delete[] channel[i];
  for (int i = 0; i < nb_rx; ++i) {
    delete[] output[i];
  }
}

#ifdef CHANNEL_SIM_CUDA
BENCHMARK(BM_channel_convolution_gpu)
    ->ArgsProduct({
        {1, 2, 4, 8, 16, 64}, // nb_rx
        {1, 2, 4, 8, 16, 64}, // nb_tx
        {1024, 2048, 30720}, // num_samples
        {8, 16, 32, 64}, // channel_length
    })
    ->Iterations(50);

// {nb_tx, nb_rx, num_samples, channel_length}: O-RU DL and UE UL calls for 4 and 8 O-RU antennas, 4 UE antennas
BENCHMARK(BM_channel_pipeline_gpu_vrtsim)
    ->Args({4, 4, 4096, 8})
    ->Args({8, 4, 4096, 8})
    ->Args({4, 4, 30720, 8})
    ->Args({4, 8, 30720, 8})
    ->UseRealTime()
    ->MinTime(2.0);

// {nb_tx, nb_rx, num_samples, channel_length, mode}
BENCHMARK(BM_channel_pipeline_gpu_vrtsim_io)
    ->ArgsProduct({{4}, {4}, {4096}, {8}, {0, 1, 2}})
    ->ArgsProduct({{8}, {4}, {4096}, {8}, {0, 1, 2}})
    ->ArgsProduct({{4}, {4, 8}, {30720}, {8}, {0, 1, 2}})
    ->UseRealTime()
    ->MinTime(2.0);
#endif

BENCHMARK(BM_channel_convolution_cpu)
    ->ArgsProduct({
        {1, 2, 4}, // nb_rx
        {1, 2, 4}, // nb_tx
        {1024, 2048, 30720}, // num_samples
        {8, 16, 32, 64}, // channel_length
    })
    ->Iterations(10);

BENCHMARK(BM_channel_convolution_tpool)
    ->ArgsProduct({
        {1, 2, 4}, // nb_rx
        {1, 2, 4}, // nb_tx
        {1024, 2048, 30720}, // num_samples
        {8, 16, 32, 64}, // channel_length
    })
    ->Iterations(10);

int main(int argc, char **argv)
{
  logInit();
  randominit();
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  return 0;
}
