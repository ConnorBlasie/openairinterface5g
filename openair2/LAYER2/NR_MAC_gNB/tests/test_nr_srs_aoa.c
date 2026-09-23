/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* Unit test for nr_srs_estimate_aoa() (openair2/LAYER2/NR_MAC_gNB/nr_srs_aoa.h): validates that the
 * phase-slope AoA estimator recovers a known azimuth from a synthetic half-wavelength-ULA SRS channel
 * matrix, within a tolerance, before ever touching real hardware/SRS wiring. This is the first
 * validation step for srs_aoa_integration.md's AoA work: confirm the estimator itself is correct on
 * a static, noiseless, exactly-known-angle input, independent of beam steering / channel model / RF. */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "LAYER2/NR_MAC_gNB/nr_srs_aoa.h"

// Tolerance for the noiseless synthetic case. The estimator is exact (up to quantization) for a
// single-tap LOS ULA input, so this only needs to absorb int16_t rounding, not channel-model noise.
#define AOA_TOL_DEG 1.0

// Build a synthetic SRS channel matrix for a plane wave at `theta_deg` on a half-wavelength ULA of
// `Ng` gNB antennas, `Nu` UE SRS ports (all identical, i.e. no per-port angle difference), `Np` PRGs
// (all identical, i.e. no frequency-selective fading). H[uI][gI][pI] = A * exp(j*gI*pi*sin(theta)).
static void build_channel_matrix(double theta_deg, int Ng, int Nu, int Np, c16_t *out)
{
  const double phase_step = M_PI * sin(theta_deg * M_PI / 180.0); // rad/antenna, d = lambda/2
  const double A = 20000.0; // well within int16_t range, mimics a normalized nonzero amplitude
  for (int uI = 0; uI < Nu; uI++) {
    for (int gI = 0; gI < Ng; gI++) {
      const double phase = gI * phase_step;
      const c16_t h = {.r = (int16_t)lround(A * cos(phase)), .i = (int16_t)lround(A * sin(phase))};
      for (int pI = 0; pI < Np; pI++)
        out[uI * Ng * Np + gI * Np + pI] = h;
    }
  }
}

static void check_angle(double true_deg, int Ng, int Nu, int Np)
{
  nfapi_nr_srs_normalized_channel_iq_matrix_t m;
  memset(&m, 0, sizeof(m));
  m.normalized_iq_representation = 1; // c16_t
  m.num_gnb_antenna_elements = Ng;
  m.num_ue_srs_ports = Nu;
  m.num_prgs = Np;
  build_channel_matrix(true_deg, Ng, Nu, Np, (c16_t *)m.channel_matrix);

  const double est = nr_srs_estimate_aoa(&m);
  if (isnan(est)) {
    fprintf(stderr, "FAIL: true=%.1f deg (Ng=%d,Nu=%d,Np=%d) -> NAN (expected a valid estimate)\n", true_deg, Ng, Nu, Np);
    abort();
  }
  const double err = fabs(est - true_deg);
  if (err > AOA_TOL_DEG) {
    fprintf(stderr,
            "FAIL: true=%.1f deg, estimated=%.2f deg, |err|=%.2f > tol=%.1f (Ng=%d,Nu=%d,Np=%d)\n",
            true_deg,
            est,
            err,
            AOA_TOL_DEG,
            Ng,
            Nu,
            Np);
    abort();
  }
  printf("OK: true=%6.1f deg -> estimated=%6.2f deg (|err|=%.3f deg, Ng=%d,Nu=%d,Np=%d)\n", true_deg, est, err, Ng, Nu, Np);
}

static void test_known_angles(void)
{
  const double angles[] = {0.0, 5.0, -5.0, 15.0, -15.0, 30.0, -30.0, 45.0, -45.0, 60.0, -60.0, 89.0, -89.0};
  const int Ng_values[] = {2, 4, 8};
  const int Np_values[] = {1, 4};
  for (unsigned a = 0; a < sizeof(angles) / sizeof(angles[0]); a++)
    for (unsigned g = 0; g < sizeof(Ng_values) / sizeof(Ng_values[0]); g++)
      for (unsigned p = 0; p < sizeof(Np_values) / sizeof(Np_values[0]); p++)
        check_angle(angles[a], Ng_values[g], /* Nu = */ 2, Np_values[p]);
}

// Averaging over multiple UE SRS ports / PRGs (accumulated coherently, one atan2 at the end) must
// not bias the estimate away from a single-port/single-PRG result for the same true angle.
static void test_multi_port_prg_consistency(void)
{
  check_angle(20.0, 4, 1, 1);
  check_angle(20.0, 4, 4, 8);
}

static void test_no_aperture_returns_nan(void)
{
  nfapi_nr_srs_normalized_channel_iq_matrix_t m;
  memset(&m, 0, sizeof(m));
  m.normalized_iq_representation = 1;
  m.num_gnb_antenna_elements = 1; // Ng < 2: no aperture
  m.num_ue_srs_ports = 1;
  m.num_prgs = 1;
  if (!isnan(nr_srs_estimate_aoa(&m))) {
    fprintf(stderr, "FAIL: Ng=1 (no aperture) should return NAN\n");
    abort();
  }

  m.num_gnb_antenna_elements = 4;
  m.num_ue_srs_ports = 0; // Nu == 0: no ports
  if (!isnan(nr_srs_estimate_aoa(&m))) {
    fprintf(stderr, "FAIL: Nu=0 should return NAN\n");
    abort();
  }
}

static void test_zero_signal_returns_nan(void)
{
  nfapi_nr_srs_normalized_channel_iq_matrix_t m;
  memset(&m, 0, sizeof(m)); // channel_matrix left all-zero: no cross-antenna phase at all
  m.normalized_iq_representation = 1;
  m.num_gnb_antenna_elements = 4;
  m.num_ue_srs_ports = 2;
  m.num_prgs = 4;
  if (!isnan(nr_srs_estimate_aoa(&m))) {
    fprintf(stderr, "FAIL: all-zero channel matrix should return NAN\n");
    abort();
  }
}

static void test_c8_representation(void)
{
  // normalized_iq_representation == 0 selects the c8_t (8-bit) path instead of c16_t.
  const int Ng = 4;
  const double true_deg = 25.0;
  const double phase_step = M_PI * sin(true_deg * M_PI / 180.0);
  nfapi_nr_srs_normalized_channel_iq_matrix_t m;
  memset(&m, 0, sizeof(m));
  m.normalized_iq_representation = 0; // c8_t
  m.num_gnb_antenna_elements = Ng;
  m.num_ue_srs_ports = 1;
  m.num_prgs = 1;
  c8_t *ch = (c8_t *)m.channel_matrix;
  const double A = 100.0; // within int8_t range
  for (int gI = 0; gI < Ng; gI++) {
    const double phase = gI * phase_step;
    ch[gI].r = (int8_t)lround(A * cos(phase));
    ch[gI].i = (int8_t)lround(A * sin(phase));
  }
  const double est = nr_srs_estimate_aoa(&m);
  if (isnan(est) || fabs(est - true_deg) > AOA_TOL_DEG) {
    fprintf(stderr, "FAIL: c8_t path: true=%.1f estimated=%.2f\n", true_deg, est);
    abort();
  }
  printf("OK: c8_t path true=%.1f deg -> estimated=%.2f deg\n", true_deg, est);
}

int main(void)
{
  test_known_angles();
  test_multi_port_prg_consistency();
  test_no_aperture_returns_nan();
  test_zero_signal_returns_nan();
  test_c8_representation();
  printf("All SRS-AoA estimator tests passed.\n");
  return 0;
}
