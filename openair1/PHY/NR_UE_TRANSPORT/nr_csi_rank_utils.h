/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * Pure-math helper for UE CSI rank estimation (effective rank of an NxN
 * Hermitian Gram matrix via leading principal minors). The estimated rank
 * drives Type-I single-panel codebook/RI selection (TS 38.214 sec 5.2.2.2.1)
 * for the nb_antennas_rx >= 3 path in csi_rx.c (enables RI 3/4).
 *
 * The Gram is built once per RI report (band-averaged over RBs), so double
 * precision here is cheap and sidesteps the int64 overflow that a 4x4 fixed-point
 * determinant would hit (products of 4 large entries). The existing per-RE 2x2
 * fixed-point path in csi_rx.c (nb_antennas_rx == 2) is unaffected.
 */

#ifndef NR_CSI_RANK_UTILS_H
#define NR_CSI_RANK_UTILS_H

#include <complex.h>

#define NR_CSI_RANK_MAX_N 4 /* up to 4 rx antennas / rank 4 */

/* Determinant of the leading k x k submatrix of a Hermitian matrix A
 * (A stored full, row-major, A[i][j] = conj(A[j][i])). Cofactor expansion;
 * k <= NR_CSI_RANK_MAX_N. The result is real for a Hermitian matrix, so we
 * return the real part (imag is ~0 up to rounding). */
static inline double nr_csi_leading_minor_det(const double _Complex A[NR_CSI_RANK_MAX_N][NR_CSI_RANK_MAX_N], int k)
{
  if (k <= 0)
    return 1.0;
  if (k == 1)
    return creal(A[0][0]);
  if (k == 2)
    return creal(A[0][0] * A[1][1] - A[0][1] * A[1][0]);
  if (k == 3) {
    double _Complex d = A[0][0] * (A[1][1] * A[2][2] - A[1][2] * A[2][1]) - A[0][1] * (A[1][0] * A[2][2] - A[1][2] * A[2][0])
                        + A[0][2] * (A[1][0] * A[2][1] - A[1][1] * A[2][0]);
    return creal(d);
  }
  /* k == 4: Laplace expansion along the first row, reusing 3x3 cofactors. */
  double _Complex det = 0;
  for (int c = 0; c < 4; c++) {
    double _Complex M[3][3];
    for (int i = 1; i < 4; i++) {
      int cc = 0;
      for (int j = 0; j < 4; j++) {
        if (j == c)
          continue;
        M[i - 1][cc++] = A[i][j];
      }
    }
    double _Complex minor = M[0][0] * (M[1][1] * M[2][2] - M[1][2] * M[2][1]) - M[0][1] * (M[1][0] * M[2][2] - M[1][2] * M[2][0])
                            + M[0][2] * (M[1][0] * M[2][1] - M[1][1] * M[2][0]);
    double sign = (c & 1) ? -1.0 : 1.0;
    det += sign * A[0][c] * minor;
  }
  return creal(det);
}

/* Effective rank of an N x N Hermitian PSD Gram matrix A (N <= NR_CSI_RANK_MAX_N).
 *
 * For a PSD Hermitian matrix, det(A_k) = product of the k largest-so-far leading
 * eigenvalue contributions; a well-conditioned rank-r matrix has det(A_k) growing
 * with k up to r, then collapsing toward zero. We report the largest k whose
 * leading-minor determinant clears a noise floor scaled from the trace:
 *   det(A_k) >= eps^k * (trace(A)/N)^k    [each dimension must contribute >~ eps*avg-eigenvalue]
 * `eps` in (0,1) is the per-dimension relative floor.
 *
 * Returns rank in [1, N]. Assumes A has positive diagonal (true for a Gram of a
 * non-zero channel); if A[0][0] ~ 0 the channel is empty and rank 1 is returned. */
static inline int nr_csi_effective_rank(const double _Complex A[NR_CSI_RANK_MAX_N][NR_CSI_RANK_MAX_N], int N, double eps)
{
  if (N <= 1)
    return 1;
  double trace = 0.0;
  for (int i = 0; i < N; i++)
    trace += creal(A[i][i]);
  const double avg_eig = trace / (double)N;
  if (avg_eig <= 0.0)
    return 1;

  int rank = 1;
  const double step = eps * avg_eig;
  for (int k = 2; k <= N; k++) {
    double floor_k = 1.0;
    for (int t = 0; t < k; t++)
      floor_k *= step;
    double det_k = nr_csi_leading_minor_det(A, k);
    if (det_k >= floor_k)
      rank = k;
    /* do not break: monotonicity of PSD leading minors makes the largest passing k
     * the effective rank, but we still evaluate every k in case of numerical noise. */
  }
  return rank;
}

#endif /* NR_CSI_RANK_UTILS_H */
