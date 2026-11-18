/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef OAI_VRTSIM_TIME_H
#define OAI_VRTSIM_TIME_H

#include <math.h>
#include <stdint.h>
#include <time.h>

/* Conversion between wall clock time and channel samples. rate is sample_rate * timescale, start is the time of sample 0. */

// Index of the last sample due at time t, rounded toward zero.
static inline int64_t ts_to_samples(double rate, const struct timespec *start, const struct timespec *t)
{
  int64_t diff = (t->tv_sec - start->tv_sec) * 1000000000 + (t->tv_nsec - start->tv_nsec);
  return rate * diff / 1e9;
}

// Earliest time at which sample n is due. Rounds up, so that ts_to_samples() of the result is at least n.
// After about one second of run time, double rounding in ts_to_samples() can give n - 1.
static inline struct timespec samples_to_ts(double rate, const struct timespec *start, uint64_t n)
{
  int64_t ns = (int64_t)ceil(n * 1e9 / rate) + start->tv_nsec;
  struct timespec t;
  t.tv_sec = start->tv_sec + ns / 1000000000;
  t.tv_nsec = ns % 1000000000;
  return t;
}

#endif
