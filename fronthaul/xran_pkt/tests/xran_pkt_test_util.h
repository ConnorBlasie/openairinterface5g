/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Shared by the xran_pkt unit tests. Include it in one file of each test executable: it defines exit_function().

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// The AssertError() handler for tests that link the codecs without the OAI utilities library
void exit_function(const char *file, const char *function, const int line, const char *s, const int assertflag)
{
  fprintf(stderr, "Error at %s:%s:%d - %s\n", file, function, line, s ? s : "None");
  exit(1);
}

#define FILL 0xA5 // written to outputs and buffers before a call, to see what the call writes

static inline bool is_fill(const void *p, size_t n)
{
  const uint8_t *b = p;
  for (size_t i = 0; i < n; i++)
    if (b[i] != FILL)
      return false;
  return true;
}
