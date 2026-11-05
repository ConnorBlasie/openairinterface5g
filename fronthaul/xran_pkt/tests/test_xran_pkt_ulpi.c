/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Checks the ULPI (DMRS-BF) section extension codecs of xran_pkt_ulpi.h against CUS v16.01 clauses 7.7.10 (SE 10),
// 7.7.24 (SE 24), 7.7.25 (SE 25), 7.7.26 (SE 26) and 7.7.27 (SE 27).

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "xran_pkt_cp.h"
#include "xran_pkt_ext.h"
#include "xran_pkt_ulpi.h"
#include "xran_pkt_test_util.h"

#define SENTINEL 0xEE // in the encode buffer after the extension

// Checks an encoded extension in buf, which was SENTINEL before the encode: length is a multiple of 4, matches extLen
// and the extension walk, nothing is written after it, and the bytes from content_len to the end are zero
static void check_encoded(uint8_t ext_type, const uint8_t *buf, size_t avail, size_t len, size_t content_len)
{
  assert(len % 4 == 0 && len < avail);
  assert(buf[1] == len / 4);
  assert(buf[len] == SENTINEL);
  size_t walk_len = 0;
  assert(xran_section_ext_len(ext_type, buf, avail, &walk_len) == XRAN_EXT_OK);
  assert(walk_len == len);
  for (size_t i = content_len; i < len; i++)
    assert(buf[i] == 0);
}

// Decodes the extension in buf with room for n - 1 elements, which must give XRAN_EXT_ERR_TOO_MANY and write nothing,
// then with room for exactly n (1 for n = 0), which must pass and write nothing after element n. out must be an array
// with room for n + 1 elements.
#define DECODE_EXACT_CAPACITY(decode, buf, len, n, hdr_out, out)                 \
  do {                                                                           \
    memset(&(hdr_out), FILL, sizeof(hdr_out));                                   \
    memset(out, FILL, sizeof(out));                                              \
    if ((n) > 1) {                                                               \
      assert(decode(buf, len, (n)-1, &(hdr_out), out) == XRAN_EXT_ERR_TOO_MANY); \
      assert(is_fill(&(hdr_out), sizeof(hdr_out)) && is_fill(out, sizeof(out))); \
    }                                                                            \
    assert(decode(buf, len, (n) > 0 ? (n) : 1, &(hdr_out), out) == XRAN_EXT_OK); \
    assert(is_fill(&(out)[n], sizeof(out) - (size_t)(n) * sizeof((out)[0])));    \
  } while (0)

/**********************************************************************
 * SE 10 (CUS v16.01 7.7.10)
 **********************************************************************/

static void assert_se10_eq(const xran_se10_hdr_t *ha,
                           const xran_se10_port_t *pa,
                           const xran_se10_hdr_t *hb,
                           const xran_se10_port_t *pb)
{
  assert(ha->ef == hb->ef);
  assert(ha->beamGroupType == hb->beamGroupType);
  assert(ha->numPortc == hb->numPortc);
  if (ha->beamGroupType == XRAN_SE10_BGT_11B)
    assert(ha->firstPortListIndex == hb->firstPortListIndex);
  for (int k = 0; k < xran_se10_num_ports(ha); k++) {
    assert(pa[k].id == pb[k].id);
    if (ha->beamGroupType == XRAN_SE10_BGT_11B)
      assert(pa[k].portListIndex == pb[k].portListIndex);
  }
}

// Encodes to buf, checks it with check_encoded() up to the encoded length, decodes with DECODE_EXACT_CAPACITY() and
// compares. 00b and 01b pass ports = NULL. Returns the length.
static size_t roundtrip_se10(const xran_se10_hdr_t *hdr, const xran_se10_port_t *ports, uint8_t buf[256])
{
  memset(buf, SENTINEL, 256);
  size_t len = 0;
  assert(xran_encode_se10(hdr, ports, buf, 256, &len) == XRAN_EXT_OK);
  check_encoded(XRAN_CP_SECTIONEXTCMD_10, buf, 256, len, len);

  xran_se10_hdr_t hdr_out;
  xran_se10_port_t ports_out[XRAN_SE10_MAX_PORTS + 1];
  DECODE_EXACT_CAPACITY(xran_decode_se10, buf, len, xran_se10_num_ports(hdr), hdr_out, ports_out);
  assert_se10_eq(hdr, ports, &hdr_out, ports_out);
  return len;
}

// Every mode: the four beamGroupTypes, numPortc 1 to 64 and ef 0 and 1. The ids take 0, 0x7FFE, 0x7FFF (port not
// scheduled, 7.7.10.1) and other values; portListIndex and firstPortListIndex take 0, 1, 255 and other values.
static void test_se10_all_modes(void)
{
  int n_cases = 0;
  for (int bgt = XRAN_SE10_BGT_00B; bgt <= XRAN_SE10_BGT_11B; bgt++) {
    for (int num_portc = 1; num_portc <= XRAN_SE10_MAX_PORTS; num_portc++) {
      for (int ef = 0; ef <= 1; ef++) {
        const uint8_t pli[] = {0, 1, 255, (uint8_t)(num_portc * 7)};
        xran_se10_hdr_t hdr = {.ef = ef, .beamGroupType = bgt, .numPortc = num_portc, .firstPortListIndex = pli[num_portc % 4]};
        xran_se10_port_t ports[XRAN_SE10_MAX_PORTS];
        for (int k = 0; k < XRAN_SE10_MAX_PORTS; k++) {
          const uint16_t ids[] = {0, 0x7FFE, 0x7FFF, (uint16_t)((k * 0x1357) & 0x7FFF)};
          ports[k] = (xran_se10_port_t){.id = ids[(k + num_portc) % 4], .portListIndex = pli[(k + ef) % 4]};
        }
        bool listed = bgt == XRAN_SE10_BGT_10B || bgt == XRAN_SE10_BGT_11B;
        uint8_t buf[256];
        roundtrip_se10(&hdr, listed ? ports : NULL, buf);
        n_cases++;
      }
    }
  }
  assert(n_cases == 4 * 64 * 2);
  printf("SE 10 round trip, all %d modes, passed\n", n_cases);
}

// Lengths from Tables 7.7.10.1-1 to 7.7.10.1-3: 00b and 01b are 4 bytes, 10b is 3 bytes + 2 per port, 11b is 4 bytes
// + 3 per port after the first. The filler after the content must be zero. All ids and portListIndex values are
// non-zero, so the last content byte is not zero and the content length can't be too long either.
static void test_se10_lengths(void)
{
  const struct {
    uint8_t bgt;
    int numPortc;
    size_t content_len;
    size_t ext_len;
  } cases[] = {
      {XRAN_SE10_BGT_00B, 1, 4, 4},
      {XRAN_SE10_BGT_00B, 64, 4, 4},
      {XRAN_SE10_BGT_01B, 1, 4, 4},
      {XRAN_SE10_BGT_01B, 64, 4, 4},
      {XRAN_SE10_BGT_10B, 1, 5, 8},
      {XRAN_SE10_BGT_10B, 2, 7, 8},
      {XRAN_SE10_BGT_10B, 3, 9, 12},
      {XRAN_SE10_BGT_10B, 63, 129, 132},
      {XRAN_SE10_BGT_10B, 64, 131, 132},
      {XRAN_SE10_BGT_11B, 1, 4, 4},
      {XRAN_SE10_BGT_11B, 2, 7, 8},
      {XRAN_SE10_BGT_11B, 3, 10, 12},
      {XRAN_SE10_BGT_11B, 33, 100, 100},
      {XRAN_SE10_BGT_11B, 64, 193, 196},
  };
  xran_se10_port_t ports[XRAN_SE10_MAX_PORTS];
  for (int k = 0; k < XRAN_SE10_MAX_PORTS; k++)
    ports[k] = (xran_se10_port_t){.id = 0x7FFF, .portListIndex = 0xFF};
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    xran_se10_hdr_t hdr = {.ef = 1, .beamGroupType = cases[c].bgt, .numPortc = cases[c].numPortc, .firstPortListIndex = 0xFF};
    uint8_t buf[256];
    bool listed = cases[c].bgt >= XRAN_SE10_BGT_10B;
    size_t len = roundtrip_se10(&hdr, listed ? ports : NULL, buf);
    assert(len == cases[c].ext_len);
    check_encoded(XRAN_CP_SECTIONEXTCMD_10, buf, sizeof(buf), len, cases[c].content_len);
    if (listed)
      assert(buf[cases[c].content_len - 1] == 0xFF); // last id byte or portListIndex, not filler
  }
  printf("SE 10 lengths passed\n");
}

/**********************************************************************
 * SE 24 (CUS v16.01 7.7.24)
 **********************************************************************/

static void assert_se24_hdr_eq(const xran_se24_hdr_t *a, const xran_se24_hdr_t *b)
{
  assert(a->ef == b->ef);
  assert(a->aIpnPerSym == b->aIpnPerSym);
  assert(a->antDmrsSnr == b->antDmrsSnr);
  assert(a->userGroupSize == b->userGroupSize);
  assert(a->userGroupId == b->userGroupId);
}

static void assert_se24_entry_eq(const xran_se24_entry_t *a, const xran_se24_entry_t *b)
{
  assert(a->entryType == b->entryType);
  assert(a->dmrsPortNumber == b->dmrsPortNumber);
  assert(a->ueIdReset == b->ueIdReset);
  assert(a->dmrsSymbolMask == b->dmrsSymbolMask);
  assert(a->scrambling == b->scrambling);
  assert(a->nscid == b->nscid);
  assert(a->firstPrb == b->firstPrb);
  assert(a->lastPrb == b->lastPrb);
  assert(a->dType == b->dType);
  assert(a->cdmWithoutData == b->cdmWithoutData);
  assert(a->lambda == b->lambda);
  assert(a->lowPaprType == b->lowPaprType);
  assert(a->hoppingMode == b->hoppingMode);
}

static void roundtrip_se24(const xran_se24_hdr_t *hdr, const xran_se24_entry_t *entries, int n)
{
  uint8_t buf[256];
  size_t len = 0;
  assert(xran_encode_se24(hdr, entries, n, buf, sizeof(buf), &len) == XRAN_EXT_OK);
  size_t walk_len = 0;
  assert(xran_section_ext_len(XRAN_CP_SECTIONEXTCMD_24, buf, len, &walk_len) == XRAN_EXT_OK);
  assert(walk_len == len);
  xran_se24_hdr_t hdr_out;
  xran_se24_entry_t out[16];
  memset(out, FILL, sizeof(out));
  assert(xran_decode_se24(buf, len, n, &hdr_out, out) == XRAN_EXT_OK);
  assert_se24_hdr_eq(hdr, &hdr_out);
  for (int i = 0; i < n; i++)
    assert_se24_entry_eq(&entries[i], &out[i]);
}

// Each field at its minimum, middle and maximum value (bit width limits). The table has one entry of each entryType,
// so a field that leaks into a neighbour entry or field fails the comparison.
static void test_se24_field_roundtrip(void)
{
  const xran_se24_hdr_t base_hdr = {.ef = 1, .aIpnPerSym = 0, .antDmrsSnr = 1, .userGroupSize = 0x0A, .userGroupId = 0x5A};
  const xran_se24_entry_t base[4] = {
      {.entryType = XRAN_SE24_ENTRY_CP_OFDM,
       .dmrsPortNumber = 0x0A,
       .ueIdReset = 1,
       .dmrsSymbolMask = 0x2A5A,
       .scrambling = 0xA55A,
       .nscid = 0,
       .firstPrb = 0x0A5,
       .lastPrb = 0x15A,
       .dType = 1,
       .cdmWithoutData = 2,
       .lambda = 1},
      {.entryType = XRAN_SE24_ENTRY_INHERIT_PERSIST, .dmrsPortNumber = 0x15},
      {.entryType = XRAN_SE24_ENTRY_DFT_S_OFDM,
       .dmrsPortNumber = 0x15,
       .ueIdReset = 0,
       .dmrsSymbolMask = 0x15A5,
       .scrambling = 0x5AA5,
       .nscid = 1,
       .firstPrb = 0x15A,
       .lastPrb = 0x0A5,
       .lowPaprType = 1,
       .hoppingMode = 2},
      {.entryType = XRAN_SE24_ENTRY_INHERIT_RESET, .dmrsPortNumber = 0x0A},
  };
  roundtrip_se24(&base_hdr, base, 4);

#define RT_HDR(field, max)                         \
  do {                                             \
    const unsigned vals[] = {0, (max) / 2, (max)}; \
    for (int i = 0; i < 3; i++) {                  \
      xran_se24_hdr_t h = base_hdr;                \
      h.field = vals[i];                           \
      roundtrip_se24(&h, base, 4);                 \
    }                                              \
  } while (0)
  RT_HDR(ef, 0x1);
  RT_HDR(aIpnPerSym, 0x1);
  RT_HDR(antDmrsSnr, 0x1);
  RT_HDR(userGroupSize, 0x1F);
  RT_HDR(userGroupId, 0xFF);
#undef RT_HDR

#define RT_ENTRY(idx, field, max)                  \
  do {                                             \
    const unsigned vals[] = {0, (max) / 2, (max)}; \
    for (int i = 0; i < 3; i++) {                  \
      xran_se24_entry_t e[4];                      \
      memcpy(e, base, sizeof(e));                  \
      e[idx].field = vals[i];                      \
      roundtrip_se24(&base_hdr, e, 4);             \
    }                                              \
  } while (0)
  for (int idx = 0; idx < 4; idx++)
    RT_ENTRY(idx, dmrsPortNumber, 0x1F);
  for (int idx = 0; idx < 4; idx += 2) { // entryType 2 and 3
    RT_ENTRY(idx, ueIdReset, 0x1);
    RT_ENTRY(idx, dmrsSymbolMask, 0x3FFF);
    RT_ENTRY(idx, scrambling, 0xFFFF);
    RT_ENTRY(idx, nscid, 0x1);
    RT_ENTRY(idx, firstPrb, 0x1FF);
    RT_ENTRY(idx, lastPrb, 0x1FF);
  }
  RT_ENTRY(0, dType, 0x1);
  RT_ENTRY(0, cdmWithoutData, 0x3);
  RT_ENTRY(0, lambda, 0x3);
  RT_ENTRY(2, lowPaprType, 0x3);
  RT_ENTRY(2, hoppingMode, 0x3);
#undef RT_ENTRY
  printf("SE 24 field round trip passed\n");
}

/**********************************************************************
 * Byte vectors, encoded by hand from the spec tables
 **********************************************************************/

static void test_se10_vectors(void)
{
  // Table 7.7.10.1-2, beamGroupType 10b, 3 ports after the section header port
  const uint8_t v10b[] = {
      0x8A, // ef 1 | extType 0x0A
      0x03, // extLen 3 words
      0x83, // beamGroupType 10 | numPortc 00 0011
      0x01, // reserved 0 | 2nd port ueId[14:8]
      0x02, // 2nd port ueId[7:0]: 0x0102
      0x7F, // reserved 0 | 3rd port ueId[14:8]
      0xFF, // 3rd port ueId[7:0]: 0x7FFF (not scheduled)
      0x12, // reserved 0 | 4th port ueId[14:8]
      0x34, // 4th port ueId[7:0]: 0x1234
      0x00,
      0x00,
      0x00, // filler
  };
  const xran_se10_hdr_t h10b = {.ef = 1, .beamGroupType = XRAN_SE10_BGT_10B, .numPortc = 3};
  const xran_se10_port_t p10b[] = {{.id = 0x0102}, {.id = 0x7FFF}, {.id = 0x1234}};
  // Table 7.7.10.1-3, beamGroupType 11b, 2 ports in total
  const uint8_t v11b[] = {
      0x0A, // ef 0 | extType 0x0A
      0x02, // extLen 2 words
      0xC2, // beamGroupType 11 | numPortc 00 0010
      0x01, // 1st portListIndex
      0x00, // reserved 0 | 2nd port ueId[14:8]
      0x05, // 2nd port ueId[7:0]: 0x0005
      0x03, // 2nd portListIndex
      0x00, // filler
  };
  const xran_se10_hdr_t h11b = {.ef = 0, .beamGroupType = XRAN_SE10_BGT_11B, .numPortc = 2, .firstPortListIndex = 1};
  const xran_se10_port_t p11b[] = {{.id = 0x0005, .portListIndex = 3}};
  // Table 7.7.10.1-1, beamGroupType 00b, 4 ports
  const uint8_t v00b[] = {
      0x8A, // ef 1 | extType 0x0A
      0x01, // extLen 1 word
      0x04, // beamGroupType 00 | numPortc 00 0100
      0x00, // reserved
  };
  const xran_se10_hdr_t h00b = {.ef = 1, .beamGroupType = XRAN_SE10_BGT_00B, .numPortc = 4};
  // Table 7.7.10.1-1, beamGroupType 01b, 64 ports
  const uint8_t v01b[] = {
      0x0A, // ef 0 | extType 0x0A
      0x01, // extLen 1 word
      0x40, // beamGroupType 01 | numPortc 00 0000 (64)
      0x00, // reserved
  };
  const xran_se10_hdr_t h01b = {.ef = 0, .beamGroupType = XRAN_SE10_BGT_01B, .numPortc = 64};

  const struct {
    const uint8_t *bytes;
    size_t len;
    const xran_se10_hdr_t *hdr;
    const xran_se10_port_t *ports;
  } vectors[] = {{v00b, sizeof(v00b), &h00b, NULL},
                 {v01b, sizeof(v01b), &h01b, NULL},
                 {v10b, sizeof(v10b), &h10b, p10b},
                 {v11b, sizeof(v11b), &h11b, p11b}};
  for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
    xran_se10_hdr_t hdr;
    xran_se10_port_t ports[XRAN_SE10_MAX_PORTS];
    assert(xran_decode_se10(vectors[v].bytes, vectors[v].len, XRAN_SE10_MAX_PORTS, &hdr, ports) == XRAN_EXT_OK);
    assert_se10_eq(&hdr, ports, vectors[v].hdr, vectors[v].ports);
    uint8_t buf[16];
    size_t len = 0;
    assert(xran_encode_se10(vectors[v].hdr, vectors[v].ports, buf, sizeof(buf), &len) == XRAN_EXT_OK);
    assert(len == vectors[v].len);
    assert(memcmp(buf, vectors[v].bytes, len) == 0);
  }
  printf("SE 10 byte vectors passed\n");
}

static void test_se24_vectors(void)
{
  // Layout of the example in Table 7.7.24.1-2: entryType 2, 0, 1, 1, 0, 3, 0, 0. The example says extLen = 7, but its
  // 30 bytes need 8 words (v16.01 and v21.00 both).
  const uint8_t v1[] = {
      0x18, // ef 0 | extType 0x18
      0x08, // extLen 8 words
      0x00, // aIpnPerSym 0 | antDmrsSnr 0 | reserved | userGroupSize 0
      0x00, // userGroupId 0
      0x40, // entryType 010 | dmrsPortNumber 0 0000
      0x82, // ueIdReset 1 | reserved | dmrsSymbolMask[13:8] 00 0010
      0x04, // dmrsSymbolMask[7:0]: 0x0204
      0xAB, // scrambling[15:8]
      0xCD, // scrambling[7:0]: 0xABCD
      0xA6, // nscid 1 | dType 0 | cdmWithoutData 10 | lambda 01 | firstPrb[8:7] 10
      0x0B, // firstPrb[6:0] 000 0101: 0x105 | lastPrb[8] 1
      0xA0, // lastPrb[7:0]: 0x1A0
      0x00, 0x00, // reserved
      0x01, // entryType 000 | dmrsPortNumber 1
      0x22, // entryType 001 | dmrsPortNumber 2
      0x23, // entryType 001 | dmrsPortNumber 3
      0x04, // entryType 000 | dmrsPortNumber 4
      0x65, // entryType 011 | dmrsPortNumber 5
      0x3F, // ueIdReset 0 | reserved | dmrsSymbolMask[13:8] 11 1111
      0xFF, // dmrsSymbolMask[7:0]: 0x3FFF
      0x00, // scrambling[15:8]
      0x01, // scrambling[7:0]: 0x0001
      0x38, // nscid 0 | reserved | lowPaprType 11 | hoppingMode 10 | firstPrb[8:7] 00
      0x01, // firstPrb[6:0] 0 | lastPrb[8] 1
      0xFF, // lastPrb[7:0]: 0x1FF
      0x00, 0x00, // reserved
      0x06, // entryType 000 | dmrsPortNumber 6
      0x07, // entryType 000 | dmrsPortNumber 7
      0x00, 0x00, // padding
  };
  const xran_se24_hdr_t h1 = {0};
  const xran_se24_entry_t e1[] = {
      {.entryType = 2,
       .dmrsPortNumber = 0,
       .ueIdReset = 1,
       .dmrsSymbolMask = 0x0204,
       .scrambling = 0xABCD,
       .nscid = 1,
       .dType = 0,
       .cdmWithoutData = 2,
       .lambda = 1,
       .firstPrb = 0x105,
       .lastPrb = 0x1A0},
      {.entryType = 0, .dmrsPortNumber = 1},
      {.entryType = 1, .dmrsPortNumber = 2},
      {.entryType = 1, .dmrsPortNumber = 3},
      {.entryType = 0, .dmrsPortNumber = 4},
      {.entryType = 3,
       .dmrsPortNumber = 5,
       .ueIdReset = 0,
       .dmrsSymbolMask = 0x3FFF,
       .scrambling = 0x0001,
       .nscid = 0,
       .lowPaprType = 3,
       .hoppingMode = 2,
       .firstPrb = 0x000,
       .lastPrb = 0x1FF},
      {.entryType = 0, .dmrsPortNumber = 6},
      {.entryType = 0, .dmrsPortNumber = 7},
  };
  // Header flags set, one entryType 2 entry
  const uint8_t v2[] = {
      0x98, // ef 1 | extType 0x18
      0x04, // extLen 4 words
      0xCC, // aIpnPerSym 1 | antDmrsSnr 1 | reserved | userGroupSize 0 1100
      0xFE, // userGroupId 0xFE
      0x4B, // entryType 010 | dmrsPortNumber 0 1011
      0x20, // ueIdReset 0 | reserved | dmrsSymbolMask[13:8] 10 0000
      0x00, // dmrsSymbolMask[7:0]: 0x2000
      0xFF, // scrambling[15:8]
      0xFF, // scrambling[7:0]: 0xFFFF
      0x73, // nscid 0 | dType 1 | cdmWithoutData 11 | lambda 00 | firstPrb[8:7] 11
      0xFE, // firstPrb[6:0] 111 1111: 0x1FF | lastPrb[8] 0
      0x00, // lastPrb[7:0]: 0x000
      0x00,
      0x00, // reserved
      0x00,
      0x00, // padding
  };
  const xran_se24_hdr_t h2 = {.ef = 1, .aIpnPerSym = 1, .antDmrsSnr = 1, .userGroupSize = 12, .userGroupId = 0xFE};
  const xran_se24_entry_t e2[] = {{.entryType = 2,
                                   .dmrsPortNumber = 11,
                                   .ueIdReset = 0,
                                   .dmrsSymbolMask = 0x2000,
                                   .scrambling = 0xFFFF,
                                   .nscid = 0,
                                   .dType = 1,
                                   .cdmWithoutData = 3,
                                   .lambda = 0,
                                   .firstPrb = 0x1FF,
                                   .lastPrb = 0x000}};

  const struct {
    const uint8_t *bytes;
    size_t len;
    const xran_se24_hdr_t *hdr;
    const xran_se24_entry_t *entries;
    int n;
  } vectors[] = {{v1, sizeof(v1), &h1, e1, 8}, {v2, sizeof(v2), &h2, e2, 1}};
  for (size_t v = 0; v < 2; v++) {
    xran_se24_hdr_t hdr;
    xran_se24_entry_t out[8];
    assert(xran_decode_se24(vectors[v].bytes, vectors[v].len, vectors[v].n, &hdr, out) == XRAN_EXT_OK);
    assert_se24_hdr_eq(&hdr, vectors[v].hdr);
    for (int i = 0; i < vectors[v].n; i++)
      assert_se24_entry_eq(&out[i], &vectors[v].entries[i]);
    uint8_t buf[64];
    size_t len = 0;
    assert(xran_encode_se24(vectors[v].hdr, vectors[v].entries, vectors[v].n, buf, sizeof(buf), &len) == XRAN_EXT_OK);
    assert(len == vectors[v].len);
    assert(memcmp(buf, vectors[v].bytes, len) == 0);
  }
  printf("SE 24 byte vectors passed\n");
}

/**********************************************************************
 * SE 25, SE 26 and SE 27 (CUS v16.01 7.7.25 to 7.7.27)
 **********************************************************************/

// numLayers 1 to 4, 12 and the maximum 145. Content lengths: 2 + 7 per layer (Table 7.7.25.1-1). For each layer count,
// 16 passes put every 4-bit value at every symbol of every layer.
static void test_se25_roundtrip(void)
{
  const struct {
    int numLayers;
    size_t content_len;
    size_t ext_len;
  } cases[] = {{1, 9, 12}, {2, 16, 16}, {3, 23, 24}, {4, 30, 32}, {12, 86, 88}, {XRAN_SE25_MAX_LAYERS, 1017, 1020}};
  static xran_se25_layer_t in[XRAN_SE25_MAX_LAYERS], out[XRAN_SE25_MAX_LAYERS + 1];
  static uint8_t buf[1100];
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    for (int seed = 0; seed < 16; seed++) {
      xran_se25_hdr_t hdr = {.ef = seed & 1, .numLayers = cases[c].numLayers};
      for (int l = 0; l < hdr.numLayers; l++)
        for (int sym = 0; sym < XRAN_SE25_NUM_SYMBOLS; sym++)
          in[l].txWinForOnAirSymbol[sym] = (uint8_t)((sym + l + seed) & 0xF);
      memset(buf, SENTINEL, sizeof(buf));
      size_t len = 0;
      assert(xran_encode_se25(&hdr, in, buf, sizeof(buf), &len) == XRAN_EXT_OK);
      assert(len == cases[c].ext_len);
      check_encoded(XRAN_CP_SECTIONEXTCMD_25, buf, sizeof(buf), len, cases[c].content_len);

      xran_se25_hdr_t hdr_out;
      DECODE_EXACT_CAPACITY(xran_decode_se25, buf, len, hdr.numLayers, hdr_out, out);
      assert(hdr_out.ef == hdr.ef && hdr_out.numLayers == hdr.numLayers);
      assert(memcmp(in, out, sizeof(in[0]) * hdr.numLayers) == 0);
    }
  }
  printf("SE 25 round trip passed\n");
}

// numFoFb 0 to 127 (bit width; 0 and 127 are reserved values). Each freqOffsetFb takes the range ends, 0x8000 (value not
// provided), +-1, 0 and other values. Content lengths: 4 + 2 per value (Table 7.7.26.1-1).
static void test_se26_roundtrip(void)
{
  const struct {
    int numFoFb;
    size_t content_len;
    size_t ext_len;
  } lengths[] = {{0, 4, 4}, {1, 6, 8}, {2, 8, 8}, {3, 10, 12}, {126, 256, 256}, {127, 258, 260}};
  for (int n = 0; n <= XRAN_SE26_MAX_FOFB; n++) {
    xran_se26_hdr_t hdr = {.ef = n & 1, .numFoFb = n};
    int16_t in[XRAN_SE26_MAX_FOFB], out[XRAN_SE26_MAX_FOFB + 1];
    for (int i = 0; i < XRAN_SE26_MAX_FOFB; i++) {
      const int16_t vals[] = {INT16_MIN, -30000, -1, 0, 1, 30000, INT16_MAX, (int16_t)(i * 1237)};
      in[i] = vals[(i + n) % 8];
    }
    uint8_t buf[300];
    memset(buf, SENTINEL, sizeof(buf));
    size_t len = 0;
    assert(xran_encode_se26(&hdr, in, buf, sizeof(buf), &len) == XRAN_EXT_OK);
    size_t content_len = len;
    for (size_t c = 0; c < sizeof(lengths) / sizeof(lengths[0]); c++) {
      if (lengths[c].numFoFb == n) {
        assert(len == lengths[c].ext_len);
        content_len = lengths[c].content_len;
      }
    }
    check_encoded(XRAN_CP_SECTIONEXTCMD_26, buf, sizeof(buf), len, content_len);

    xran_se26_hdr_t hdr_out;
    DECODE_EXACT_CAPACITY(xran_decode_se26, buf, len, n, hdr_out, out);
    assert(hdr_out.ef == hdr.ef && hdr_out.numFoFb == hdr.numFoFb);
    assert(memcmp(in, out, sizeof(in[0]) * n) == 0);
  }
  printf("SE 26 round trip, numFoFb 0 to 127, passed\n");
}

// beamType 00b and 01b with numElements 1 to 256 and ef 0 and 1. The beamIds take 0, 1, 0x7FFE, 0x7FFF and other
// values. Content lengths: 4 + 2 per beamId (Tables 7.7.27.1-1 and 7.7.27.1-2). A range carries one beamId only.
static void test_se27_roundtrip(void)
{
  const struct {
    uint8_t beamType;
    int numElements;
    size_t content_len;
    size_t ext_len;
  } lengths[] = {
      {XRAN_SE27_BEAM_LIST, 1, 6, 8},
      {XRAN_SE27_BEAM_LIST, 2, 8, 8},
      {XRAN_SE27_BEAM_LIST, 3, 10, 12},
      {XRAN_SE27_BEAM_LIST, 255, 514, 516},
      {XRAN_SE27_BEAM_LIST, 256, 516, 516},
      {XRAN_SE27_BEAM_RANGE, 1, 6, 8},
      {XRAN_SE27_BEAM_RANGE, 256, 6, 8},
  };
  int n_cases = 0;
  for (int bt = XRAN_SE27_BEAM_LIST; bt <= XRAN_SE27_BEAM_RANGE; bt++) {
    for (int n = 1; n <= XRAN_SE27_MAX_ELEMENTS; n++) {
      for (int ef = 0; ef <= 1; ef++) {
        xran_se27_hdr_t hdr = {.ef = ef, .beamType = bt, .numElements = n};
        uint16_t in[XRAN_SE27_MAX_ELEMENTS], out[XRAN_SE27_MAX_ELEMENTS + 1];
        for (int i = 0; i < XRAN_SE27_MAX_ELEMENTS; i++) {
          const uint16_t vals[] = {0, 1, 0x7FFE, 0x7FFF, (uint16_t)((i * 0x1357) & 0x7FFF)};
          in[i] = vals[(i + n + ef) % 5];
        }
        uint8_t buf[600];
        memset(buf, SENTINEL, sizeof(buf));
        size_t len = 0;
        assert(xran_encode_se27(&hdr, in, buf, sizeof(buf), &len) == XRAN_EXT_OK);
        size_t content_len = len;
        for (size_t c = 0; c < sizeof(lengths) / sizeof(lengths[0]); c++) {
          if (lengths[c].beamType == bt && lengths[c].numElements == n) {
            assert(len == lengths[c].ext_len);
            content_len = lengths[c].content_len;
          }
        }
        check_encoded(XRAN_CP_SECTIONEXTCMD_27, buf, sizeof(buf), len, content_len);

        int n_ids = xran_se27_num_beam_ids(&hdr);
        xran_se27_hdr_t hdr_out;
        DECODE_EXACT_CAPACITY(xran_decode_se27, buf, len, n_ids, hdr_out, out);
        assert(hdr_out.ef == hdr.ef && hdr_out.beamType == hdr.beamType && hdr_out.numElements == hdr.numElements);
        assert(memcmp(in, out, sizeof(in[0]) * n_ids) == 0);
        n_cases++;
      }
    }
  }
  assert(n_cases == 2 * 256 * 2);
  printf("SE 27 round trip, all %d modes, passed\n", n_cases);
}

static void test_se25_se26_se27_vectors(void)
{
  // Table 7.7.25.2-1 (per-window symbol reordering). The table shows symbols 0 to 3 and 10 to 13; the full order is
  // from Figure 7.7.25.2-2: on-air symbols 2, 3, 10, 11, 0, 1, 4, 5, 6, 7, 8, 9, 12, 13 in tx windows 0 to 13.
  const uint8_t v25_window[] = {
      0x19, // ef 0 | extType 0x19
      0x03, // extLen 3 words
      0x45, // symbol 0: window 4 | symbol 1: window 5
      0x01, // 2: 0 | 3: 1
      0x67, // 4: 6 | 5: 7
      0x89, // 6: 8 | 7: 9
      0xAB, // 8: 10 | 9: 11
      0x23, // 10: 2 | 11: 3
      0xCD, // 12: 12 | 13: 13
      0x00,
      0x00,
      0x00, // padding
  };
  const xran_se25_layer_t l25_window[] = {{{4, 5, 0, 1, 6, 7, 8, 9, 10, 11, 2, 3, 12, 13}}};
  // Table 7.7.25.3-2 (per-section tx-window reassignment, 2 layers). The full values are from Figure 7.7.25.3-4: layer 0
  // sends two on-air symbols in each of windows 0 to 6, layer 1 the same in windows 7 to 13.
  const uint8_t v25_layers[] = {
      0x19, // ef 0 | extType 0x19
      0x04, // extLen 4 words
      0x11,
      0x02,
      0x23,
      0x34,
      0x45,
      0x50,
      0x66, // 1st layer
      0x88,
      0x79,
      0x9A,
      0xAB,
      0xBC,
      0xC7,
      0xDD, // 2nd layer
  };
  const xran_se25_layer_t l25_layers[] = {{{1, 1, 0, 2, 2, 3, 3, 4, 4, 5, 5, 0, 6, 6}},
                                          {{8, 8, 7, 9, 9, 10, 10, 11, 11, 12, 12, 7, 13, 13}}};
  const struct {
    const uint8_t *bytes;
    size_t len;
    int numLayers;
    const xran_se25_layer_t *layers;
  } v25[] = {{v25_window, sizeof(v25_window), 1, l25_window}, {v25_layers, sizeof(v25_layers), 2, l25_layers}};
  for (size_t v = 0; v < 2; v++) {
    xran_se25_hdr_t hdr;
    xran_se25_layer_t layers[XRAN_SE25_MAX_LAYERS];
    assert(xran_decode_se25(v25[v].bytes, v25[v].len, XRAN_SE25_MAX_LAYERS, &hdr, layers) == XRAN_EXT_OK);
    assert(hdr.ef == 0 && hdr.numLayers == v25[v].numLayers);
    assert(memcmp(layers, v25[v].layers, sizeof(layers[0]) * hdr.numLayers) == 0);
    uint8_t buf[32];
    size_t len = 0;
    assert(xran_encode_se25(&hdr, v25[v].layers, buf, sizeof(buf), &len) == XRAN_EXT_OK);
    assert(len == v25[v].len && memcmp(buf, v25[v].bytes, len) == 0);
  }

  // Table 7.7.26.1-1. v16.01 shows extLen = 0x01, but the length depends on numFoFb (v21.00 shows extLen variable).
  const uint8_t v26[] = {
      0x9A, // ef 1 | extType 0x1A
      0x03, // extLen 3 words
      0x00, // reserved
      0x03, // reserved | numFoFb 3
      0x75,
      0x30, // +30000: +0.5 subcarrier
      0x8A,
      0xD0, // -30000: -0.5 subcarrier
      0x80,
      0x00, // value not provided
      0x00,
      0x00, // padding
  };
  const int16_t f26[] = {30000, -30000, INT16_MIN};
  xran_se26_hdr_t h26;
  int16_t fofb[XRAN_SE26_MAX_FOFB];
  assert(xran_decode_se26(v26, sizeof(v26), XRAN_SE26_MAX_FOFB, &h26, fofb) == XRAN_EXT_OK);
  assert(h26.ef == 1 && h26.numFoFb == 3 && memcmp(fofb, f26, sizeof(f26)) == 0);
  uint8_t buf[16];
  size_t len = 0;
  assert(xran_encode_se26(&h26, f26, buf, sizeof(buf), &len) == XRAN_EXT_OK);
  assert(len == sizeof(v26) && memcmp(buf, v26, len) == 0);

  // Table 7.7.27.1-1 (list, 3 beamIds, padding because numElements is odd)
  const uint8_t v27_list[] = {
      0x1B, // ef 0 | extType 0x1B
      0x03, // extLen 3 words
      0x00, // beamType 00 | reserved
      0x03, // numElements 3
      0x00,
      0x01, // reserved 0 | beamId 1
      0x7F,
      0xFF, // reserved 0 | beamId 0x7FFF
      0x01,
      0x00, // reserved 0 | beamId 0x0100
      0x00,
      0x00, // padding
  };
  const uint16_t b27_list[] = {1, 0x7FFF, 0x0100};
  // Table 7.7.27.1-2 (range of 256 beamIds from 0x1234)
  const uint8_t v27_range[] = {
      0x9B, // ef 1 | extType 0x1B
      0x02, // extLen 2 words
      0x40, // beamType 01 | reserved
      0x00, // numElements 0 (256)
      0x12,
      0x34, // reserved 0 | beamId 0x1234
      0x00,
      0x00, // padding
  };
  const uint16_t b27_range[] = {0x1234};
  const struct {
    const uint8_t *bytes;
    size_t len;
    xran_se27_hdr_t hdr;
    const uint16_t *beamId;
  } v27[] = {{v27_list, sizeof(v27_list), {.ef = 0, .beamType = XRAN_SE27_BEAM_LIST, .numElements = 3}, b27_list},
             {v27_range, sizeof(v27_range), {.ef = 1, .beamType = XRAN_SE27_BEAM_RANGE, .numElements = 256}, b27_range}};
  for (size_t v = 0; v < 2; v++) {
    xran_se27_hdr_t hdr;
    uint16_t ids[XRAN_SE27_MAX_ELEMENTS];
    assert(xran_decode_se27(v27[v].bytes, v27[v].len, XRAN_SE27_MAX_ELEMENTS, &hdr, ids) == XRAN_EXT_OK);
    assert(hdr.ef == v27[v].hdr.ef && hdr.beamType == v27[v].hdr.beamType && hdr.numElements == v27[v].hdr.numElements);
    assert(memcmp(ids, v27[v].beamId, sizeof(ids[0]) * xran_se27_num_beam_ids(&hdr)) == 0);
    assert(xran_encode_se27(&v27[v].hdr, v27[v].beamId, buf, sizeof(buf), &len) == XRAN_EXT_OK);
    assert(len == v27[v].len && memcmp(buf, v27[v].bytes, len) == 0);
  }
  printf("SE 25, SE 26 and SE 27 byte vectors passed\n");
}

int main(void)
{
  test_se10_all_modes();
  test_se10_lengths();
  test_se24_field_roundtrip();
  test_se10_vectors();
  test_se24_vectors();
  test_se25_roundtrip();
  test_se26_roundtrip();
  test_se27_roundtrip();
  test_se25_se26_se27_vectors();
  printf("All ULPI tests passed!\n");
  return 0;
}
