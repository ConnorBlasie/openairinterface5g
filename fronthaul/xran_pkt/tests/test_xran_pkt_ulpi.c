/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Checks the ULPI (DMRS-BF) C-plane formats of CUS v16.01:
// - the Section Type 5 structs of xran_pkt_cp.h against Table 7.4.7-1. Wire bytes are converted with the same in-place
//   swaps that oru_packet_processor.c applies to Section Type 1: rte_be_to_cpu_32 on the common header bits and
//   rte_be_to_cpu_64 on the 8-byte section.
// - the SE 10 and SE 24 codecs of xran_pkt_ulpi.h against clauses 7.7.10 and 7.7.24.

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <rte_byteorder.h>
#include "xran_pkt_cp.h"
#include "xran_pkt_bfw.h"
#include "xran_pkt_ulpi.h"

void exit_function(const char *file, const char *function, const int line, const char *s, const int assertflag)
{
  fprintf(stderr, "Error at %s:%s:%d - %s\n", file, function, line, s ? s : "None");
  exit(1);
}

_Static_assert(sizeof(struct xran_cp_radioapp_section5_header) == 8, "Table 7.4.7-1 octets 9 to 16");
_Static_assert(sizeof(struct xran_cp_radioapp_section5) == 8, "Table 7.4.7-1 octets 17 to 24");

#define ST5_WIRE_LEN (sizeof(struct xran_cp_radioapp_section5_header) + sizeof(struct xran_cp_radioapp_section5))

typedef struct {
  // common header
  unsigned dataDirection, payloadVersion, filterIndex, frameId, subframeId, slotId, startSymbolId, numberOfSections;
  unsigned udIqWidth, udCompMeth;
  // section
  unsigned sectionId, rb, symInc, startPrbc, numPrbc, reMask, numSymbol, ef, ueId;
} st5_fields_t;

typedef union {
  uint64_t align;
  uint8_t bytes[ST5_WIRE_LEN];
} st5_wire_t;

static void fields_to_wire(const st5_fields_t *f, st5_wire_t *w)
{
  memset(w, 0, sizeof(*w));
  struct xran_cp_radioapp_section5_header *hdr = (void *)w->bytes;
  struct xran_cp_radioapp_section5 *sec = (void *)(w->bytes + sizeof(*hdr));
  hdr->cmnhdr.field.dataDirection = f->dataDirection;
  hdr->cmnhdr.field.payloadVer = f->payloadVersion;
  hdr->cmnhdr.field.filterIndex = f->filterIndex;
  hdr->cmnhdr.field.frameId = f->frameId;
  hdr->cmnhdr.field.subframeId = f->subframeId;
  hdr->cmnhdr.field.slotId = f->slotId;
  hdr->cmnhdr.field.startSymbolId = f->startSymbolId;
  hdr->cmnhdr.field.all_bits = rte_cpu_to_be_32(hdr->cmnhdr.field.all_bits);
  hdr->cmnhdr.numOfSections = f->numberOfSections;
  hdr->cmnhdr.sectionType = XRAN_CP_SECTIONTYPE_5;
  hdr->udComp.udIqWidth = f->udIqWidth;
  hdr->udComp.udCompMeth = f->udCompMeth;
  sec->hdr.u1.common.sectionId = f->sectionId;
  sec->hdr.u1.common.rb = f->rb;
  sec->hdr.u1.common.symInc = f->symInc;
  sec->hdr.u1.common.startPrbc = f->startPrbc;
  sec->hdr.u1.common.numPrbc = f->numPrbc;
  sec->hdr.u.s5.reMask = f->reMask;
  sec->hdr.u.s5.numSymbol = f->numSymbol;
  sec->hdr.u.s5.ef = f->ef;
  sec->hdr.u.s5.ueId = f->ueId;
  *((uint64_t *)sec) = rte_cpu_to_be_64(*((uint64_t *)sec));
}

static void wire_to_fields(const st5_wire_t *in, st5_fields_t *f)
{
  st5_wire_t w = *in;
  struct xran_cp_radioapp_section5_header *hdr = (void *)w.bytes;
  struct xran_cp_radioapp_section5 *sec = (void *)(w.bytes + sizeof(*hdr));
  hdr->cmnhdr.field.all_bits = rte_be_to_cpu_32(hdr->cmnhdr.field.all_bits);
  *((uint64_t *)sec) = rte_be_to_cpu_64(*((uint64_t *)sec));
  assert(hdr->cmnhdr.sectionType == XRAN_CP_SECTIONTYPE_5);
  *f = (st5_fields_t){.dataDirection = hdr->cmnhdr.field.dataDirection,
                      .payloadVersion = hdr->cmnhdr.field.payloadVer,
                      .filterIndex = hdr->cmnhdr.field.filterIndex,
                      .frameId = hdr->cmnhdr.field.frameId,
                      .subframeId = hdr->cmnhdr.field.subframeId,
                      .slotId = hdr->cmnhdr.field.slotId,
                      .startSymbolId = hdr->cmnhdr.field.startSymbolId,
                      .numberOfSections = hdr->cmnhdr.numOfSections,
                      .udIqWidth = hdr->udComp.udIqWidth,
                      .udCompMeth = hdr->udComp.udCompMeth,
                      .sectionId = sec->hdr.u1.common.sectionId,
                      .rb = sec->hdr.u1.common.rb,
                      .symInc = sec->hdr.u1.common.symInc,
                      .startPrbc = sec->hdr.u1.common.startPrbc,
                      .numPrbc = sec->hdr.u1.common.numPrbc,
                      .reMask = sec->hdr.u.s5.reMask,
                      .numSymbol = sec->hdr.u.s5.numSymbol,
                      .ef = sec->hdr.u.s5.ef,
                      .ueId = sec->hdr.u.s5.ueId};
}

static void assert_fields_eq(const st5_fields_t *a, const st5_fields_t *b)
{
  assert(a->dataDirection == b->dataDirection);
  assert(a->payloadVersion == b->payloadVersion);
  assert(a->filterIndex == b->filterIndex);
  assert(a->frameId == b->frameId);
  assert(a->subframeId == b->subframeId);
  assert(a->slotId == b->slotId);
  assert(a->startSymbolId == b->startSymbolId);
  assert(a->numberOfSections == b->numberOfSections);
  assert(a->udIqWidth == b->udIqWidth);
  assert(a->udCompMeth == b->udCompMeth);
  assert(a->sectionId == b->sectionId);
  assert(a->rb == b->rb);
  assert(a->symInc == b->symInc);
  assert(a->startPrbc == b->startPrbc);
  assert(a->numPrbc == b->numPrbc);
  assert(a->reMask == b->reMask);
  assert(a->numSymbol == b->numSymbol);
  assert(a->ef == b->ef);
  assert(a->ueId == b->ueId);
}

// Each field at its minimum, middle and maximum value (bit width limits), with the other fields at a mixed base value,
// so a bitfield that is too narrow or overlaps a neighbour fails the comparison.
static void test_field_roundtrip(void)
{
  const st5_fields_t base = {.dataDirection = 1,
                             .payloadVersion = 1,
                             .filterIndex = 0x5,
                             .frameId = 0x96,
                             .subframeId = 0x6,
                             .slotId = 0x2A,
                             .startSymbolId = 0x15,
                             .numberOfSections = 0x69,
                             .udIqWidth = 0x9,
                             .udCompMeth = 0x6,
                             .sectionId = 0x5A5,
                             .rb = 1,
                             .symInc = 0,
                             .startPrbc = 0x2A5,
                             .numPrbc = 0x5A,
                             .reMask = 0xA5A,
                             .numSymbol = 0x5,
                             .ef = 1,
                             .ueId = 0x2A5A};
#define RT_FIELD(field, max)                       \
  do {                                             \
    const unsigned vals[] = {0, (max) / 2, (max)}; \
    for (int i = 0; i < 3; i++) {                  \
      st5_fields_t in = base, out;                 \
      st5_wire_t w;                                \
      in.field = vals[i];                          \
      fields_to_wire(&in, &w);                     \
      wire_to_fields(&w, &out);                    \
      assert_fields_eq(&in, &out);                 \
    }                                              \
  } while (0)
  RT_FIELD(dataDirection, 0x1);
  RT_FIELD(payloadVersion, 0x7);
  RT_FIELD(filterIndex, 0xF);
  RT_FIELD(frameId, 0xFF);
  RT_FIELD(subframeId, 0xF);
  RT_FIELD(slotId, 0x3F);
  RT_FIELD(startSymbolId, 0x3F);
  RT_FIELD(numberOfSections, 0xFF);
  RT_FIELD(udIqWidth, 0xF);
  RT_FIELD(udCompMeth, 0xF);
  RT_FIELD(sectionId, 0xFFF);
  RT_FIELD(rb, 0x1);
  RT_FIELD(symInc, 0x1);
  RT_FIELD(startPrbc, 0x3FF);
  RT_FIELD(numPrbc, 0xFF);
  RT_FIELD(reMask, 0xFFF);
  RT_FIELD(numSymbol, 0xF);
  RT_FIELD(ef, 0x1);
  RT_FIELD(ueId, 0x7FFF);
#undef RT_FIELD
  printf("ST 5 field round trip passed\n");
}

typedef struct {
  const char *name;
  uint8_t bytes[ST5_WIRE_LEN]; // octets 9 to 24
  st5_fields_t fields;
} st5_vector_t;

// Encoded by hand from CUS v16.01 Table 7.4.7-1.
static const st5_vector_t vectors[] = {
    {.name = "UL, 9-bit BFP, ef = 1",
     .bytes =
         {
             0x10, // dataDirection 0 | payloadVersion 001 | filterIndex 0000
             0x5A, // frameId 0x5A
             0x70, // subframeId 0111 | slotId[5:2] 0000
             0x42, // slotId[1:0] 01 | startSymbolId 00 0010
             0x01, // numberOfSections 1
             0x05, // sectionType 5
             0x91, // udIqWidth 1001 | udCompMeth 0001
             0x00, // reserved
             0xAB, // sectionId[11:4]
             0xC6, // sectionId[3:0] 1100 | rb 0 | symInc 1 | startPrbc[9:8] 10
             0xF5, // startPrbc[7:0]
             0x6A, // numPrbc 106
             0xFF, // reMask[11:4]
             0xFC, // reMask[3:0] 1111 | numSymbol 1100
             0x92, // ef 1 | ueId[14:8] 001 0010
             0x34, // ueId[7:0]
         },
     .fields = {.dataDirection = 0,
                .payloadVersion = 1,
                .filterIndex = 0,
                .frameId = 0x5A,
                .subframeId = 7,
                .slotId = 1,
                .startSymbolId = 2,
                .numberOfSections = 1,
                .udIqWidth = 9,
                .udCompMeth = 1,
                .sectionId = 0xABC,
                .rb = 0,
                .symInc = 1,
                .startPrbc = 0x2F5,
                .numPrbc = 106,
                .reMask = 0xFFF,
                .numSymbol = 12,
                .ef = 1,
                .ueId = 0x1234}},
    {.name = "DL, uncompressed, all PRBs, ueId 0x7FFF",
     .bytes =
         {
             0x90, // dataDirection 1 | payloadVersion 001 | filterIndex 0000
             0xFF, // frameId 0xFF
             0x93, // subframeId 1001 | slotId[5:2] 0011
             0xCD, // slotId[1:0] 11 | startSymbolId 00 1101
             0xFF, // numberOfSections 255
             0x05, // sectionType 5
             0x00, // udIqWidth 0000 (16 bits) | udCompMeth 0000
             0x00, // reserved
             0x00, // sectionId[11:4]
             0x19, // sectionId[3:0] 0001 | rb 1 | symInc 0 | startPrbc[9:8] 01
             0x00, // startPrbc[7:0]
             0x00, // numPrbc 0 (all PRBs)
             0xA5, // reMask[11:4]
             0xA1, // reMask[3:0] 1010 | numSymbol 0001
             0x7F, // ef 0 | ueId[14:8] 111 1111
             0xFF, // ueId[7:0]
         },
     .fields = {.dataDirection = 1,
                .payloadVersion = 1,
                .filterIndex = 0,
                .frameId = 0xFF,
                .subframeId = 9,
                .slotId = 15,
                .startSymbolId = 13,
                .numberOfSections = 255,
                .udIqWidth = 0,
                .udCompMeth = 0,
                .sectionId = 0x001,
                .rb = 1,
                .symInc = 0,
                .startPrbc = 0x100,
                .numPrbc = 0,
                .reMask = 0xA5A,
                .numSymbol = 1,
                .ef = 0,
                .ueId = 0x7FFF}},
};

static void test_spec_vectors(void)
{
  for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
    const st5_vector_t *vec = &vectors[v];
    st5_wire_t w;
    memcpy(w.bytes, vec->bytes, sizeof(w.bytes));
    st5_fields_t f;
    wire_to_fields(&w, &f);
    assert_fields_eq(&f, &vec->fields);

    fields_to_wire(&f, &w);
    assert(memcmp(w.bytes, vec->bytes, sizeof(w.bytes)) == 0);
    printf("ST 5 spec vector \"%s\" passed\n", vec->name);
  }
}

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

// Encodes, checks the length against the extension walk and that nothing is written after the extension, decodes
// and compares. 00b and 01b pass ports = NULL, and the decoder must not touch ports_out. The decode has room for
// exactly the listed ports; with one place less it must return XRAN_ULPI_ERR_TOO_MANY. Returns the length.
static size_t roundtrip_se10(const xran_se10_hdr_t *hdr, const xran_se10_port_t *ports)
{
  uint8_t buf[256];
  memset(buf, 0xEE, sizeof(buf));
  size_t len = 0;
  assert(xran_encode_se10(hdr, ports, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
  assert(len % 4 == 0 && len < sizeof(buf));
  assert(buf[len] == 0xEE);
  size_t walk_len = 0;
  assert(xran_section_ext_len(XRAN_CP_SECTIONEXTCMD_10, buf, sizeof(buf), &walk_len) == XRAN_BFW_OK);
  assert(walk_len == len);

  int n_ports = xran_se10_num_ports(hdr);
  xran_se10_hdr_t hdr_out;
  xran_se10_port_t ports_out[XRAN_SE10_MAX_PORTS + 1];
  memset(&hdr_out, 0xA5, sizeof(hdr_out));
  memset(ports_out, 0xA5, sizeof(ports_out));
  if (n_ports > 1) {
    assert(xran_decode_se10(buf, len, n_ports - 1, &hdr_out, ports_out) == XRAN_ULPI_ERR_TOO_MANY);
    assert(hdr_out.numPortc == (int)0xA5A5A5A5 && ports_out[0].id == 0xA5A5);
  }
  assert(xran_decode_se10(buf, len, n_ports > 0 ? n_ports : 1, &hdr_out, ports_out) == XRAN_ULPI_OK);
  assert_se10_eq(hdr, ports, &hdr_out, ports_out);
  assert(ports_out[n_ports].id == 0xA5A5 && ports_out[n_ports].portListIndex == 0xA5);
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
        roundtrip_se10(&hdr, listed ? ports : NULL);
        n_cases++;
      }
    }
  }
  assert(n_cases == 4 * 64 * 2);
  printf("SE 10 round trip, all %d modes, passed\n", n_cases);
}

// Lengths from Tables 7.7.10.1-1 to 7.7.10.1-3: 00b and 01b are 4 bytes, 10b is 3 bytes + 2 per port, 11b is 4 bytes
// + 3 per port after the first. The filler after the content must be zero.
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
    size_t len = 0;
    assert(xran_encode_se10(&hdr, ports, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
    assert(len == cases[c].ext_len);
    assert(buf[1] == cases[c].ext_len / 4); // extLen in 4-byte words
    if (cases[c].bgt >= XRAN_SE10_BGT_10B)
      assert(buf[cases[c].content_len - 1] == 0xFF); // last id byte or portListIndex, not filler
    for (size_t i = cases[c].content_len; i < cases[c].ext_len; i++)
      assert(buf[i] == 0);
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
  assert(xran_encode_se24(hdr, entries, n, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
  size_t walk_len = 0;
  assert(xran_section_ext_len(XRAN_CP_SECTIONEXTCMD_24, buf, len, &walk_len) == XRAN_BFW_OK);
  assert(walk_len == len);
  xran_se24_hdr_t hdr_out;
  xran_se24_entry_t out[16];
  memset(out, 0xA5, sizeof(out));
  assert(xran_decode_se24(buf, len, n, &hdr_out, out) == XRAN_ULPI_OK);
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
    assert(xran_decode_se10(vectors[v].bytes, vectors[v].len, XRAN_SE10_MAX_PORTS, &hdr, ports) == XRAN_ULPI_OK);
    assert_se10_eq(&hdr, ports, vectors[v].hdr, vectors[v].ports);
    uint8_t buf[16];
    size_t len = 0;
    assert(xran_encode_se10(vectors[v].hdr, vectors[v].ports, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
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
    assert(xran_decode_se24(vectors[v].bytes, vectors[v].len, vectors[v].n, &hdr, out) == XRAN_ULPI_OK);
    assert_se24_hdr_eq(&hdr, vectors[v].hdr);
    for (int i = 0; i < vectors[v].n; i++)
      assert_se24_entry_eq(&out[i], &vectors[v].entries[i]);
    uint8_t buf[64];
    size_t len = 0;
    assert(xran_encode_se24(vectors[v].hdr, vectors[v].entries, vectors[v].n, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
    assert(len == vectors[v].len);
    assert(memcmp(buf, vectors[v].bytes, len) == 0);
  }
  printf("SE 24 byte vectors passed\n");
}

/**********************************************************************
 * SE 25, SE 26 and SE 27 (CUS v16.01 7.7.25 to 7.7.27)
 **********************************************************************/

// Checks an encoded extension: length is a multiple of 4, matches extLen and the extension walk, nothing is written
// after it, and the bytes from content_len to the end are zero
static void check_encoded(uint8_t ext_type, const uint8_t *buf, size_t avail, size_t len, size_t content_len)
{
  assert(len % 4 == 0 && len < avail);
  assert(buf[1] == len / 4);
  assert(buf[len] == 0xEE);
  size_t walk_len = 0;
  assert(xran_section_ext_len(ext_type, buf, avail, &walk_len) == XRAN_BFW_OK);
  assert(walk_len == len);
  for (size_t i = content_len; i < len; i++)
    assert(buf[i] == 0);
}

// numLayers 1 to 4, 12 and the maximum 145. Content lengths: 2 + 7 per layer (Table 7.7.25.1-1). For each layer count,
// 16 passes put every 4-bit value at every symbol of every layer. The decode has room for exactly numLayers layers;
// with one place less it must return XRAN_ULPI_ERR_TOO_MANY.
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
      memset(buf, 0xEE, sizeof(buf));
      size_t len = 0;
      assert(xran_encode_se25(&hdr, in, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
      assert(len == cases[c].ext_len);
      check_encoded(XRAN_CP_SECTIONEXTCMD_25, buf, sizeof(buf), len, cases[c].content_len);

      xran_se25_hdr_t hdr_out;
      memset(&hdr_out, 0xA5, sizeof(hdr_out));
      memset(out, 0xA5, sizeof(out));
      if (hdr.numLayers > 1) {
        assert(xran_decode_se25(buf, len, hdr.numLayers - 1, &hdr_out, out) == XRAN_ULPI_ERR_TOO_MANY);
        assert(hdr_out.numLayers == (int)0xA5A5A5A5 && out[0].txWinForOnAirSymbol[0] == 0xA5);
      }
      assert(xran_decode_se25(buf, len, hdr.numLayers, &hdr_out, out) == XRAN_ULPI_OK);
      assert(hdr_out.ef == hdr.ef && hdr_out.numLayers == hdr.numLayers);
      assert(memcmp(in, out, sizeof(in[0]) * hdr.numLayers) == 0);
      assert(out[hdr.numLayers].txWinForOnAirSymbol[0] == 0xA5);
    }
  }
  printf("SE 25 round trip passed\n");
}

// numFoFb 0 to 127 (bit width; 0 and 127 are reserved values). Each freqOffsetFb takes the range ends, 0x8000 (value not
// provided), +-1, 0 and other values. Content lengths: 4 + 2 per value (Table 7.7.26.1-1). The decode has room for
// exactly numFoFb values (1 for numFoFb 0); with one place less it must return XRAN_ULPI_ERR_TOO_MANY.
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
    memset(buf, 0xEE, sizeof(buf));
    size_t len = 0;
    assert(xran_encode_se26(&hdr, in, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
    size_t content_len = len;
    for (size_t c = 0; c < sizeof(lengths) / sizeof(lengths[0]); c++) {
      if (lengths[c].numFoFb == n) {
        assert(len == lengths[c].ext_len);
        content_len = lengths[c].content_len;
      }
    }
    check_encoded(XRAN_CP_SECTIONEXTCMD_26, buf, sizeof(buf), len, content_len);

    xran_se26_hdr_t hdr_out;
    memset(&hdr_out, 0xA5, sizeof(hdr_out));
    memset(out, 0xA5, sizeof(out));
    if (n > 1) {
      assert(xran_decode_se26(buf, len, n - 1, &hdr_out, out) == XRAN_ULPI_ERR_TOO_MANY);
      assert(hdr_out.numFoFb == 0xA5 && out[0] == (int16_t)0xA5A5);
    }
    assert(xran_decode_se26(buf, len, n > 0 ? n : 1, &hdr_out, out) == XRAN_ULPI_OK);
    assert(hdr_out.ef == hdr.ef && hdr_out.numFoFb == hdr.numFoFb);
    assert(memcmp(in, out, sizeof(in[0]) * n) == 0);
    assert(out[n] == (int16_t)0xA5A5);
  }
  printf("SE 26 round trip, numFoFb 0 to 127, passed\n");
}

// beamType 00b and 01b with numElements 1 to 256 and ef 0 and 1. The beamIds take 0, 1, 0x7FFE, 0x7FFF and other
// values. Content lengths: 4 + 2 per beamId (Tables 7.7.27.1-1 and 7.7.27.1-2). The decode has room for exactly
// xran_se27_num_beam_ids() beamIds; with one place less it must return XRAN_ULPI_ERR_TOO_MANY.
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
        memset(buf, 0xEE, sizeof(buf));
        size_t len = 0;
        assert(xran_encode_se27(&hdr, in, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
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
        memset(&hdr_out, 0xA5, sizeof(hdr_out));
        memset(out, 0xA5, sizeof(out));
        if (n_ids > 1) {
          assert(xran_decode_se27(buf, len, n_ids - 1, &hdr_out, out) == XRAN_ULPI_ERR_TOO_MANY);
          assert(hdr_out.numElements == (int)0xA5A5A5A5 && out[0] == 0xA5A5);
        }
        assert(xran_decode_se27(buf, len, n_ids, &hdr_out, out) == XRAN_ULPI_OK);
        assert(hdr_out.ef == hdr.ef && hdr_out.beamType == hdr.beamType && hdr_out.numElements == hdr.numElements);
        assert(memcmp(in, out, sizeof(in[0]) * n_ids) == 0);
        assert(out[n_ids] == 0xA5A5); // a range carries one beamId only
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
    assert(xran_decode_se25(v25[v].bytes, v25[v].len, XRAN_SE25_MAX_LAYERS, &hdr, layers) == XRAN_ULPI_OK);
    assert(hdr.ef == 0 && hdr.numLayers == v25[v].numLayers);
    assert(memcmp(layers, v25[v].layers, sizeof(layers[0]) * hdr.numLayers) == 0);
    uint8_t buf[32];
    size_t len = 0;
    assert(xran_encode_se25(&hdr, v25[v].layers, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
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
  assert(xran_decode_se26(v26, sizeof(v26), XRAN_SE26_MAX_FOFB, &h26, fofb) == XRAN_ULPI_OK);
  assert(h26.ef == 1 && h26.numFoFb == 3 && memcmp(fofb, f26, sizeof(f26)) == 0);
  uint8_t buf[16];
  size_t len = 0;
  assert(xran_encode_se26(&h26, f26, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
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
    assert(xran_decode_se27(v27[v].bytes, v27[v].len, XRAN_SE27_MAX_ELEMENTS, &hdr, ids) == XRAN_ULPI_OK);
    assert(hdr.ef == v27[v].hdr.ef && hdr.beamType == v27[v].hdr.beamType && hdr.numElements == v27[v].hdr.numElements);
    assert(memcmp(ids, v27[v].beamId, sizeof(ids[0]) * xran_se27_num_beam_ids(&hdr)) == 0);
    assert(xran_encode_se27(&v27[v].hdr, v27[v].beamId, buf, sizeof(buf), &len) == XRAN_ULPI_OK);
    assert(len == v27[v].len && memcmp(buf, v27[v].bytes, len) == 0);
  }
  printf("SE 25, SE 26 and SE 27 byte vectors passed\n");
}

// An ST 5 section with ef = 1, then SE 10 (10b) and SE 24, walked as a receiver does: the extension lengths from
// xran_section_ext_len(), and the SE 24 entry count from the ueIds other than 0x7FFF (7.7.24.3).
static void test_st5_se10_se24_section(void)
{
  uint8_t pkt[128] = {0};
  st5_fields_t f = vectors[0].fields; // ef = 1, ueId 0x1234
  st5_wire_t w;
  fields_to_wire(&f, &w);
  memcpy(pkt, w.bytes, ST5_WIRE_LEN);
  size_t off = ST5_WIRE_LEN;

  const xran_se10_hdr_t se10 = {.ef = 1, .beamGroupType = XRAN_SE10_BGT_10B, .numPortc = 3};
  const xran_se10_port_t se10_ports[] = {{.id = 0x1235}, {.id = 0x7FFF}, {.id = 0x1236}};
  size_t len = 0;
  assert(xran_encode_se10(&se10, se10_ports, pkt + off, sizeof(pkt) - off, &len) == XRAN_ULPI_OK);
  off += len;
  const xran_se24_hdr_t hdr = {.ef = 0};
  const xran_se24_entry_t entries[] = {
      {.entryType = 2, .dmrsPortNumber = 0, .ueIdReset = 1, .dmrsSymbolMask = 0x0004, .cdmWithoutData = 2, .lastPrb = 105},
      {.entryType = 1, .dmrsPortNumber = 1},
      {.entryType = 1, .dmrsPortNumber = 2},
  };
  assert(xran_encode_se24(&hdr, entries, 3, pkt + off, sizeof(pkt) - off, &len) == XRAN_ULPI_OK);
  size_t pkt_len = off + len;

  // Receive side
  memcpy(w.bytes, pkt, ST5_WIRE_LEN);
  wire_to_fields(&w, &f);
  assert(f.ef == 1);
  int n_layers = f.ueId != 0x7FFF;
  off = ST5_WIRE_LEN;
  int ext_count = 0;
  int ef = 1;
  while (ef) {
    uint8_t ext_type = pkt[off] & 0x7F;
    ef = pkt[off] >> 7;
    size_t ext_len = 0;
    assert(xran_section_ext_len(ext_type, pkt + off, pkt_len - off, &ext_len) == XRAN_BFW_OK);
    if (ext_count == 0) {
      assert(ext_type == XRAN_CP_SECTIONEXTCMD_10);
      xran_se10_hdr_t out;
      xran_se10_port_t ports[XRAN_SE10_MAX_PORTS];
      assert(xran_decode_se10(pkt + off, ext_len, XRAN_SE10_MAX_PORTS, &out, ports) == XRAN_ULPI_OK);
      assert_se10_eq(&se10, se10_ports, &out, ports);
      for (int k = 0; k < xran_se10_num_ports(&out); k++)
        n_layers += ports[k].id != 0x7FFF;
    } else {
      assert(ext_type == XRAN_CP_SECTIONEXTCMD_24);
      assert(n_layers == 3);
      xran_se24_hdr_t hdr_out;
      xran_se24_entry_t out[3];
      assert(xran_decode_se24(pkt + off, ext_len, n_layers, &hdr_out, out) == XRAN_ULPI_OK);
      for (int i = 0; i < 3; i++)
        assert_se24_entry_eq(&entries[i], &out[i]);
    }
    off += ext_len;
    ext_count++;
  }
  assert(ext_count == 2);
  assert(off == pkt_len);
  printf("ST 5 section with SE 10 and SE 24 passed\n");
}

int main(void)
{
  test_field_roundtrip();
  test_spec_vectors();
  test_se10_all_modes();
  test_se10_lengths();
  test_se24_field_roundtrip();
  test_se10_vectors();
  test_se24_vectors();
  test_se25_roundtrip();
  test_se26_roundtrip();
  test_se27_roundtrip();
  test_se25_se26_se27_vectors();
  test_st5_se10_se24_section();
  printf("All ULPI tests passed!\n");
  return 0;
}
