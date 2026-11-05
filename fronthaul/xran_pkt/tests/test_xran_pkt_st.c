/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Checks the Section Type 5 and Section Type 10 structs of xran_pkt_cp.h against CUS v16.01 Tables 7.4.7-1 and
// 7.4.12-1, and the walk of their section extensions. Wire bytes are converted with the same in-place swaps that
// oru_packet_processor.c applies to Section Type 1: rte_be_to_cpu_32 on the common header bits and rte_be_to_cpu_64
// on the 8-byte section.

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <rte_byteorder.h>
#include "xran_pkt_cp.h"
#include "xran_pkt_ext.h"
#include "xran_pkt_ulpi.h"
#include "xran_pkt_test_util.h"

_Static_assert(sizeof(struct xran_cp_radioapp_section5_header) == 8, "Table 7.4.7-1 octets 9 to 16");
_Static_assert(sizeof(struct xran_cp_radioapp_section5) == 8, "Table 7.4.7-1 octets 17 to 24");
_Static_assert(sizeof(struct xran_cp_radioapp_section5_header) == sizeof(struct xran_cp_radioapp_section1_header),
               "same layout as Section Type 1");
_Static_assert(sizeof(struct xran_cp_radioapp_section5) == sizeof(struct xran_cp_radioapp_section1),
               "same layout as Section Type 1");
_Static_assert(sizeof(struct xran_cp_radioapp_section10_header) == 8, "Table 7.4.12-1 octets 9 to 16");
_Static_assert(sizeof(struct xran_cp_radioapp_section10) == 8, "Table 7.4.12-1 octets 17 to 24");
_Static_assert(sizeof(struct xran_cp_radioapp_section10) == sizeof(struct xran_cp_radioapp_section5),
               "same layout as Section Type 5");

#define HDR_LEN 8 // section header (common header + 2 bytes), the same for Section Types 5 and 10
#define WIRE_LEN (HDR_LEN + sizeof(struct xran_cp_radioapp_section5))

// The fields of Tables 7.4.7-1 and 7.4.12-1. Section Type 10 has no filterIndex, udCompHdr or symInc: those bits are
// reserved and stay 0.
typedef struct {
  unsigned sectionType; // XRAN_CP_SECTIONTYPE_5 or XRAN_CP_SECTIONTYPE_10
  // common header
  unsigned dataDirection, payloadVersion, filterIndex, frameId, subframeId, slotId, startSymbolId, numberOfSections;
  unsigned udIqWidth, udCompMeth; // Section Type 5 only
  // section
  unsigned sectionId, rb, symInc, startPrbc, numPrbc, reMask, numSymbol, ef, ueId;
} st_fields_t;

typedef union {
  uint64_t align;
  uint8_t bytes[WIRE_LEN];
} st_wire_t;

static void fields_to_wire(const st_fields_t *f, st_wire_t *w)
{
  memset(w, 0, sizeof(*w));
  struct xran_cp_radioapp_common_header *cmn = (void *)w->bytes;
  struct xran_cp_radioapp_section_header *sec = (void *)(w->bytes + HDR_LEN);
  cmn->field.dataDirection = f->dataDirection;
  cmn->field.payloadVer = f->payloadVersion;
  cmn->field.filterIndex = f->filterIndex;
  cmn->field.frameId = f->frameId;
  cmn->field.subframeId = f->subframeId;
  cmn->field.slotId = f->slotId;
  cmn->field.startSymbolId = f->startSymbolId;
  cmn->field.all_bits = rte_cpu_to_be_32(cmn->field.all_bits);
  cmn->numOfSections = f->numberOfSections;
  cmn->sectionType = f->sectionType;
  if (f->sectionType == XRAN_CP_SECTIONTYPE_5) {
    struct xran_cp_radioapp_section5_header *hdr = (void *)w->bytes;
    hdr->udComp.udIqWidth = f->udIqWidth;
    hdr->udComp.udCompMeth = f->udCompMeth;
  }
  sec->u1.common.sectionId = f->sectionId;
  sec->u1.common.rb = f->rb;
  sec->u1.common.symInc = f->symInc;
  sec->u1.common.startPrbc = f->startPrbc;
  sec->u1.common.numPrbc = f->numPrbc;
  sec->u.s5.reMask = f->reMask;
  sec->u.s5.numSymbol = f->numSymbol;
  sec->u.s5.ef = f->ef;
  sec->u.s5.ueId = f->ueId;
  *((uint64_t *)sec) = rte_cpu_to_be_64(*((uint64_t *)sec));
}

static void wire_to_fields(const st_wire_t *in, st_fields_t *f)
{
  st_wire_t w = *in;
  struct xran_cp_radioapp_common_header *cmn = (void *)w.bytes;
  struct xran_cp_radioapp_section_header *sec = (void *)(w.bytes + HDR_LEN);
  cmn->field.all_bits = rte_be_to_cpu_32(cmn->field.all_bits);
  *((uint64_t *)sec) = rte_be_to_cpu_64(*((uint64_t *)sec));
  assert(cmn->sectionType == XRAN_CP_SECTIONTYPE_5 || cmn->sectionType == XRAN_CP_SECTIONTYPE_10);
  *f = (st_fields_t){.sectionType = cmn->sectionType,
                     .dataDirection = cmn->field.dataDirection,
                     .payloadVersion = cmn->field.payloadVer,
                     .filterIndex = cmn->field.filterIndex,
                     .frameId = cmn->field.frameId,
                     .subframeId = cmn->field.subframeId,
                     .slotId = cmn->field.slotId,
                     .startSymbolId = cmn->field.startSymbolId,
                     .numberOfSections = cmn->numOfSections,
                     .sectionId = sec->u1.common.sectionId,
                     .rb = sec->u1.common.rb,
                     .symInc = sec->u1.common.symInc,
                     .startPrbc = sec->u1.common.startPrbc,
                     .numPrbc = sec->u1.common.numPrbc,
                     .reMask = sec->u.s5.reMask,
                     .numSymbol = sec->u.s5.numSymbol,
                     .ef = sec->u.s5.ef,
                     .ueId = sec->u.s5.ueId};
  if (f->sectionType == XRAN_CP_SECTIONTYPE_5) {
    const struct xran_cp_radioapp_section5_header *hdr = (const void *)w.bytes;
    f->udIqWidth = hdr->udComp.udIqWidth;
    f->udCompMeth = hdr->udComp.udCompMeth;
  }
}

static void assert_fields_eq(const st_fields_t *a, const st_fields_t *b)
{
  assert(a->sectionType == b->sectionType);
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

// Section Type 10 reserved bits are 0 on the wire: filterIndex position, octets 15 and 16, and symInc
static void assert_st10_reserved_zero(const st_wire_t *w)
{
  assert((w->bytes[0] & 0x0F) == 0);
  assert(w->bytes[6] == 0 && w->bytes[7] == 0);
  assert((w->bytes[HDR_LEN + 1] & 0x04) == 0);
}

static void roundtrip(const st_fields_t *in)
{
  st_wire_t w;
  fields_to_wire(in, &w);
  if (in->sectionType == XRAN_CP_SECTIONTYPE_10)
    assert_st10_reserved_zero(&w);
  st_fields_t out;
  wire_to_fields(&w, &out);
  assert_fields_eq(in, &out);
}

// Each field at its minimum, middle and maximum value (bit width limits), with the other fields at a mixed base value,
// so a bitfield that is too narrow, overlaps a neighbour or (Section Type 10) leaks into a reserved bit fails.
static void test_field_roundtrip(void)
{
  const st_fields_t base5 = {.sectionType = XRAN_CP_SECTIONTYPE_5,
                             .dataDirection = 1,
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
  st_fields_t base10 = base5;
  base10.sectionType = XRAN_CP_SECTIONTYPE_10;
  base10.dataDirection = 0;
  base10.filterIndex = base10.udIqWidth = base10.udCompMeth = 0;
#define RT_FIELD(base, field, max)                 \
  do {                                             \
    const unsigned vals[] = {0, (max) / 2, (max)}; \
    for (int i = 0; i < 3; i++) {                  \
      st_fields_t in = (base);                     \
      in.field = vals[i];                          \
      roundtrip(&in);                              \
    }                                              \
  } while (0)
  // Fields of both section types
  const st_fields_t *bases[] = {&base5, &base10};
  for (int b = 0; b < 2; b++) {
    RT_FIELD(*bases[b], dataDirection, 0x1);
    RT_FIELD(*bases[b], payloadVersion, 0x7);
    RT_FIELD(*bases[b], frameId, 0xFF);
    RT_FIELD(*bases[b], subframeId, 0xF);
    RT_FIELD(*bases[b], slotId, 0x3F);
    RT_FIELD(*bases[b], startSymbolId, 0x3F);
    RT_FIELD(*bases[b], numberOfSections, 0xFF);
    RT_FIELD(*bases[b], sectionId, 0xFFF);
    RT_FIELD(*bases[b], rb, 0x1);
    RT_FIELD(*bases[b], startPrbc, 0x3FF);
    RT_FIELD(*bases[b], numPrbc, 0xFF);
    RT_FIELD(*bases[b], reMask, 0xFFF);
    RT_FIELD(*bases[b], numSymbol, 0xF);
    RT_FIELD(*bases[b], ef, 0x1);
    RT_FIELD(*bases[b], ueId, 0x7FFF);
  }
  // Section Type 5 only
  RT_FIELD(base5, filterIndex, 0xF);
  RT_FIELD(base5, udIqWidth, 0xF);
  RT_FIELD(base5, udCompMeth, 0xF);
  RT_FIELD(base5, symInc, 0x1);
#undef RT_FIELD
  printf("ST 5 and ST 10 field round trip passed\n");
}

typedef struct {
  const char *name;
  uint8_t bytes[WIRE_LEN]; // octets 9 to 24
  st_fields_t fields;
} st_vector_t;

// Encoded by hand from CUS v16.01 Tables 7.4.7-1 and 7.4.12-1
static const st_vector_t vectors[] = {
    {.name = "ST 5, UL, 9-bit BFP, ef = 1",
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
     .fields = {.sectionType = XRAN_CP_SECTIONTYPE_5,
                .dataDirection = 0,
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
    {.name = "ST 5, DL, uncompressed, all PRBs, ueId 0x7FFF",
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
     .fields = {.sectionType = XRAN_CP_SECTIONTYPE_5,
                .dataDirection = 1,
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
    {.name = "ST 10, ef = 1",
     .bytes =
         {
             0x10, // dataDirection 0 | payloadVersion 001 | reserved 0000
             0x2C, // frameId 0x2C
             0x31, // subframeId 0011 | slotId[5:2] 0001
             0x42, // slotId[1:0] 01 | startSymbolId 00 0010
             0x01, // numberOfSections 1
             0x0A, // sectionType 10
             0x00,
             0x00, // reserved
             0x12, // sectionId[11:4]
             0x31, // sectionId[3:0] 0011 | rb 0 | reserved 0 | startPrbc[9:8] 01
             0x0A, // startPrbc[7:0]: 0x10A
             0x33, // numPrbc 51
             0xFF, // reMask[11:4]
             0xF1, // reMask[3:0] 1111 | numSymbol 0001
             0x84, // ef 1 | ueId[14:8] 000 0100
             0x56, // ueId[7:0]: 0x0456
         },
     .fields = {.sectionType = XRAN_CP_SECTIONTYPE_10,
                .dataDirection = 0,
                .payloadVersion = 1,
                .frameId = 0x2C,
                .subframeId = 3,
                .slotId = 5,
                .startSymbolId = 2,
                .numberOfSections = 1,
                .sectionId = 0x123,
                .rb = 0,
                .startPrbc = 0x10A,
                .numPrbc = 51,
                .reMask = 0xFFF,
                .numSymbol = 1,
                .ef = 1,
                .ueId = 0x0456}},
};

static void test_spec_vectors(void)
{
  for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
    const st_vector_t *vec = &vectors[v];
    st_wire_t w;
    memcpy(w.bytes, vec->bytes, sizeof(w.bytes));
    st_fields_t f;
    wire_to_fields(&w, &f);
    assert_fields_eq(&f, &vec->fields);

    fields_to_wire(&f, &w);
    assert(memcmp(w.bytes, vec->bytes, sizeof(w.bytes)) == 0);
    printf("spec vector \"%s\" passed\n", vec->name);
  }
}

// An ST 5 section with ef = 1, then SE 10 (10b) and SE 24, walked as a receiver does: the extension lengths from
// xran_section_ext_len(), and the SE 24 entry count from the ueIds other than 0x7FFF (7.7.24.3). The chain length
// must match the walk. test_xran_pkt_ulpi checks each field of the extensions.
static void test_st5_se10_se24_section(void)
{
  uint8_t pkt[128] = {0};
  st_fields_t f = vectors[0].fields; // ef = 1, ueId 0x1234
  st_wire_t w;
  fields_to_wire(&f, &w);
  memcpy(pkt, w.bytes, WIRE_LEN);
  size_t off = WIRE_LEN;

  const xran_se10_hdr_t se10 = {.ef = 1, .beamGroupType = XRAN_SE10_BGT_10B, .numPortc = 3};
  const xran_se10_port_t se10_ports[] = {{.id = 0x1235}, {.id = 0x7FFF}, {.id = 0x1236}};
  size_t len = 0;
  assert(xran_encode_se10(&se10, se10_ports, pkt + off, sizeof(pkt) - off, &len) == XRAN_EXT_OK);
  off += len;
  const xran_se24_hdr_t hdr = {.ef = 0};
  const xran_se24_entry_t entries[] = {
      {.entryType = 2, .dmrsPortNumber = 0, .ueIdReset = 1, .dmrsSymbolMask = 0x0004, .cdmWithoutData = 2, .lastPrb = 105},
      {.entryType = 1, .dmrsPortNumber = 1},
      {.entryType = 1, .dmrsPortNumber = 2},
  };
  assert(xran_encode_se24(&hdr, entries, 3, pkt + off, sizeof(pkt) - off, &len) == XRAN_EXT_OK);
  size_t pkt_len = off + len;

  // Receive side
  memcpy(w.bytes, pkt, WIRE_LEN);
  wire_to_fields(&w, &f);
  assert(f.ef == 1);
  int n_layers = f.ueId != 0x7FFF;
  off = WIRE_LEN;
  int ext_count = 0;
  int ef = 1;
  while (ef) {
    uint8_t ext_type = pkt[off] & 0x7F;
    ef = pkt[off] >> 7;
    size_t ext_len = 0;
    assert(xran_section_ext_len(ext_type, pkt + off, pkt_len - off, &ext_len) == XRAN_EXT_OK);
    if (ext_count == 0) {
      assert(ext_type == XRAN_CP_SECTIONEXTCMD_10);
      xran_se10_hdr_t out;
      xran_se10_port_t ports[XRAN_SE10_MAX_PORTS];
      assert(xran_decode_se10(pkt + off, ext_len, XRAN_SE10_MAX_PORTS, &out, ports) == XRAN_EXT_OK);
      assert(xran_se10_num_ports(&out) == 3);
      for (int k = 0; k < xran_se10_num_ports(&out); k++) {
        assert(ports[k].id == se10_ports[k].id);
        n_layers += ports[k].id != 0x7FFF;
      }
    } else {
      assert(ext_type == XRAN_CP_SECTIONEXTCMD_24);
      assert(n_layers == 3);
      xran_se24_hdr_t hdr_out;
      xran_se24_entry_t out[3];
      assert(xran_decode_se24(pkt + off, ext_len, n_layers, &hdr_out, out) == XRAN_EXT_OK);
      for (int i = 0; i < 3; i++)
        assert(out[i].entryType == entries[i].entryType && out[i].dmrsPortNumber == entries[i].dmrsPortNumber);
    }
    off += ext_len;
    ext_count++;
  }
  assert(ext_count == 2);
  assert(off == pkt_len);
  size_t chain_len = 0;
  assert(xran_section_ext_chain_len(pkt + WIRE_LEN, pkt_len - WIRE_LEN, &chain_len) == XRAN_EXT_OK);
  assert(chain_len == pkt_len - WIRE_LEN);
  printf("ST 5 section with SE 10 and SE 24 passed\n");
}

// The 1st measurement report of an ST 10 section follows the section and, if ef, the extension chain (Table
// 7.4.12-1). The section is the ST 10 vector, then SE 10 (00b) and a MEAS_UE_TAE report (Table 7.4.12-2).
static void test_st10_report_offset(void)
{
  const uint8_t tail[] = {
      0x0A, // SE 10: ef 0 | extType 0x0A
      0x01, // extLen 1 word
      0x04, // beamGroupType 00 | numPortc 4
      0x00, // reserved
      0x01, // mf 0 | measTypeId 1 (MEAS_UE_TAE)
      0x00, // reserved
      0x00,
      0x02, // measDataSize 2 words
      0x00,
      0x10, // ueTae
      0x00,
      0x00, // reserved
  };
  uint8_t pkt[WIRE_LEN + sizeof(tail)];
  memcpy(pkt, vectors[2].bytes, WIRE_LEN);
  memcpy(pkt + WIRE_LEN, tail, sizeof(tail));

  // Receive side, as the O-RU does for Section Type 1: swap the section, read ef from the struct
  st_wire_t w;
  memcpy(w.bytes, pkt, WIRE_LEN);
  st_fields_t f;
  wire_to_fields(&w, &f);
  assert(f.sectionType == XRAN_CP_SECTIONTYPE_10 && f.ef == 1);
  size_t chain_len = 0;
  assert(xran_section_ext_chain_len(pkt + WIRE_LEN, sizeof(pkt) - WIRE_LEN, &chain_len) == XRAN_EXT_OK);
  size_t report = WIRE_LEN + chain_len;
  assert(report == WIRE_LEN + 4);
  assert((pkt[report] & 0x7F) == 1 && ((pkt[report + 2] << 8) | pkt[report + 3]) * 4 == sizeof(pkt) - report);
  printf("ST 10 report offset passed\n");
}

// xran_section_ext_chain_len() over an 8-bit and a 16-bit extLen (7.6.2.3), and its TRUNCATED and EXT_LEN cases
static void test_ext_chain_len(void)
{
  // SE 10 (ef 1, 1 word), then an SE 11 shape (ef 0, 16-bit extLen 2 words)
  uint8_t chain[12] = {[0] = 0x8A, [1] = 0x01, [2] = 0x04, [4] = 0x0B, [5] = 0x00, [6] = 0x02};
  size_t len = 0;
  assert(xran_section_ext_chain_len(chain, sizeof(chain), &len) == XRAN_EXT_OK && len == 12);
  assert(xran_section_ext_chain_len(chain + 4, 8, &len) == XRAN_EXT_OK && len == 8); // one extension

  len = 0xDEAD;
  assert(xran_section_ext_chain_len(chain, 11, &len) == XRAN_EXT_ERR_TRUNCATED); // 2nd extension cut
  // ef set, but the packet ends after the 1st extension: an exact-size heap copy, so AddressSanitizer sees any read
  // past it
  uint8_t *first_only = malloc(4);
  memcpy(first_only, chain, 4);
  assert(xran_section_ext_chain_len(first_only, 4, &len) == XRAN_EXT_ERR_TRUNCATED);
  free(first_only);
  chain[1] = 0x00;
  assert(xran_section_ext_chain_len(chain, sizeof(chain), &len) == XRAN_EXT_ERR_EXT_LEN); // extLen 0 (reserved)
  assert(len == 0xDEAD);
  printf("section extension chain length passed\n");
}

int main(void)
{
  test_field_roundtrip();
  test_spec_vectors();
  test_st5_se10_se24_section();
  test_st10_report_offset();
  test_ext_chain_len();
  printf("All Section Type 5 and 10 tests passed!\n");
  return 0;
}
