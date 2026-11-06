/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Writes the ULPI (DMRS-BF) C-plane formats of P2 to a pcap, for a cross-check with the Wireshark O-RAN dissector:
// Section Type 5 sections with SE 10, 24, 25, 26 and 27, and one Section Type 10 section with two measurement
// reports. The sections and extensions come from the structs of xran_pkt_cp.h and the encoders of xran_pkt_ulpi.h;
// only the measurement reports (P8.1) are hand-encoded. Usage: xran_pkt_p2_pcap OUT.pcap

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pcap.h>
#include "xran_pkt_cp.h"
#include "xran_pkt_ext.h"
#include "xran_pkt_ulpi.h"
#include "xran_pkt_test_util.h"
#include "xran_pkt_st_wire.h"

#define ETH_HDR_LEN 14
#define ECPRI_CMN_HDR_LEN 4
#define ECPRI_HDR_LEN 8 // common header (4), ecpriRtcid (2), ecpriSeqid (2): eCPRI v2.0 3.2.4.4
#define FRAME_MAX 512

typedef struct {
  uint8_t data[FRAME_MAX];
  size_t len;
  size_t ext_len; // len_out of the last xran_encode_se*() call
} frame_t;

static void put(frame_t *f, const void *bytes, size_t n)
{
  assert(f->len + n <= FRAME_MAX);
  memcpy(f->data + f->len, bytes, n);
  f->len += n;
}

// Ethernet (eCPRI EtherType 0xAEFE) and an eCPRI real-time control header for eAxC 0; frame_end() sets the size
static void frame_begin(frame_t *f, uint8_t seq_id)
{
  const uint8_t hdr[ETH_HDR_LEN + ECPRI_HDR_LEN] = {
      0x00,   0x11, 0x22, 0x33, 0x44, 0x55, // destination
      0x00,   0x11, 0x22, 0x33, 0x44, 0x66, // source
      0xAE,   0xFE, // EtherType eCPRI
      0x10, // ecpriVersion 1 | reserved | ecpriConcatenation 0
      0x02, // ecpriMessage: real-time control data
      0x00,   0x00, // ecpriPayload, set by frame_end()
      0x00,   0x00, // ecpriRtcid: eAxC 0
      seq_id, 0x80, // ecpriSeqid: E = 1, subsequence 0
  };
  f->len = 0;
  put(f, hdr, sizeof(hdr));
}

static void frame_end(frame_t *f)
{
  size_t payload = f->len - ETH_HDR_LEN - ECPRI_CMN_HDR_LEN; // the bytes after the eCPRI common header
  f->data[ETH_HDR_LEN + 2] = (uint8_t)(payload >> 8);
  f->data[ETH_HDR_LEN + 3] = (uint8_t)payload;
}

// The section header and the first 8-byte section
static void put_st(frame_t *f, const st_fields_t *fields)
{
  st_wire_t w;
  st_fields_to_wire(fields, &w);
  put(f, w.bytes, ST_WIRE_LEN);
}

// One more 8-byte section in the same message
static void put_section(frame_t *f, const st_fields_t *fields)
{
  st_wire_t w;
  st_fields_to_wire(fields, &w);
  put(f, w.bytes + ST_HDR_LEN, ST_WIRE_LEN - ST_HDR_LEN);
}

// The free bytes at the end of the frame and the length output: the last 3 arguments of an xran_encode_se*() call
#define TAIL(f) ((f)->data + (f)->len), (FRAME_MAX - (f)->len), &(f)->ext_len

static void put_ext(frame_t *f, xran_ext_err_t err)
{
  assert(err == XRAN_EXT_OK);
  f->len += f->ext_len;
}

static const st_fields_t st5_base = {.sectionType = XRAN_CP_SECTIONTYPE_5,
                                     .dataDirection = 0,
                                     .payloadVersion = 1,
                                     .frameId = 0x5A,
                                     .subframeId = 7,
                                     .slotId = 1,
                                     .startSymbolId = 0,
                                     .numberOfSections = 1,
                                     .udIqWidth = 9,
                                     .udCompMeth = 1,
                                     .rb = 0,
                                     .startPrbc = 0,
                                     .numPrbc = 106,
                                     .reMask = 0xFFF,
                                     .numSymbol = 14,
                                     .ef = 1};

// SE 10 (10b) with 3 UEs, then SE 24 (one entry for each UE), SE 25 (one layer for each ueId, 7.7.25.3) and SE 26
// (one value for each UE, 7.7.26.3)
static void frame_se10_10b_se24_se25_se26(frame_t *f)
{
  frame_begin(f, 0);
  st_fields_t s = st5_base;
  s.sectionId = 1;
  s.ueId = 0x0000;
  put_st(f, &s);
  const xran_se10_hdr_t h10 = {.ef = 1, .beamGroupType = XRAN_SE10_BGT_10B, .numPortc = 2};
  const xran_se10_port_t ports[] = {{.id = 0x0100}, {.id = 0x0200}};
  put_ext(f, xran_encode_se10(&h10, ports, TAIL(f)));
  const xran_se24_hdr_t h24 = {.ef = 1, .userGroupSize = 3, .userGroupId = 1};
  const xran_se24_entry_t entries[] = {
      {.entryType = XRAN_SE24_ENTRY_CP_OFDM,
       .dmrsPortNumber = 0,
       .ueIdReset = 1,
       .dmrsSymbolMask = 0x0004,
       .scrambling = 0x1234,
       .nscid = 0,
       .dType = 1,
       .cdmWithoutData = 2,
       .lambda = 0,
       .firstPrb = 0,
       .lastPrb = 105},
      {.entryType = XRAN_SE24_ENTRY_INHERIT_RESET, .dmrsPortNumber = 1},
      {.entryType = XRAN_SE24_ENTRY_INHERIT_RESET, .dmrsPortNumber = 2},
  };
  put_ext(f, xran_encode_se24(&h24, entries, 3, TAIL(f)));
  const xran_se25_hdr_t h25 = {.ef = 1, .numLayers = 3};
  const xran_se25_layer_t layers[] = {{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
                                      {{1, 1, 0, 2, 2, 3, 3, 4, 4, 5, 5, 0, 6, 6}},
                                      {{15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}}};
  put_ext(f, xran_encode_se25(&h25, layers, TAIL(f)));
  const xran_se26_hdr_t h26 = {.ef = 0, .numFoFb = 3};
  const int16_t fofb[] = {30000, -30000, INT16_MIN};
  put_ext(f, xran_encode_se26(&h26, fofb, TAIL(f)));
  frame_end(f);
}

// SE 10 (11b) with a not-scheduled port, then SE 24 (one entry for each ueId other than 0x7FFF) and SE 27 (list)
static void frame_se10_11b_se24_se27(frame_t *f)
{
  frame_begin(f, 1);
  st_fields_t s = st5_base;
  s.sectionId = 2;
  s.ueId = 0x0300;
  put_st(f, &s);
  const xran_se10_hdr_t h10 = {.ef = 1, .beamGroupType = XRAN_SE10_BGT_11B, .numPortc = 3, .firstPortListIndex = 1};
  const xran_se10_port_t ports[] = {{.id = 0x0301, .portListIndex = 2},
                                    {.id = 0x7FFF, .portListIndex = 3}}; // 0 is reserved (7.7.10.3a)
  put_ext(f, xran_encode_se10(&h10, ports, TAIL(f)));
  const xran_se24_hdr_t h24 = {.ef = 1, .userGroupSize = 2, .userGroupId = 2};
  const xran_se24_entry_t entries[] = {
      {.entryType = XRAN_SE24_ENTRY_DFT_S_OFDM,
       .dmrsPortNumber = 0,
       .ueIdReset = 0,
       .dmrsSymbolMask = 0x0804,
       .scrambling = 0x00FF,
       .nscid = 1,
       .lowPaprType = 1,
       .hoppingMode = 2,
       .firstPrb = 10,
       .lastPrb = 59},
      {.entryType = XRAN_SE24_ENTRY_INHERIT_PERSIST, .dmrsPortNumber = 1},
  };
  put_ext(f, xran_encode_se24(&h24, entries, 2, TAIL(f)));
  const xran_se27_hdr_t h27 = {.ef = 0, .beamType = XRAN_SE27_BEAM_LIST, .numElements = 3};
  const uint16_t ids[] = {1, 0x7FFF, 0x0100};
  put_ext(f, xran_encode_se27(&h27, ids, TAIL(f)));
  frame_end(f);
}

// Two sections without SE 10: SE 24 with the header flags, SE 25 (per-window), SE 26 (one value, 7.7.26.3) and SE 27
// (range of 256); then SE 24 (entryType 3) only
static void frame_two_sections(frame_t *f)
{
  frame_begin(f, 2);
  st_fields_t s = st5_base;
  s.numberOfSections = 2;
  s.sectionId = 3;
  s.ueId = 0x0400;
  put_st(f, &s);
  const xran_se24_hdr_t h24 = {.ef = 1, .aIpnPerSym = 1, .antDmrsSnr = 1, .userGroupSize = 1, .userGroupId = 3};
  const xran_se24_entry_t e24 = {.entryType = XRAN_SE24_ENTRY_CP_OFDM,
                                 .dmrsPortNumber = 11, // 12 to 31 are reserved
                                 .ueIdReset = 1,
                                 .dmrsSymbolMask = 0x2244,
                                 .scrambling = 0xFFFF,
                                 .nscid = 1,
                                 .dType = 0,
                                 .cdmWithoutData = 1,
                                 .lambda = 3,
                                 .firstPrb = 0x1FF,
                                 .lastPrb = 0x1FF};
  put_ext(f, xran_encode_se24(&h24, &e24, 1, TAIL(f)));
  const xran_se25_hdr_t h25 = {.ef = 1, .numLayers = 1};
  const xran_se25_layer_t window = {{4, 5, 0, 1, 6, 7, 8, 9, 10, 11, 2, 3, 12, 13}};
  put_ext(f, xran_encode_se25(&h25, &window, TAIL(f)));
  const xran_se26_hdr_t h26 = {.ef = 1, .numFoFb = 1};
  const int16_t fofb = -1;
  put_ext(f, xran_encode_se26(&h26, &fofb, TAIL(f)));
  const xran_se27_hdr_t h27 = {.ef = 0, .beamType = XRAN_SE27_BEAM_RANGE, .numElements = 256};
  const uint16_t first = 0x1234;
  put_ext(f, xran_encode_se27(&h27, &first, TAIL(f)));

  s.sectionId = 4;
  s.ueId = 0x0500;
  s.startPrbc = 106;
  s.numPrbc = 0;
  put_section(f, &s);
  const xran_se24_hdr_t h24b = {.ef = 0, .userGroupSize = 1, .userGroupId = 4};
  const xran_se24_entry_t e24b = {.entryType = XRAN_SE24_ENTRY_DFT_S_OFDM,
                                  .dmrsPortNumber = 0,
                                  .dmrsSymbolMask = 0x0004,
                                  .lowPaprType = 0,
                                  .hoppingMode = 1,
                                  .firstPrb = 106,
                                  .lastPrb = 272};
  put_ext(f, xran_encode_se24(&h24b, &e24b, 1, TAIL(f)));
  frame_end(f);
}

// Section Type 10 without extensions, with a MEAS_UE_TAE report (Table 7.4.12-2) and a MEAS_UE_LAYER_POWER report for
// one layer (Table 7.4.12-3). The reports are hand-encoded (P8.1 adds their codec).
static void frame_st10(frame_t *f)
{
  frame_begin(f, 3);
  st_fields_t s = st5_base; // st_fields_to_wire() writes no udCompHdr for Section Type 10
  s.sectionType = XRAN_CP_SECTIONTYPE_10;
  s.sectionId = 3;
  s.ef = 0;
  s.ueId = 0x0400;
  put_st(f, &s);
  const uint8_t reports[] = {
      0x81, // mf 1 | measTypeId 1 (MEAS_UE_TAE)
      0x00, // reserved
      0x00,
      0x02, // measDataSize 2 words
      0x00,
      0x10, // ueTae
      0x00,
      0x00, // reserved
      0x02, // mf 0 | measTypeId 2 (MEAS_UE_LAYER_POWER)
      0x00, // reserved
      0x00,
      0x02, // measDataSize 2 words
      0x12,
      0x34, // ueLayerPower of the layer
      0x00,
      0x00, // padding
  };
  put(f, reports, sizeof(reports));
  frame_end(f);
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    fprintf(stderr, "usage: %s OUT.pcap\n", argv[0]);
    return 2;
  }
  pcap_t *p = pcap_open_dead(DLT_EN10MB, FRAME_MAX);
  pcap_dumper_t *d = pcap_dump_open(p, argv[1]);
  if (d == NULL) {
    fprintf(stderr, "%s\n", pcap_geterr(p));
    return 1;
  }
  void (*const builders[])(frame_t *) = {frame_se10_10b_se24_se25_se26, frame_se10_11b_se24_se27, frame_two_sections, frame_st10};
  for (size_t i = 0; i < sizeof(builders) / sizeof(builders[0]); i++) {
    frame_t f;
    builders[i](&f);
    const struct pcap_pkthdr h = {.ts = {.tv_usec = i * 1000}, .caplen = f.len, .len = f.len};
    pcap_dump((u_char *)d, &h, f.data);
  }
  pcap_dump_close(d);
  pcap_close(p);
  printf("wrote %zu frames to %s\n", sizeof(builders) / sizeof(builders[0]), argv[1]);
  return 0;
}
