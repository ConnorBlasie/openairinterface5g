/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// The Section Type 5 and Section Type 10 fields (CUS v16.01 Tables 7.4.7-1 and 7.4.12-1) and their wire bytes, for the
// xran_pkt unit tests and the P2 pcap generator. Wire bytes are converted with the same in-place swaps that
// oru_packet_processor.c applies to Section Type 1: rte_be_to_cpu_32 on the common header bits and rte_be_to_cpu_64
// on the 8-byte section.

#pragma once

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <rte_byteorder.h>
#include "xran_pkt_cp.h"

#define ST_HDR_LEN 8 // section header (common header + 2 bytes), the same for Section Types 5 and 10
#define ST_WIRE_LEN (ST_HDR_LEN + sizeof(struct xran_cp_radioapp_section5))

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
  uint8_t bytes[ST_WIRE_LEN];
} st_wire_t;

static inline void st_fields_to_wire(const st_fields_t *f, st_wire_t *w)
{
  memset(w, 0, sizeof(*w));
  struct xran_cp_radioapp_common_header *cmn = (void *)w->bytes;
  struct xran_cp_radioapp_section_header *sec = (void *)(w->bytes + ST_HDR_LEN);
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

static inline void st_wire_to_fields(const st_wire_t *in, st_fields_t *f)
{
  st_wire_t w = *in;
  struct xran_cp_radioapp_common_header *cmn = (void *)w.bytes;
  struct xran_cp_radioapp_section_header *sec = (void *)(w.bytes + ST_HDR_LEN);
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
