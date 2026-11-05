/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include "xran_pkt_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

// Section extension codecs for ULPI (DMRS-BF), CUS v16.01. Each buffer starts at the ef/extType byte of the extension.
// The decoders return the wire values only: implicit values (entryType 0/1 inheritance, ueIdReset of entryType 0/1,
// dType and cdmWithoutData of entryType 3) are for the caller to apply.

/**********************************************************************
 * SE 10: Group configuration of multiple ports (CUS v16.01 7.7.10)
 **********************************************************************/

// beamGroupType (7.7.10.2). Section Type 5 does not allow 00b and 01b; the codec supports all four.
#define XRAN_SE10_BGT_00B 0 // common beam, Table 7.7.10.1-1
#define XRAN_SE10_BGT_01B 1 // beam matrix indication, Table 7.7.10.1-1
#define XRAN_SE10_BGT_10B 2 // beam vector listing, Table 7.7.10.1-2
#define XRAN_SE10_BGT_11B 3 // listing with portListIndex, Table 7.7.10.1-3
#define XRAN_SE10_MAX_PORTS 64

typedef struct {
  uint8_t ef;
  uint8_t beamGroupType; // 2 bits, XRAN_SE10_BGT_*
  int numPortc; // 1 to 64; 64 is 0 on the wire
  uint8_t firstPortListIndex; // 11b only: the 1st portListIndex, for the section header ueId (or beamId)
} xran_se10_hdr_t;

// One port listed in SE 10 (10b and 11b). Port k of the list is port k + 2 of the group; the section header carries
// port 1.
typedef struct {
  uint16_t id; // 15 bits, ueId (or beamId); ueId 0x7FFF = port not scheduled (7.7.10.1)
  uint8_t portListIndex; // 11b only
} xran_se10_port_t;

// Number of ports listed in the extension: 0 for 00b and 01b, numPortc for 10b, numPortc - 1 for 11b
static inline int xran_se10_num_ports(const xran_se10_hdr_t *hdr)
{
  switch (hdr->beamGroupType) {
    case XRAN_SE10_BGT_10B:
      return hdr->numPortc;
    case XRAN_SE10_BGT_11B:
      return hdr->numPortc - 1;
    default:
      return 0;
  }
}

// Writes SE 10 with the xran_se10_num_ports() ports of ports to buf (avail bytes), with the filler to the 4-byte
// boundary, and its length to len_out. ports can be NULL for 00b and 01b. Returns XRAN_EXT_OK, XRAN_EXT_ERR_TRUNCATED
// or XRAN_EXT_ERR_RANGE. Nothing is written on error.
xran_ext_err_t xran_encode_se10(const xran_se10_hdr_t *hdr,
                                const xran_se10_port_t *ports,
                                uint8_t *buf,
                                size_t avail,
                                size_t *len_out);

// Decodes SE 10 from ext, with len bytes from xran_section_ext_len(). The xran_se10_num_ports() listed ports go to
// ports_out, which has room for max_ports. Returns XRAN_EXT_OK, XRAN_EXT_ERR_TOO_MANY if there are more than
// max_ports ports, or an error if the extension is malformed. hdr_out and ports_out are not changed on error.
xran_ext_err_t xran_decode_se10(const uint8_t *ext,
                                size_t len,
                                int max_ports,
                                xran_se10_hdr_t *hdr_out,
                                xran_se10_port_t *ports_out);

/**********************************************************************
 * SE 24: PUSCH DMRS configuration (CUS v16.01 7.7.24)
 **********************************************************************/

#define XRAN_SE24_ENTRY_INHERIT_PERSIST 0 // inherit, ueIdReset = 0, Table 7.7.24.3-1
#define XRAN_SE24_ENTRY_INHERIT_RESET 1 // inherit, ueIdReset = 1, Table 7.7.24.3-1
#define XRAN_SE24_ENTRY_CP_OFDM 2 // transform precoding disabled, Table 7.7.24.3-2
#define XRAN_SE24_ENTRY_DFT_S_OFDM 3 // transform precoding enabled, Table 7.7.24.3-3

typedef struct {
  uint8_t ef;
  uint8_t aIpnPerSym; // 1 bit
  uint8_t antDmrsSnr; // 1 bit
  uint8_t userGroupSize; // 5 bits
  uint8_t userGroupId; // 8 bits
} xran_se24_hdr_t;

// One entry of the table of DMRS configurations. Fields not carried by the entryType are 0 on decode and ignored on
// encode.
typedef struct {
  uint8_t entryType; // 3 bits, 0 to 3
  uint8_t dmrsPortNumber; // 5 bits
  // entryType 2 and 3
  uint8_t ueIdReset; // 1 bit
  uint16_t dmrsSymbolMask; // 14 bits
  uint16_t scrambling;
  uint8_t nscid; // 1 bit
  uint16_t firstPrb; // 9 bits
  uint16_t lastPrb; // 9 bits
  // entryType 2
  uint8_t dType; // 1 bit
  uint8_t cdmWithoutData; // 2 bits
  uint8_t lambda; // 2 bits
  // entryType 3
  uint8_t lowPaprType; // 2 bits
  uint8_t hoppingMode; // 2 bits
} xran_se24_entry_t;

// Writes SE 24 with n_entries entries to buf (avail bytes), with the zero padding to the 4-byte boundary, and its
// length to len_out. Returns XRAN_EXT_OK, XRAN_EXT_ERR_TRUNCATED, XRAN_EXT_ERR_RANGE or XRAN_EXT_ERR_ENTRY_TYPE.
// Nothing is written on error.
xran_ext_err_t xran_encode_se24(const xran_se24_hdr_t *hdr,
                                const xran_se24_entry_t *entries,
                                int n_entries,
                                uint8_t *buf,
                                size_t avail,
                                size_t *len_out);

// Decodes SE 24 from ext, with len bytes from xran_section_ext_len(). The padding can't be told apart from entries, so
// the caller gives n_entries: one for each ueId other than 0x7FFF in the section header and SE 10 (7.7.24.3).
// Returns XRAN_EXT_OK, or an error if the extension is malformed, has a reserved entryType or its extLen doesn't
// match n_entries. hdr_out and entries_out are not changed on error.
xran_ext_err_t xran_decode_se24(const uint8_t *ext,
                                size_t len,
                                int n_entries,
                                xran_se24_hdr_t *hdr_out,
                                xran_se24_entry_t *entries_out);

/**********************************************************************
 * SE 25: Symbol reordering for DMRS-BF (CUS v16.01 7.7.25)
 **********************************************************************/

#define XRAN_SE25_NUM_SYMBOLS 14
// Each layer is 7 bytes after the 2-byte header, so an 8-bit extLen holds at most (255 * 4 - 2) / 7 layers
#define XRAN_SE25_MAX_LAYERS 145

typedef struct {
  uint8_t ef;
  int numLayers; // not a wire field: from extLen. 1 for per-window reordering (7.7.25.2), else 1 for each layer
} xran_se25_hdr_t;

typedef struct {
  uint8_t txWinForOnAirSymbol[XRAN_SE25_NUM_SYMBOLS]; // 4 bits each; 0xF = no information, 0xE reserved (7.7.25.4)
} xran_se25_layer_t;

// Writes SE 25 with hdr->numLayers layers to buf (avail bytes), with the zero padding to the 4-byte boundary, and its
// length to len_out. Returns XRAN_EXT_OK, XRAN_EXT_ERR_TRUNCATED or XRAN_EXT_ERR_RANGE. Nothing is written on
// error.
xran_ext_err_t xran_encode_se25(const xran_se25_hdr_t *hdr,
                                const xran_se25_layer_t *layers,
                                uint8_t *buf,
                                size_t avail,
                                size_t *len_out);

// Decodes SE 25 from ext, with len bytes from xran_section_ext_len(). The number of layers comes from extLen: the
// padding (0 to 3 bytes) is shorter than a layer (7 bytes). The layers go to layers_out, which has room for
// max_layers. Returns XRAN_EXT_OK, XRAN_EXT_ERR_TOO_MANY if there are more than max_layers layers, or an error if
// the extension is malformed. hdr_out and layers_out are not changed on error.
xran_ext_err_t xran_decode_se25(const uint8_t *ext,
                                size_t len,
                                int max_layers,
                                xran_se25_hdr_t *hdr_out,
                                xran_se25_layer_t *layers_out);

/**********************************************************************
 * SE 26: Frequency offset feedback (CUS v16.01 7.7.26)
 **********************************************************************/

#define XRAN_SE26_MAX_FOFB 127 // 7-bit numFoFb

typedef struct {
  uint8_t ef;
  uint8_t numFoFb; // 7 bits; 1 to 126 are valid, 0 and 127 reserved (7.7.26.2)
} xran_se26_hdr_t;

// Writes SE 26 with the hdr->numFoFb values of freqOffsetFb to buf (avail bytes), with the zero padding to the 4-byte
// boundary, and its length to len_out. freqOffsetFb is in units of 2^(mu - 2) Hz; INT16_MIN = value not provided
// (7.7.26.3). Returns XRAN_EXT_OK, XRAN_EXT_ERR_TRUNCATED or XRAN_EXT_ERR_RANGE. Nothing is written on error.
xran_ext_err_t xran_encode_se26(const xran_se26_hdr_t *hdr,
                                const int16_t *freqOffsetFb,
                                uint8_t *buf,
                                size_t avail,
                                size_t *len_out);

// Decodes SE 26 from ext, with len bytes from xran_section_ext_len(). The numFoFb values go to freqOffsetFb_out, which
// has room for max_fofb. Returns XRAN_EXT_OK, XRAN_EXT_ERR_TOO_MANY if numFoFb > max_fofb, or an error if the
// extension is malformed. hdr_out and freqOffsetFb_out are not changed on error.
xran_ext_err_t xran_decode_se26(const uint8_t *ext, size_t len, int max_fofb, xran_se26_hdr_t *hdr_out, int16_t *freqOffsetFb_out);

/**********************************************************************
 * SE 27: O-DU controlled dimensionality reduction (CUS v16.01 7.7.27)
 **********************************************************************/

#define XRAN_SE27_BEAM_LIST 0 // list of numElements beamIds, Table 7.7.27.1-1
#define XRAN_SE27_BEAM_RANGE 1 // range of numElements beamIds from one beamId, Table 7.7.27.1-2
#define XRAN_SE27_MAX_ELEMENTS 256

typedef struct {
  uint8_t ef;
  uint8_t beamType; // 2 bits, XRAN_SE27_BEAM_LIST or XRAN_SE27_BEAM_RANGE
  int numElements; // 1 to 256; 256 is 0 on the wire
} xran_se27_hdr_t;

// Number of beamIds in the extension: numElements for a list, 1 for a range
static inline int xran_se27_num_beam_ids(const xran_se27_hdr_t *hdr)
{
  return hdr->beamType == XRAN_SE27_BEAM_LIST ? hdr->numElements : 1;
}

// Writes SE 27 with the xran_se27_num_beam_ids() 15-bit values of beamId to buf (avail bytes), with the zero padding
// to the 4-byte boundary, and its length to len_out. Returns XRAN_EXT_OK, XRAN_EXT_ERR_TRUNCATED,
// XRAN_EXT_ERR_RANGE or XRAN_EXT_ERR_BEAM_TYPE. Nothing is written on error.
xran_ext_err_t xran_encode_se27(const xran_se27_hdr_t *hdr, const uint16_t *beamId, uint8_t *buf, size_t avail, size_t *len_out);

// Decodes SE 27 from ext, with len bytes from xran_section_ext_len(). The xran_se27_num_beam_ids() beamIds go to
// beamId_out, which has room for max_beam_ids. Returns XRAN_EXT_OK, XRAN_EXT_ERR_TOO_MANY if there are more than
// max_beam_ids beamIds, or an error if the extension is malformed or has a reserved beamType. hdr_out and beamId_out
// are not changed on error.
xran_ext_err_t xran_decode_se27(const uint8_t *ext, size_t len, int max_beam_ids, xran_se27_hdr_t *hdr_out, uint16_t *beamId_out);

#ifdef __cplusplus
}
#endif
