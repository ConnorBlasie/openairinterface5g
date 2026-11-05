/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xran_pkt_ulpi.h"
#include "xran_pkt_cp.h"
#include "common/utils/assertions.h"
#include <string.h>

static size_t pad4(size_t len)
{
  return (len + 3) & ~(size_t)3;
}

// Starts the decode of an extension with an 8-bit extLen: at least hdr_len bytes, the extType of the decoder, and an
// extLen that is not 0 and fits in len. Writes the extension length to ext_len_out. The caller then checks it
// against the content.
static xran_ext_err_t se_open(const uint8_t *ext, size_t len, uint8_t ext_type, size_t hdr_len, size_t *ext_len_out)
{
  if (len < hdr_len)
    return XRAN_EXT_ERR_TRUNCATED;
  if ((ext[0] & 0x7F) != ext_type)
    return XRAN_EXT_ERR_EXT_TYPE;
  return xran_section_ext_len(ext_type, ext, len, ext_len_out);
}

// Starts the encode of an extension with an 8-bit extLen and content_len bytes of content: checks ef, the extLen
// range and avail, then zeroes the extension with its padding and writes the ef/extType and extLen bytes. Writes the
// extension length to len_out. The caller then writes the content.
static xran_ext_err_t se_begin(uint8_t *buf, size_t avail, uint8_t ext_type, uint8_t ef, size_t content_len, size_t *len_out)
{
  size_t len = pad4(content_len);
  if (ef > 1 || len / 4 > 0xFF)
    return XRAN_EXT_ERR_RANGE;
  if (len > avail)
    return XRAN_EXT_ERR_TRUNCATED;
  memset(buf, 0, len);
  buf[0] = (uint8_t)(ef << 7 | ext_type);
  buf[1] = (uint8_t)(len / 4);
  *len_out = len;
  return XRAN_EXT_OK;
}

/**********************************************************************
 * SE 10
 **********************************************************************/

#define SE10_HDR_LEN 3 // ef/extType, extLen, beamGroupType/numPortc

// Content length without the filler: Table 7.7.10.1-1 (00b, 01b) is 3 bytes and a reserved byte, Table 7.7.10.1-2
// (10b) has a 2-byte id per port, Table 7.7.10.1-3 (11b) has the 1st portListIndex and then a 2-byte id and a
// portListIndex for each further port.
static size_t se10_content_len(int beam_group_type, int num_portc)
{
  switch (beam_group_type) {
    case XRAN_SE10_BGT_10B:
      return SE10_HDR_LEN + (size_t)2 * num_portc;
    case XRAN_SE10_BGT_11B:
      return SE10_HDR_LEN + 1 + (size_t)3 * (num_portc - 1);
    default:
      return SE10_HDR_LEN + 1;
  }
}

xran_ext_err_t xran_encode_se10(const xran_se10_hdr_t *hdr,
                                const xran_se10_port_t *ports,
                                uint8_t *buf,
                                size_t avail,
                                size_t *len_out)
{
  AssertError(hdr != NULL && buf != NULL && len_out != NULL,
              return XRAN_EXT_ERR_ARG,
              "hdr %p buf %p len_out %p\n",
              hdr,
              buf,
              len_out);
  if (hdr->beamGroupType > XRAN_SE10_BGT_11B || hdr->numPortc < 1 || hdr->numPortc > XRAN_SE10_MAX_PORTS)
    return XRAN_EXT_ERR_RANGE;
  int n_ports = xran_se10_num_ports(hdr);
  AssertError(n_ports == 0 || ports != NULL, return XRAN_EXT_ERR_ARG, "ports NULL for %d ports\n", n_ports);
  for (int k = 0; k < n_ports; k++)
    if (ports[k].id > 0x7FFF)
      return XRAN_EXT_ERR_RANGE;
  size_t content_len = se10_content_len(hdr->beamGroupType, hdr->numPortc);
  xran_ext_err_t err = se_begin(buf, avail, XRAN_CP_SECTIONEXTCMD_10, hdr->ef, content_len, len_out);
  if (err != XRAN_EXT_OK)
    return err;

  buf[2] = (uint8_t)(hdr->beamGroupType << 6 | (hdr->numPortc & 0x3F)); // 64 ports is 0
  uint8_t *p = buf + SE10_HDR_LEN;
  if (hdr->beamGroupType == XRAN_SE10_BGT_11B)
    *p++ = hdr->firstPortListIndex;
  for (int k = 0; k < n_ports; k++) {
    *p++ = (uint8_t)(ports[k].id >> 8); // msb is reserved
    *p++ = (uint8_t)(ports[k].id & 0xFF);
    if (hdr->beamGroupType == XRAN_SE10_BGT_11B)
      *p++ = ports[k].portListIndex;
  }
  return XRAN_EXT_OK;
}

xran_ext_err_t xran_decode_se10(const uint8_t *ext,
                                size_t len,
                                int max_ports,
                                xran_se10_hdr_t *hdr_out,
                                xran_se10_port_t *ports_out)
{
  AssertError(ext != NULL && hdr_out != NULL && ports_out != NULL && max_ports > 0,
              return XRAN_EXT_ERR_ARG,
              "ext %p hdr_out %p ports_out %p max_ports %d\n",
              ext,
              hdr_out,
              ports_out,
              max_ports);
  size_t ext_len;
  xran_ext_err_t err = se_open(ext, len, XRAN_CP_SECTIONEXTCMD_10, SE10_HDR_LEN, &ext_len);
  if (err != XRAN_EXT_OK)
    return err;
  xran_se10_hdr_t hdr = {.ef = ext[0] >> 7,
                         .beamGroupType = ext[2] >> 6,
                         .numPortc = (ext[2] & 0x3F) == 0 ? XRAN_SE10_MAX_PORTS : ext[2] & 0x3F};
  if (ext_len != pad4(se10_content_len(hdr.beamGroupType, hdr.numPortc)))
    return XRAN_EXT_ERR_EXT_LEN;
  int n_ports = xran_se10_num_ports(&hdr);
  if (n_ports > max_ports)
    return XRAN_EXT_ERR_TOO_MANY;

  const uint8_t *p = ext + SE10_HDR_LEN;
  if (hdr.beamGroupType == XRAN_SE10_BGT_11B)
    hdr.firstPortListIndex = *p++;
  for (int k = 0; k < n_ports; k++) {
    xran_se10_port_t port = {.id = (uint16_t)((p[0] & 0x7F) << 8 | p[1])};
    p += 2;
    if (hdr.beamGroupType == XRAN_SE10_BGT_11B)
      port.portListIndex = *p++;
    ports_out[k] = port;
  }
  *hdr_out = hdr;
  return XRAN_EXT_OK;
}

/**********************************************************************
 * SE 24
 **********************************************************************/

#define SE24_HDR_LEN 4 // Table 7.7.24.1-1
#define SE24_ENTRY_SHORT_LEN 1 // entryType 0 and 1, Table 7.7.24.3-1
#define SE24_ENTRY_LONG_LEN 10 // entryType 2 and 3, Tables 7.7.24.3-2 and 7.7.24.3-3

static size_t se24_entry_len(uint8_t entry_type)
{
  return entry_type <= XRAN_SE24_ENTRY_INHERIT_RESET ? SE24_ENTRY_SHORT_LEN : SE24_ENTRY_LONG_LEN;
}

static xran_ext_err_t se24_check_entry(const xran_se24_entry_t *e)
{
  if (e->entryType > XRAN_SE24_ENTRY_DFT_S_OFDM)
    return XRAN_EXT_ERR_ENTRY_TYPE;
  if (e->dmrsPortNumber > 0x1F)
    return XRAN_EXT_ERR_RANGE;
  if (e->entryType <= XRAN_SE24_ENTRY_INHERIT_RESET)
    return XRAN_EXT_OK;
  if (e->ueIdReset > 1 || e->dmrsSymbolMask > 0x3FFF || e->nscid > 1 || e->firstPrb > 0x1FF || e->lastPrb > 0x1FF)
    return XRAN_EXT_ERR_RANGE;
  if (e->entryType == XRAN_SE24_ENTRY_CP_OFDM && (e->dType > 1 || e->cdmWithoutData > 3 || e->lambda > 3))
    return XRAN_EXT_ERR_RANGE;
  if (e->entryType == XRAN_SE24_ENTRY_DFT_S_OFDM && (e->lowPaprType > 3 || e->hoppingMode > 3))
    return XRAN_EXT_ERR_RANGE;
  return XRAN_EXT_OK;
}

xran_ext_err_t xran_encode_se24(const xran_se24_hdr_t *hdr,
                                const xran_se24_entry_t *entries,
                                int n_entries,
                                uint8_t *buf,
                                size_t avail,
                                size_t *len_out)
{
  AssertError(hdr != NULL && entries != NULL && buf != NULL && len_out != NULL && n_entries > 0,
              return XRAN_EXT_ERR_ARG,
              "hdr %p entries %p buf %p len_out %p n_entries %d\n",
              hdr,
              entries,
              buf,
              len_out,
              n_entries);
  if (hdr->aIpnPerSym > 1 || hdr->antDmrsSnr > 1 || hdr->userGroupSize > 0x1F)
    return XRAN_EXT_ERR_RANGE;
  size_t content_len = SE24_HDR_LEN;
  for (int i = 0; i < n_entries; i++) {
    xran_ext_err_t err = se24_check_entry(&entries[i]);
    if (err != XRAN_EXT_OK)
      return err;
    content_len += se24_entry_len(entries[i].entryType);
  }
  xran_ext_err_t err = se_begin(buf, avail, XRAN_CP_SECTIONEXTCMD_24, hdr->ef, content_len, len_out);
  if (err != XRAN_EXT_OK)
    return err;

  buf[2] = (uint8_t)(hdr->aIpnPerSym << 7 | hdr->antDmrsSnr << 6 | hdr->userGroupSize);
  buf[3] = hdr->userGroupId;
  uint8_t *p = buf + SE24_HDR_LEN;
  for (int i = 0; i < n_entries; i++) {
    const xran_se24_entry_t *e = &entries[i];
    p[0] = (uint8_t)(e->entryType << 5 | e->dmrsPortNumber);
    if (e->entryType >= XRAN_SE24_ENTRY_CP_OFDM) {
      p[1] = (uint8_t)(e->ueIdReset << 7 | e->dmrsSymbolMask >> 8);
      p[2] = (uint8_t)(e->dmrsSymbolMask & 0xFF);
      p[3] = (uint8_t)(e->scrambling >> 8);
      p[4] = (uint8_t)(e->scrambling & 0xFF);
      if (e->entryType == XRAN_SE24_ENTRY_CP_OFDM)
        p[5] = (uint8_t)(e->nscid << 7 | e->dType << 6 | e->cdmWithoutData << 4 | e->lambda << 2 | e->firstPrb >> 7);
      else
        p[5] = (uint8_t)(e->nscid << 7 | e->lowPaprType << 4 | e->hoppingMode << 2 | e->firstPrb >> 7);
      p[6] = (uint8_t)((e->firstPrb & 0x7F) << 1 | e->lastPrb >> 8);
      p[7] = (uint8_t)(e->lastPrb & 0xFF);
      // p[8], p[9] reserved
    }
    p += se24_entry_len(e->entryType);
  }
  return XRAN_EXT_OK;
}

xran_ext_err_t xran_decode_se24(const uint8_t *ext,
                                size_t len,
                                int n_entries,
                                xran_se24_hdr_t *hdr_out,
                                xran_se24_entry_t *entries_out)
{
  AssertError(ext != NULL && hdr_out != NULL && entries_out != NULL && n_entries > 0,
              return XRAN_EXT_ERR_ARG,
              "ext %p hdr_out %p entries_out %p n_entries %d\n",
              ext,
              hdr_out,
              entries_out,
              n_entries);
  size_t ext_len;
  xran_ext_err_t err = se_open(ext, len, XRAN_CP_SECTIONEXTCMD_24, SE24_HDR_LEN, &ext_len);
  if (err != XRAN_EXT_OK)
    return err;

  // First pass: entry types and lengths, so nothing is written on error
  size_t content_len = SE24_HDR_LEN;
  for (int i = 0; i < n_entries; i++) {
    if (content_len >= ext_len)
      return XRAN_EXT_ERR_EXT_LEN;
    uint8_t entry_type = ext[content_len] >> 5;
    if (entry_type > XRAN_SE24_ENTRY_DFT_S_OFDM)
      return XRAN_EXT_ERR_ENTRY_TYPE;
    content_len += se24_entry_len(entry_type);
  }
  if (pad4(content_len) != ext_len)
    return XRAN_EXT_ERR_EXT_LEN;

  *hdr_out = (xran_se24_hdr_t){.ef = ext[0] >> 7,
                               .aIpnPerSym = ext[2] >> 7,
                               .antDmrsSnr = (ext[2] >> 6) & 0x1,
                               .userGroupSize = ext[2] & 0x1F,
                               .userGroupId = ext[3]};
  const uint8_t *p = ext + SE24_HDR_LEN;
  for (int i = 0; i < n_entries; i++) {
    xran_se24_entry_t e = {.entryType = p[0] >> 5, .dmrsPortNumber = p[0] & 0x1F};
    if (e.entryType >= XRAN_SE24_ENTRY_CP_OFDM) {
      e.ueIdReset = p[1] >> 7;
      e.dmrsSymbolMask = (uint16_t)((p[1] & 0x3F) << 8 | p[2]);
      e.scrambling = (uint16_t)(p[3] << 8 | p[4]);
      e.nscid = p[5] >> 7;
      if (e.entryType == XRAN_SE24_ENTRY_CP_OFDM) {
        e.dType = (p[5] >> 6) & 0x1;
        e.cdmWithoutData = (p[5] >> 4) & 0x3;
        e.lambda = (p[5] >> 2) & 0x3;
      } else {
        e.lowPaprType = (p[5] >> 4) & 0x3;
        e.hoppingMode = (p[5] >> 2) & 0x3;
      }
      e.firstPrb = (uint16_t)((p[5] & 0x3) << 7 | p[6] >> 1);
      e.lastPrb = (uint16_t)((p[6] & 0x1) << 8 | p[7]);
    }
    entries_out[i] = e;
    p += se24_entry_len(e.entryType);
  }
  return XRAN_EXT_OK;
}

/**********************************************************************
 * SE 25
 **********************************************************************/

#define SE25_HDR_LEN 2 // Table 7.7.25.1-1
#define SE25_LAYER_LEN (XRAN_SE25_NUM_SYMBOLS / 2) // two 4-bit txWinForOnAirSymbol for each byte

xran_ext_err_t xran_encode_se25(const xran_se25_hdr_t *hdr,
                                const xran_se25_layer_t *layers,
                                uint8_t *buf,
                                size_t avail,
                                size_t *len_out)
{
  AssertError(hdr != NULL && layers != NULL && buf != NULL && len_out != NULL,
              return XRAN_EXT_ERR_ARG,
              "hdr %p layers %p buf %p len_out %p\n",
              hdr,
              layers,
              buf,
              len_out);
  if (hdr->numLayers < 1 || hdr->numLayers > XRAN_SE25_MAX_LAYERS)
    return XRAN_EXT_ERR_RANGE;
  for (int l = 0; l < hdr->numLayers; l++)
    for (int sym = 0; sym < XRAN_SE25_NUM_SYMBOLS; sym++)
      if (layers[l].txWinForOnAirSymbol[sym] > 0xF)
        return XRAN_EXT_ERR_RANGE;
  size_t content_len = SE25_HDR_LEN + (size_t)SE25_LAYER_LEN * hdr->numLayers;
  xran_ext_err_t err = se_begin(buf, avail, XRAN_CP_SECTIONEXTCMD_25, hdr->ef, content_len, len_out);
  if (err != XRAN_EXT_OK)
    return err;

  uint8_t *p = buf + SE25_HDR_LEN;
  for (int l = 0; l < hdr->numLayers; l++)
    for (int sym = 0; sym < XRAN_SE25_NUM_SYMBOLS; sym += 2)
      *p++ = (uint8_t)(layers[l].txWinForOnAirSymbol[sym] << 4 | layers[l].txWinForOnAirSymbol[sym + 1]);
  return XRAN_EXT_OK;
}

xran_ext_err_t xran_decode_se25(const uint8_t *ext,
                                size_t len,
                                int max_layers,
                                xran_se25_hdr_t *hdr_out,
                                xran_se25_layer_t *layers_out)
{
  AssertError(ext != NULL && hdr_out != NULL && layers_out != NULL && max_layers > 0,
              return XRAN_EXT_ERR_ARG,
              "ext %p hdr_out %p layers_out %p max_layers %d\n",
              ext,
              hdr_out,
              layers_out,
              max_layers);
  size_t ext_len;
  xran_ext_err_t err = se_open(ext, len, XRAN_CP_SECTIONEXTCMD_25, SE25_HDR_LEN, &ext_len);
  if (err != XRAN_EXT_OK)
    return err;
  int num_layers = (int)((ext_len - SE25_HDR_LEN) / SE25_LAYER_LEN);
  if (num_layers < 1 || pad4(SE25_HDR_LEN + (size_t)SE25_LAYER_LEN * num_layers) != ext_len)
    return XRAN_EXT_ERR_EXT_LEN;
  if (num_layers > max_layers)
    return XRAN_EXT_ERR_TOO_MANY;

  const uint8_t *p = ext + SE25_HDR_LEN;
  for (int l = 0; l < num_layers; l++) {
    for (int sym = 0; sym < XRAN_SE25_NUM_SYMBOLS; sym += 2) {
      layers_out[l].txWinForOnAirSymbol[sym] = *p >> 4;
      layers_out[l].txWinForOnAirSymbol[sym + 1] = *p & 0xF;
      p++;
    }
  }
  *hdr_out = (xran_se25_hdr_t){.ef = ext[0] >> 7, .numLayers = num_layers};
  return XRAN_EXT_OK;
}

/**********************************************************************
 * SE 26
 **********************************************************************/

#define SE26_HDR_LEN 4 // Table 7.7.26.1-1

xran_ext_err_t xran_encode_se26(const xran_se26_hdr_t *hdr,
                                const int16_t *freqOffsetFb,
                                uint8_t *buf,
                                size_t avail,
                                size_t *len_out)
{
  AssertError(hdr != NULL && buf != NULL && len_out != NULL,
              return XRAN_EXT_ERR_ARG,
              "hdr %p buf %p len_out %p\n",
              hdr,
              buf,
              len_out);
  if (hdr->numFoFb > XRAN_SE26_MAX_FOFB)
    return XRAN_EXT_ERR_RANGE;
  AssertError(hdr->numFoFb == 0 || freqOffsetFb != NULL,
              return XRAN_EXT_ERR_ARG,
              "freqOffsetFb NULL for %d values\n",
              hdr->numFoFb);
  size_t content_len = SE26_HDR_LEN + (size_t)2 * hdr->numFoFb;
  xran_ext_err_t err = se_begin(buf, avail, XRAN_CP_SECTIONEXTCMD_26, hdr->ef, content_len, len_out);
  if (err != XRAN_EXT_OK)
    return err;

  buf[3] = hdr->numFoFb; // buf[2] and the msb of buf[3] are reserved
  uint8_t *p = buf + SE26_HDR_LEN;
  for (int i = 0; i < hdr->numFoFb; i++) {
    uint16_t v = (uint16_t)freqOffsetFb[i];
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)(v & 0xFF);
  }
  return XRAN_EXT_OK;
}

xran_ext_err_t xran_decode_se26(const uint8_t *ext, size_t len, int max_fofb, xran_se26_hdr_t *hdr_out, int16_t *freqOffsetFb_out)
{
  AssertError(ext != NULL && hdr_out != NULL && freqOffsetFb_out != NULL && max_fofb > 0,
              return XRAN_EXT_ERR_ARG,
              "ext %p hdr_out %p freqOffsetFb_out %p max_fofb %d\n",
              ext,
              hdr_out,
              freqOffsetFb_out,
              max_fofb);
  size_t ext_len;
  xran_ext_err_t err = se_open(ext, len, XRAN_CP_SECTIONEXTCMD_26, SE26_HDR_LEN, &ext_len);
  if (err != XRAN_EXT_OK)
    return err;
  int num_fofb = ext[3] & 0x7F;
  if (ext_len != pad4(SE26_HDR_LEN + (size_t)2 * num_fofb))
    return XRAN_EXT_ERR_EXT_LEN;
  if (num_fofb > max_fofb)
    return XRAN_EXT_ERR_TOO_MANY;

  const uint8_t *p = ext + SE26_HDR_LEN;
  for (int i = 0; i < num_fofb; i++, p += 2)
    freqOffsetFb_out[i] = (int16_t)(uint16_t)(p[0] << 8 | p[1]);
  *hdr_out = (xran_se26_hdr_t){.ef = ext[0] >> 7, .numFoFb = num_fofb};
  return XRAN_EXT_OK;
}

/**********************************************************************
 * SE 27
 **********************************************************************/

#define SE27_HDR_LEN 4 // Tables 7.7.27.1-1 and 7.7.27.1-2

xran_ext_err_t xran_encode_se27(const xran_se27_hdr_t *hdr, const uint16_t *beamId, uint8_t *buf, size_t avail, size_t *len_out)
{
  AssertError(hdr != NULL && beamId != NULL && buf != NULL && len_out != NULL,
              return XRAN_EXT_ERR_ARG,
              "hdr %p beamId %p buf %p len_out %p\n",
              hdr,
              beamId,
              buf,
              len_out);
  if (hdr->beamType > XRAN_SE27_BEAM_RANGE)
    return XRAN_EXT_ERR_BEAM_TYPE;
  if (hdr->numElements < 1 || hdr->numElements > XRAN_SE27_MAX_ELEMENTS)
    return XRAN_EXT_ERR_RANGE;
  int n_ids = xran_se27_num_beam_ids(hdr);
  for (int i = 0; i < n_ids; i++)
    if (beamId[i] > 0x7FFF)
      return XRAN_EXT_ERR_RANGE;
  size_t content_len = SE27_HDR_LEN + (size_t)2 * n_ids;
  xran_ext_err_t err = se_begin(buf, avail, XRAN_CP_SECTIONEXTCMD_27, hdr->ef, content_len, len_out);
  if (err != XRAN_EXT_OK)
    return err;

  buf[2] = (uint8_t)(hdr->beamType << 6);
  buf[3] = (uint8_t)(hdr->numElements & 0xFF); // 256 elements is 0
  uint8_t *p = buf + SE27_HDR_LEN;
  for (int i = 0; i < n_ids; i++) {
    *p++ = (uint8_t)(beamId[i] >> 8); // msb is reserved
    *p++ = (uint8_t)(beamId[i] & 0xFF);
  }
  return XRAN_EXT_OK;
}

xran_ext_err_t xran_decode_se27(const uint8_t *ext, size_t len, int max_beam_ids, xran_se27_hdr_t *hdr_out, uint16_t *beamId_out)
{
  AssertError(ext != NULL && hdr_out != NULL && beamId_out != NULL && max_beam_ids > 0,
              return XRAN_EXT_ERR_ARG,
              "ext %p hdr_out %p beamId_out %p max_beam_ids %d\n",
              ext,
              hdr_out,
              beamId_out,
              max_beam_ids);
  size_t ext_len;
  xran_ext_err_t err = se_open(ext, len, XRAN_CP_SECTIONEXTCMD_27, SE27_HDR_LEN, &ext_len);
  if (err != XRAN_EXT_OK)
    return err;
  xran_se27_hdr_t hdr = {.ef = ext[0] >> 7, .beamType = ext[2] >> 6, .numElements = ext[3] == 0 ? XRAN_SE27_MAX_ELEMENTS : ext[3]};
  if (hdr.beamType > XRAN_SE27_BEAM_RANGE)
    return XRAN_EXT_ERR_BEAM_TYPE;
  int n_ids = xran_se27_num_beam_ids(&hdr);
  if (ext_len != pad4(SE27_HDR_LEN + (size_t)2 * n_ids))
    return XRAN_EXT_ERR_EXT_LEN;
  if (n_ids > max_beam_ids)
    return XRAN_EXT_ERR_TOO_MANY;

  const uint8_t *p = ext + SE27_HDR_LEN;
  for (int i = 0; i < n_ids; i++, p += 2)
    beamId_out[i] = (uint16_t)((p[0] & 0x7F) << 8 | p[1]);
  *hdr_out = hdr;
  return XRAN_EXT_OK;
}
