/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xran_pkt_ulpi.h"
#include "xran_pkt_cp.h"
#include "common/utils/assertions.h"
#include <string.h>

#define SE24_HDR_LEN 4 // Table 7.7.24.1-1
#define SE24_ENTRY_SHORT_LEN 1 // entryType 0 and 1, Table 7.7.24.3-1
#define SE24_ENTRY_LONG_LEN 10 // entryType 2 and 3, Tables 7.7.24.3-2 and 7.7.24.3-3

const char *xran_ulpi_strerror(xran_ulpi_err_t err)
{
  switch (err) {
    case XRAN_ULPI_OK:
      return "no error";
    case XRAN_ULPI_ERR_ARG:
      return "invalid argument";
    case XRAN_ULPI_ERR_TRUNCATED:
      return "runs past the end of the buffer";
    case XRAN_ULPI_ERR_EXT_LEN:
      return "extLen doesn't match the content";
    case XRAN_ULPI_ERR_EXT_TYPE:
      return "wrong extType";
    case XRAN_ULPI_ERR_ENTRY_TYPE:
      return "reserved SE 24 entryType";
    case XRAN_ULPI_ERR_RANGE:
      return "field value doesn't fit its bit width";
    case XRAN_ULPI_ERR_TOO_MANY:
      return "more elements than the caller has room for";
    default:
      return "unknown error";
  }
}

static size_t pad4(size_t len)
{
  return (len + 3) & ~(size_t)3;
}

/**********************************************************************
 * SE 10
 **********************************************************************/

// Content length without the filler: Table 7.7.10.1-1 (00b, 01b) is 3 bytes and a reserved byte, Table 7.7.10.1-2
// (10b) has a 2-byte id per port, Table 7.7.10.1-3 (11b) has the 1st portListIndex and then a 2-byte id and a
// portListIndex for each further port.
static size_t se10_content_len(int beam_group_type, int num_portc)
{
  switch (beam_group_type) {
    case XRAN_SE10_BGT_10B:
      return 3 + (size_t)2 * num_portc;
    case XRAN_SE10_BGT_11B:
      return 4 + (size_t)3 * (num_portc - 1);
    default:
      return 4;
  }
}

xran_ulpi_err_t xran_encode_se10(const xran_se10_hdr_t *hdr,
                                 const xran_se10_port_t *ports,
                                 uint8_t *buf,
                                 size_t avail,
                                 size_t *len_out)
{
  AssertError(hdr != NULL && buf != NULL && len_out != NULL,
              return XRAN_ULPI_ERR_ARG,
              "hdr %p buf %p len_out %p\n",
              hdr,
              buf,
              len_out);
  if (hdr->ef > 1 || hdr->beamGroupType > XRAN_SE10_BGT_11B || hdr->numPortc < 1 || hdr->numPortc > XRAN_SE10_MAX_PORTS)
    return XRAN_ULPI_ERR_RANGE;
  int n_ports = xran_se10_num_ports(hdr);
  AssertError(n_ports == 0 || ports != NULL, return XRAN_ULPI_ERR_ARG, "ports NULL for %d ports\n", n_ports);
  for (int k = 0; k < n_ports; k++)
    if (ports[k].id > 0x7FFF)
      return XRAN_ULPI_ERR_RANGE;
  size_t len = pad4(se10_content_len(hdr->beamGroupType, hdr->numPortc));
  if (len > avail)
    return XRAN_ULPI_ERR_TRUNCATED;

  memset(buf, 0, len);
  buf[0] = (uint8_t)(hdr->ef << 7 | XRAN_CP_SECTIONEXTCMD_10);
  buf[1] = (uint8_t)(len / 4);
  buf[2] = (uint8_t)(hdr->beamGroupType << 6 | (hdr->numPortc & 0x3F)); // 64 ports is 0
  uint8_t *p = buf + 3;
  if (hdr->beamGroupType == XRAN_SE10_BGT_11B)
    *p++ = hdr->firstPortListIndex;
  for (int k = 0; k < n_ports; k++) {
    *p++ = (uint8_t)(ports[k].id >> 8); // msb is reserved
    *p++ = (uint8_t)(ports[k].id & 0xFF);
    if (hdr->beamGroupType == XRAN_SE10_BGT_11B)
      *p++ = ports[k].portListIndex;
  }
  *len_out = len;
  return XRAN_ULPI_OK;
}

xran_ulpi_err_t xran_decode_se10(const uint8_t *ext,
                                 size_t len,
                                 int max_ports,
                                 xran_se10_hdr_t *hdr_out,
                                 xran_se10_port_t *ports_out)
{
  AssertError(ext != NULL && hdr_out != NULL && ports_out != NULL && max_ports > 0,
              return XRAN_ULPI_ERR_ARG,
              "ext %p hdr_out %p ports_out %p max_ports %d\n",
              ext,
              hdr_out,
              ports_out,
              max_ports);
  if (len < 3)
    return XRAN_ULPI_ERR_TRUNCATED;
  if ((ext[0] & 0x7F) != XRAN_CP_SECTIONEXTCMD_10)
    return XRAN_ULPI_ERR_EXT_TYPE;
  int beam_group_type = ext[2] >> 6;
  int num_portc = (ext[2] & 0x3F) == 0 ? XRAN_SE10_MAX_PORTS : ext[2] & 0x3F;
  size_t ext_len = (size_t)ext[1] * 4;
  if (ext_len != pad4(se10_content_len(beam_group_type, num_portc)))
    return XRAN_ULPI_ERR_EXT_LEN;
  if (ext_len > len)
    return XRAN_ULPI_ERR_TRUNCATED;

  xran_se10_hdr_t hdr = {.ef = ext[0] >> 7, .beamGroupType = beam_group_type, .numPortc = num_portc};
  int n_ports = xran_se10_num_ports(&hdr);
  if (n_ports > max_ports)
    return XRAN_ULPI_ERR_TOO_MANY;
  const uint8_t *p = ext + 3;
  if (beam_group_type == XRAN_SE10_BGT_11B)
    hdr.firstPortListIndex = *p++;
  for (int k = 0; k < n_ports; k++) {
    xran_se10_port_t port = {.id = (uint16_t)((p[0] & 0x7F) << 8 | p[1])};
    p += 2;
    if (beam_group_type == XRAN_SE10_BGT_11B)
      port.portListIndex = *p++;
    ports_out[k] = port;
  }
  *hdr_out = hdr;
  return XRAN_ULPI_OK;
}

/**********************************************************************
 * SE 24
 **********************************************************************/

static size_t se24_entry_len(uint8_t entry_type)
{
  return entry_type <= XRAN_SE24_ENTRY_INHERIT_RESET ? SE24_ENTRY_SHORT_LEN : SE24_ENTRY_LONG_LEN;
}

static xran_ulpi_err_t se24_check_entry(const xran_se24_entry_t *e)
{
  if (e->entryType > XRAN_SE24_ENTRY_DFT_S_OFDM)
    return XRAN_ULPI_ERR_ENTRY_TYPE;
  if (e->dmrsPortNumber > 0x1F)
    return XRAN_ULPI_ERR_RANGE;
  if (e->entryType <= XRAN_SE24_ENTRY_INHERIT_RESET)
    return XRAN_ULPI_OK;
  if (e->ueIdReset > 1 || e->dmrsSymbolMask > 0x3FFF || e->nscid > 1 || e->firstPrb > 0x1FF || e->lastPrb > 0x1FF)
    return XRAN_ULPI_ERR_RANGE;
  if (e->entryType == XRAN_SE24_ENTRY_CP_OFDM && (e->dType > 1 || e->cdmWithoutData > 3 || e->lambda > 3))
    return XRAN_ULPI_ERR_RANGE;
  if (e->entryType == XRAN_SE24_ENTRY_DFT_S_OFDM && (e->lowPaprType > 3 || e->hoppingMode > 3))
    return XRAN_ULPI_ERR_RANGE;
  return XRAN_ULPI_OK;
}

xran_ulpi_err_t xran_encode_se24(const xran_se24_hdr_t *hdr,
                                 const xran_se24_entry_t *entries,
                                 int n_entries,
                                 uint8_t *buf,
                                 size_t avail,
                                 size_t *len_out)
{
  AssertError(hdr != NULL && entries != NULL && buf != NULL && len_out != NULL && n_entries > 0,
              return XRAN_ULPI_ERR_ARG,
              "hdr %p entries %p buf %p len_out %p n_entries %d\n",
              hdr,
              entries,
              buf,
              len_out,
              n_entries);
  if (hdr->ef > 1 || hdr->aIpnPerSym > 1 || hdr->antDmrsSnr > 1 || hdr->userGroupSize > 0x1F)
    return XRAN_ULPI_ERR_RANGE;
  size_t len = SE24_HDR_LEN;
  for (int i = 0; i < n_entries; i++) {
    xran_ulpi_err_t err = se24_check_entry(&entries[i]);
    if (err != XRAN_ULPI_OK)
      return err;
    len += se24_entry_len(entries[i].entryType);
  }
  len = pad4(len);
  if (len / 4 > 0xFF) // 8-bit extLen
    return XRAN_ULPI_ERR_RANGE;
  if (len > avail)
    return XRAN_ULPI_ERR_TRUNCATED;

  memset(buf, 0, len);
  buf[0] = (uint8_t)(hdr->ef << 7 | XRAN_CP_SECTIONEXTCMD_24);
  buf[1] = (uint8_t)(len / 4);
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
  *len_out = len;
  return XRAN_ULPI_OK;
}

xran_ulpi_err_t xran_decode_se24(const uint8_t *ext,
                                 size_t len,
                                 int n_entries,
                                 xran_se24_hdr_t *hdr_out,
                                 xran_se24_entry_t *entries_out)
{
  AssertError(ext != NULL && hdr_out != NULL && entries_out != NULL && n_entries > 0,
              return XRAN_ULPI_ERR_ARG,
              "ext %p hdr_out %p entries_out %p n_entries %d\n",
              ext,
              hdr_out,
              entries_out,
              n_entries);
  if (len < SE24_HDR_LEN)
    return XRAN_ULPI_ERR_TRUNCATED;
  if ((ext[0] & 0x7F) != XRAN_CP_SECTIONEXTCMD_24)
    return XRAN_ULPI_ERR_EXT_TYPE;
  size_t ext_len = (size_t)ext[1] * 4;
  if (ext_len > len)
    return XRAN_ULPI_ERR_TRUNCATED;

  // First pass: entry types and lengths, so nothing is written on error
  size_t content_len = SE24_HDR_LEN;
  for (int i = 0; i < n_entries; i++) {
    if (content_len >= ext_len)
      return XRAN_ULPI_ERR_EXT_LEN;
    uint8_t entry_type = ext[content_len] >> 5;
    if (entry_type > XRAN_SE24_ENTRY_DFT_S_OFDM)
      return XRAN_ULPI_ERR_ENTRY_TYPE;
    content_len += se24_entry_len(entry_type);
  }
  if (pad4(content_len) != ext_len)
    return XRAN_ULPI_ERR_EXT_LEN;

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
  return XRAN_ULPI_OK;
}
