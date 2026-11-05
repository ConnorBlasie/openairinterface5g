/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Bad input for the ULPI section extension codecs of xran_pkt_ulpi.h. Each case starts from a valid extension made by
// the encoder and changes one byte or one length. A decoder must return the expected error, write nothing to its
// outputs and read nothing past len: each decode reads an exact-size heap copy, so AddressSanitizer sees an over-read.
// An encoder must return the expected error and write nothing.

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

/**********************************************************************
 * One encoder and one decoder for each extension, with the same signatures
 **********************************************************************/

#define SE24_N_ENTRIES 3

// Encodes a valid extension with the given ef
typedef xran_ext_err_t (*encode_fn)(uint8_t ef, uint8_t *buf, size_t avail, size_t *len_out);
// Decodes with room for the maximum count. On error, asserts that the outputs are unchanged.
typedef xran_ext_err_t (*decode_fn)(const uint8_t *ext, size_t len);

// 11b, numPortc 3: content 4 + 3 * 2 = 10 bytes
static xran_ext_err_t enc_se10(uint8_t ef, uint8_t *buf, size_t avail, size_t *len_out)
{
  const xran_se10_hdr_t hdr = {.ef = ef, .beamGroupType = XRAN_SE10_BGT_11B, .numPortc = 3, .firstPortListIndex = 1};
  const xran_se10_port_t ports[] = {{.id = 0x0102, .portListIndex = 2}, {.id = 0x7FFF, .portListIndex = 3}};
  return xran_encode_se10(&hdr, ports, buf, avail, len_out);
}

static xran_ext_err_t dec_se10(const uint8_t *ext, size_t len)
{
  xran_se10_hdr_t hdr;
  xran_se10_port_t ports[XRAN_SE10_MAX_PORTS];
  memset(&hdr, FILL, sizeof(hdr));
  memset(ports, FILL, sizeof(ports));
  xran_ext_err_t err = xran_decode_se10(ext, len, XRAN_SE10_MAX_PORTS, &hdr, ports);
  if (err != XRAN_EXT_OK)
    assert(is_fill(&hdr, sizeof(hdr)) && is_fill(ports, sizeof(ports)));
  return err;
}

// entryType 2, 0, 3 at offsets 4, 14, 15: content 4 + 10 + 1 + 10 = 25 bytes
static const xran_se24_entry_t se24_entries[SE24_N_ENTRIES] = {
    {.entryType = XRAN_SE24_ENTRY_CP_OFDM, .dmrsPortNumber = 1, .dmrsSymbolMask = 0x0004, .lastPrb = 105},
    {.entryType = XRAN_SE24_ENTRY_INHERIT_PERSIST, .dmrsPortNumber = 2},
    {.entryType = XRAN_SE24_ENTRY_DFT_S_OFDM, .dmrsPortNumber = 3, .dmrsSymbolMask = 0x0004, .lastPrb = 50},
};

static xran_ext_err_t enc_se24(uint8_t ef, uint8_t *buf, size_t avail, size_t *len_out)
{
  const xran_se24_hdr_t hdr = {.ef = ef, .userGroupSize = 3};
  return xran_encode_se24(&hdr, se24_entries, SE24_N_ENTRIES, buf, avail, len_out);
}

static xran_ext_err_t dec_se24_n(const uint8_t *ext, size_t len, int n_entries)
{
  xran_se24_hdr_t hdr;
  xran_se24_entry_t entries[8];
  memset(&hdr, FILL, sizeof(hdr));
  memset(entries, FILL, sizeof(entries));
  xran_ext_err_t err = xran_decode_se24(ext, len, n_entries, &hdr, entries);
  if (err != XRAN_EXT_OK)
    assert(is_fill(&hdr, sizeof(hdr)) && is_fill(entries, sizeof(entries)));
  return err;
}

static xran_ext_err_t dec_se24(const uint8_t *ext, size_t len)
{
  return dec_se24_n(ext, len, SE24_N_ENTRIES);
}

// 2 layers: content 2 + 2 * 7 = 16 bytes
static xran_ext_err_t enc_se25(uint8_t ef, uint8_t *buf, size_t avail, size_t *len_out)
{
  const xran_se25_hdr_t hdr = {.ef = ef, .numLayers = 2};
  const xran_se25_layer_t layers[] = {{{1, 1, 0, 2, 2, 3, 3, 4, 4, 5, 5, 0, 6, 6}},
                                      {{8, 8, 7, 9, 9, 10, 10, 11, 11, 12, 12, 7, 13, 13}}};
  return xran_encode_se25(&hdr, layers, buf, avail, len_out);
}

static xran_ext_err_t dec_se25(const uint8_t *ext, size_t len)
{
  xran_se25_hdr_t hdr;
  xran_se25_layer_t layers[XRAN_SE25_MAX_LAYERS];
  memset(&hdr, FILL, sizeof(hdr));
  memset(layers, FILL, sizeof(layers));
  xran_ext_err_t err = xran_decode_se25(ext, len, XRAN_SE25_MAX_LAYERS, &hdr, layers);
  if (err != XRAN_EXT_OK)
    assert(is_fill(&hdr, sizeof(hdr)) && is_fill(layers, sizeof(layers)));
  return err;
}

// numFoFb 3: content 4 + 3 * 2 = 10 bytes
static xran_ext_err_t enc_se26(uint8_t ef, uint8_t *buf, size_t avail, size_t *len_out)
{
  const xran_se26_hdr_t hdr = {.ef = ef, .numFoFb = 3};
  const int16_t fofb[] = {30000, -30000, INT16_MIN};
  return xran_encode_se26(&hdr, fofb, buf, avail, len_out);
}

static xran_ext_err_t dec_se26(const uint8_t *ext, size_t len)
{
  xran_se26_hdr_t hdr;
  int16_t fofb[XRAN_SE26_MAX_FOFB];
  memset(&hdr, FILL, sizeof(hdr));
  memset(fofb, FILL, sizeof(fofb));
  xran_ext_err_t err = xran_decode_se26(ext, len, XRAN_SE26_MAX_FOFB, &hdr, fofb);
  if (err != XRAN_EXT_OK)
    assert(is_fill(&hdr, sizeof(hdr)) && is_fill(fofb, sizeof(fofb)));
  return err;
}

// list of 3 beamIds: content 4 + 3 * 2 = 10 bytes
static xran_ext_err_t enc_se27(uint8_t ef, uint8_t *buf, size_t avail, size_t *len_out)
{
  const xran_se27_hdr_t hdr = {.ef = ef, .beamType = XRAN_SE27_BEAM_LIST, .numElements = 3};
  const uint16_t ids[] = {1, 0x7FFF, 0x0100};
  return xran_encode_se27(&hdr, ids, buf, avail, len_out);
}

static xran_ext_err_t dec_se27(const uint8_t *ext, size_t len)
{
  xran_se27_hdr_t hdr;
  uint16_t ids[XRAN_SE27_MAX_ELEMENTS];
  memset(&hdr, FILL, sizeof(hdr));
  memset(ids, FILL, sizeof(ids));
  xran_ext_err_t err = xran_decode_se27(ext, len, XRAN_SE27_MAX_ELEMENTS, &hdr, ids);
  if (err != XRAN_EXT_OK)
    assert(is_fill(&hdr, sizeof(hdr)) && is_fill(ids, sizeof(ids)));
  return err;
}

typedef struct {
  const char *name;
  uint8_t ext_type;
  encode_fn encode;
  decode_fn decode;
} codec_t;

static const codec_t se10_codec = {"SE 10", XRAN_CP_SECTIONEXTCMD_10, enc_se10, dec_se10};
static const codec_t se24_codec = {"SE 24", XRAN_CP_SECTIONEXTCMD_24, enc_se24, dec_se24};
static const codec_t se25_codec = {"SE 25", XRAN_CP_SECTIONEXTCMD_25, enc_se25, dec_se25};
static const codec_t se26_codec = {"SE 26", XRAN_CP_SECTIONEXTCMD_26, enc_se26, dec_se26};
static const codec_t se27_codec = {"SE 27", XRAN_CP_SECTIONEXTCMD_27, enc_se27, dec_se27};
static const codec_t *const codecs[] = {&se10_codec, &se24_codec, &se25_codec, &se26_codec, &se27_codec};

// Decodes the first len bytes of ext from an exact-size heap copy
static xran_ext_err_t decode_exact(decode_fn decode, const uint8_t *ext, size_t len)
{
  uint8_t *copy = malloc(len > 0 ? len : 1);
  memcpy(copy, ext, len);
  xran_ext_err_t err = decode(copy, len);
  free(copy);
  return err;
}

static size_t encode_valid(const codec_t *c, uint8_t buf[64])
{
  size_t len = 0;
  assert(c->encode(1, buf, 64, &len) == XRAN_EXT_OK && len > 0 && len < 64);
  assert(decode_exact(c->decode, buf, len) == XRAN_EXT_OK);
  return len;
}

/**********************************************************************
 * Bad input common to all decoders and encoders
 **********************************************************************/

// Every length shorter than the extension (header cut, or extLen past the end) is TRUNCATED. extLen 1 word more
// than the packet is TRUNCATED, extLen 0 is EXT_LEN, and another extType is EXT_TYPE. With two faults, the first check
// wins: a short header before extType, extType before extLen.
static void test_common_decode_errors(void)
{
  int n_cases = 0;
  for (size_t c = 0; c < sizeof(codecs) / sizeof(codecs[0]); c++) {
    const codec_t *codec = codecs[c];
    uint8_t valid[64], ext[64];
    size_t len = encode_valid(codec, valid);

    for (size_t cut = 0; cut < len; cut++, n_cases++)
      assert(decode_exact(codec->decode, valid, cut) == XRAN_EXT_ERR_TRUNCATED);

    memcpy(ext, valid, len);
    ext[1]++; // extLen past the end of the packet
    assert(decode_exact(codec->decode, ext, len) == XRAN_EXT_ERR_TRUNCATED);

    memcpy(ext, valid, len);
    ext[1] = 0; // reserved
    assert(decode_exact(codec->decode, ext, len) == XRAN_EXT_ERR_EXT_LEN);

    memcpy(ext, valid, len);
    ext[0] = (uint8_t)((ext[0] & 0x80) | XRAN_CP_SECTIONEXTCMD_11); // another extType, same ef
    assert(decode_exact(codec->decode, ext, len) == XRAN_EXT_ERR_EXT_TYPE);
    ext[1] = 0;
    assert(decode_exact(codec->decode, ext, len) == XRAN_EXT_ERR_EXT_TYPE);
    assert(decode_exact(codec->decode, ext, 1) == XRAN_EXT_ERR_TRUNCATED);
    n_cases += 5;
  }
  printf("common decode errors, %d cases, passed\n", n_cases);
}

// ef > 1 is RANGE and a buffer 1 byte too short is TRUNCATED. The buffer is unchanged in both cases.
static void test_common_encode_errors(void)
{
  for (size_t c = 0; c < sizeof(codecs) / sizeof(codecs[0]); c++) {
    const codec_t *codec = codecs[c];
    uint8_t valid[64], buf[64];
    size_t len = encode_valid(codec, valid);

    size_t out = 0xDEAD;
    memset(buf, FILL, sizeof(buf));
    assert(codec->encode(2, buf, sizeof(buf), &out) == XRAN_EXT_ERR_RANGE);
    assert(is_fill(buf, sizeof(buf)) && out == 0xDEAD);

    assert(codec->encode(1, buf, len - 1, &out) == XRAN_EXT_ERR_TRUNCATED);
    assert(is_fill(buf, sizeof(buf)) && out == 0xDEAD);
  }
  printf("common encode errors passed\n");
}

/**********************************************************************
 * Bad input specific to one extension
 **********************************************************************/

// SE 10: a numPortc that doesn't match extLen
static void test_se10_errors(void)
{
  uint8_t ext[64];
  size_t len = encode_valid(&se10_codec, ext);
  assert(len == 12);
  ext[2] = (uint8_t)((ext[2] & 0xC0) | 4); // 11b, 4 ports: content 13 bytes, 16 with the filler, not 12
  assert(decode_exact(dec_se10, ext, len) == XRAN_EXT_ERR_EXT_LEN);
  ext[2] = (uint8_t)(ext[2] & 0xC0); // numPortc 0 = 64 ports
  assert(decode_exact(dec_se10, ext, len) == XRAN_EXT_ERR_EXT_LEN);
  printf("SE 10 errors passed\n");
}

// SE 24: entryType 4 to 7 (reserved) in the first or a later entry, and an n_entries that doesn't match the content.
// The padding looks the same as entryType 0 entries, so an n_entries that runs into the padding decodes: only the
// caller's count from the ueIds guards it (7.7.24.3).
static void test_se24_errors(void)
{
  uint8_t valid[64], ext[64];
  size_t len = encode_valid(&se24_codec, valid);
  assert(len == 28);
  const size_t entry_offsets[] = {4, 14, 15};
  for (int e = 0; e < SE24_N_ENTRIES; e++) {
    for (int type = 4; type <= 7; type++) {
      memcpy(ext, valid, len);
      ext[entry_offsets[e]] = (uint8_t)((type << 5) | (ext[entry_offsets[e]] & 0x1F));
      assert(decode_exact(dec_se24, ext, len) == XRAN_EXT_ERR_ENTRY_TYPE);
    }
  }
  assert(decode_exact(dec_se24, ext, 3) == XRAN_EXT_ERR_TRUNCATED); // a short header before entryType

  uint8_t *copy = malloc(len);
  memcpy(copy, valid, len);
  assert(dec_se24_n(copy, len, 2) == XRAN_EXT_ERR_EXT_LEN); // 15 bytes of entries: 16 with the padding, not 28
  assert(dec_se24_n(copy, len, 6) == XRAN_EXT_OK); // 3 padding bytes read as entryType 0
  assert(dec_se24_n(copy, len, 7) == XRAN_EXT_ERR_EXT_LEN); // past the padding
  free(copy);
  printf("SE 24 errors passed\n");
}

// SE 25: the layer count comes from extLen, so only an extLen with no layer is EXT_LEN
static void test_se25_errors(void)
{
  uint8_t ext[64];
  size_t len = encode_valid(&se25_codec, ext);
  assert(len == 16);
  for (uint8_t words = 1; words <= 2; words++) { // 4 and 8 bytes: no 7-byte layer after the 2-byte header
    ext[1] = words;
    assert(decode_exact(dec_se25, ext, len) == XRAN_EXT_ERR_EXT_LEN);
  }
  printf("SE 25 errors passed\n");
}

// SE 26: a numFoFb that doesn't match extLen
static void test_se26_errors(void)
{
  uint8_t ext[64];
  size_t len = encode_valid(&se26_codec, ext);
  assert(len == 12);
  ext[3] = 5; // content 14 bytes, 16 with the padding, not 12
  assert(decode_exact(dec_se26, ext, len) == XRAN_EXT_ERR_EXT_LEN);
  ext[3] = 0; // content 4 bytes, not 12
  assert(decode_exact(dec_se26, ext, len) == XRAN_EXT_ERR_EXT_LEN);
  printf("SE 26 errors passed\n");
}

// SE 27: beamType 10b and 11b (reserved), and a numElements that doesn't match extLen. A reserved beamType wins over a
// length mismatch, because the length depends on the beamType.
static void test_se27_errors(void)
{
  uint8_t valid[64], ext[64];
  size_t len = encode_valid(&se27_codec, valid);
  assert(len == 12);
  for (int bt = 2; bt <= 3; bt++) {
    memcpy(ext, valid, len);
    ext[2] = (uint8_t)(bt << 6);
    assert(decode_exact(dec_se27, ext, len) == XRAN_EXT_ERR_BEAM_TYPE);
    ext[3] = 5;
    assert(decode_exact(dec_se27, ext, len) == XRAN_EXT_ERR_BEAM_TYPE);
  }
  memcpy(ext, valid, len);
  ext[3] = 5; // content 14 bytes, 16 with the padding, not 12
  assert(decode_exact(dec_se27, ext, len) == XRAN_EXT_ERR_EXT_LEN);
  ext[2] = (uint8_t)(XRAN_SE27_BEAM_RANGE << 6); // one beamId: content 6 bytes, 8 with the padding, not 12
  assert(decode_exact(dec_se27, ext, len) == XRAN_EXT_ERR_EXT_LEN);

  const xran_se27_hdr_t hdr = {.beamType = 2, .numElements = 1};
  const uint16_t id = 1;
  uint8_t buf[16];
  size_t out = 0xDEAD;
  memset(buf, FILL, sizeof(buf));
  assert(xran_encode_se27(&hdr, &id, buf, sizeof(buf), &out) == XRAN_EXT_ERR_BEAM_TYPE);
  assert(is_fill(buf, sizeof(buf)) && out == 0xDEAD);
  printf("SE 27 errors passed\n");
}

int main(void)
{
  test_common_decode_errors();
  test_common_encode_errors();
  test_se10_errors();
  test_se24_errors();
  test_se25_errors();
  test_se26_errors();
  test_se27_errors();
  printf("All ULPI bad-input tests passed!\n");
  return 0;
}
