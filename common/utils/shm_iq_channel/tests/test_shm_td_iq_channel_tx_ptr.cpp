/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <gtest/gtest.h>
#include <string>
#include <unistd.h>
#include <vector>
extern "C" {
#include "shm_td_iq_channel.h"
}

class ShmTxPtr : public testing::Test {
 protected:
  void SetUp() override
  {
    name = "/test_tx_ptr_" + std::to_string(getpid());
    ch = shm_td_iq_channel_create(name.c_str(), 2, 1);
  }
  void TearDown() override
  {
    shm_td_iq_channel_destroy(ch);
  }
  std::string name;
  ShmTDIQChannel *ch;
};

TEST_F(ShmTxPtr, InPlaceWriteEqualsTx)
{
  const uint64_t ts = 1000, n = 4096;
  std::vector<sample_t> data(n);
  for (uint64_t i = 0; i < n; i++)
    data[i] = 0x10000 * i + 7;
  sample_t *p = shm_td_iq_channel_tx_ptr(ch, ts, n, 0);
  ASSERT_NE(p, nullptr);
  std::copy(data.begin(), data.end(), p);
  EXPECT_EQ(shm_td_iq_channel_tx_commit(ch, ts, n, 0), CHANNEL_NO_ERROR);
  EXPECT_EQ(shm_td_iq_channel_tx(ch, ts, n, 1, data.data()), CHANNEL_NO_ERROR);
  const sample_t *p1 = shm_td_iq_channel_tx_ptr(ch, ts, n, 1);
  ASSERT_NE(p1, nullptr);
  EXPECT_EQ(p1 - p, CIRCULAR_BUFFER_SIZE);
  EXPECT_TRUE(std::equal(data.begin(), data.end(), p1));
}

TEST_F(ShmTxPtr, NullWhenTxWouldRejectOrWrap)
{
  const uint64_t ring = CIRCULAR_BUFFER_SIZE;
  shm_td_iq_channel_produce_samples(ch, ring / 2);
  EXPECT_EQ(shm_td_iq_channel_tx_ptr(ch, ring / 2 - 1, 100, 0), nullptr); // late
  EXPECT_EQ(shm_td_iq_channel_tx_ptr(ch, ring + ring / 2 - 50, 100, 0), nullptr); // too early
  EXPECT_NE(shm_td_iq_channel_tx_ptr(ch, ring - 200, 200, 0), nullptr); // ends at the ring end
  EXPECT_EQ(shm_td_iq_channel_tx_ptr(ch, ring - 100, 200, 0), nullptr); // wraps
  std::vector<sample_t> data(200, 1);
  EXPECT_EQ(shm_td_iq_channel_tx(ch, ring - 100, 200, 0, data.data()), CHANNEL_NO_ERROR); // the fallback takes it
}

TEST_F(ShmTxPtr, CommitClearsSpanWhenReaderPassed)
{
  const uint64_t ts = 10, n = 100;
  sample_t *p = shm_td_iq_channel_tx_ptr(ch, ts, n, 0);
  ASSERT_NE(p, nullptr);
  std::fill(p, p + n, 0xabcd);
  shm_td_iq_channel_produce_samples(ch, ts + 1);
  EXPECT_EQ(shm_td_iq_channel_tx_commit(ch, ts, n, 0), CHANNEL_ERROR_TOO_LATE);
  EXPECT_TRUE(std::all_of(p, p + n, [](sample_t s) { return s == 0; }));
}

int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
