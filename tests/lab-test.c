#include "harness/unity.h"
#include "../src/lab.h"

#include <stddef.h>
#include <stdint.h>

void setUp(void) {}
void tearDown(void) {}

void test_ip_parse_accepts_valid_addresses(void)
{
  uint32_t addr = 0;
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010A), addr);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), addr);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFF), addr);
}

void test_ip_parse_rejects_malformed_addresses(void)
{
  static const char *const invalid[] = {
    "", "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1",
    "010.0.0.1", "1.2.3.4x", "+1.2.3.4", "1.2.3.-4",
    "1.2.3.04", "1.2.3.4 ", " 1.2.3.4"
  };
  uint32_t addr = UINT32_C(0x12345678);

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    TEST_ASSERT_FALSE(ip_parse(invalid[i], &addr));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), addr);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
}

void test_ip_format_formats_all_octets(void)
{
  char text[IP_STR_LEN];
  ip_format(UINT32_C(0xC0A8010A), text);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", text);
  ip_format(UINT32_C(0), text);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", text);
  ip_format(UINT32_C(0xFFFFFFFF), text);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", text);
}

void test_cidr_parse_accepts_valid_blocks(void)
{
  cidr_t block = {0, 0};
  TEST_ASSERT_TRUE(cidr_parse("192.168.1.10/24", &block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010A), block.addr);
  TEST_ASSERT_EQUAL_UINT8(24, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT8(0, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &block));
  TEST_ASSERT_EQUAL_UINT8(32, block.prefix);
}

void test_cidr_parse_rejects_malformed_blocks(void)
{
  static const char *const invalid[] = {
    "", "1.2.3.4", "/24", "1.2.3.4/", "1.2.3/24",
    "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/+2",
    "1.2.3.4/2x", "1.2.3.4/2/3", "255.255.255.2555/24"
  };
  cidr_t block = {UINT32_C(0x12345678), 17};

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    TEST_ASSERT_FALSE(cidr_parse(invalid[i], &block));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), block.addr);
    TEST_ASSERT_EQUAL_UINT8(17, block.prefix);
  }
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));
}

void test_cidr_format_preserves_address_and_clamps_prefix(void)
{
  char text[CIDR_STR_LEN];
  cidr_t block = {UINT32_C(0x84B2E30B), 25};
  cidr_format(block, text);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", text);

  block.addr = UINT32_C(0xFFFFFFFF);
  block.prefix = 99;
  cidr_format(block, text);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", text);
}

void test_cidr_mask_handles_every_boundary(void)
{
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x80000000), cidr_mask(1));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFF00), cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), cidr_mask(31));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(99));
}

void test_cidr_network_and_broadcast_clear_and_set_host_bits(void)
{
  cidr_t block = {UINT32_C(0x84B2E30B), 25};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E300), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E37F), cidr_broadcast(block));

  block.addr = UINT32_C(0x12345678);
  block.prefix = 0;
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_broadcast(block));
}

void test_cidr_host_ranges_handle_regular_31_and_32_blocks(void)
{
  cidr_t block = {UINT32_C(0xC0A8010A), 24};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A80101), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A801FE), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(254), cidr_host_count(block));

  block.addr = UINT32_C(0xC0A8010B);
  block.prefix = 31;
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010A), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010B), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(2), cidr_host_count(block));

  block.prefix = 32;
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010B), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010B), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(1), cidr_host_count(block));

  block.prefix = 99;
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(1), cidr_host_count(block));
}

void test_cidr_host_count_uses_64_bit_arithmetic_for_default_route(void)
{
  cidr_t block = {0, 0};
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(1), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), cidr_last_host(block));
}

void test_cidr_contains_and_is_network(void)
{
  cidr_t block = {UINT32_C(0x0A010200), 24};
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x0A010200)));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x0A0102FF)));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_C(0x0A010300)));
  TEST_ASSERT_TRUE(cidr_is_network(block));

  block.addr = UINT32_C(0x0A010201);
  TEST_ASSERT_FALSE(cidr_is_network(block));

  block.addr = UINT32_C(0xDEADBEEF);
  block.prefix = 0;
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0)));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_MAX));
  TEST_ASSERT_FALSE(cidr_is_network(block));
}

void test_cidr_subnet_returns_requested_equal_subnet(void)
{
  cidr_t block = {UINT32_C(0xC0A80100), 24};
  cidr_t subnet = {0, 0};

  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A80100), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A801C0), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);

  TEST_ASSERT_TRUE(cidr_subnet(block, 1, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(block.addr, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(block.prefix, subnet.prefix);
}

void test_cidr_subnet_supports_a_very_large_legal_split(void)
{
  cidr_t block = {0, 0};
  cidr_t subnet = {0, 0};
  uint32_t n = UINT32_C(1) << 31U;

  TEST_ASSERT_TRUE(cidr_subnet(block, n, n - 1U, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(31, subnet.prefix);
}

void test_cidr_subnet_rejects_invalid_requests_without_changing_output(void)
{
  cidr_t network = {UINT32_C(0xC0A80100), 24};
  cidr_t host_block = {UINT32_C(0xC0A80105), 24};
  cidr_t too_small = {UINT32_C(0xC0A80100), 31};
  cidr_t invalid_prefix = {UINT32_C(0xC0A80100), 33};
  cidr_t sentinel = {UINT32_C(0x12345678), 17};

  TEST_ASSERT_FALSE(cidr_subnet(network, 4, 0, NULL));
  TEST_ASSERT_FALSE(cidr_subnet(host_block, 4, 0, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(network, 0, 0, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(network, 3, 0, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(network, 4, 4, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(too_small, 4, 0, &sentinel));
  TEST_ASSERT_FALSE(cidr_subnet(invalid_prefix, 1, 0, &sentinel));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), sentinel.addr);
  TEST_ASSERT_EQUAL_UINT8(17, sentinel.prefix);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_accepts_valid_addresses);
  RUN_TEST(test_ip_parse_rejects_malformed_addresses);
  RUN_TEST(test_ip_format_formats_all_octets);
  RUN_TEST(test_cidr_parse_accepts_valid_blocks);
  RUN_TEST(test_cidr_parse_rejects_malformed_blocks);
  RUN_TEST(test_cidr_format_preserves_address_and_clamps_prefix);
  RUN_TEST(test_cidr_mask_handles_every_boundary);
  RUN_TEST(test_cidr_network_and_broadcast_clear_and_set_host_bits);
  RUN_TEST(test_cidr_host_ranges_handle_regular_31_and_32_blocks);
  RUN_TEST(test_cidr_host_count_uses_64_bit_arithmetic_for_default_route);
  RUN_TEST(test_cidr_contains_and_is_network);
  RUN_TEST(test_cidr_subnet_returns_requested_equal_subnet);
  RUN_TEST(test_cidr_subnet_supports_a_very_large_legal_split);
  RUN_TEST(test_cidr_subnet_rejects_invalid_requests_without_changing_output);
  return UNITY_END();
}
