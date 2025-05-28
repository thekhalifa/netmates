/**
 * @file test_protocol.c
 * nm-protocol tests
 *
 * SPDX-License-Identifier: GPL-3.0
 */
#include "munit.h"

#include "nm-protocol.h"


static const uint8_t sample_mdns_services_query[] = {
    0x12, 0x34,     //query id
    0x00, 0x00,     //flags
    0x00, 0x01,     //question count
    0x00, 0x00,     //answer count
    0x00, 0x00,     //authority count
    0x00, 0x00,     //additional count
    // _services._dns-sd._udp.local.
    0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 0x07, '_', 'd', 'n', 's', '-', 's', 'd',
    0x04, '_', 'u', 'd', 'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    0x00, 0x0C,     //type PTR
    0x80, 0x01      //class: unicast, IN
};


static const uint8_t sample_dns_query1[] = {
    0x56, 0x01,     //query id
    0x00, 0x00,     //flags
    0x00, 0x01,     //question count
    0x00, 0x00,     //answer count
    0x00, 0x00,     //authority count
    0x00, 0x00,     //additional count
    // _services._dns-sd._udp.local.
    0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x0C,     //type PTR
    0x00, 0x01      //class: unicast, IN
};

static const uint8_t sample_dns_query2[] = {
    0x56, 0x02,     //query id
    0x00, 0x00,     //flags
    0x00, 0x01,     //question count
    0x00, 0x00,     //answer count
    0x00, 0x00,     //authority count
    0x00, 0x00,     //additional count
    // 4.3.2.1.in-addr.arpa
    0x01, '4', 0x01, '3', 0x01, '2', 0x01, '1',
    0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r',
    0x04, 'a', 'r', 'p', 'a',
    0x00,
    0x00, 0x0C,     //type PTR
    0x00, 0x01      //class: unicast, IN
};

MunitResult test_probe_generate_query(MUNIT_ARGS)
{

    char buffer[512];
    int retsize;
    struct sockaddr_in saddr;
    saddr.sin_addr.s_addr = (4 << 24 | 3 << 16 | 2 << 8 | 1);

    retsize = proto_generate_query_mdns(buffer, sizeof(buffer), "_services._dns-sd._udp.local", (struct sockaddr *)&saddr);
    munit_assert_int(retsize, ==, sizeof(sample_mdns_services_query));
    munit_assert_memory_equal(sizeof(sample_mdns_services_query), buffer, sample_mdns_services_query);

    retsize = proto_generate_query_dns(buffer, sizeof(buffer), "com", (struct sockaddr *)&saddr);
    munit_assert_int(retsize, ==, sizeof(sample_dns_query1));
    munit_assert_memory_equal(sizeof(sample_dns_query1), buffer, sample_dns_query1);

    retsize = proto_generate_query_dns_targetptr(buffer, sizeof(buffer), "", (struct sockaddr *)&saddr);
    munit_assert_int(retsize, ==, sizeof(sample_dns_query2));
    munit_assert_memory_equal(sizeof(sample_dns_query2), buffer, sample_dns_query2);

    return MUNIT_OK;
}


MUNIT_TESTS(tests,
            MUNIT_TEST("probe_generate_query", test_probe_generate_query)
           );

MUNIT_SUITE(suite, "/protocol/", tests);
MUNIT_MAIN(suite);
