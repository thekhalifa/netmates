/**
 * @file test_scan.c
 * nm-scan tests
 *
 * SPDX-License-Identifier: GPL-3.0
 */
#include "munit.h"

#include "nm-common.h"
#include "nm-scan.h"

void queue_scan_address(uint32_t addr, GAsyncQueue *results_queue, GThreadPool *thread_pool, GError **error)
{
    uint32_t unused_work, returned_count, max_test_time = 60;
    g_thread_pool_push(thread_pool, (gpointer)(intptr_t) ntohl(addr), error);

    int i = 0;
    for (; i <= max_test_time; i++) {
        sleep(1);
        unused_work = g_thread_pool_unprocessed(thread_pool);
        returned_count = g_async_queue_length(results_queue);
        if (unused_work > 0 || returned_count < 1)
            continue;
        else if (returned_count == 1)
            break;
    }
    g_assert_cmpuint(i, <, max_test_time);
}

void check_scan_result(GAsyncQueue *results_queue, uint32_t addr, int response)
{
    probe_result *result;
    result = g_async_queue_pop(results_queue);
    g_assert_nonnull(result);
    g_assert_cmpuint(result->target.inaddr.s_addr, ==, ntohl(addr));
    g_assert_cmpint(result->response, !=, PROBE_HSTATE_UNKNOWN);
    if (response != -1)
        g_assert_cmpuint(result->response, ==, response);
    free(result);
}


void check_subnet_range(char *ip_str, char *netmask_str, const char *start_str,
                        const char *stop_str, int length, uint32_t base_addr)
{
    uint32_t addr;
    scan_range range;

    //struct in_addr startinaddr, endinaddr;
    char startbuff[INET_ADDRSTRLEN];
    char endbuff[INET_ADDRSTRLEN];

    munit_assert_true(scan_util_calc_subnet_range(ip_str, netmask_str, &range));
    inet_ntop(AF_INET, &range.start_addr, startbuff, sizeof(startbuff));
    inet_ntop(AF_INET, &range.stop_addr, endbuff, sizeof(endbuff));
    munit_assert_string_equal(startbuff, start_str);
    munit_assert_string_equal(endbuff, stop_str);
    //g_assert_cmpstr(start_str, ==, range.start_ipstr);
    //g_assert_cmpstr(stop_str, ==, range.stop_ipstr);
    munit_assert_int(length, ==, range.length);

    addr = ntohl(base_addr + 1);
    munit_assert_uint(addr, ==, range.start_addr.s_addr);
    addr = ntohl(base_addr + length);
    munit_assert_uint(addr, ==, range.stop_addr.s_addr);
    //scan_util_destroy_subnet_range(&range);
}


MunitResult test_subnet_range(MUNIT_ARGS)
{

    check_subnet_range("192.168.0.1", "255.255.255.0", "192.168.0.1", "192.168.0.254", 254, 0xC0A80000);
    check_subnet_range("192.168.254.255", "255.255.255.0", "192.168.254.1", "192.168.254.254", 254, 0xC0A8FE00);
    check_subnet_range("192.168.254.255", "255.255.0.0", "192.168.254.1", "192.168.254.254", 254, 0xC0A8FE00);
    check_subnet_range("192.168.254.255", "0.0.0.0", "192.168.254.1", "192.168.254.254", 254, 0xC0A8FE00);
    check_subnet_range("192.168.254.255", "0", "192.168.254.1", "192.168.254.254", 254, 0xC0A8FE00);
    check_subnet_range("10.10.0.0", "0", "10.10.0.1", "10.10.0.254", 254, 0x0A0A0000);
    check_subnet_range("10.10.0.0", "255.255.255.248", "10.10.0.1", "10.10.0.6", 6, 0x0A0A0000);
    check_subnet_range("10.10.0.153", "255.255.255.248", "10.10.0.153", "10.10.0.158", 6, 0x0A0A0098);

    return MUNIT_OK;
}


MunitResult test_scan_thread(MUNIT_ARGS)
{
    GAsyncQueue *results_queue;
    GThreadPool *thread_pool;
    GError *error = NULL;

    results_queue = g_async_queue_new();
    g_test_queue_destroy((GDestroyNotify)g_async_queue_unref, results_queue);
    thread_pool = g_thread_pool_new(scan_connect_thread, results_queue, 1,
                                    FALSE, &error);
    g_assert_null(error);

    uint32_t addrs[] = {0xC0A80177, 0xC0A80101, 0xC0A800DC};
    int resps[] = {PROBE_HSTATE_LIVE, PROBE_HSTATE_LIVE, PROBE_HSTATE_DEAD};
    int len = sizeof(addrs) / sizeof(addrs[0]);

    for (int i = 0; i < len; i++) {
        g_test_message("  -> Queue scan address for %x ", addrs[i]);
        queue_scan_address(addrs[i], results_queue, thread_pool, &error);
        g_assert_null(error);
        check_scan_result(results_queue, addrs[i], resps[i]);
    }


    g_thread_pool_free(thread_pool, TRUE, TRUE);
    thread_pool = NULL;
    return MUNIT_OK;

}

void check_saddr(struct sockaddr *saddr, int family, const char *ip, uint16_t port)
{

    char ipbuff[128];
    munit_assert_int(saddr->sa_family, ==, family);
    if (saddr->sa_family == AF_INET) {
        struct sockaddr_in *saddr4 = (struct sockaddr_in *)saddr;
        inet_ntop(family, &saddr4->sin_addr, ipbuff, sizeof(ipbuff));
        munit_assert_uint(saddr4->sin_port, ==, htons(port));
        munit_assert_uint(saddr4->sin_addr.s_addr, ==, inet_addr(ip));
        munit_assert_string_equal(ipbuff, ip);
    } else if (saddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)saddr;
        struct in6_addr in6;
        inet_ntop(family, &saddr6->sin6_addr, ipbuff, sizeof(ipbuff));
        munit_assert_uint(saddr6->sin6_port, ==, htons(port));
        inet_pton(AF_INET6, ip, &in6);
        munit_assert_string_equal(ipbuff, ip);
        munit_assert_memory_equal(sizeof(in6), &saddr6->sin6_addr, &in6);
    } else
        munit_assert(false);    //should not be here

}

MunitResult test_socket_set_saddr(MUNIT_ARGS)
{

    struct sockaddr_in saddr4;
    struct in_addr addr4;

    addr4.s_addr = inet_addr("192.168.0.1");
    probe_sock_set_saddr((struct sockaddr *)&saddr4, PROBE_FAMILY_INET4, &addr4, 80);
    check_saddr((struct sockaddr *)&saddr4, AF_INET, "192.168.0.1", 80);

    addr4.s_addr = inet_addr("192.168.1.152");
    probe_sock_set_saddr((struct sockaddr *)&saddr4, PROBE_FAMILY_INET4, &addr4, 65350);
    check_saddr((struct sockaddr *)&saddr4, AF_INET, "192.168.1.152", 65350);

    struct sockaddr_in saddr6;
    struct in6_addr addr6;

    inet_pton(AF_INET6, "0123:4567:89ab:cdef:0123:4567:89ab:cdef", &addr6);
    probe_sock_set_saddr((struct sockaddr *)&saddr6, PROBE_FAMILY_INET6, (struct in_addr *)&addr6, 80);
    check_saddr((struct sockaddr *)&saddr6, AF_INET6, "123:4567:89ab:cdef:123:4567:89ab:cdef", 80);

    inet_pton(AF_INET6, "fed0::1", &addr6);
    probe_sock_set_saddr((struct sockaddr *)&saddr6, PROBE_FAMILY_INET6, (struct in_addr *)&addr6, 65432);
    check_saddr((struct sockaddr *)&saddr6, AF_INET6, "fed0::1", 65432);

    return MUNIT_OK;
}



MunitResult test_socket_new_addr(MUNIT_ARGS)
{

    struct sockaddr_in saddr4;

    probe_sock_addr_from_ip((struct sockaddr *)&saddr4, PROBE_FAMILY_INET4, "192.168.0.1", 80);
    check_saddr((struct sockaddr *)&saddr4, AF_INET, "192.168.0.1", 80);

    probe_sock_addr_from_ip((struct sockaddr *)&saddr4, PROBE_FAMILY_INET4, "10.255.0.1", 12345);
    check_saddr((struct sockaddr *)&saddr4, AF_INET, "10.255.0.1", 12345);


    struct sockaddr_in6 saddr6;

    probe_sock_addr_from_ip((struct sockaddr *)&saddr6, PROBE_FAMILY_INET6, "beef::1", 80);
    check_saddr((struct sockaddr *)&saddr6, AF_INET6, "beef::1", 80);

    probe_sock_addr_from_ip((struct sockaddr *)&saddr6, PROBE_FAMILY_INET6, "0123:4567:89ab:cdef:0123:4567:89ab:cdef", 12345);
    check_saddr((struct sockaddr *)&saddr6, AF_INET6, "123:4567:89ab:cdef:123:4567:89ab:cdef", 12345);

    return MUNIT_OK;
}


MUNIT_TESTS(tests,
            MUNIT_TEST("subnet_range", test_subnet_range)
            MUNIT_TEST("socket_set_saddr", test_socket_set_saddr)
            MUNIT_TEST("socket_new_addr", test_socket_new_addr)
           );

MUNIT_SUITE(suite, "/scan/", tests);
MUNIT_MAIN(suite);

