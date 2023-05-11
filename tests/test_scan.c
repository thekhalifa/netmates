#include "nm-common.h"
#include "nm-scan.h"

void queue_scan_address(uint32_t addr, GAsyncQueue *results_queue, GThreadPool *thread_pool, GError **error) {
    uint32_t unused_work, returned_count, max_test_time = 60;
    g_thread_pool_push(thread_pool, (gpointer)(intptr_t) ntohl(addr), error);

    int i=0;
    for(; i<=max_test_time;i++) {
        sleep(1);
        unused_work = g_thread_pool_unprocessed(thread_pool);
        returned_count = g_async_queue_length(results_queue);
        if(unused_work > 0 || returned_count < 1)
            continue;
        else if(returned_count == 1)
            break;
    }
    g_assert_cmpuint(i, <, max_test_time);
}

void check_scan_result(GAsyncQueue *results_queue, uint32_t addr, int response) {
    scan_result *result;
    result = g_async_queue_pop(results_queue);
    g_assert_nonnull(result);
    g_assert_cmpuint(result->target_addr.s_addr, ==, ntohl(addr));
    g_assert_cmpint(result->response, !=, SCAN_HSTATE_UNKNOWN);
    if(response != -1)
        g_assert_cmpuint(result->response, ==, response);
    free(result);
}


void check_subnet_range(char *ip_str, char *netmask_str, const char *start_str, const char *stop_str, int length, uint32_t base_addr){
    uint32_t addr;
    scan_range range;

    g_assert_true(scan_util_calc_subnet_range(ip_str, netmask_str, &range));
    g_assert_cmpstr(start_str, ==, range.start_ipstr);
    g_assert_cmpstr(stop_str, ==, range.stop_ipstr);
    g_assert_cmpint(length, ==, range.length);

    addr = ntohl(base_addr+1);
    g_assert_cmpuint(addr, ==, range.start_addr.s_addr);
    addr = ntohl(base_addr+length);
    g_assert_cmpuint(addr, ==, range.stop_addr.s_addr);
    scan_util_destroy_subnet_range(&range);
}


void test_util_hw_address(){

    // check binary address -> string
    char big_buffer[64];
    unsigned char mac1[] = {0xab, 0xbc, 0xcd, 0xde, 0xef, 0xff};
    struct sockaddr_ll sa_ll;
    sa_ll.sll_halen = 6;
    memcpy(sa_ll.sll_addr, mac1, 6);
    scan_util_format_hw_address(big_buffer, sizeof(big_buffer), &sa_ll);
    g_assert_cmpstr(big_buffer, ==, "ab:bc:cd:de:ef:ff");

    unsigned char mac2[] = {0x0, 0x1, 0x2, 0xde, 0xFF, 0x00};
    sa_ll.sll_halen = 6;
    memcpy(sa_ll.sll_addr, mac2, sa_ll.sll_halen);
    scan_util_format_hw_address(big_buffer, sizeof(big_buffer), &sa_ll);
    g_assert_cmpstr(big_buffer, ==, "00:01:02:de:ff:00");

    char small_buffer[9];
    scan_util_format_hw_address(small_buffer, 6, &sa_ll);
    g_assert_cmpstr(small_buffer, ==, "00:");

    scan_util_format_hw_address(small_buffer, 7, &sa_ll);
    g_assert_cmpstr(small_buffer, ==, "00:01:");

    //check string address validation
    g_assert_true(scan_util_validate_hw_address("ab:bc:cd:de:ef:ff", 0));
    g_assert_true(scan_util_validate_hw_address("ab:bc:cd:de:ef:ff", 1));
    g_assert_true(scan_util_validate_hw_address("00:00:00:00:00:00", 0));
    g_assert_false(scan_util_validate_hw_address("00:00:00:00:00:00", 1));
    g_assert_true(scan_util_validate_hw_address("ab:bc:cd:de:00:00", 1));
    g_assert_true(scan_util_validate_hw_address("ab:00:cd:de:00:ff", 1));
    g_assert_true(scan_util_validate_hw_address("ab:00:cd:00:00:ff", 1));
    g_assert_false(scan_util_validate_hw_address("ab:00:00:00:00:ff", 1));
    g_assert_false(scan_util_validate_hw_address("00", 0));
    g_assert_false(scan_util_validate_hw_address("", 0));
    g_assert_false(scan_util_validate_hw_address("00:00:00:00:00:00 wer", 0));
    g_assert_false(scan_util_validate_hw_address("00:00:00:00:00:00wer", 0));

}


void test_subnet_range(void){

    check_subnet_range("192.168.0.1", "255.255.255.0", "192.168.0.1", "192.168.0.254",
                       254, 0xC0A80000);

    check_subnet_range("192.168.254.255", "255.255.255.0", "192.168.254.1", "192.168.254.254",
                       254, 0xC0A8FE00);
    check_subnet_range("192.168.254.255", "255.255.0.0", "192.168.254.1", "192.168.254.254",
                       254, 0xC0A8FE00);
    check_subnet_range("192.168.254.255", "0.0.0.0", "192.168.254.1", "192.168.254.254",
                       254, 0xC0A8FE00);
    check_subnet_range("192.168.254.255", "0", "192.168.254.1", "192.168.254.254",
                       254, 0xC0A8FE00);

    check_subnet_range("10.10.0.0", "0", "10.10.0.1", "10.10.0.254",
                       254, 0x0A0A0000);
    check_subnet_range("10.10.0.0", "255.255.255.248", "10.10.0.1", "10.10.0.6",
                       6, 0x0A0A0000);
    check_subnet_range("10.10.0.153", "255.255.255.248", "10.10.0.153", "10.10.0.158",
                       6, 0x0A0A0098);


}

void test_scan_thread(void){
    GAsyncQueue *results_queue;
    GThreadPool *thread_pool;
    GError *error = NULL;

    results_queue = g_async_queue_new();
    g_test_queue_destroy((GDestroyNotify)g_async_queue_unref, results_queue);
    thread_pool = g_thread_pool_new(scan_run_dir_connect_thread, results_queue, 1,
                                    FALSE, &error);
    g_assert_null(error);

    uint32_t addrs[] = {0xC0A80177, 0xC0A80101, 0xC0A800DC};
    int resps[] = {SCAN_HSTATE_LIVE, SCAN_HSTATE_LIVE, SCAN_HSTATE_DEAD};
    int len = sizeof(addrs) / sizeof(addrs[0]);

    for(int i=0; i<len; i++){
        g_test_message("  -> Queue scan address for %x ", addrs[i]);
        queue_scan_address(addrs[i], results_queue, thread_pool, &error);
        g_assert_null(error);
        check_scan_result(results_queue, addrs[i], resps[i]);
    }


    g_thread_pool_free(thread_pool, TRUE, TRUE);
    thread_pool = NULL;

}

int main (int argc, char **argv){

    g_test_init(&argc, &argv, NULL);
    if(!g_test_verbose())
        g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO, nm_log_dummy, NULL);

    g_test_add_func("/scan/subnet_range", test_subnet_range);
    g_test_add_func("/scan/util_hw_address", test_util_hw_address);
    g_test_add_func("/scan/scan_thread", test_scan_thread);
    return g_test_run();
}