#include <malloc.h>

#include "munit.h"
#include "nm-common.h"
#include "nm-host.h"


MunitResult test_blank(MUNIT_ARGS){
    nm_host *entry = nm_host_init(HOST_TYPE_LOCALHOST);
    munit_assert_true(entry->type == HOST_TYPE_LOCALHOST);
    munit_assert_uint(entry->ip_addr, ==, 0);

    munit_assert_null(entry->list_hw_addr);
    munit_assert_null(entry->list_ip);
    munit_assert_null(entry->list_ip6);
    munit_assert_null(entry->ip);
    munit_assert_null(entry->ip6);
    munit_assert_null(entry->hostname);
    munit_assert_null(entry->netmask);
    munit_assert_null(entry->hw_addr);

    return MUNIT_OK;
}

MunitResult test_basic(MUNIT_ARGS){
    nm_host *entry = nm_host_init(HOST_TYPE_LOCALHOST);

    char *ip = strdup("192.168.0.0");
    nm_host_set_attributes(entry, ip, NULL, NULL, NULL, NULL);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_null(entry->ip6);
    munit_assert_null(entry->netmask);
    munit_assert_null(entry->hw_addr);
    munit_assert_null(entry->hostname);

    char *ip6 = strdup("feda:ffff:ffff:feda::1");
    nm_host_set_attributes(entry, NULL, ip6, NULL, NULL, NULL);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_string_equal(entry->ip6, ip6);
    munit_assert_null(entry->netmask);
    munit_assert_null(entry->hw_addr);
    munit_assert_null(entry->hostname);

    char *host = strdup("hostname value");
    nm_host_set_attributes(entry, NULL, NULL, NULL, NULL, host);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_string_equal(entry->ip6, ip6);
    munit_assert_null(entry->netmask);
    munit_assert_null(entry->hw_addr);
    munit_assert_string_equal(entry->hostname, host);
    char *host2 = "different.hostname";
    nm_host_set_attributes(entry, NULL, NULL, NULL, NULL, host2);
    munit_assert_string_equal(entry->hostname, host);

    char *netmask = strdup("255.255.254.0");
    nm_host_set_attributes(entry, NULL, NULL, netmask, NULL, NULL);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_string_equal(entry->ip6, ip6);
    munit_assert_string_equal(entry->netmask, netmask);
    munit_assert_null(entry->hw_addr);
    munit_assert_string_equal(entry->hostname, host);

    char *hwaddr = strdup("ab:bc:cd:de:ef:ff");
    nm_host_set_attributes(entry, NULL, NULL, NULL, hwaddr, NULL);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_string_equal(entry->ip6, ip6);
    munit_assert_string_equal(entry->netmask, netmask);
    munit_assert_string_equal(entry->hw_addr, hwaddr);
    munit_assert_string_equal(entry->hostname, host);
    char *hwaddr2 = strdup("00:12:34:de:ef:ff");
    nm_host_set_attributes(entry, NULL, NULL, NULL, hwaddr2, NULL);
    munit_assert_string_equal(entry->hw_addr, hwaddr);


    nm_host_destroy(entry);
    return MUNIT_OK;
}

MunitResult test_full_host(MUNIT_ARGS){
    nm_host *host = nm_host_init(HOST_TYPE_LOCALHOST);

    char *ip = strdup("192.168.0.0");
    char *ip6 = strdup("feda:ffff:ffff:feda::1");
    char *hostname = strdup("hostname.name");
    char *netmask = strdup("255.255.0.0");
    char *hwaddr = strdup("ab:bc:cd:de:ef:ff");
    char *service1 = strdup("Service One");
    nmlist *services1 = nm_list_add(NULL, service1);

    nm_host_set_attributes(host, ip, ip6, netmask, hwaddr, hostname);
    nm_host_add_services(host, services1);
    //check values are updated correctly
    munit_assert_string_equal(host->ip, ip);
    munit_assert_string_equal(host->ip6, ip6);
    munit_assert_string_equal(host->netmask, netmask);
    munit_assert_string_equal(host->hw_addr, hwaddr);
    munit_assert_string_equal(host->hostname, hostname);
    munit_assert_string_equal(host->list_services->data, service1);
    //but not the same pointer, it's a duplicate
    munit_assert_true(host->ip != ip);
    munit_assert_true(host->ip6 != ip6);
    munit_assert_true(host->netmask != netmask);
    munit_assert_true(host->hw_addr != hwaddr);
    munit_assert_true(host->hostname != hostname);

    char *ip_2 = strdup("192.168.0.192");
    char *ip6_2 = strdup("feda:ffff:ffff:feda::f123");
    char *hwaddr_2 = strdup("ab:bc:cd:de:12:12");
    char *service2 = strdup("Service Two");
    nmlist *services2 = nm_list_add(services1, service2);

    nm_host_set_attributes(host, ip_2, ip6_2, NULL, hwaddr_2, hostname);
    nm_host_add_services(host, services2);
    //original fields remain the same
    munit_assert_string_equal(host->ip, ip);
    munit_assert_string_equal(host->ip6, ip6);
    munit_assert_string_equal(host->hw_addr, hwaddr);
    //and _2 values are added in the list
    munit_assert_int(nm_list_len(host->list_ip), ==, 1);
    munit_assert_int(nm_list_len(host->list_ip6), ==, 1);
    munit_assert_int(nm_list_len(host->list_hw_addr), ==, 1);
    munit_assert_string_equal(host->list_ip->data, ip_2);
    munit_assert_string_equal(host->list_ip6->data, ip6_2);
    munit_assert_string_equal(host->list_hw_addr->data, hwaddr_2);

    puts("");
    nm_host_print(host);
    puts("");

    nm_host_destroy(host);
    return MUNIT_OK;
}


/*
void test_other_add(void){
    nm_host *entry = nm_host_init(HOST_TYPE_UNKNOWN);

    char *other_ip = "255.255.255.0";
    munit_assert_null(entry->list_ip);
    nmlist *list_start = nm_host_other_add(entry->list_ip, other_ip);
    entry->list_ip = list_start;
    munit_assert_not_null(entry->list_ip);
    munit_assert_not_null(entry->list_ip->data);
    munit_assert_null(entry->list_ip->next);
    munit_assert_null(entry->list_ip->prev);
    munit_assert_string_equal(entry->list_ip->data, ==, other_ip);
    g_assert_true(entry->list_ip->data != other_ip);

    char *other_ip2 = "255.0.0.0";
    entry->list_ip = nm_host_other_add(entry->list_ip, other_ip2);
    g_assert_true(entry->list_ip == list_start);
    munit_assert_not_null(entry->list_ip);
    munit_assert_string_equal(entry->list_ip->data, ==, other_ip);
    munit_assert_not_null(entry->list_ip->next);
    munit_assert_null(entry->list_ip->prev);
    munit_assert_not_null(entry->list_ip->next->prev);
    munit_assert_null(entry->list_ip->next->next);
    munit_assert_not_null(entry->list_ip->next->data);
    munit_assert_string_equal(entry->list_ip->next->data, ==, other_ip2);
}
*/

/*
void test_other_full(void){
    nm_host *entry = nm_host_init(HOST_TYPE_UNKNOWN);

    char *other_ip = "255.255.255.0";
    munit_assert_null(entry->list_ip);
    entry->list_ip = nm_host_other_add(entry->list_ip, other_ip);
    g_assert_cmpint(nm_host_other_len(entry->list_ip), ==, 1);
    entry->list_ip = nm_host_other_add(entry->list_ip, other_ip);
    g_assert_cmpint(nm_host_other_len(entry->list_ip), ==, 2);
    entry->list_ip = nm_host_other_add_unique(entry->list_ip, other_ip);
    g_assert_cmpint(nm_host_other_len(entry->list_ip), ==, 2);
    char *other_ip2 = "255.255.255.0.255";
    entry->list_ip = nm_host_other_add(entry->list_ip, other_ip2);
    g_assert_cmpint(nm_host_other_len(entry->list_ip), ==, 3);
    entry->list_ip = nm_host_other_add_unique(entry->list_ip, other_ip2);
    g_assert_cmpint(nm_host_other_len(entry->list_ip), ==, 3);

    entry->list_ip = nm_host_other_add_unique(entry->list_ip, "");
    g_assert_cmpint(nm_host_other_len(entry->list_ip), ==, 3);

    entry->list_ip = nm_host_other_add_unique(entry->list_ip, "0");
    g_assert_cmpint(nm_host_other_len(entry->list_ip), ==, 4);

    g_assert_true(nm_host_other_find(entry->list_ip, other_ip));
    g_assert_true(nm_host_other_find(entry->list_ip, other_ip2));
    g_assert_true(nm_host_other_find(entry->list_ip, "0"));

    munit_assert_string_equal(nm_host_other_index(entry->list_ip, 0), ==, other_ip);
    munit_assert_string_equal(nm_host_other_index(entry->list_ip, 1), ==, other_ip);
    munit_assert_string_equal(nm_host_other_index(entry->list_ip, 2), ==, other_ip2);
    munit_assert_string_equal(nm_host_other_index(entry->list_ip, 3), ==, "0");
    munit_assert_null(nm_host_other_index(entry->list_ip, 4));
}
*/

/*
void test_other_field_leaks(void) {

    struct mallinfo mi;
    mi = mallinfo();
    int mem_inuse = mi.uordblks;

    g_info("\t\t> Pre Allocation ------------[%6i]", mem_inuse);

    nm_host *entries[10];
    int num_entries = sizeof(entries) / sizeof(entries[0]);
    g_info("\t\t  Allocating %lu in array %i total struct sizes %lu",
           sizeof(nm_host), num_entries, num_entries * sizeof(nm_host));
    for(int i=0; i<num_entries; i++){
        entries[i] = nm_host_init(HOST_TYPE_UNKNOWN);
        entries[i]->list_ip = nm_host_other_add(entries[i]->list_ip, "255.255.255.255");
        entries[i]->list_ip = nm_host_other_add(entries[i]->list_ip, "10.255.255.255");
        entries[i]->list_ip6 = nm_host_other_add(entries[i]->list_ip6, "fido:abcd:bff7:0123:ffff:b9a1:ac35:8f3b");
        entries[i]->list_ip6 = nm_host_other_add(entries[i]->list_ip6, "dido:abcd:bff7:0123:ffff:b9a1:ac35:8f3b");
        entries[i]->list_hw_addr = nm_host_other_add(entries[i]->list_hw_addr, "AB:CD:EF:12:12:12");
        entries[i]->list_hw_addr = nm_host_other_add(entries[i]->list_hw_addr, "BB:CD:EF:12:12:12");
    }


    mi = mallinfo();
    g_info("\t\t> Post Allocation -----------[%6i] difference [%6i]", mi.uordblks, mi.uordblks - mem_inuse);

    for(int i=0; i<num_entries; i++) {
        nm_host_destroy(entries[i]);
    }

    mi = mallinfo();
    g_info("\t\t> Post Freeing --------------[%6i] difference [%6i]", mi.uordblks, mi.uordblks - mem_inuse);

}
*/

/*
int main (int argc, char **argv){

    g_test_init(&argc, &argv, NULL);

    if(!g_test_verbose())
        g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO, nm_log_dummy, NULL);

    g_test_add_func("/host/blank", test_blank);
    g_test_add_func("/host/basic", test_basic);
    g_test_add_func("/host/full", test_full_host);
    g_test_add_func("/host/host_array", test_host_array);
    g_test_add_func("/host/other_add", test_other_add);
    g_test_add_func("/host/other_full", test_other_full);
    g_test_add_func("/host/other_field_leaks", test_other_field_leaks);


    return g_test_run();
}
*/

MUNIT_TESTS(tests, 
    MUNIT_TEST("blank", test_blank)
    MUNIT_TEST("basic", test_basic)
    MUNIT_TEST("full", test_full_host)
//    MUNIT_TEST("host_array", test_host_array)
//    MUNIT_TEST("other_add", test_other_add)
//    MUNIT_TEST("other_full", test_other_full)
//    MUNIT_TEST("other_field_leaks", test_other_field_leaks)
);

MUNIT_SUITE(suite, "/host/", tests);
MUNIT_MAIN(suite);
