#include <malloc.h>

#include "munit.h"
#include "nm-common.h"
#include "nm-host.h"


MunitResult test_blank(MUNIT_ARGS)
{
    nm_host *entry = nm_host_init(HOST_TYPE_LOCALHOST);
    munit_assert_true(entry->type == HOST_TYPE_LOCALHOST);
    //munit_assert_uint(entry->ip_addr, ==, 0);
    munit_assert_null(entry->ip);
    munit_assert_null(entry->ip6);
    munit_assert_null(entry->hw_if.addr);
    munit_assert_null(entry->hw_if.vendor);
    munit_assert_null(entry->list_ip);
    munit_assert_null(entry->list_ip6);
    munit_assert_null(entry->hostname);
    munit_assert_null(entry->netmask);

    return MUNIT_OK;
}

MunitResult test_basic(MUNIT_ARGS)
{
    nm_host *entry = nm_host_init(HOST_TYPE_LOCALHOST);

    char *ip = strdup("192.168.0.0");
    nm_host_set_attributes(entry, ip, NULL, NULL, HW_IFACE_NULL, NULL);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_null(entry->ip6);
    munit_assert_null(entry->netmask);
    munit_assert_null(entry->hw_if.addr);
    munit_assert_null(entry->hw_if.vendor);
    munit_assert_null(entry->hostname);

    char *ip6 = strdup("feda:ffff:ffff:feda::1");
    nm_host_set_attributes(entry, NULL, ip6, NULL, HW_IFACE_NULL, NULL);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_string_equal(entry->ip6, ip6);
    munit_assert_null(entry->netmask);
    munit_assert_null(entry->hw_if.addr);
    munit_assert_null(entry->hw_if.vendor);
    munit_assert_null(entry->hostname);

    char *host = strdup("hostname value");
    nm_host_set_attributes(entry, NULL, NULL, NULL, HW_IFACE_NULL, host);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_string_equal(entry->ip6, ip6);
    munit_assert_null(entry->netmask);
    munit_assert_null(entry->hw_if.addr);
    munit_assert_null(entry->hw_if.vendor);
    munit_assert_string_equal(entry->hostname, host);
    char *host2 = "different.hostname";
    nm_host_set_attributes(entry, NULL, NULL, NULL, HW_IFACE_NULL, host2);
    munit_assert_string_equal(entry->hostname, host);

    char *netmask = strdup("255.255.254.0");
    nm_host_set_attributes(entry, NULL, NULL, netmask, HW_IFACE_NULL, NULL);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_string_equal(entry->ip6, ip6);
    munit_assert_string_equal(entry->netmask, netmask);
    munit_assert_null(entry->hw_if.addr);
    munit_assert_null(entry->hw_if.vendor);
    munit_assert_string_equal(entry->hostname, host);

    char *hwaddr = "ab:bc:cd:de:ef:ff";
    char *hwvendor = "Big Hardware Vendor";
    hw_details hwif = {hwaddr, hwvendor};
    nm_host_set_attributes(entry, NULL, NULL, NULL, hwif, NULL);
    munit_assert_string_equal(entry->ip, ip);
    munit_assert_string_equal(entry->ip6, ip6);
    munit_assert_string_equal(entry->netmask, netmask);
    munit_assert_string_equal(entry->hw_if.addr, hwaddr);
    munit_assert_ptr_not_equal(entry->hw_if.addr, hwaddr);
    munit_assert_string_equal(entry->hw_if.vendor, hwvendor);
    munit_assert_ptr_not_equal(entry->hw_if.vendor, hwvendor);
    munit_assert_string_equal(entry->hostname, host);
    char *hwaddr2 = "00:12:34:de:ef:ff";
    char *hwboth = "ab:bc:cd:de:ef:ff, 00:12:34:de:ef:ff";
    char *hwvendorboth = "Big Hardware Vendor, Big Hardware Vendor";
    hwif.addr = hwaddr2;
    nm_host_set_attributes(entry, NULL, NULL, NULL, hwif, NULL);
    munit_assert_string_equal(entry->hw_if.addr, hwboth);
    munit_assert_ptr_not_equal(entry->hw_if.addr, hwaddr2);
    munit_assert_string_equal(entry->hw_if.vendor, hwvendorboth);


    nm_host_destroy(entry);
    return MUNIT_OK;
}

MunitResult test_full_host(MUNIT_ARGS)
{
    nm_host *host = nm_host_init(HOST_TYPE_LOCALHOST);

    char *ip = strdup("192.168.0.0");
    char *ip6 = strdup("feda:ffff:ffff:feda::1");
    char *hostname = strdup("hostname.name");
    char *netmask = strdup("255.255.0.0");
    char *hwaddr = "ab:bc:cd:de:ef:ff";
    char *hwvendor = "Big Hardware Vendor";
    hw_details hwif = {hwaddr, hwvendor};
    char *service1 = strdup("Service One");
    nmlist *services1 = nm_list_add(NULL, service1);

    nm_host_set_attributes(host, ip, ip6, netmask, hwif, hostname);
    nm_host_add_services(host, services1);
    //check values are updated correctly
    munit_assert_string_equal(host->ip, ip);
    munit_assert_string_equal(host->ip6, ip6);
    munit_assert_string_equal(host->netmask, netmask);
    munit_assert_string_equal(host->hw_if.addr, hwaddr);
    munit_assert_string_equal(host->hw_if.vendor, hwvendor);
    munit_assert_string_equal(host->hostname, hostname);
    munit_assert_string_equal(host->list_services->data, service1);
    //but not the same pointer, it's a duplicate
    munit_assert_true(host->ip != ip);
    munit_assert_true(host->ip6 != ip6);
    munit_assert_true(host->netmask != netmask);
    munit_assert_ptr_not_equal(host->hw_if.addr, hwaddr);
    munit_assert_ptr_not_equal(host->hw_if.vendor, hwvendor);
    munit_assert_true(host->hostname != hostname);

    char *ip_2 = strdup("192.168.0.192");
    char *ip6_2 = strdup("feda:ffff:ffff:feda::f123");
    char *service2 = strdup("Service Two");
    nmlist *services2 = nm_list_add(services1, service2);

    nm_host_set_attributes(host, ip_2, ip6_2, NULL, HW_IFACE_NULL, hostname);
    nm_host_add_services(host, services2);
    //original fields remain the same
    munit_assert_string_equal(host->ip, ip);
    munit_assert_string_equal(host->ip6, ip6);
    munit_assert_string_equal(host->hw_if.addr, hwaddr);
    munit_assert_string_equal(host->hw_if.vendor, hwvendor);
    //and _2 values are added in the list
    munit_assert_int(nm_list_len(host->list_ip), ==, 1);
    munit_assert_int(nm_list_len(host->list_ip6), ==, 1);
    munit_assert_string_equal(host->list_ip->data, ip_2);
    munit_assert_string_equal(host->list_ip6->data, ip6_2);

    puts("");
    nm_host_print_long(host);
    puts("");

    nm_host_destroy(host);
    return MUNIT_OK;
}


MunitResult test_sort_list(MUNIT_ARGS)
{
    nm_host *host;
    nmlist *list1;
    nmlist *result;

    host = nm_host_init(HOST_TYPE_LOCALHOST);
    list1 = nm_list_add(NULL, host);

    result = nm_host_sort_list(list1);
    munit_assert_not_null(result);
    munit_assert_int(((nm_host *)result->data)->type, ==, HOST_TYPE_LOCALHOST);
    munit_assert_null(result->next);

    host = nm_host_init(HOST_TYPE_PRINTER);
    nm_host_set_attributes(host, "200.2.2.2", NULL, NULL, HW_IFACE_NULL, NULL);
    nm_list_add(list1, host);

    host = nm_host_init(HOST_TYPE_PC);
    nm_host_set_attributes(host, "100.1.1.1", NULL, NULL, HW_IFACE_NULL, NULL);
    nm_list_add(list1, host);

    host = nm_host_init(HOST_TYPE_DEVICE);
    nm_host_set_attributes(host, NULL, "fedo:dedo:bedo::1234", NULL, HW_IFACE_NULL, NULL);
    nm_list_add(list1, host);

    host = nm_host_init(HOST_TYPE_DEVICE);
    nm_host_set_attributes(host, "0.0.0.0", NULL, NULL, HW_IFACE_NULL, NULL);
    nm_list_add(list1, host);

    host = nm_host_init(HOST_TYPE_ROUTER);
    nm_host_set_attributes(host, "192.168.0.1", NULL, NULL, HW_IFACE_NULL, NULL);
    nm_list_add(list1, host);

    result = nm_host_sort_list(list1);
    munit_assert_not_null(result);
    host = (nm_host *)result->data;
    munit_assert_int(host->type, ==, HOST_TYPE_LOCALHOST);

    host = (nm_host *)result->next->data;
    munit_assert_int(host->type, ==, HOST_TYPE_ROUTER);
    munit_assert_string_equal(host->ip, "192.168.0.1");

    host = (nm_host *)result->next->next->data;
    munit_assert_int(host->type, ==, HOST_TYPE_DEVICE);
    munit_assert_string_equal(host->ip, "0.0.0.0");

    host = (nm_host *)result->next->next->next->data;
    munit_assert_int(host->type, ==, HOST_TYPE_PC);
    munit_assert_string_equal(host->ip, "100.1.1.1");

    host = (nm_host *)result->next->next->next->next->data;
    munit_assert_int(host->type, ==, HOST_TYPE_PRINTER);
    munit_assert_string_equal(host->ip, "200.2.2.2");

    host = (nm_host *)result->next->next->next->next->next->data;
    munit_assert_int(host->type, ==, HOST_TYPE_DEVICE);
    munit_assert_null(host->ip);
    munit_assert_string_equal(host->ip6, "fedo:dedo:bedo::1234");

    return MUNIT_OK;
}


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


MUNIT_TESTS(tests,
            MUNIT_TEST("blank", test_blank)
            MUNIT_TEST("basic", test_basic)
            MUNIT_TEST("full", test_full_host)
            MUNIT_TEST("sort_list", test_sort_list)
           );

MUNIT_SUITE(suite, "/host/", tests);
MUNIT_MAIN(suite);
