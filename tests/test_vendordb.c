#include "munit.h"

#include "nm-common.h"
#include "nm-vendordb.h"


MunitResult test_db_full(MUNIT_ARGS){
    munit_assert_null(vendor_db_query("123456"));
    munit_assert_false(vendor_db_init());
    munit_assert_null(vendor_db_query(NULL));
    munit_assert_null(vendor_db_query(""));
    munit_assert_null(vendor_db_query("1"));
    munit_assert_null(vendor_db_query("12345"));

    munit_assert_string_equal(vendor_db_query("2405F5"), "Integrated Device Technology (Malaysia) Sdn. Bhd.");
    munit_assert_not_null(vendor_db_query("70B3D5"));
    munit_assert_string_equal(vendor_db_query("C4084A"), "Nokia");
    munit_assert_string_equal(vendor_db_query("006B9E"), "Vizio, Inc");
    munit_assert_string_equal(vendor_db_query("14144B"), "Ruijie Networks Co.,LTD");

    //init-destroy cycle
    munit_assert_false(vendor_db_init());
    munit_assert_string_equal(vendor_db_query("C4084A"), "Nokia");

    munit_assert_false(vendor_db_destroy());
    munit_assert_null(vendor_db_query("C4084A"));

    munit_assert_false(vendor_db_init());
    munit_assert_string_equal(vendor_db_query("C4084A"), "Nokia");

    munit_assert_false(vendor_db_destroy());
    
    return MUNIT_OK;
}


MunitResult test_db_timing(MUNIT_ARGS){

    munit_assert_false(vendor_db_init());

    unsigned long start = nm_time_ms();
    for (int i = 0; i < 1000; ++i) {
        munit_assert_not_null(vendor_db_query("70B3D5"));
        munit_assert_string_equal(vendor_db_query("2405F5"), "Integrated Device Technology (Malaysia) Sdn. Bhd.");
        munit_assert_string_equal(vendor_db_query("C4084A"), "Nokia");
        munit_assert_string_equal(vendor_db_query("006B9E"), "Vizio, Inc");
        munit_assert_string_equal(vendor_db_query("14144B"), "Ruijie Networks Co.,LTD");
    }
    unsigned long diff = nm_time_ms_diff(start);
    munit_logf(MUNIT_LOG_INFO, "Query Time %lu (ms)", diff);
    munit_assert_double(diff, <, 10);

    munit_assert_false(vendor_db_destroy());
    return MUNIT_OK;
}


MUNIT_TESTS(tests, 
    MUNIT_TEST("db_full", test_db_full)
    MUNIT_TEST("db_timing", test_db_timing)
);

MUNIT_SUITE(suite, "/vendordb/", tests);
MUNIT_MAIN(suite);
