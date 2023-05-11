#include "munit.h"

MunitResult test_simple_pass1(const MunitParameter params[], void* user_data_or_fixture) {
    int x = 1;
    munit_assert_int(x, ==, 1);
    return MUNIT_OK;
}

MunitResult test_simple_fail1(const MunitParameter params[], void* user_data_or_fixture) {
    int x = 1;
    munit_assert_int(x, ==, 3);
    return MUNIT_OK;
}

MunitTest tests[] = {
    {   "/basic1", /* name */
        test_simple_pass1, /* test */
        NULL, /* setup */ NULL, /* tear_down */
        MUNIT_TEST_OPTION_NONE, /* options */
        NULL /* parameters */
        
    },
    {   "/basic2", test_simple_fail1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    /* Mark the end of the array with an entry where the test function is NULL */
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite suite = {
  "/basic-tests", /* name */
  tests, /* tests */
  NULL, /* suites */
  1, /* iterations */
  MUNIT_SUITE_OPTION_NONE /* options */
};

int main(int argc, char* const argv[]) {
    /* Use µnit here. */
    munit_suite_main(&suite, NULL, argc, argv);

}
