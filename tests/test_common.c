#include "munit.h"

#include "nm-common.h"


MunitResult test_time_ms(MUNIT_ARGS) {

    munit_assert_uint(nm_time_ms(), >, 0);
    munit_assert_uint(nm_time_ms_diff(0), >, 0);

    unsigned long start, end;
    start = nm_time_ms();
    usleep(2000);
    end = nm_time_ms();
    munit_logf(MUNIT_LOG_INFO, "\ttest_util_time: start: %lu ms, end: %lu ms, diff: %lu ms", start, end, end-start);
    munit_assert_uint(end-start, >, 1);
    munit_assert_uint(end-start, <=, 3);

    start = nm_time_ms();
    usleep(20000);
    end = nm_time_ms();
    munit_assert_uint(end-start, >, 19);
    munit_assert_uint(end-start, <=, 21);

    start = nm_time_ms();
    usleep(25000);
    end = nm_time_ms_diff(start);
    munit_assert_uint(end, >, 24);
    munit_assert_uint(end, <=, 26);

    return MUNIT_OK;
}

MunitResult test_string_extract_token(MUNIT_ARGS) {

    char string1[64];
    strcpy(string1, "String With Spaces");
    munit_assert_string_equal(nm_string_extract_token(string1, ' ', 2), "Spaces");
    munit_assert_string_equal(nm_string_extract_token(string1, ' ', 1), "With");
    munit_assert_string_equal(nm_string_extract_token(string1, ' ', 0), "String");

    char string2[64];
    strcpy(string2, " String    With    Spaces  ");
    munit_assert_string_equal(nm_string_extract_token(string2, ' ', 2), "Spaces");
    munit_assert_string_equal(nm_string_extract_token(string2, ' ', 1), "With");
    munit_assert_string_equal(nm_string_extract_token(string2, ' ', 0), "String");

    char string3[64];
    strcpy(string3, "1 2 3");
    munit_assert_string_equal(nm_string_extract_token(string3, ' ', 2), "3");
    munit_assert_string_equal(nm_string_extract_token(string3, ' ', 1), "2");
    munit_assert_string_equal(nm_string_extract_token(string3, ' ', 0), "1");

    char string4[64];
    strcpy(string4, "1 2 3\n");
    munit_assert_string_equal(nm_string_extract_token(string4, ' ', 2), "3");
    munit_assert_string_equal(nm_string_extract_token(string4, ' ', 1), "2");
    munit_assert_string_equal(nm_string_extract_token(string4, ' ', 0), "1");

    return MUNIT_OK;
}


MunitResult test_string_count_lines(MUNIT_ARGS) {

    char *lines1 = "";
    char *lines2 = "\n";
    char *lines3 = "Abcd\n";
    char *lines4 = "Abcd\nEfghi";
    char *lines5 = "Abcd\nEfghi\n";
    char *lines6 = "Abcd\r\nEfghi\r\n";
    char *lines7 = "Abcd\r\nEfghi\r\n\r\n";


    munit_assert_int(nm_string_count_lines(lines1, 10), ==, 0);
    munit_assert_int(nm_string_count_lines(lines2, 10), ==, 1);
    munit_assert_int(nm_string_count_lines(lines3, 10), ==, 1);
    munit_assert_int(nm_string_count_lines(lines4, 10), ==, 1);
    munit_assert_int(nm_string_count_lines(lines5, 10), ==, 1);
    munit_assert_int(nm_string_count_lines(lines5, 11), ==, 2);
    munit_assert_int(nm_string_count_lines(lines6, strlen(lines6)), ==, 2);
    munit_assert_int(nm_string_count_lines(lines7, strlen(lines7)), ==, 3);

    return MUNIT_OK;
}


MunitResult test_string_copy_line(MUNIT_ARGS) {

    char *lines1 = "";
    char *lines2 = "\n";
    char *lines3 = "Abcd\n";
    char *lines4 = "Abcd\nEfghi";
    char *lines5 = "Abcd\nEfghi\n";
    char *lines6 = "Abcd\r\nEfghi\r\n";
    char test_buff[256];


    nm_string_copy_line(lines1, strlen(lines1), 0, test_buff, sizeof(test_buff));
    munit_assert_string_equal(test_buff, "");
    nm_string_copy_line(lines2, strlen(lines2), 0, test_buff, sizeof(test_buff));
    munit_assert_string_equal(test_buff, "");
    nm_string_copy_line(lines3, strlen(lines3), 0, test_buff, sizeof(test_buff));
    munit_assert_string_equal(test_buff, "Abcd");

    nm_string_copy_line(lines4, strlen(lines4), 0, test_buff, sizeof(test_buff));
    munit_assert_string_equal(test_buff, "Abcd");
    nm_string_copy_line(lines4, strlen(lines4), 1, test_buff, sizeof(test_buff));
    munit_assert_string_equal(test_buff, "Efghi");
    nm_string_copy_line(lines5, strlen(lines5), 1, test_buff, sizeof(test_buff));
    munit_assert_string_equal(test_buff, "Efghi");

    nm_string_copy_line(lines6, strlen(lines6), 1, test_buff, sizeof(test_buff));
    munit_assert_string_equal(test_buff, "Efghi");

    return MUNIT_OK;
}


MunitResult test_list_add(MUNIT_ARGS) {

    
    char *str1 = "Test String";
    nmlist *list1 = nm_list_add(NULL, str1);
    munit_assert_not_null(list1);
    munit_assert_not_null(list1->data);
    munit_assert_string_equal(list1->data, str1);
    munit_assert_null(list1->next);
    munit_assert_null(list1->prev);
    
    char *str2 = "Different String";
    nmlist *list2 = nm_list_add(list1, str2);
    munit_assert_not_null(list2);
    munit_assert_ptr(list1, ==, list2);
    munit_assert_not_null(list2->next->data);
    munit_assert_string_equal(list2->next->data, str2);
    

    return MUNIT_OK;
}

MunitResult test_list_free(MUNIT_ARGS) {

    char *str1 = strdup("new string 1");
    nmlist *list1 = nm_list_add(NULL, str1);
    char *str2 = strdup("new string 2");
    nmlist *list2 = nm_list_add(list1, str2);
    char *str3 = strdup("new string 3");
    nmlist *list3 = nm_list_add(list2, str3);

    munit_assert_not_null(list1);
    munit_assert_not_null(list2);
    munit_assert_not_null(list3);

    nm_list_free(list3, true);
    
    munit_assert_not_null(list1);
    munit_assert_not_null(list2);
    munit_assert_null(list3->prev);
    munit_assert_null(list2->prev);
    munit_assert_null(list2->next);
    munit_assert_null(list3->data);
    
    nm_list_free(list1, true);
//     munit_assert_null(list1->data);
//     munit_assert_null(list2->data);
//     munit_assert_null(list3->data);

//     char *str4 = "static text";
//     nmlist *list4 = nm_list_add(NULL, str4);
//     nm_list_free(list4, false);
//     munit_assert_true(list4->data == str4);
//     munit_assert_string_equal(str4, "static text");
    

    return MUNIT_OK;
}

MunitResult test_list_find(MUNIT_ARGS) {

    char *str1 = "new string 1";
    char *str2 = "new string 2";
    char *str3 = "new";
    
    nmlist *list1 = nm_list_add(NULL, str1);
    nmlist *list2 = nm_list_add(list1, str2);
    nmlist *list3 = nm_list_add(list1, str3);
    
    nmlist *f1 = nm_list_find_string(list1, str1);
    munit_assert_ptr_equal(f1, list1);
    nmlist *f2 = nm_list_find_string(list1, str2);
    munit_assert_ptr_equal(f2, list1->next);
    nmlist *f3 = nm_list_find_string(list1, str3);
    munit_assert_ptr_equal(f3, list1->next->next);
    f3 = nm_list_find_string(list1, "new");
    munit_assert_ptr_equal(f3, list1->next->next);

    munit_assert_not_null(nm_list_find_string(list3, str1));
    munit_assert_not_null(nm_list_find_string(list3, str2));
    


    nm_list_free(list1, false);
    


    return MUNIT_OK;
}


MunitResult test_list_all(MUNIT_ARGS) {

    nmlist *list1 = NULL;
    munit_assert_null(list1);
    munit_assert_int(nm_list_len(list1), ==, 0);
    
    char *str2 = strdup("Test String");
    nmlist *list2 = nm_list_add(NULL, str2);
    munit_assert_int(nm_list_len(list2), ==, 1);

    nm_list_add(list2, strdup("Other String 2"));
    nm_list_add(list2, strdup("Other String 3"));
    nm_list_add(list2, strdup("Other String 4"));
    munit_assert_int(nm_list_len(list2), ==, 4);
    munit_assert_string_equal(list2->data, str2);

    return MUNIT_OK;
}




/*

MunitTest tests[] = {
    {"/time_ms", test_time_ms, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/string_extract_token", test_string_extract_token, NULL, NULL, 0, NULL},
    {"/string_count_lines", test_string_count_lines, NULL, NULL, 0, NULL},
    {"/string_copy_line", test_string_copy_line, NULL, NULL, 0, NULL},
    { 0 }
};

static const MunitSuite suite = {"/common", tests, NULL, 1, 0 };

int main(int argc, char* const argv[]) {
    munit_suite_main(&suite, NULL, argc, argv);
    return 0;
}
*/


MUNIT_TESTS(tests, 
    MUNIT_TEST("time_ms", test_time_ms)
    MUNIT_TEST("string_extract_token", test_string_extract_token)
    MUNIT_TEST("string_count_lines", test_string_count_lines)
    MUNIT_TEST("string_copy_line", test_string_copy_line)
    MUNIT_TEST("list_add", test_list_add)
    MUNIT_TEST("list_free", test_list_free)
    MUNIT_TEST("list_find", test_list_find)
    MUNIT_TEST("list_all", test_list_all)
);

MUNIT_SUITE(suite, "/common/", tests);
MUNIT_MAIN(suite);
