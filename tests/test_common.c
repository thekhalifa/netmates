#include "munit.h"

#include "nm-common.h"


MunitResult test_time_ms(MUNIT_ARGS)
{
    munit_assert_uint(nm_time_ms(), >, 0);
    munit_assert_uint(nm_time_ms_diff(0), >, 0);

    unsigned long start, end;
    start = nm_time_ms();
    usleep(2000);
    end = nm_time_ms();
    munit_logf(MUNIT_LOG_INFO, "\ttest_util_time: start: %lu ms, end: %lu ms, diff: %lu ms", start, end, end - start);
    munit_assert_uint(end - start, >, 1);
    munit_assert_uint(end - start, <=, 3);

    start = nm_time_ms();
    usleep(20000);
    end = nm_time_ms();
    munit_assert_uint(end - start, >, 19);
    munit_assert_uint(end - start, <=, 21);

    start = nm_time_ms();
    usleep(25000);
    end = nm_time_ms_diff(start);
    munit_assert_uint(end, >, 24);
    munit_assert_uint(end, <=, 26);

    return MUNIT_OK;
}

MunitResult test_string_extract_token(MUNIT_ARGS)
{
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


MunitResult test_string_count_lines(MUNIT_ARGS)
{
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


MunitResult test_string_copy_line(MUNIT_ARGS)
{
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


MunitResult test_list_add(MUNIT_ARGS)
{
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

MunitResult test_list_free(MUNIT_ARGS)
{
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

MunitResult test_list_find(MUNIT_ARGS)
{
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


MunitResult test_list_all(MUNIT_ARGS)
{
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


MunitResult test_util_hw_address(MUNIT_ARGS)
{
    // check binary address -> string
    char big_buffer[64];
    unsigned char mac1[] = {0xab, 0xbc, 0xcd, 0xde, 0xef, 0xff};
    struct sockaddr_ll sa_ll;
    sa_ll.sll_halen = 6;
    memcpy(sa_ll.sll_addr, mac1, 6);
    nm_format_hw_address(big_buffer, sizeof(big_buffer), &sa_ll);
    munit_assert_string_equal(big_buffer, "ab:bc:cd:de:ef:ff");

    unsigned char mac2[] = {0x0, 0x1, 0x2, 0xde, 0xFF, 0x00};
    sa_ll.sll_halen = 6;
    memcpy(sa_ll.sll_addr, mac2, sa_ll.sll_halen);
    nm_format_hw_address(big_buffer, sizeof(big_buffer), &sa_ll);
    munit_assert_string_equal(big_buffer, "00:01:02:de:ff:00");

    char small_buffer[9];
    nm_format_hw_address(small_buffer, 6, &sa_ll);
    munit_assert_string_equal(small_buffer, "00:");

    nm_format_hw_address(small_buffer, 7, &sa_ll);
    munit_assert_string_equal(small_buffer, "00:01:");

    //check string address validation
    munit_assert_true(nm_validate_hw_address("ab:bc:cd:de:ef:ff", 0));
    munit_assert_true(nm_validate_hw_address("ab:bc:cd:de:ef:ff", 1));
    munit_assert_true(nm_validate_hw_address("00:00:00:00:00:00", 0));
    munit_assert_false(nm_validate_hw_address("00:00:00:00:00:00", 1));
    munit_assert_true(nm_validate_hw_address("ab:bc:cd:de:00:00", 1));
    munit_assert_true(nm_validate_hw_address("ab:00:cd:de:00:ff", 1));
    munit_assert_true(nm_validate_hw_address("ab:00:cd:00:00:ff", 1));
    munit_assert_false(nm_validate_hw_address("ab:00:00:00:00:ff", 1));
    munit_assert_false(nm_validate_hw_address("00", 0));
    munit_assert_false(nm_validate_hw_address("", 0));
    munit_assert_false(nm_validate_hw_address("00:00:00:00:00:00 wer", 0));
    munit_assert_false(nm_validate_hw_address("00:00:00:00:00:00wer", 0));

    return MUNIT_OK;
}


MunitResult test_log_trace_bytes(MUNIT_ARGS)
{
    unsigned char mac1[] = {0xab, 0xbc, 0xcd, 0xde, 0xef, 0xff};
    size_t len = 6;

    log_set_level(LOG_WARN);
    nm_log_trace_bytes("test_log_trace_bytes1", mac1, len);

    log_set_level(LOG_TRACE);
    nm_log_trace_bytes("test_log_trace_bytes2", mac1, len);

    munit_assert_true(1);

    uint8_t buffer2[] = {
        0x12,  '4', 0x84, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x09,  '_',  's',  'e',         //000f
        'r',  'v',  'i',  'c',  'e',  's', 0x07,  '_',  'd',  'n',  's',  '-',  's',  'd', 0x04,  '_',         //001f
        'u',  'd',  'p', 0x05,  'l',  'o',  'c',  'a',  'l', 0x00, 0x00, 0x0C, 0x80, 0x01, 0xC0, 0x0C,         //002f
        0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x0C, 0x04,  '_',  's',  'm',  'b', 0x04,         //003f
        '_',  't',  'c',  'p', 0xC0,  '#', 0xC0, 0x0C, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A,         //004f
        0x00, 0x0F, 0x0C,  '_',  'd',  'e',  'v',  'i',  'c',  'e',  '-',  'i',  'n',  'f',  'o', 0xC0,         //005f
        '?',
    };

    nm_log_trace_bytes("test_log_trace_bytes3", buffer2, sizeof(buffer2));

    return MUNIT_OK;
}


MunitResult test_path_string(MUNIT_ARGS)
{
    char pathbuff[512];
    setenv("HOME", "/home/testuser12", 1);

    munit_assert_ptr_equal(nm_path_string("/home/user/dir1", pathbuff), pathbuff);
    munit_assert_string_equal(pathbuff, "/home/user/dir1");

    munit_assert_ptr_equal(nm_path_string("/home/user/dir1/and file name /something - with hyphen", pathbuff), pathbuff);
    munit_assert_string_equal(pathbuff, "/home/user/dir1/and file name /something - with hyphen");

    munit_assert_ptr_equal(nm_path_string("~/dir2", pathbuff), pathbuff);
    munit_assert_string_equal(pathbuff, "/home/testuser12/dir2");

    munit_assert_ptr_equal(nm_path_string("~/dir1/and file name /something - with hyphen", pathbuff), pathbuff);
    munit_assert_string_equal(pathbuff, "/home/testuser12/dir1/and file name /something - with hyphen");

    munit_assert_ptr_equal(nm_path_string("/dir2~notattheend~", pathbuff), pathbuff);
    munit_assert_string_equal(pathbuff, "/dir2~notattheend~");

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
            MUNIT_TEST("util_hw_address", test_util_hw_address)
            MUNIT_TEST("log_trace_bytes", test_log_trace_bytes)
            MUNIT_TEST("path_string", test_path_string)
           );

MUNIT_SUITE(suite, "/common/", tests);
MUNIT_MAIN(suite);
