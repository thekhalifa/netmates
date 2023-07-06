#include "nm-common.h"


#define COLOUR_TITLE "\e[0m\e[1m\e[32m"
#define COLOUR_STRONG "\e[0m\e[1m\e[34m"
#define COLOUR_LIGHT "\e[0m\e[36m"
#define COLOUR_OFF  "\e[0m"

char *nm_clr_title = "";
char *nm_clr_strong = "";
char *nm_clr_light = "";
char *nm_clr_off = "";

void nm_enable_colour()
{
    nm_clr_title = COLOUR_TITLE;
    nm_clr_strong = COLOUR_STRONG;
    nm_clr_light = COLOUR_LIGHT;
    nm_clr_off = COLOUR_OFF;
}

unsigned long nm_time_ms()
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_nsec / 1000000 + t.tv_sec * 1000;
}

unsigned long nm_time_ms_diff(unsigned long start)
{
    return nm_time_ms() - start;
}


void nm_string_toupper(char *str)
{
    if (str == NULL)
        return;
    size_t len = strlen(str);
    for (int i = 0; i < len; ++i) {
        str[i] = (char)toupper(str[i]);
    }
}

char *nm_string_extract_token(char *line, char delimiter, int index)
{
    char *scan_pointer, *scan_delim, delim_str[4], *scan_eol;
    size_t span = 0;
    //scan the line
    scan_pointer = line;
    scan_eol = strchr(scan_pointer, 0xA);
    if (scan_eol == NULL)
        scan_eol = strchr(scan_pointer, 0);

    delim_str[0] = delimiter;
    delim_str[1] = 0;

    for (int i = 0; i <= index; i++) {
        /* increment pointer if we start with delimiter chars */
        if ((span = strspn(scan_pointer, delim_str)))
            scan_pointer += span;
        /* find the delimiter */
        scan_delim = strchr(scan_pointer + 1, delimiter);
        if (scan_delim != NULL && scan_delim < scan_eol) {
            if (i == index) {
                *scan_delim = '\0';
                return scan_pointer;
            } else {
                span = strspn(scan_delim + 1, delim_str);
                scan_pointer = scan_delim + 1 + span;
            }
        } else if (scan_eol != NULL && i == index) {
            *scan_eol = 0;
            return scan_pointer;
        } else if (i < index) {
            continue;
        }
    }
    return NULL;
}

int nm_string_count_lines(const char *line, size_t len)
{
    int num_lines = 0;
    const char *pointer = line;

    while (*pointer && pointer < (line + len)) {
        if (*pointer == '\n')
            num_lines++;
        pointer = pointer + 1;
    }
    return num_lines;
}


void nm_string_copy_line(const char *line, size_t line_len, int index, char *copy_to, size_t copy_max)
{
    int line_index = 0, found_len;
    const char *pointer = line;
    const char *start_pointer = line, *end_pointer = NULL;

    while (*pointer && pointer < (line + line_len)) {
        if (line_index == index) {
            start_pointer = pointer;
            pointer++;
            break;
        }
        if (*pointer == '\n')
            line_index++;
        pointer++;
    }

    while (*pointer && pointer < (line + line_len)) {
        if (*pointer == '\n')
            break;
        pointer++;
    }
    end_pointer = pointer - 1;
    if (*end_pointer == '\r')
        end_pointer--;

    found_len = (int)(end_pointer - start_pointer);
    if (found_len) {
        strncpy(copy_to, start_pointer, copy_max < found_len ? copy_max : found_len + 1);
        copy_to[found_len + 1] = 0;
    } else {
        *copy_to = 0;
    }

}

nmlist *nm_list_add(nmlist *to, void *newdata)
{
    return g_list_append(to, newdata);
}

void nm_list_free(nmlist *list, bool free_data)
{
    if (list && list->prev)
        list->prev->next = NULL;

    if (free_data) {
        g_list_free_full(list, free);
    } else {
        g_list_free(list);
    }
}


uint nm_list_len(nmlist *list)
{
    return g_list_length(list);
}

nmlist *nm_list_find_string(nmlist *list, const char *data)
{
    nm_list_foreach(node, list) {
        if (node->data && !strcmp(data, node->data))
            return node;
    }

    return NULL;
}

void nm_format_hw_address(char *buff, size_t buff_len, struct sockaddr_ll *sa_ll)
{
    if (sa_ll == NULL)
        return;

    int len = 0;
    for (int i = 0; i < sa_ll->sll_halen && (len + 3) < buff_len; i++)
        len += sprintf(&buff[len], "%02x%s", sa_ll->sll_addr[i], i + 1 < sa_ll->sll_halen ? ":" : "");
}

void nm_format_hw_address_direct(char *buff, char *lladdr)
{
    if (buff == NULL || lladdr == NULL)
        return;

    char *pointer = buff;
    for (int i = 0; i < 6; i++)
        pointer += sprintf(pointer, "%02x%s", (unsigned char)lladdr[i], i < 5 ? ":" : "");
}

bool nm_validate_hw_address(char *address, int real_address)
{
    if (address == NULL || strlen(address) != 17)
        return false;

    //ab:bc:cd:de:ef:ff
    uint32_t segment[6];
    char buffer[64];
    int num_tokens = sscanf(address, "%2x:%2x:%2x:%2x:%2x:%2x%s",
                            &segment[0], &segment[1], &segment[2], &segment[3], &segment[4], &segment[5], buffer);
    if (num_tokens != 6)
        return false;
    for (int i = 0; i < 6; i++) {
        if ((segment[i] & 0xFFFFFF00) != 0)
            return false;
    }
    if (real_address) {
        int count_zeros = 0;
        for (int i = 0; i < 6; i++) {
            if (segment[i] == 0)
                count_zeros++;
        }
        if (count_zeros > 3)
            return false;
    }
    return true;
}

void nm_update_hw_vendor(char *hw_vendor, size_t size, const char *hw_addr)
{
    assert(hw_vendor != NULL);

    hw_vendor[0] = 0;
    if (hw_addr == NULL || strlen(hw_addr) == 0) {
        return;
    }

    if (strlen(hw_addr) < NM_HWADDR_STRLEN - 1)
        return;

    int tokens;
    char addr_buffer[32];
    tokens = sscanf(hw_addr, "%c%c:%c%c:%c%c:%*s", &addr_buffer[0], &addr_buffer[1],
                    &addr_buffer[2], &addr_buffer[3], &addr_buffer[4], &addr_buffer[5]);
    addr_buffer[6] = 0;
    if (tokens != 6 || strlen(addr_buffer) != 6)
        return;

    const char *vendor_org = vendor_db_query(addr_buffer);
    if (vendor_org != NULL)
        snprintf(hw_vendor, size, "[%s]", vendor_org);
}


void nm_copy_netbytes_to_shorts(uint16_t *buff, const uint8_t *src, size_t len)
{
    if (len % 2 == 1)
        return;

    for (int i = 0; i < len / 2; i++) {
        buff[i] = ntohs(src[i * 2 + 1] << 8 | src[i * 2]);
    }
}


void nm_log_trace_buffer(const char *sign, const void *buffer, int len)
{
    if (log_get_level() != LOG_TRACE)
        return;

    char logbuffer[NM_GEN_BUFFSIZE];
    snprintf(logbuffer, (sizeof(logbuffer) < len ? sizeof(logbuffer) : len),
             "%s", (char *)buffer);
    log_trace("%s: buffer with %li bytes", sign, len);
    log_trace("--\n%s", logbuffer);

}

void nm_log_trace_bytes(const char *sign, const uint8_t *data, int len)
{
    if (log_get_level() != LOG_TRACE)
        return;

    char buffer[NM_LARGE_BUFFSIZE];
    char *buffpoint = buffer;
    int width = 16;
    const uint8_t *start = data;
    const uint8_t *point;

    buffpoint += sprintf(buffpoint, "    ");
    for (int i = 0; i < len && (buffpoint - buffer) < NM_LARGE_BUFFSIZE; i++) {
        point = start + i;

        if (isprint(*point) || ispunct(*point))
            buffpoint += sprintf(buffpoint, " '%c', ", (int) * point);
        else
            buffpoint += sprintf(buffpoint, "0x%02X, ", *point);

        if ((i + 1) % width == 0 || i == len)
            buffpoint += sprintf(buffpoint, "        //%04x\n    ", i);
    }
    buffpoint += sprintf(buffpoint, "\n");

    log_trace("%s: buffer with %li bytes", sign, len);
    log_trace("--\n%s", buffer);
}


void nm_log_set_lock(bool state, void *data)
{
    if (state)
        g_mutex_lock(&nm_log_lock);
    else
        g_mutex_unlock(&nm_log_lock);
}

char *nm_path_string(const char *inpath, char *fullpath)
{
    const char *from = inpath;
    char *pointer = fullpath;
    if (strchr(from, '~') == inpath) {
        char *homedir = getenv("HOME");
        pointer = stpcpy(pointer, homedir);
        from = inpath + 1;
    }

    strcpy(pointer, from);
    return fullpath;
}
