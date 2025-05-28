#ifndef NETWORK_MATES_NM_COMMON_H
#define NETWORK_MATES_NM_COMMON_H

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib-2.0/glib.h>
#include "log.h"
#include "nm-vendordb.h"

#define NM_APP_NAME "netmates"
#define NM_APP_VERSION  "0.2.3"

#define NM_SMALL_BUFFSIZE 64
#define NM_GEN_BUFFSIZE 512
#define NM_MID_BUFFSIZE 256
#define NM_LARGE_BUFFSIZE BUFSIZ
#define NM_HOST_STRLEN 128
#define NM_HWADDR_STRLEN 18
#define NL_MIN_NETMASK_VALUE 0x00FFFFFF


typedef GList nmlist;

static GMutex nm_log_lock;

extern char *nm_clr_title;
extern char *nm_clr_strong;
extern char *nm_clr_light;
extern char *nm_clr_off;

/* get current time in milliseconds */
unsigned long   nm_time_ms();
unsigned long   nm_time_ms_diff(unsigned long start);

void        nm_string_toupper(char *str);
char       *nm_string_extract_token(char *line, char delimiter, int index);
int         nm_string_count_lines(const char *line, size_t len);
void        nm_string_copy_line(const char *line, size_t line_len, int index,
                                char *copy_to, size_t copy_max);

nmlist     *nm_list_add(nmlist *to, void *newdata);
void        nm_list_free(nmlist *list, bool free_data);
uint        nm_list_len(nmlist *list);
nmlist     *nm_list_find_string(nmlist *list, const char *data);
#define     nm_list_foreach(n, l) for(nmlist* n = l; n; n = n->next)

void        nm_format_hw_address(char *buff, size_t buff_len, struct sockaddr_ll *sa_ll);
void        nm_format_hw_address_direct(char *buff, char *lladdr);
bool        nm_validate_hw_address(char *address, int real_address);
void        nm_update_hw_vendor(char *hw_vendor, size_t size, const char *hw_addr);

void        nm_copy_netbytes_to_shorts(uint16_t *buff, const uint8_t *src, size_t len);
void        nm_log_trace_buffer(const char *sign, const void *buffer, int len);
void        nm_log_trace_bytes(const char *sign, const uint8_t *data, int len);
void        nm_log_set_lock(bool state, void *data);
void        nm_enable_colour();
char       *nm_path_string(const char *inpath, char *fullpath);

static inline unsigned long nm_string_len(const char *str)
{
    if (str) return strlen(str);
    return 0;
}

#endif //NETWORK_MATES_NM_COMMON_H
