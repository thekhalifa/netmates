#ifndef NETWORK_MATES_NM_COMMON_H
#define NETWORK_MATES_NM_COMMON_H

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib-2.0/glib.h>
#include "log.h"

#define NM_APP_CLI_NAME "nmlite"

#define NL_GEN_BUFF 512
#define NL_LARGE_BUFF BUFSIZ
#define NM_MAX_BUFF_HOST 128
#define NM_MAX_BUFF_HWADDR 128
#define NM_MAX_BUFF_IP INET_ADDRSTRLEN
#define NM_MAX_BUFF_IP6 INET6_ADDRSTRLEN
#define NL_MIN_NETMASK_VALUE 0x00FFFFFF


/* Basic data structures */
/*
typedef struct _nmlist nmlist;

struct _nmlist{
    nmlist *next;
    nmlist *prev;
    void *data;
};

typedef struct {
    int size;
    void *data;
} nmarray;
*/

//typedef GArray nmarray;
typedef GList nmlist;
typedef GHashTable nmtable;



/* get current time in milliseconds */
unsigned long   nm_time_ms();
unsigned long   nm_time_ms_diff(unsigned long start);

void    nm_string_toupper(char *str);
char   *nm_string_extract_token(char *line, char delimiter, int index);
int     nm_string_count_lines(const char *line, size_t len);
void    nm_string_copy_line(const char *line, size_t line_len, int index,
                                    char *copy_to, size_t copy_max);
static inline unsigned long nm_string_len(const char *str){
    if(str) return strlen(str);
    return 0;
}

nmlist     *nm_list_add(nmlist* to, void *newdata);
void        nm_list_free(nmlist *list, bool free_data);
uint        nm_list_len(nmlist *list);
nmlist     *nm_list_find_string(nmlist *list, const char *data);
#define     nm_list_foreach(n, l) for(nmlist* n = l; n; n = n->next)

nmtable    *nm_table_new();
uint        nm_table_len(nmtable *table);
void       *nm_table_get_num(nmtable *table, uint32_t num);
void        nm_table_set_num(nmtable *table, uint32_t num, void *data);
void        nm_table_free(nmtable *table);


#endif //NETWORK_MATES_NM_COMMON_H
