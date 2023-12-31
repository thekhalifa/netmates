#ifndef NETWORK_MATES_NM_VENDORDB_H
#define NETWORK_MATES_NM_VENDORDB_H

#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#include "nm-common.h"


#define NL_VDB_CAP_SEGMENT 1024
#define NL_VDB_PATH1 "~/.config/ieee-oui.csv"
#define NL_VDB_PATH2 "/var/lib/ieee-data/oui.csv"
#define NL_VDB_PATH3 "/usr/share/ieee-data/oui.csv"
#define NL_VDB_MAX_LINES 100000
#define NL_VDB_MAX_ERRORS 100

/* This is the expected full header, but we only want the first 3 fields
 *     Registry,Assignment,Organization Name,Organization Address */
#define NL_VDB_EXP_HEADER_LINE "Registry,Assignment,Organization Name"
#define NL_VDB_EXP_FLD_ASSIGN_SIZE 6


typedef struct {
    char *assignment;
    char *organisation;
} nm_reg_record;

typedef struct {
    int initialised;
    int num_records;
    size_t capacity;
    nm_reg_record *reg_records;
} nm_reg_database;

int             vendor_db_init();
int             vendor_db_destroy();
const char     *vendor_db_query(const char *assigned);


#endif //NETWORK_MATES_NM_VENDORDB_H
