#include "nm-vendordb.h"

static nm_reg_database reg_database = {0, 0, 0, .reg_records = NULL};


static int
vendor_db_util_compare_record(const void *a, const void *b){
    nm_reg_record *rec_a =(nm_reg_record *)a;
    nm_reg_record *rec_b =(nm_reg_record *)b;
    return strcmp(rec_a->assignment, rec_b->assignment);
}

static char *
vendor_db_util_extract_token(char *line, int index){
    char *scan_pointer, *scan_eol;
    char *scan_comma, *scan_quote, *scan_endquote;

    //scan the line
    scan_pointer = line;
    scan_eol = strchr(scan_pointer, 0xA);
    if(scan_eol == NULL)
        scan_eol = strchr(scan_pointer, 0);

    for(int i=0; i<=index; i++){
        scan_comma = strchr(scan_pointer+1, ',');
        scan_quote = strchr(scan_pointer, '"');
        /* find a comma with no quote, or a comma and quote but comma comes first */
        if((scan_comma != NULL && scan_quote == NULL) || (scan_comma != NULL && scan_comma < scan_quote)){
            if(i == index){
                *scan_comma = '\0';
                return scan_pointer;
            }else{
                scan_pointer = scan_comma+1;
            }
        }else if(scan_quote != NULL){
            scan_endquote = strchr(scan_quote+1, '"');
            if(i == index){
                *scan_quote = '\0';
                *scan_endquote = '\0';
                return scan_quote+1;
            }else{
                scan_pointer = scan_endquote+1;
            }
        }else if(scan_eol != NULL && i == index){ //last token
            *scan_eol = 0;
            return scan_pointer;
        }else{
            //shouldn't be here
            break;
        }
    }
    return NULL;
}

static int
vendor_db_util_add_record(char *fld_assignment, char *fld_organisation){

    if(reg_database.num_records == reg_database.capacity) {
        //resize the record storage first
        size_t new_capacity = reg_database.capacity + NL_VDB_CAP_SEGMENT;
        size_t new_size = (new_capacity) * sizeof(nm_reg_record);
        void *new_block = realloc(reg_database.reg_records, new_size);
        if(new_block == NULL){
            perror("Error resizing");
            return 0;
        }
        reg_database.capacity = new_capacity;
        reg_database.reg_records = new_block;
    }

    //add the record
    reg_database.reg_records[reg_database.num_records].assignment = fld_assignment;
    reg_database.reg_records[reg_database.num_records].organisation = fld_organisation;
    reg_database.num_records++;
    return 1;
}


int
vendor_db_init() {

    if(reg_database.initialised)
        return 0;

    FILE *fd = fopen(NL_VDB_PATH, "r");
    if(fd == NULL){
        //try the second path
        fd = fopen(NL_VDB_PATH2, "r");
        if(fd == NULL) {
            return 1;
        }
    }

    int num_read = 0;
    char line[BUFSIZ], *fld_assignment, *fld_organisation;
    nm_reg_record *record;

    //check header line
    if(fgets(line, sizeof(line), fd)){
        if(strncmp(line, NL_VDB_EXP_HEADER_LINE, strlen(NL_VDB_EXP_HEADER_LINE)) != 0){
            perror("NL_VDB: Header line was not as expected, moving ahead with data\n");
        }
    }

    while(fgets(line, sizeof(line), fd) && num_read < NL_VDB_MAX_LINES){
        num_read++;
        //extract in reverse order as we break the line buffer
        fld_organisation = vendor_db_util_extract_token(line, 2);
        fld_assignment = vendor_db_util_extract_token(line, 1);
        if(fld_organisation && fld_assignment){
            fld_assignment = strdup(fld_assignment);
            nm_string_toupper(fld_assignment);
            fld_organisation = strdup(fld_organisation);
            vendor_db_util_add_record(fld_assignment, fld_organisation);
        }
    }
    qsort(reg_database.reg_records, reg_database.num_records, sizeof(nm_reg_record),
          vendor_db_util_compare_record);
    reg_database.initialised = 1;

    return 0;
}

int
vendor_db_destroy() {
    if(!reg_database.initialised)
        return 1;

    for (int i = 0; i < reg_database.num_records; ++i) {
        free(reg_database.reg_records[i].assignment);
        free(reg_database.reg_records[i].organisation);
    }
    free(reg_database.reg_records);
    reg_database.reg_records = 0;
    reg_database.num_records = 0;
    reg_database.capacity = 0;
    reg_database.initialised = 0;

    return 0;
}

const char *
vendor_db_query_linear(const char *address) {
    if(!reg_database.initialised)
        return NULL;
    if(address == NULL || strlen(address) < NL_VDB_EXP_FLD_ASSIGN_SIZE){
        return NULL;
    }
    char assignment[NL_VDB_EXP_FLD_ASSIGN_SIZE+1];
    strncpy(assignment, address, NL_VDB_EXP_FLD_ASSIGN_SIZE+1);
    assignment[NL_VDB_EXP_FLD_ASSIGN_SIZE] = 0;

    for (int i = 0; i < reg_database.num_records; ++i) {
        if(strcmp(assignment, reg_database.reg_records[i].assignment) == 0){
            return reg_database.reg_records[i].organisation;
        }
    }
    return NULL;
}

const char *
vendor_db_query(const char *address) {
    if(!reg_database.initialised)
        return NULL;

    if(address == NULL || strlen(address) < NL_VDB_EXP_FLD_ASSIGN_SIZE){
        return NULL;
    }
    char assignment[NL_VDB_EXP_FLD_ASSIGN_SIZE+1];
    strncpy(assignment, address, NL_VDB_EXP_FLD_ASSIGN_SIZE+1);
    assignment[NL_VDB_EXP_FLD_ASSIGN_SIZE] = 0;
    nm_string_toupper(assignment);

    nm_reg_record key_record;
    key_record.assignment = assignment;

    nm_reg_record *record = bsearch(&key_record, reg_database.reg_records, reg_database.num_records,
                                    sizeof(nm_reg_record), vendor_db_util_compare_record);
    if(record)
        return record->organisation;

    return NULL;
}

