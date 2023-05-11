#include "nm-common.h"


unsigned long nm_time_ms(){
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_nsec / 1000000 + t.tv_sec * 1000;
}

unsigned long nm_time_ms_diff(unsigned long start){
    return nm_time_ms() - start;
}


void nm_string_toupper(char *str){
    if(str == NULL)
        return;
    size_t len = strlen(str);
    for (int i = 0; i < len; ++i) {
        str[i] = (char)toupper(str[i]);
    }
}


char *nm_string_extract_token(char *line, char delimiter, int index){
    char *scan_pointer, *scan_delim, delim_str[4], *scan_eol;
    size_t span = 0;
    //scan the line
    scan_pointer = line;
    scan_eol = strchr(scan_pointer, 0xA);
    if(scan_eol == NULL)
        scan_eol = strchr(scan_pointer, 0);

    delim_str[0] = delimiter;
    delim_str[1] = 0;

    for(int i=0; i<=index; i++){
        /* increment pointer if we start with delimiter chars */
        if((span = strspn(scan_pointer, delim_str)))
            scan_pointer += span;
        /* find the delimiter */
        scan_delim = strchr(scan_pointer+1, delimiter);
        if(scan_delim != NULL && scan_delim < scan_eol){
            if(i == index){
                *scan_delim = '\0';
                return scan_pointer;
            }else{
                span = strspn(scan_delim + 1, delim_str);
                scan_pointer = scan_delim + 1 + span;
            }
        }else if(scan_eol != NULL && i == index){
            *scan_eol = 0;
            return scan_pointer;
        }else if(i < index){
            continue;
        }
    }
    return NULL;
}

int nm_string_count_lines(const char *line, size_t len){
    int num_lines = 0;
    const char *pointer = line;

    while(*pointer && pointer < (line + len)){
        if(*pointer == '\n')
            num_lines++;
        pointer = pointer + 1;
    }
    return num_lines;
}


void nm_string_copy_line(const char *line, size_t line_len, int index, char *copy_to, size_t copy_max){
    int line_index = 0, found_len;
    const char *pointer = line;
    const char *start_pointer = line, *end_pointer = NULL;

    while(*pointer && pointer < (line + line_len)){
        if(line_index == index){
            start_pointer = pointer;
            pointer++;
            break;
        }
        if(*pointer == '\n')
            line_index++;
        pointer++;
    }

    while(*pointer && pointer < (line + line_len)){
        if(*pointer == '\n')
            break;
        pointer++;
    }
    end_pointer = pointer - 1;
    if(*end_pointer == '\r')
        end_pointer--;

    found_len = (int) (end_pointer - start_pointer);
    if(found_len){
        strncpy(copy_to, start_pointer, copy_max < found_len ? copy_max : found_len + 1);
        copy_to[found_len+1] = 0;
    }else{
        *copy_to = 0;
    }

}

/*
GArray *
nm_copy_string_list_as_array(GList *src_list){
    char *curr_text;
    guint list_len = g_list_length(src_list);
    GList *curr_list = src_list;

    GArray *dst_array = g_array_sized_new(FALSE, FALSE, sizeof(char *), list_len);
    for(int i=0; i < list_len; i++){
        curr_text = strdup((char *)curr_list->data);
        g_array_append_val(dst_array, curr_text);
        curr_list = curr_list->next;
    }

    return dst_array;
}
*/

nmlist * nm_list_add(nmlist* to, void *newdata) {
    
    return g_list_append(to, newdata);
    /*
    // allocate and set new node
    nmlist *newnode = malloc(sizeof(nmlist));
    memset(newnode, 0, sizeof(nmlist));
    newnode->data = newdata;

    // attach node to list
    nm_list_foreach(node, to) {
        if(node->next == NULL){
            node->next = newnode;
            newnode->prev = node;
            break;
        }
    }
    return newnode;
    */
    
}

void nm_list_free(nmlist *list, bool free_data) {
    
    if(list && list->prev)
            list->prev->next = NULL;
    
    if (free_data) {
        g_list_free_full(list, free);
    }else {
        g_list_free(list);
    }
    
    /*
    nmlist *currnode = list;
    nmlist *nextnode;
    
    while(currnode) {
        nextnode = currnode->next;
        if(currnode->prev)
            currnode->prev->next = NULL;
        
        if(free_data && currnode->data) {
            free(currnode->data);
            currnode->data = NULL;
        }
        free(currnode);
        
        currnode = nextnode;
    }
    */
    

}


uint nm_list_len(nmlist *list) {

    return g_list_length(list);
    /*
    int length = 0;
    
    nm_list_foreach(node, list)
        length++;
    
    return length;
    */
}

nmlist* nm_list_find_string(nmlist *list, const char *data) {
    
    nm_list_foreach(node, list) {
        if(node->data && !strcmp(data, node->data))
            return node;
    }
    
    return NULL;
}



nmtable *nm_table_new() {
    return g_hash_table_new(NULL, NULL);
}

uint nm_table_len(nmtable *table) {
    return g_hash_table_size(table);
}

void *nm_table_get_num(nmtable *table, uint32_t num) {
    return g_hash_table_lookup(table, (void*)(intptr_t)num);
}

void nm_table_set_num(nmtable *table, uint32_t num, void *data) {
    g_hash_table_insert(table, (void*)(intptr_t)num, data);
}

//someone else frees the data?
void nm_table_free(nmtable *table) {
    g_hash_table_destroy(table);
}
