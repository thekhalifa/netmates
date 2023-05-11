// full app 
#include "nm-app.h"

int main (int argc, char **argv){
    
//     printf("strlen 1: %lu\n", strlen("abcd"));
//     //printf("strlen 2: %lu\n", strlen(NULL));
//     return 0;
    return init_application(argc, argv);
    
}


// host only
/*
#include "nm-host.h"

int main (int argc, char **argv){
    //return init_application(argc, argv);
    
    nm_host host1;
    host1.hostname = NULL;
    
    return 0;
}
*/
