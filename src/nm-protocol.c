#include "nm-protocol.h"
#include "nm-scan.h"

static proto_query proto_ssdp_queries[] = {
    {
        .message = ""
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n\r\n"
    },
    {
        .message = ""
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n"
    },
    {},
};

static proto_signature proto_ssdp_signatures[] = {
    {.signature = "upnp:rootdevice", 
        .service_name = "upnp", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "urn:dial-multiscreen-org:service:dial", 
        .service_name = "screen", .host_type = HOST_TYPE_SMART_TV},
    {.signature = "urn:mdx-netflix-com:service:target",
        .service_name = "netflix", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "FIRETVSTICK",
        .service_name = "firetv", .host_type = HOST_TYPE_SMART_TV},
    {.signature = "urn:schemas-upnp-org:device:InternetGatewayDevice",
        .service_name = "gateway", .host_type = HOST_TYPE_ROUTER},
    {.signature = "urn:schemas-upnp-org:device:MediaRenderer",
        .service_name = "media", .host_type = HOST_TYPE_SMART_TV},
    {.signature = "urn:schemas-upnp-org:device:MediaServer",
        .service_name = "media", .host_type = HOST_TYPE_PC},
    {.signature = "roku:ecp",
        .service_name = "roku", .host_type = HOST_TYPE_SMART_TV},
    {.signature = "urn:schemas-upnp-org:device:ZonePlayer",
        .service_name = "sonos", .host_type = HOST_TYPE_SMART_TV},
    {},
};


proto_def proto_ssdp_definition = {
    .send_ip = "239.255.255.250", 
    .queries = proto_ssdp_queries,
    .signatures = proto_ssdp_signatures,
};



static proto_query proto_mdns_queries[] = {
    {.message = "_amzn-wplay._tcp.local"},
//     {.message = "_services._dns-sd._udp.local"},
//     {.message = "_smb._tcp.local"},
//     {.message = "_hap._tcp.local"},
//     {.message = "_spotify-connect._tcp.local"},
//     {.message = "_homekit._tcp.local"},
//     {.message = "_matterc._udp.local"},
//     {.message = "_companion-link._tcp.local"},
    {},
};

static proto_signature proto_mdns_signatures[] = {
    {.signature = "_smb._tcp", 
        .service_name = "smb-mdns", .host_type = HOST_TYPE_PC},
    {.signature = "_hap._tcp", 
        .service_name = "hap", .host_type = HOST_TYPE_SMART_DEVICE},
    {.signature = "_spotify-connect._tcp", 
        .service_name = "spotify", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "_amzn-wplay._tcp", 
        .service_name = "amazon-wplay", .host_type = HOST_TYPE_SMART_TV},
    {.signature = "_homekit._tcp", 
        .service_name = "homekit", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "_matterc._udp", 
        .service_name = "matterc", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "_companion-link._tcp", 
        .service_name = "hap", .host_type = HOST_TYPE_UNKNOWN},
    {},
};


proto_def proto_mdns_definition = {
    .send_ip = "224.0.0.251", 
    .queries = proto_mdns_queries,
    .signatures = proto_mdns_signatures,
};


static proto_query proto_dns_queries[] = {
    {.message = "192.168.1.1"},
    {},
};

proto_def proto_dns_definition = {
    .queries = proto_dns_queries,
};

/*
bool probe_ssdp_query(int sd, void *lp){
    assert(sd > 0);
    
    scan_port *listen_port = lp;
    
    log_trace("probe_ssdp_query: sending query");

    struct sockaddr_in send_addr;
    send_addr.sin_family = AF_INET;
    send_addr.sin_port = htons(listen_port->port);
    send_addr.sin_addr.s_addr = inet_addr(proto_sdp_definition.send_ip);

    int queries_sent = 0;
    ssize_t bytes_sent;
    proto_query *query = proto_sdp_definition.queries;
    
    while(query->message) {
        bytes_sent = sendto(sd, query->message, strlen(query->message), 0,
                            (struct sockaddr*)&send_addr, sizeof(send_addr));
        if(bytes_sent < 0){
            log_debug("scan_proto_ssdp_query: could not send query, err %i, %s", errno, strerror(errno));
            return false;
        }
        log_trace("probe_ssdp_query: query with %li bytes", bytes_sent);
        log_trace("--\n%s", query->message);
        
        query = query + 1;
        queries_sent++;
    }
    
    log_trace("probe_ssdp_query: sent %i queries", queries_sent);
    
    return true;
}
*/

int probe_string_generate_query(char *buff, size_t buffsize, char *message, struct in_addr addr) {
    
    size_t msgsize = strlen(message);
    msgsize = msgsize > buffsize ? buffsize : msgsize;
    strncpy(buff, message, msgsize);
    return msgsize;

}

bool probe_ssdp_response(scan_result *result, const uint8_t *in_buffer, ssize_t in_size){
    assert(in_buffer != NULL);

    //static char *header_search = "M-SEARCH * HTTP/1.1";
    static char *response_header_notify = "NOTIFY * HTTP/1.1";
    static char *response_header_ok = "HTTP/1.1 200 OK";
    static char *key_notify_type = "NT:";
    static char *key_search_type = "ST:";
    
    char line[NM_GEN_BUFFSIZE], key_token[64], value_token[NM_GEN_BUFFSIZE];
    char *key_type = NULL;
    proto_signature *signature;

    nm_log_trace_buffer("probe_ssdp_response", in_buffer, in_size);

    int num_lines = nm_string_count_lines((const char*)in_buffer, in_size);
    if(num_lines < 5){
        log_debug("scan_proto_ssdp_response - not enough lines to begin checking, skipping");
        return false;
    }

    nm_string_copy_line((const char*)in_buffer, in_size, 0, line, sizeof(line));
    if(!strncmp(line, response_header_notify, 
                strlen(response_header_notify))){
        key_type = key_notify_type;
    }else if(!strncmp(line, response_header_ok,
                strlen(response_header_ok))){
        key_type = key_search_type;
    }
    if(!key_type)
        return NULL;
    
    //log_trace("probe_ssdp_response - looking for key: %s", key_type);
    //probe_ssdp_process(result, in_buffer, in_size, key_type, num_lines);
    
    //char line[256], ;
    //int num_records = sizeof(proto_sdp_service_signatures) / sizeof(proto_sdp_service_signatures[0]);
    //log_trace("probe_ssdp_process: processing response with %i lines", num_lines);
    
    for(int i=0; i<num_lines; i++){
        nm_string_copy_line((const char*)in_buffer, in_size, i, line, sizeof(line));
        key_token[0] = 0; value_token[0] = 0;
        sscanf(line, "%[a-zA-Z0-9:-] %s", key_token, value_token);
        //log_trace("probe_ssdp_process: scanf of line '%s' gives key '%s' and value '%s'",
        //            line, key_token, value_token);
        if(!strlen(key_token) || strcmp(key_token, key_type))
            continue;

        //key matches, now compare value to known signatures
        for(signature = proto_ssdp_definition.signatures; signature->signature; signature++){
            if(strstr(value_token, signature->signature)){
                log_trace("probe_ssdp_process: found signature: %s", signature->signature);
                if(signature->service_name)
                    result->services = nm_list_add(result->services, strdup(signature->service_name));
                return true;
            }
        }
        break;
    }

    return false;
}


static size_t proto_dns_compile_string(const char *name, uint8_t *buffer, size_t bufflen) {
    //s -> _ u d p .
    //i -> 0 1 2 3 4
    //rs-> 0 1 2 3 4
    //pt-> 0 0 0 0 0/5
    //ms-> 4 _ u d p
    int namelen = strlen(name);
    uint8_t *mstr_pointer = buffer;
    int runsize = 0, i = 0;
    for(i = 0; i <= namelen && i < bufflen; i++) {
        runsize++;
        if (name[i] != '.' && name[i] != 0)
            continue;

        *mstr_pointer = runsize - 1;
        mstr_pointer++;
        memcpy(mstr_pointer, &name[i-runsize+1], runsize);
        mstr_pointer = mstr_pointer + runsize - 1;
        runsize = 0;
    }
    *(++mstr_pointer) = 0;
    return mstr_pointer - buffer;
}


static size_t proto_dns_decompile_string(const uint8_t *name, const uint8_t *fullmsg, char *buffer, size_t bufflen) {
    int runsize = 0;
    char *pointer = buffer;
    const uint8_t *mstr = name;
    const uint8_t straddr;

    memset(buffer, 0, bufflen);
    //*pointer = 0;
    while(*mstr && ! (*mstr & PROTO_DNS_COMPRESS_MASK) && (pointer - buffer) < bufflen){
        runsize = *mstr++;
        strncpy(pointer, (const char*)mstr, runsize);
        pointer[runsize] = '.';
        pointer += runsize + 1;
        mstr = mstr + runsize;
    }
    
    if(*mstr & PROTO_DNS_COMPRESS_MASK && fullmsg != 0) {
        nm_copy_netbytes_to_shorts((void*)&straddr, mstr, 2);
        proto_dns_decompile_string(fullmsg + straddr, fullmsg, pointer, bufflen - (pointer - buffer));
        pointer += strlen(pointer) + 1;
    }
    
    if(!*mstr)
        mstr += 1;
    else if(*mstr & PROTO_DNS_COMPRESS_MASK)
        mstr += 2;
    
    if(pointer > buffer){
        pointer--;
        *pointer = 0;
    }
    
    return mstr - name;

}


size_t proto_dns_compose_query(uint8_t *buff, size_t bufflen, uint16_t mid, char *queryname,
                               uint16_t qtype, uint16_t qclass) {

    size_t chunksize = 0;
    uint8_t *pointer = buff;
    proto_dns_message message;
    
    if(bufflen < (sizeof(message.header) + sizeof(message.question) + strlen(queryname) + 2)){
        return 0;
    }
    
    memset(&message, 0, sizeof(proto_dns_message));
    message.header.id = htons(mid);
    message.header.qdcount = htons(1);
    message.question.type = htons(qtype);
    message.question.class = htons(qclass);
    
    //1. header
    chunksize = sizeof(message.header);
    memcpy(pointer, &message.header, chunksize);
    pointer += chunksize;
    
    //2.1 qname first
    chunksize = proto_dns_compile_string(queryname, pointer, bufflen - sizeof(message.question));
    pointer += chunksize;
    
    //2.2 qheader
    chunksize = sizeof(message.question);
    memcpy(pointer, &message.question, chunksize);
    pointer += chunksize;
    
    return pointer - buff;
    
}

//TODO: remove me
void proto_dns_parse_response(const void *msg, size_t msglen) {

    const uint8_t *pointer = msg, *endpointer = msg + msglen;
    char buffer[512];
    char ipbuffer[128];
    size_t retsize;
    uint16_t port;
    char *rtype = "Answer";
    
    proto_dns_message message;
    memset(&message, 0, sizeof(proto_dns_message));

    //1. header
    nm_copy_netbytes_to_shorts((uint16_t*)&message.header, msg, sizeof(message.header));
    /*
    printf("> Header, id: 0x%04hx, flags: 0x%04hx, qcount: %hu, ancount: %hu, nscount: %hu, add count: %hu\n", 
           message.header.id, message.header.flags, message.header.qdcount, message.header.ancount,
           message.header.nscount, message.header.arcount);
    */
    pointer += sizeof(message.header);
    if(pointer > endpointer)
        return;
    
    //2. questions
    for (int i = 0; i < message.header.qdcount; i++ ) {
        retsize = proto_dns_decompile_string(pointer, msg, buffer, sizeof(buffer));
        pointer += retsize;
        //printf("> Question %i, size: %zi -> %s\n", i+1, retsize, buffer);
        nm_copy_netbytes_to_shorts((uint16_t*)&message.question, 
                            (uint8_t*)(proto_dns_qheader*)pointer, PROTO_DNS_Q_HDR_SIZE);
        pointer += PROTO_DNS_Q_HDR_SIZE;
        if(pointer > endpointer)
            return;
    }

    //3. answers
    int totalrr = message.header.ancount + message.header.nscount + message.header.arcount;
    for (int i = 0; i < totalrr; i++ ) {
        
        if(i >= (message.header.ancount + message.header.nscount))
            rtype = "Additional";
        else if(i >= message.header.ancount)
            rtype = "Authoritative";
        
        retsize = proto_dns_decompile_string(pointer, msg, buffer, sizeof(buffer));
        pointer += retsize;
        message.rrecord.type = ntohs(*(uint16_t*)pointer);
        message.rrecord.class = ntohs(*(uint16_t*)(pointer+2));
        message.rrecord.ttl = ntohl(*(uint32_t*)(pointer+4));
        message.rrecord.rdlength = ntohs(*(uint16_t*)(pointer+8));
        pointer += PROTO_DNS_RR_HDR_SIZE;
        /*
        printf("> %s %i, class: 0x%04hX, type: 0x%04hX, ttl: %i, rdlen: %02hi, size: %zi -> %s\n", 
               rtype, i + 1, message.rrecord.class, message.rrecord.type, message.rrecord.ttl,
               message.rrecord.rdlength, retsize, buffer);
        */
        
        if(message.rrecord.type == PROTO_DNS_TYPE_PTR){
            retsize = proto_dns_decompile_string(pointer, msg, buffer, sizeof(buffer));
        }else if(message.rrecord.type == PROTO_DNS_TYPE_A){
            ipbuffer[0] = 0;
            inet_ntop(AF_INET, pointer, ipbuffer, sizeof(ipbuffer));
        }else if(message.rrecord.type == PROTO_DNS_TYPE_AAAA){
            ipbuffer[0] = 0;
            inet_ntop(AF_INET6, pointer, ipbuffer, sizeof(ipbuffer));
        }else if(message.rrecord.type == PROTO_DNS_TYPE_SRV){
            port = ntohs(*((uint16_t*)pointer+4));
            retsize = proto_dns_decompile_string(pointer+6, msg, buffer, sizeof(buffer));
        }else if(message.rrecord.type == PROTO_DNS_TYPE_TXT){
            retsize = proto_dns_decompile_string(pointer, msg, buffer, sizeof(buffer));
        }else{
        }
        
        pointer += message.rrecord.rdlength;
    }
}

/*
bool probe_mdns_query(int sd, void *lp){
    assert(sd > 0);

    log_trace("probe_mdns_query: sending query");
    
    scan_port *listen_port = lp;
    
    struct sockaddr_in send_addr;
    send_addr.sin_family = AF_INET;
    send_addr.sin_port = htons(listen_port->port);
    send_addr.sin_addr.s_addr = inet_addr(proto_mdns_definition.send_ip);

    size_t msgsize;
    int queries_sent = 0;
    ssize_t bytes_sent;
    char buff[NM_GEN_BUFFSIZE];
    proto_query *query = proto_mdns_definition.queries;
    
    while(query->message) {
        
        msgsize = proto_dns_compose_query((void *)buff, sizeof(buff), 0x1234, 
                                          query->message, PROTO_DNS_TYPE_PTR,
                                          PROTO_DNS_CLASS_IN_UNICAST);
        
        bytes_sent = sendto(sd, buff, msgsize, 0, (struct sockaddr*)&send_addr, sizeof(send_addr));
        if(bytes_sent < 0){
            log_debug("probe_mdns_query: could not send query, err %i, %s", errno, strerror(errno));
            return false;
        }
        log_trace("probe_mdns_query: query with %li bytes", bytes_sent);
        //log_trace("--\n%s", query->message);
        
        query = query + 1;
        queries_sent++;
    }
    
    log_trace("probe_mdns_query: sent %i queries", queries_sent);
    
    return true;
}*/


int probe_dns_generate_query_targetptr(char *buff, size_t buffsize, char *message, struct in_addr addr){
    size_t msgsize;
    char query[NM_MAX_BUFF_HOST];
    uint32_t netaddr = htonl(addr.s_addr);
    sprintf(query, "%u.%u.%u.%u.in-addr.arpa", 
            (netaddr & 0xFF), (netaddr & 0xFF00) >> 8, (netaddr & 0xFF0000) >> 16, (netaddr & 0xFF000000) >> 24);
    
    msgsize = proto_dns_compose_query((void *)buff, buffsize, 0x5602, 
                                        query, PROTO_DNS_TYPE_PTR,
                                        PROTO_DNS_CLASS_IN);
    return msgsize;
}


int probe_dns_generate_query(char *buff, size_t buffsize, char *message, struct in_addr addr){
    size_t msgsize;
    
    msgsize = proto_dns_compose_query((void *)buff, buffsize, 0x5601, 
                                        message, PROTO_DNS_TYPE_PTR,
                                        PROTO_DNS_CLASS_IN);
    return msgsize;
}

int probe_mdns_generate_query(char *buff, size_t buffsize, char *message, struct in_addr addr){
    size_t msgsize;
    msgsize = proto_dns_compose_query((void *)buff, buffsize, 0x1234, 
                                        message, PROTO_DNS_TYPE_PTR,
                                        PROTO_DNS_CLASS_IN_UNICAST);
    return msgsize;
}


bool probe_mdns_response(scan_result *result, const uint8_t *in_buffer, ssize_t in_size){
    assert(in_buffer != NULL);

    const uint8_t *pointer = in_buffer;
    const uint8_t *endpointer = pointer + in_size;
    char buffer[512];
    size_t retsize;
    proto_dns_message message;
    memset(&message, 0, sizeof(proto_dns_message));
    
    //nm_log_trace_buffer("probe_mdns_response", in_buffer, in_size);
    nm_log_trace_bytes("probe_mdns_response", in_buffer, in_size);

    //1. header
    nm_copy_netbytes_to_shorts((uint16_t*)&message.header,
                               (const uint8_t *)in_buffer, sizeof(message.header));
    log_trace(  "probe_mdns_response: > Header, id: 0x%04hx, flags: 0x%04hx, "
                "qcount: %hu, ancount: %hu, nscount: %hu, add count: %hu", 
                message.header.id, message.header.flags, message.header.qdcount, 
                message.header.ancount, message.header.nscount, message.header.arcount);

    pointer += sizeof(message.header);
    if(pointer > endpointer)
        return false;
    
    //2. questions
    for (int i = 0; i < message.header.qdcount; i++ ) {
        retsize = proto_dns_decompile_string(pointer, in_buffer, buffer, sizeof(buffer));
        pointer += retsize;
        log_trace("probe_mdns_response: > Question %i, size: %zi -> %s", i+1, retsize, buffer);
        nm_copy_netbytes_to_shorts((uint16_t*)&message.question, 
                           (uint8_t*)(proto_dns_qheader*)pointer, PROTO_DNS_Q_HDR_SIZE);
        pointer += PROTO_DNS_Q_HDR_SIZE;
        if(pointer > endpointer)
            return false;
    }

    //3. answers
    //int totalrr = message.header.ancount + message.header.nscount + message.header.arcount;
    for (int i = 0; i < message.header.ancount; i++ ) {
        
        retsize = proto_dns_decompile_string(pointer, in_buffer, buffer, sizeof(buffer));
        pointer += retsize;
        message.rrecord.type = ntohs(*(uint16_t*)pointer);
        message.rrecord.class = ntohs(*(uint16_t*)(pointer+2));
        message.rrecord.ttl = ntohl(*(uint32_t*)(pointer+4));
        message.rrecord.rdlength = ntohs(*(uint16_t*)(pointer+8));
        pointer += PROTO_DNS_RR_HDR_SIZE;
        
        log_trace(  "probe_mdns_response: > Answer %i, class: 0x%04hX, "
                    "type: 0x%04hX, ttl: %i, rdlen: %02hi, size: %zi -> %s\n", 
                    i + 1, message.rrecord.class, message.rrecord.type, message.rrecord.ttl,
                    message.rrecord.rdlength, retsize, buffer);
        if(message.rrecord.type == PROTO_DNS_TYPE_PTR){
            retsize = proto_dns_decompile_string(pointer, in_buffer, buffer, sizeof(buffer));
            for(proto_signature *s = proto_mdns_definition.signatures; s->signature; s++){
                //log_trace("probe_mdns_response: looking for signature: %s in %s", s->signature, buffer);
                if(strstr(buffer, s->signature)){
                    log_trace("probe_mdns_response: found signature: %s", s->signature);
                    result->host_type = s->host_type;
                    if(s->service_name)
                        result->services = nm_list_add(result->services, strdup(s->service_name));
                    break;
                }
            }
            
        }
        pointer += message.rrecord.rdlength;
    }
    
    return true;
}
