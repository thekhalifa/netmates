#include "nm-protocol.h"
#include "nm-scan.h"

static proto_query proto_ssdp_queries[] = {
    {.message = ""
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    },
    {.message = ""
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n"
    },
    {},
};

static proto_signature proto_ssdp_signatures[] = {
    {.signature = "upnp:rootdevice", .service_name = "upnp", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "urn:dial-multiscreen-org:service:dial",  .service_name = "screen", .host_type = HOST_TYPE_TV},
    {.signature = "urn:mdx-netflix-com:service:target", .service_name = "netflix", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "FIRETVSTICK", .service_name = "firetv", .host_type = HOST_TYPE_TV},
    {.signature = "urn:schemas-upnp-org:device:InternetGatewayDevice", .service_name = "gateway", 
        .host_type = HOST_TYPE_ROUTER},
    {.signature = "urn:schemas-upnp-org:device:MediaRenderer", .service_name = "media", .host_type = HOST_TYPE_TV},
    {.signature = "urn:schemas-upnp-org:device:MediaServer", .service_name = "media", .host_type = HOST_TYPE_PC},
    {.signature = "roku:ecp", .service_name = "roku", .host_type = HOST_TYPE_TV},
    {.signature = "urn:schemas-upnp-org:device:ZonePlayer", .service_name = "sonos", .host_type = HOST_TYPE_TV},
    {},
};


proto_def proto_ssdp_definition = {
    .queries = proto_ssdp_queries,
    .signatures = proto_ssdp_signatures,
};


static proto_query proto_mdns_queries[] = {
    {.message = "_services._dns-sd._udp.local"},
    {.message = "_amzn-wplay._tcp.local"},
    {.message = "_amzn-alexa._tcp.local"},
    {.message = "_spotify-connect._tcp.local"},
    {.message = "_smb._tcp.local"},
    {.message = "_ipp._tcp.local"},
    {.message = "_hap._tcp.local"},
    {.message = "_homekit._tcp.local"},
    {.message = "_airplay._tcp.local"},
    {.message = "_companion-link._tcp.local"},
    {.message = "_raop._tcp.local"},
    {.message = "_matter._udp.local"},
    {.message = "_matterc._udp.local"},
    {.message = "_webdav._tcp.local"},
    //{.message = "_viziocast._udp.local"},
    //{.message = "_sengled._udp.local"},
    {},
};

static proto_signature proto_mdns_signatures[] = {
    {.signature = "_amzn-wplay._tcp", .service_name = "amazon-wplay", .host_type = HOST_TYPE_TV},
    {.signature = "_amzn-alexa._tcp", .service_name = "alexa", .host_type = HOST_TYPE_DEVICE},
    {.signature = "_spotify-connect._tcp", .service_name = "spotify", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "_smb._tcp", .service_name = "smb-mdns", .host_type = HOST_TYPE_PC},
    {.signature = "_ipp._tcp", .service_name = "ipp", .host_type = HOST_TYPE_DEVICE},
    {.signature = "_hap._tcp", .service_name = "hap", .host_type = HOST_TYPE_DEVICE},
    {.signature = "_homekit._tcp", .service_name = "homekit", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "_airplay._tcp", .service_name = "homekit", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "_companion-link._tcp", .service_name = "homekit", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "_webdav._tcp", .service_name = "webdav", .host_type = HOST_TYPE_PC},
    {.signature = "_raop._tcp", .service_name = "homekit", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "_matter._udp", .service_name = "matterc", .host_type = HOST_TYPE_UNKNOWN},
    {.signature = "_matterc._udp", .service_name = "matterc", .host_type = HOST_TYPE_UNKNOWN},
    //{.signature = "_viziocast._tcp", .service_name = "hap", .host_type = HOST_TYPE_UNKNOWN},
    {},
};


proto_def proto_mdns_definition = {
    .queries = proto_mdns_queries,
    .signatures = proto_mdns_signatures,
};


static proto_query proto_dns_queries[] = {
    {},
};

proto_def proto_dns_definition = {
    .queries = proto_dns_queries,
};

int probe_string_generate_query(char *buff, size_t buffsize, char *message, struct sockaddr *targetaddr) {
    
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
        log_trace("probe_ssdp_response - not enough lines to begin checking, skipping");
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
        return false;
    
    if(!nm_list_find_string(result->services, "ssdp"))
        result->services = nm_list_add(result->services, strdup("ssdp"));
    
    for(int i=0; i<num_lines; i++){
        nm_string_copy_line((const char*)in_buffer, in_size, i, line, sizeof(line));
        key_token[0] = 0; value_token[0] = 0;
        sscanf(line, "%[a-zA-Z0-9:-] %s", key_token, value_token);
        if(!strlen(key_token) || strcmp(key_token, key_type))
            continue;

        //key matches, now compare value to known signatures
        for(signature = proto_ssdp_definition.signatures; signature->signature; signature++){
            if(strstr(value_token, signature->signature)){
                log_trace("probe_ssdp_response: found signature: %s", signature->signature);
                if(signature->service_name)
                    result->services = nm_list_add(result->services, strdup(signature->service_name));
                return true;
            }
        }
        break;
    }

    return true;
}

/* convert c-string to dns-string prefixed by length and no . */
static size_t proto_dns_compile_string(const char *name, uint8_t *buffer, size_t bufflen) {
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

/* convert dns-string to normal c-string */
static size_t proto_dns_decompile_string(const uint8_t *name, const uint8_t *fullmsg, char *buffer, size_t bufflen) {
    int runsize = 0;
    char *pointer = buffer;
    const uint8_t *mstr = name;
    const uint8_t straddr;

    memset(buffer, 0, bufflen);
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

/* generate a PTR query to the /addr/ ip 1.2.3.4 becomes 4.3.2.1.in-addr.arpa */
int probe_dns_generate_query_targetptr(char *buff, size_t buffsize, char *message, struct sockaddr *targetaddr){
    size_t msgsize;
    char query[NM_HOST_STRLEN];
    
    //TODO: Add ipv6 support
    assert(targetaddr->sa_family == AF_INET);

    struct sockaddr_in *target4 = (struct sockaddr_in*)targetaddr;
    uint32_t netaddr = htonl(target4->sin_addr.s_addr);
    sprintf(query, "%u.%u.%u.%u.in-addr.arpa", 
            (netaddr & 0xFF), (netaddr & 0xFF00) >> 8, (netaddr & 0xFF0000) >> 16, (netaddr & 0xFF000000) >> 24);
    
    msgsize = proto_dns_compose_query((void *)buff, buffsize, 0x5602, 
                                        query, PROTO_DNS_TYPE_PTR,
                                        PROTO_DNS_CLASS_IN);
    return msgsize;
}

/* generate a PTR query with /message/ */
int probe_dns_generate_query(char *buff, size_t buffsize, char *message, struct sockaddr *targetaddr){
    size_t msgsize;
    
    msgsize = proto_dns_compose_query((void *)buff, buffsize, 0x5601, 
                                        message, PROTO_DNS_TYPE_PTR,
                                        PROTO_DNS_CLASS_IN);
    return msgsize;
}

/* generate a PTR query with /message/ and UNICAST flag */
int probe_mdns_generate_query(char *buff, size_t buffsize, char *message, struct sockaddr *targetaddr){
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
    
    if(!nm_list_find_string(result->services, "mdns"))
        result->services = nm_list_add(result->services, strdup("mdns"));
    
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

    //3. answers. total: ancount + nscount + arcount;
    for (int i = 0; i < message.header.ancount; i++ ) {
        
        retsize = proto_dns_decompile_string(pointer, in_buffer, buffer, sizeof(buffer));
        pointer += retsize;
        message.rrecord.type = ntohs(*(uint16_t*)pointer);
        message.rrecord.class = ntohs(*(uint16_t*)(pointer+2));
        message.rrecord.ttl = ntohl(*(uint32_t*)(pointer+4));
        message.rrecord.rdlength = ntohs(*(uint16_t*)(pointer+8));
        pointer += PROTO_DNS_RR_HDR_SIZE;
        
        log_trace(  "probe_mdns_response: > Answer %i, class: 0x%04hX, "
                    "type: 0x%04hX, ttl: %i, rdlen: %02hi, size: %zi -> %s", 
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
