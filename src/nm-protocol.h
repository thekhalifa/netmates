#ifndef NM_PROTOCOL_H_INCLUDED
#define NM_PROTOCOL_H_INCLUDED

#include "nm-common.h"
#include "nm-host.h"


#define PROTO_NBS_QUERY "\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21" \
"\x00\x01"

//HTTP Header ==>
//     GET / HTTP/1.1<CR><LF>
//     User-Agent: Wget/1.21
//     Accept: */*
//     Accept-Encoding: identity
//     Host: 192.168.1.1:5000
//     Connection: Keep-Alive
//

//HTTP Response <==
//     HTTP/1.1 404 Not Found
//     Content-Type: text/html
//     Connection: close
//     Content-Length: 134
//     Server: OpenWRT/21.02-SNAPSHOT UPnP/1.1 MiniUPnPd/2.2.1
//     Ext:
// 
//     <HTML><HEAD>
//     </BODY></HTML>


typedef struct scan_result scan_result;


typedef struct {
    int length;
    char *message;
} proto_payload;

typedef struct {
    char *signature;
    char *service_name;
    enum nm_host_type host_type;
} proto_signature;

typedef struct {
    char *message;
} proto_query;

typedef struct proto_def {
    char *send_ip;
    proto_query *queries;
    proto_signature *signatures;
} proto_def;



//rfc1035
#define PROTO_DNS_CLASS_IN          1
#define PROTO_DNS_CLASS_IN_UNICAST  0x8001  //rfc6762
#define PROTO_DNS_COMPRESS_MASK     0xC0
enum proto_dns_type {
    PROTO_DNS_TYPE_A        = 1,
    PROTO_DNS_TYPE_PTR      = 12,
    PROTO_DNS_TYPE_TXT      = 16,
    PROTO_DNS_TYPE_AAAA     = 28,
    PROTO_DNS_TYPE_SRV      = 33,
    PROTO_DNS_TYPE_ALL      = 255,
};

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;   //questions
    uint16_t ancount;   //answers
    uint16_t nscount;   //authority
    uint16_t arcount;   //additional
} proto_dns_header;


typedef struct {
    //name[];
    uint16_t type;
    uint16_t class;
} proto_dns_qheader;
#define PROTO_DNS_Q_HDR_SIZE 4


typedef struct {
    //name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    //rdata;
} proto_dns_rheader;
#define PROTO_DNS_RR_HDR_SIZE       10
//TODO: remove?
#define PROTO_DNS_RR_SRV_HDR_SIZE   6

typedef struct {
    proto_dns_header     header;
    proto_dns_qheader    question;
    proto_dns_rheader    rrecord;
} proto_dns_message;

extern proto_def proto_ssdp_definition;
extern proto_def proto_dns_definition;
extern proto_def proto_mdns_definition;


//bool    probe_ssdp_query(int sd, void *lp);
int     probe_string_generate_query(char *buff, size_t buffsize, char *message, struct in_addr addr);

bool    probe_ssdp_response(scan_result *result, const uint8_t *in_buffer, ssize_t in_size);


int     probe_dns_generate_query_targetptr(char *buff, size_t buffsize, char *message, struct in_addr addr);
int     probe_dns_generate_query(char *buff, size_t buffsize, char *message, struct in_addr addr);

int     probe_mdns_generate_query(char *buff, size_t buffsize, char *message, struct in_addr addr);
bool    probe_mdns_response(scan_result *result, const uint8_t *in_buffer, ssize_t in_size);








#endif // NM_PROTOCOL_H_INCLUDED
