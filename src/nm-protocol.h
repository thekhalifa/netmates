#ifndef NM_PROTOCOL_H_INCLUDED
#define NM_PROTOCOL_H_INCLUDED

#include "nm-common.h"
#include "nm-host.h"


#define UDP_QUERY_DNS "\x71\x80\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x08\x61\x6f\x75" \
"\x72\x67\x61\x74\x65\x03\x6c\x61\x6e\x00\x00\x01\x00\x01\x00\x00" \
"\x29\x02\x00\x00\x00\x00\x00\x00\x00"
// switch to a simple "query com PTR"

#define UDP_QUERY_NBS "\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41" \
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

bool    probe_ssdp_query(int sd, void *lp);
bool    probe_ssdp_response(scan_result *result, const uint8_t *in_buffer, ssize_t in_size);

bool    probe_mdns_query(int sd, void *lp);
bool    probe_mdns_response(scan_result *result, const uint8_t *in_buffer, ssize_t in_size);


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


typedef struct {
    proto_def def;
    char *send_ip;
    char *header_search;
    char *response_header_notify;
    char *response_header_ok;
    char *key_notify_type;
    char *key_search_type;
    proto_query *queries;
    proto_signature *signatures;
} proto_sdp;



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

//static proto_sdp proto_sdp_definition;
extern proto_def proto_dns_definition;
extern proto_def proto_mdns_definition;


int    probe_dns_generate_query_targetptr(char *buff, size_t buffsize, char *message, struct in_addr addr);
int    probe_dns_generate_query(char *buff, size_t buffsize, char *message, struct in_addr addr);
int    probe_mdns_generate_query(char *buff, size_t buffsize, char *message, struct in_addr addr);








#endif // NM_PROTOCOL_H_INCLUDED
