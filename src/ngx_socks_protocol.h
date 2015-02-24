#ifndef _SOCKS5_H
#define _SOCKS5_H


#define SOCKS5_STATE_PREPARE 0
#define SOCKS5_STATE_RUNNING 1
#define SOCKS5_STATE_STOP 2

/* auth */
#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_RAW				0x00
#define SOCKS5_AUTH_GSSAPI			0x01
#define SOCKS5_AUTH_USERPASS		0x02
#define SOCKS5_AUTH_NO_SUPPORT		0xFF

/* estab the channel */
#define SOCKS5_CMD_CONNECT			0x01
#define SOCKS5_CMD_BIND				0x02
#define SOCKS5_CMD_UDP				0x03

#define SOCKS5_IPV4					0x01
#define SOCKS5_DOMAIN				0x03
#define SOCKS5_IPV6					0x04

#define SOCKS5_REP_SUCCEED				0x00
#define SOCKS5_REP_GENERAL_FAILURE		0x01
/* remote server error */
#define SOCKS5_REP_CMD_NOT_SUPPORTED	0x07
#define SOCKS5_REP_ADDR_NOT_SUPPORTED	0x08

#define SOCKS5_RSV						0x00



#define NGX_SOCKS_AUTH_BUFFER_LEN 100
#define NGX_SOCKS_PROXY_BUFFER_LEN 2048 

typedef struct socks5_method_req_s
{
    u_char ver;
    u_char nmethods;
}socks5_method_req_t;

typedef struct socks5_method_res_s
{
    u_char ver;
    u_char method;
}socks5_method_res_t;

typedef struct socks5_request_s
{
    u_char ver;
    u_char cmd;
    u_char rsv;
    u_char atype;
}socks5_request_t;

typedef socks5_request_t socks5_response_t;

#endif
