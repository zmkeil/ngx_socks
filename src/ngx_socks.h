
#ifndef _NGX_SOCKS_H_INCLUDED_
#define _NGX_SOCKS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_socks_protocol.h>

/* config file , the key directives */

#define NGX_SOCKS_MODULE         0x70785544/* SOCKS */

#define NGX_SOCKS_MAIN_CONF      0x02000000
#define NGX_SOCKS_SRV_CONF       0x04000000 
     
#define NGX_SOCKS_MAIN_CONF_OFFSET  offsetof(ngx_socks_conf_ctx_t, main_conf)
#define NGX_SOCKS_SRV_CONF_OFFSET   offsetof(ngx_socks_conf_ctx_t, srv_conf)

#define ngx_socks_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_socks_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_socks_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;

#define ngx_socks_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_socks_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_socks_conf_get_module_main_conf(cf, module)                       \
    ((ngx_socks_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_socks_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_socks_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

extern ngx_uint_t    ngx_socks_max_module;
extern ngx_module_t  ngx_socks_core_module;

typedef struct ngx_socks_listen_s ngx_socks_listen_t;  
typedef struct ngx_socks_conf_port_s ngx_socks_conf_port_t; 

typedef struct ngx_socks_conf_addr_s ngx_socks_conf_addr_t;
typedef struct ngx_socks_addr_conf_s ngx_socks_addr_conf_t;
typedef struct ngx_socks_in_addr_s ngx_socks_in_addr_t;
typedef struct ngx_socks_in6_addr_s ngx_socks_in6_addr_t;
typedef struct ngx_socks_port_s ngx_socks_port_t;


typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_socks_conf_ctx_t;


typedef struct {
    ngx_array_t             servers;     /* ngx_socks_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_socks_listen_t */
} ngx_socks_core_main_conf_t;


typedef struct {

    ngx_msec_t              timeout;
    ngx_msec_t              resolver_timeout;

    ngx_flag_t              so_keepalive;

    ngx_str_t               server_name;

    u_char                 *file_name;
    ngx_int_t               line;

    ngx_resolver_t         *resolver;

    /* server ctx */
    ngx_socks_conf_ctx_t    *ctx;
} ngx_socks_core_srv_conf_t;


typedef struct {

    void                       *(*create_main_conf)(ngx_conf_t *cf);
    char                       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(ngx_conf_t *cf);
    char                       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                      void *conf);
} ngx_socks_module_t;


struct ngx_socks_listen_s {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_socks_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_SOCKS_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
};


struct ngx_socks_conf_port_s {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_socks_conf_addr_t */
};


struct ngx_socks_conf_addr_s {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_socks_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_SOCKS_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} ;


struct ngx_socks_addr_conf_s {
    ngx_socks_conf_ctx_t    *ctx;
    ngx_str_t               addr_text;
#if (NGX_SOCKS_SSL)
    ngx_uint_t              ssl;    /* unsigned   ssl:1; */
#endif
} ;


struct ngx_socks_in_addr_s {
	in_addr_t               addr;
    ngx_socks_addr_conf_t    conf;
} ;


#if (NGX_HAVE_INET6)
struct ngx_socks_in6_addr_s {
    struct in6_addr         addr6;
    ngx_socks_addr_conf_t    conf;
} ;
#endif

struct ngx_socks_port_s {
    /* ngx_socks_in_addr_t or ngx_socks_in6_addr_t */
    void                   *addrs;
    ngx_uint_t              naddrs;
} ;





/* SOCKS5 related */

typedef struct ngx_socks_session_s ngx_socks_session_t;

typedef struct {
    ngx_str_t              *client;
    ngx_socks_session_t     *session;
} ngx_socks_log_ctx_t;

struct ngx_socks_session_s {
    ngx_connection_t       *connection;
	ngx_connection_t	   *r_connection;

	unsigned				c_halfshut;
	unsigned				s_halfshut;

    ngx_str_t               out;
	ngx_str_t				in;

	ngx_buf_t			   *upstream;		/* request from client */
	ngx_buf_t			   *downstream;		/* response from remote */

	unsigned				up_buf_wrap;
	unsigned				down_buf_wrap;

    void                  **main_conf;
    void                  **srv_conf;

	struct sockaddr_in      r_addr;
	ngx_int_t               r_addr_len;

    unsigned                blocked:1;
    unsigned                quit:1;
	unsigned				auth_state:2;

    ngx_str_t              *addr_text;
};


/* handle handshake */
void ngx_socks_send(ngx_event_t *wev);
void ngx_socks_process_negotiate(ngx_event_t *rev);

/* handle proxy */
void ngx_socks_send_proxy(ngx_event_t *wev);
void ngx_socks_recv_proxy(ngx_event_t *rev); 

/* lib func */
void ngx_socks_finalize_session(ngx_socks_session_t *s, char *msg);
void ngx_socks_close_connection(ngx_connection_t *c);


#endif
