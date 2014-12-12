
/***********************************************
  File name		: ngx_socks_handler.c
  Create date	: 2014-03-17 21:55
  Modified date : 2014-12-13 04:17
  Author		: zmkeil, alibaba.inc
  Express : 
  
 **********************************************/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_socks.h>

static void ngx_socks_init_session(ngx_connection_t *c);

#define IS_CLIENT_CONNECTION 1
#define IS_SERVER_CONNECTION 2


/* lib */

void
ngx_socks_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;


	if(!c) {
		return;
	}

    c->destroyed = 1;
	
    pool = c->pool;

    ngx_close_connection(c);

	if(pool) {
		ngx_destroy_pool(pool);
	}
}

static u_char *
ngx_socks_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_socks_session_t  *s;
    ngx_socks_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, "server: %V",
                     s->addr_text);
    len -= p - buf;
    buf = p;

/*    if (s->login.len == 0) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", login: \"%V\"", &s->login);
    len -= p - buf;
    buf = p;

    if (s->proxy == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);
*/
    return p;
}

void
ngx_socks_finalize_session(ngx_socks_session_t *s, char *msg)
{
	ngx_connection_t	*c;
	ngx_connection_t 	*remote_c=NULL;

	c = s->connection;
	remote_c = s->r_connection;

    ngx_log_error(NGX_ERROR_ERR, c->log, 0,
                   "^^%s^^\tclose socks connection: %d.%d\t", msg, c->fd, remote_c ? remote_c->fd:-1);

	if(c) {
		ngx_socks_close_connection(c);
	}
	if(remote_c) {
		ngx_socks_close_connection(remote_c);
	}
}



/* phase handler */

void
ngx_socks_init_connection(ngx_connection_t *c)
{
    ngx_uint_t             i;
    ngx_socks_port_t       *port;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_socks_log_ctx_t    *ctx;
    ngx_socks_in_addr_t    *addr;
    ngx_socks_session_t    *s;
    ngx_socks_addr_conf_t  *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
    ngx_socks_in6_addr_t   *addr6;
#endif


    /* find the server configuration for the address:port */

    /* AF_INET only */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_socks_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_socks_session_t));
    if (s == NULL) {
        ngx_socks_close_connection(c);
        return;
    }
	memset(s,0,sizeof(ngx_socks_session_t));

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

	s->up_buf_wrap = 0;
	s->down_buf_wrap = 0;

    s->addr_text = &addr_conf->addr_text;
	s->auth_state = 0;

    c->data = s;
    s->connection = c;

    ngx_log_error(NGX_LOG_EMERG, c->log, 0, "*%ui client %V connected to games",
                  c->number, &c->addr_text);
ctx = ngx_palloc(c->pool, sizeof(ngx_socks_log_ctx_t));
    if (ctx == NULL) {
		ngx_socks_finalize_session(s, "ctx lloc error");
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_socks_log_error;
    c->log->data = ctx;
    c->log->action = "\t||AUTH||\t";

    c->log_error = NGX_ERROR_INFO;

    ngx_socks_init_session(c);
}

static void
ngx_socks_init_session(ngx_connection_t *c)
{
    ngx_socks_session_t        *s;
	ngx_socks_core_srv_conf_t  *cscf;

    s = c->data;
    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

	s->upstream = ngx_create_temp_buf(c->pool, NGX_SOCKS_PROXY_BUFFER_LEN);
	s->downstream = ngx_create_temp_buf(c->pool, NGX_SOCKS_PROXY_BUFFER_LEN);

	s->in.data = ngx_pcalloc(c->pool, NGX_SOCKS_AUTH_BUFFER_LEN);
	s->in.len = 0;
	s->out.data = ngx_pcalloc(c->pool, NGX_SOCKS_AUTH_BUFFER_LEN);
	s->out.len = 0;
//	s->proxy_data.data = ngx_pcalloc(c->pool, 1000);
    if (s->in.data == NULL || s->out.data == NULL) {
		ngx_socks_finalize_session(s, "proxy_data lloc error");
        return;
    }

	ngx_log_error(NGX_ERROR_ERR,c->log,0,"first come into auth");

    c->write->handler = ngx_socks_send;
	c->read->handler = ngx_socks_process_negotiate;
	ngx_add_timer(c->read, cscf->timeout);
	ngx_socks_process_negotiate(c->read);

}

void
ngx_socks_recv_proxy(ngx_event_t *rev) 
{
	ngx_int_t				len, n;
	ngx_connection_t		*c;
	ngx_connection_t		*other_c = NULL;
	ngx_socks_session_t		*s;
	ngx_buf_t				*buf=NULL;
	ngx_int_t				cs_flag=0;
	unsigned				*buf_wrap=NULL;

    ngx_socks_core_srv_conf_t  *cscf;

	c = rev->data;
	s = c->data;
	if(c == s->connection) {
		other_c = s->r_connection;
		buf = s->upstream;
		cs_flag = IS_CLIENT_CONNECTION;
		buf_wrap = &s->up_buf_wrap;
		ngx_log_error(NGX_ERROR_ERR,c->log,0,"client connection recv");
	}
	else if(c == s->r_connection) {
		other_c = s->connection;
		buf = s->downstream;
		cs_flag = IS_SERVER_CONNECTION;
		buf_wrap = &s->down_buf_wrap;
		ngx_log_error(NGX_ERROR_ERR,c->log,0,"remote connection recv");
	}

	if(other_c == NULL) {
		ngx_socks_finalize_session(s, "no other connection");
	}

	ngx_log_error(NGX_ERROR_ERR,c->log,0,"proxy after auth");

    if (rev->timedout) {
        c->timedout = 1;
		ngx_socks_finalize_session(s, "proxy one end timed out");
        return;
    }

	for(;;) 
	{
		if(!(*buf_wrap)) {
			len = buf->end - buf->last;
		} else if(*buf_wrap) {
			len = buf->pos - buf->last;
		}

		if(len == 0) {
			ngx_socks_send_proxy(other_c->write);

			if (ngx_handle_read_event(rev, 0) != NGX_OK) {
				ngx_socks_finalize_session(s, "server internal error");
			}
			return;
		}

		n = c->recv(c, buf->last, len);

		if(n == NGX_AGAIN) {
			if (!rev->timer_set) {
				cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
				ngx_add_timer(rev, cscf->timeout);
			}

			if (ngx_handle_read_event(rev, 0) != NGX_OK) {
				ngx_socks_finalize_session(s, "server internal error");
			}
			return;
		}

		if(n == 0) {
			(cs_flag == IS_CLIENT_CONNECTION) ? (s->c_halfshut = 1) : (s->s_halfshut = 1);
			ngx_socks_send_proxy(other_c->write);
			return;
		}

		if(n == NGX_ERROR) {
			c->error = 1;
			ngx_socks_finalize_session(s, "read error from one end");
			return;
		}

		buf->last += n;
		c->received += n;
		if(buf->last == buf->end) {
			buf->last = buf->start;
			*buf_wrap = 1;
		}
		ngx_socks_send_proxy(other_c->write);

		/* next loop */
	}

}

void
ngx_socks_send_proxy(ngx_event_t *wev)
{
    ngx_int_t                  len, n;
    ngx_connection_t          *c, *other_c=NULL;
    ngx_socks_session_t        *s;
    ngx_socks_core_srv_conf_t  *cscf;

	ngx_buf_t					*buf=NULL;
	ngx_int_t					cs_flag=0;
	unsigned					*buf_wrap=NULL;


    c = wev->data;
    s = c->data;

	if(c == s->connection) {
		other_c = s->r_connection;
		buf = s->downstream;
		cs_flag = IS_CLIENT_CONNECTION;
		buf_wrap = &(s->down_buf_wrap);
		ngx_log_error(NGX_ERROR_ERR,c->log,0,"send to client");
	}
	else if(c == s->r_connection) {
		other_c = s->connection;
		buf = s->upstream;
		cs_flag = IS_SERVER_CONNECTION;
		buf_wrap = &(s->up_buf_wrap);
		ngx_log_error(NGX_ERROR_ERR,c->log,0,"send to remote");
	}

	if(other_c == NULL) {
		ngx_socks_finalize_session(s, "no other connection");
	}

	if (wev->timedout) {
		ngx_log_error(NGX_ERROR_ERR, c->log, 0, "send timeout");
		c->timedout = 1;
		/* send timeout means peer network bad */
		ngx_socks_finalize_session(s, "send timeout");
		return;
	}

	for(;;) 
	{
		/* pos follow last */
		if(!(*buf_wrap)) {
			len = buf->last - buf->pos;
		} else if(*buf_wrap) {
			len = buf->end - buf->pos;
		}

		if (len == 0) {
			ngx_log_error(NGX_ERROR_ERR, c->log, 0, "sned len = 0");
			//		ngx_socks_recv_proxy(other_c->read);
			if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
				ngx_socks_finalize_session(s, "inter error");
			}

			return;
		}

		ngx_log_error(NGX_ERROR_ERR,c->log,0,"send proxy data to other end");
		n = c->send(c, buf->pos, len);

		if (n == NGX_ERROR) {
			ngx_socks_finalize_session(s, "inter error");
			return;
		}

		if(n == NGX_AGAIN) {
			cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
			ngx_add_timer(c->write, cscf->timeout);

			if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
				ngx_socks_finalize_session(s, "inter error");
			}
			return;

		}

		/* n > 0 , NGX_OK */
		buf->pos += n;
		if(buf->pos == buf->end) {
			buf->pos = buf->start;
			*buf_wrap = 0;
		}

		if(buf->pos == buf->last) {
			if((cs_flag == IS_CLIENT_CONNECTION && s->s_halfshut) \
					|| (cs_flag == IS_SERVER_CONNECTION && s->c_halfshut)) {
				if(s->s_halfshut && s->c_halfshut) {
					ngx_socks_finalize_session(s, "session over");
					return;
				}
				ngx_close_connection(c);
				return;
			}
		}

		/*next loop */
	}
}


