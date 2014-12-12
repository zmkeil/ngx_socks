
/***********************************************
  File name		: ngx_socks_handshake.c
  Create date	: 2014-12-10 00:42
  Modified date : 2014-12-13 04:10
  Author		: zmkeil, alibaba.inc
  Express : 
  
 **********************************************/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_socks.h>

static ssize_t ngx_socks_parse_negotiate(ngx_socks_session_t *s);
static void ngx_socks_process_connect_remote(ngx_event_t *rev);
static ssize_t ngx_socks_parse_remote(ngx_socks_session_t *s);
static ssize_t ngx_socks_read_header(ngx_socks_session_t *s);

void
ngx_socks_process_negotiate(ngx_event_t *rev)
{
	ssize_t              n;   
	ngx_int_t            rc;
	ngx_connection_t     *c;  
	ngx_socks_session_t  *s;  

	c = rev->data;
	s = c->data;

	if (rev->timedout) {
		c->timedout = 1; 
		ngx_socks_finalize_session(s, "client timed out");
		return;
	}    

	rc = NGX_AGAIN;

	for ( ;; ) {

		if (rc == NGX_AGAIN) {
			n = ngx_socks_read_header(s);

			if (n == NGX_AGAIN || n == NGX_ERROR) {
				/* ERROR is processed in ngx_socks_read_header */
				return;
			}    
		}    

		rc = ngx_socks_parse_negotiate(s);

		if(rc == NGX_OK) {
			/* do huifu, and next rev->handler */			
			s->out.data[0] = 0x05;
			s->out.data[1] = 0x00;
			s->out.len = 2;
			ngx_socks_send(c->write);

			rev->handler = ngx_socks_process_connect_remote;
			ngx_socks_process_connect_remote(rev);
			return;
		}

		if(rc != NGX_AGAIN) {
			/* ERROR is processed in ngx_socks_parse_negotiate */
			return;
		}

		/* NGX_AGAIN, next loop */
	}
}


static ssize_t
ngx_socks_parse_negotiate(ngx_socks_session_t *s)
{
	u_char			*start;
	ngx_int_t		ret, i;

	i = s->in.len;
	if(i < 2)
		return NGX_AGAIN;

	start = s->in.data - s->in.len;

	if(((socks5_method_req_t *)start)->ver != SOCKS5_VERSION) {
		ngx_socks_finalize_session(s, "versin not support");
		return NGX_ERROR;
	}	

	ret = ((socks5_method_req_t *)start)->nmethods;
	if(ret > i - 2)
		return NGX_AGAIN;
	for(i=2;i<=ret+1;i++) {
		if(start[i] == 0x00) {
			break;
		}
	}
	if(start[i] != 0x00) {
		ngx_socks_finalize_session(s, "auth not support");
		return NGX_ERROR;
	}
	
	/* SUCCEED, recover s->in */
	s->in.data -= s->in.len;
	s->in.len = 0;
	return NGX_OK;
}

static void
ngx_socks_process_connect_remote(ngx_event_t *rev)
{
	ssize_t              n;   
	ngx_int_t            rc, rv;
	ngx_connection_t     *c, *remote_c;  
	ngx_socks_session_t  *s;  
	ngx_socket_t       		remote;
    ngx_socks_core_srv_conf_t  *cscf;

	c = rev->data;
	s = c->data;

	if (rev->timedout) {
		c->timedout = 1; 
		ngx_socks_finalize_session(s, "client timed out");
		return;
	}    

	rc = NGX_AGAIN;

	for ( ;; ) {

		if (rc == NGX_AGAIN) {
			n = ngx_socks_read_header(s);

			if (n == NGX_AGAIN || n == NGX_ERROR) {
				return;
			}    
		}    

		rc = ngx_socks_parse_remote(s);

		/* SUCCEED parse, come into proxy state */
		if(rc == NGX_OK) {
			remote = ngx_socket(AF_INET, SOCK_STREAM, 0);
			if (remote == -1) {
				ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
						ngx_socket_n " failed");
				ngx_socks_finalize_session(s, "r_socket err");
				return;
			}
			remote_c = ngx_get_connection(remote, c->log); 
			if (remote_c == NULL) {
				if (ngx_close_socket(remote) == -1) {
					ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
							ngx_close_socket_n "failed");
					ngx_socks_finalize_session(s, "r_socket close err");
				}
				return;
			}

			remote_c->recv = ngx_unix_recv;
			remote_c->send = ngx_unix_send;
			remote_c->recv_chain = ngx_readv_chain;
			remote_c->send_chain = ngx_linux_sendfile_chain;

			remote_c->pool = c->pool;

			remote_c->data = s;
			s->r_connection = remote_c;

			if (ngx_nonblocking(remote) == -1) {
				ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
						ngx_nonblocking_n " failed");
				ngx_socks_finalize_session(s, "r_socket nonblock error");
				return;
			}
			/* set nonblock before connect */

			rv = connect(remote, (struct sockaddr *)&s->r_addr, sizeof(s->r_addr));
			if (rv == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
				ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
						"connect() failed");
				s->out.data[1] = SOCKS5_REP_GENERAL_FAILURE;
				s->out.len = 4;
			} else {
				memcpy(s->out.data + 4, &(s->r_addr.sin_addr.s_addr), 4);
				memcpy(s->out.data + 8, &(s->r_addr.sin_port), 2);
				s->out.len = 10;
			}

			ngx_socks_send(c->write);

			/* come into proxy state */
			c->read->handler = ngx_socks_recv_proxy;
			remote_c->read->handler = ngx_socks_recv_proxy;
			if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
				ngx_socks_finalize_session(s, "internal error");
			}
			if (ngx_handle_read_event(remote_c->read, 0) != NGX_OK) {
				ngx_socks_finalize_session(s, "internal error");
			}
			cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
			ngx_add_timer(c->read, cscf->timeout);
//			ngx_add_timer(remote_c->read, cscf->timeout);

			c->write->handler = ngx_socks_send_proxy;
			remote_c->write->handler = ngx_socks_send_proxy;
			c->log->action = "\t||PROXY||\t";
			return;
		}

		/* ERROR parse, send info, wait for next CONNECT|TYPE request */
		if(rc != NGX_AGAIN) {
			ngx_socks_send(c->write);

			if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
				ngx_socks_finalize_session(s, "internal error");
			
			return;
		}

		/* NGX_AGAIN, next loop */
		}
	}
}

static ssize_t
ngx_socks_parse_remote(ngx_socks_session_t *s)
{
	u_char				*start;
	ngx_connection_t 	*c;
	ngx_int_t			i;

	c = s->connection;
	start = s->in.data - s->in.len;

	i = s->in.len;
	if(i < 10)
		return NGX_AGAIN;

	((socks5_response_t *)s->out.data)->ver = SOCKS5_VERSION;
	((socks5_response_t *)s->out.data)->cmd = SOCKS5_REP_SUCCEED;
	((socks5_response_t *)s->out.data)->rsv = 0;
	((socks5_response_t *)s->out.data)->atype = SOCKS5_IPV4;

	if (SOCKS5_VERSION != ((socks5_request_t *)start)->ver
			|| SOCKS5_CMD_CONNECT != ((socks5_request_t *)start)->cmd)
	{
		((socks5_response_t *)s->out.data)->cmd = SOCKS5_REP_CMD_NOT_SUPPORTED;
		s->out.len = 4;
		s->in.data -= s->in.len;
		s->in.len = 0;
		return NGX_ERROR;
	}

	if (SOCKS5_IPV4 == ((socks5_request_t *)start)->atype)
	{
		bzero((char *)&s->r_addr, sizeof(struct sockaddr_in));
		s->r_addr.sin_family = AF_INET;

		ngx_memcpy(&(s->r_addr.sin_addr.s_addr), start + 4, 4);
		ngx_memcpy(&(s->r_addr.sin_port), start + 8, 2);
		ngx_log_error(NGX_ERROR_ERR,c->log,0,"remote IP:PORT = %s:%d.",inet_ntoa(s->r_addr.sin_addr), htons(s->r_addr.sin_port));		

		s->in.data -= s->in.len;
		s->in.len = 0;
		return NGX_OK;
	}
	else {
		((socks5_response_t *)s->out.data)->cmd = SOCKS5_REP_CMD_NOT_SUPPORTED;
		s->out.len = 4;
		s->in.data -= s->in.len;
		s->in.len = 0;
		return NGX_ERROR;
	}

	/* ERROR only set s->out, wait to be processed in ngx_socks_process_connect_remote */
}

static ssize_t
ngx_socks_read_header(ngx_socks_session_t *s)
{
	ssize_t                    n;
	ngx_event_t               *rev;
	ngx_connection_t          *c;
    ngx_socks_core_srv_conf_t  *cscf;

	c = s->connection;
	rev = c->read;

	n = s->in.len;

	if (n > 0) {
		return n;
	}

	if (rev->ready) {
		n = c->recv(c, s->in.data,
				NGX_SOCKS_AUTH_BUFFER_LEN - s->in.len);	
	} else {
		n = NGX_AGAIN;
	}

	if (n == NGX_AGAIN) {
		if (!rev->timer_set) {
			cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);
			ngx_add_timer(rev, cscf->timeout);
		}

		if (ngx_handle_read_event(rev, 0) != NGX_OK) {
			ngx_socks_finalize_session(s, "server internal error");
			return NGX_ERROR;
		}

		return NGX_AGAIN;
	}

	if (n == 0) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0,
				"client closed connection in auth state");
	}

	if (n == 0 || n == NGX_ERROR) {
		c->error = 1;
		ngx_socks_finalize_session(s, "read error or client close");
		return NGX_ERROR;
	}

	s->in.data += n;
	s->in.len += n;
	c->received += n;

	return n;
}


void
ngx_socks_send(ngx_event_t *wev)
{
    ngx_int_t                  n;
    ngx_connection_t          *c;
    ngx_socks_session_t        *s;
    ngx_socks_core_srv_conf_t  *cscf;

    c = wev->data;
    s = c->data;

    if (wev->timedout) {
        c->timedout = 1;
		ngx_socks_finalize_session(s, "send timeout client");
        return;
    }

    if (s->out.len == 0) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
			ngx_socks_finalize_session(s, "inter error");
        }

        return;
    }

    n = c->send(c, s->out.data, s->out.len);

    if (n > 0) {
        s->out.len -= n;
		s->out.data += n;

		if (s->out.len != 0) {
			goto again;
		}

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        if (s->quit) {
			ngx_socks_finalize_session(s, "inter error");
            return;
        }

        if (s->blocked) {
            c->read->handler(c->read);
        }

        return;
    }

    if (n == NGX_ERROR) {
		ngx_socks_finalize_session(s, "inter error");
        return;
    }

    /* n == NGX_AGAIN */

again:
    cscf = ngx_socks_get_module_srv_conf(s, ngx_socks_core_module);

    ngx_add_timer(c->write, cscf->timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
		ngx_socks_finalize_session(s, "inter error");
        return;
    }
}
