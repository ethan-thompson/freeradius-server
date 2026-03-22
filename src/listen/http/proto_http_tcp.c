/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file proto_http_tcp.c
 * @brief HTTP handler for TCP.
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Ethan Thompson (ethan.thompson@inkbridge.io)
 */

#include <netdb.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include "proto_http.h"

extern fr_app_io_t proto_http_tcp;

typedef struct {
	char const			*name;			//!< Socket name, used for logging.
	int				sockfd;

	fr_io_address_t			*connection;		//!< For connected (child) sockets.

	fr_stats_t			stats;			//!< Statistics for this socket.
} proto_http_tcp_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< Our configuration section.

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< Maximum HTTP message size.
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes.

	uint16_t			port;			//!< Port to listen on.

	bool				recv_buff_is_set;	//!< Whether we were provided with a recv_buff.
	bool				dynamic_clients;	//!< Whether we have dynamic clients.

	fr_client_list_t		*clients;		//!< Local clients.

	fr_trie_t			*trie;			//!< For parsed networks.
	fr_ipaddr_t			*allow;			//!< Allowed networks for dynamic clients.
	fr_ipaddr_t			*deny;			//!< Denied networks for dynamic clients.

	bool				read_hexdump;		//!< Hexdump received packets.
	bool				write_hexdump;		//!< Hexdump sent packets.
} proto_http_tcp_t;

static const conf_parser_t networks_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("allow", FR_TYPE_COMBO_IP_PREFIX, CONF_FLAG_MULTI, proto_http_tcp_t, allow) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("deny",  FR_TYPE_COMBO_IP_PREFIX, CONF_FLAG_MULTI, proto_http_tcp_t, deny)  },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t tcp_listen_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr",   FR_TYPE_COMBO_IP_ADDR, 0, proto_http_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR,     0, proto_http_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR,     0, proto_http_tcp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", proto_http_tcp_t, interface) },
	{ FR_CONF_OFFSET("port_name", proto_http_tcp_t, port_name) },

	{ FR_CONF_OFFSET("port", proto_http_tcp_t, port), .dflt = "80" },
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, proto_http_tcp_t, recv_buff) },

	{ FR_CONF_OFFSET("dynamic_clients", proto_http_tcp_t, dynamic_clients) },
	{ FR_CONF_POINTER("networks", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", proto_http_tcp_t, max_packet_size), .dflt = "65536" },
	{ FR_CONF_OFFSET("max_attributes",  proto_http_tcp_t, max_attributes),  .dflt = "256"   },

	{ FR_CONF_OFFSET("read_hexdump",  proto_http_tcp_t, read_hexdump)  },
	{ FR_CONF_OFFSET("write_hexdump", proto_http_tcp_t, write_hexdump) },

	CONF_PARSER_TERMINATOR
};

/** Read a complete HTTP message from the TCP socket
 *
 * HTTP is a text framing protocol — there is no fixed-size binary header to
 * tell us how long the message is.  Instead we buffer data until we find the
 * blank line that ends the headers (\r\n\r\n), parse any Content-Length, and
 * only then return the complete message to the caller.
 *
 * @param[in]  li		Listen instance.
 * @param[in]  packet_ctx	UNUSED.
 * @param[out] recv_time_p	When we read the data.
 * @param[out] buffer		Buffer to read into.
 * @param[in]  buffer_len	Maximum length of the buffer.
 * @param[in,out] leftover	Bytes already in the buffer from a previous partial read.
 * @return
 *	- > 0  complete message length (bytes to hand to mod_decode).
 *	- 0    partial message; will be called again when more data arrives.
 *	- < 0  error; the connection should be closed.
 */
static ssize_t mod_read(fr_listen_t *li, UNUSED void **packet_ctx, fr_time_t *recv_time_p,
			uint8_t *buffer, size_t buffer_len, size_t *leftover)
{
	proto_http_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_http_tcp_thread_t);
	ssize_t			 data_size, packet_len;
	size_t			 in_buffer;

	/*
	 *	If we already have data in the buffer from a previous read,
	 *	check whether it already contains a complete HTTP message
	 *	before attempting another read.
	 */
	if (*leftover > 0) {
		packet_len = fr_http_length(buffer, *leftover);
		if (packet_len < 0) goto invalid;
		if (packet_len > 0 && packet_len <= (ssize_t)*leftover) {
			data_size = 0;
			goto have_packet;
		}
	}

	/*
	 *	Read more data from the network.
	 */
	data_size = read(thread->sockfd, buffer + (*leftover), buffer_len - (*leftover));
	if (data_size < 0) {
		switch (errno) {
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
		case EWOULDBLOCK:
#endif
		case EAGAIN:
			return 0;

		default:
			break;
		}

		ERROR("proto_http_tcp got read error (%zd) - %s", data_size, fr_syserror(errno));
		return data_size;
	}

	if (!data_size) {
		DEBUG2("proto_http_tcp - other side closed the socket.");
		return -1;
	}

have_packet:
	in_buffer = *leftover + data_size;

	packet_len = fr_http_length(buffer, in_buffer);
	if (packet_len < 0) {
	invalid:
		PERROR("Invalid HTTP message");
		return -1;
	}

	/*
	 *	The complete message (headers + body) would exceed max_packet_size.
	 *	Send 413 Content Too Large and close the connection (RFC 9110 §15.5.14).
	 */
	if (packet_len > 0 && (size_t)packet_len > buffer_len) {
		proto_http_tcp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_http_tcp_t);
		static char const	 too_large[] = "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

		ERROR("proto_http_tcp - request too large (%zd bytes, max_packet_size %u)",
		      packet_len, inst->max_packet_size);
		if (write(thread->sockfd, too_large, sizeof(too_large) - 1) < 0) {
			WARN("proto_http_tcp - failed sending 413 response: %s", fr_syserror(errno));
		}
		return -1;
	}

	/*
	 *	Headers haven't arrived yet, or the body is still incomplete.
	 *	Tell the framework to call us again when more data arrives.
	 */
	if (packet_len == 0 || (size_t)packet_len > in_buffer) {
		*leftover = in_buffer;
		DEBUG3("proto_http_tcp - Received fragment (%zu bytes buffered)", in_buffer);
		return 0;
	}

	/*
	 *	We have at least one complete message.  Leave any remaining
	 *	bytes in the buffer for the next call.
	 */
	*leftover = in_buffer - packet_len;

	*recv_time_p = fr_time();
	thread->stats.total_requests++;

	FR_PROTO_HEX_DUMP(buffer, packet_len, "http_tcp_recv");

	if (DEBUG_ENABLED2) {
		/* Print the first line of the request for quick identification */
		uint8_t const *nl = memchr(buffer, '\r', packet_len < 128 ? packet_len : 128);
		int first_line_len = nl ? (int)(nl - buffer) : (int)packet_len;

		DEBUG2("proto_http_tcp - Received request \"%.*s\" length %zd %s",
		       first_line_len, (char const *)buffer,
		       packet_len, thread->name);
	}

	return packet_len;
}

static ssize_t mod_write(fr_listen_t *li, UNUSED void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	proto_http_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_http_tcp_thread_t);
	ssize_t			 data_size;

	fr_assert(written < buffer_len);
	fr_assert(buffer_len < (1 << 20)); /* shut up coverity */

	if (written == 0) {
		thread->stats.total_responses++;
	}

	data_size = write(thread->sockfd, buffer + written, buffer_len - written);
	if (data_size <= 0) return data_size;

	fr_assert((size_t)data_size <= buffer_len); /* shut up coverity */

	/* coverity[return_overflow] */
	return data_size + written;
}

static int mod_connection_set(fr_listen_t *li, fr_io_address_t *connection)
{
	proto_http_tcp_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_http_tcp_thread_t);

	thread->connection = connection;

	return 0;
}

static void mod_network_get(int *ipproto, bool *dynamic_clients, fr_trie_t const **trie, void *instance)
{
	proto_http_tcp_t *inst = talloc_get_type_abort(instance, proto_http_tcp_t);

	*ipproto         = IPPROTO_TCP;
	*dynamic_clients = inst->dynamic_clients;
	*trie            = inst->trie;
}

/** Open a TCP listener for HTTP
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_http_tcp_t const		*inst   = talloc_get_type_abort_const(li->app_io_instance, proto_http_tcp_t);
	proto_http_tcp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_http_tcp_thread_t);

	int		 sockfd;
	fr_ipaddr_t	 ipaddr = inst->ipaddr;
	uint16_t	 port   = inst->port;

	fr_assert(!thread->connection);

	li->fd = sockfd = fr_socket_server_tcp(&inst->ipaddr, &port, inst->port_name, true);
	if (sockfd < 0) {
		cf_log_err(li->cs, "Failed opening TCP socket - %s", fr_strerror());
	error:
		return -1;
	}

	(void) fr_nonblock(sockfd);

	if (fr_socket_bind(sockfd, inst->interface, &ipaddr, &port) < 0) {
		close(sockfd);
		cf_log_err(li->cs, "Failed binding to socket - %s", fr_strerror());
		cf_log_err(li->cs, DOC_ROOT_REF(troubleshooting/network/bind));
		goto error;
	}

	if (listen(sockfd, 8) < 0) {
		close(sockfd);
		cf_log_err(li->cs, "Failed listening on socket - %s", fr_syserror(errno));
		goto error;
	}

	thread->sockfd = sockfd;

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));

	thread->name = fr_app_io_socket_name(thread, &proto_http_tcp,
					     NULL, 0,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}

/** Set the file descriptor for a connected (child) socket.
 *
 */
static int mod_fd_set(fr_listen_t *li, int fd)
{
	proto_http_tcp_t const		*inst   = talloc_get_type_abort_const(li->app_io_instance, proto_http_tcp_t);
	proto_http_tcp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_http_tcp_thread_t);

	thread->sockfd = fd;

	thread->name = fr_app_io_socket_name(thread, &proto_http_tcp,
					     &thread->connection->socket.inet.src_ipaddr,
					     thread->connection->socket.inet.src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}

static char const *mod_name(fr_listen_t *li)
{
	proto_http_tcp_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_http_tcp_thread_t);

	return thread->name;
}

static void mod_hexdump_set(fr_listen_t *li, void *data)
{
	proto_http_tcp_t *inst = talloc_get_type_abort(data, proto_http_tcp_t);

	li->read_hexdump  = inst->read_hexdump;
	li->write_hexdump = inst->write_hexdump;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_http_tcp_t	*inst = talloc_get_type_abort(mctx->mi->data, proto_http_tcp_t);
	CONF_SECTION		*conf = mctx->mi->conf;
	size_t			 num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;

	inst->cs = conf;

	if (inst->ipaddr.af == AF_UNSPEC) {
		cf_log_err(conf, "No 'ipaddr' was specified in the 'tcp' section");
		return -1;
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 512);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 1048576);

	if (!inst->port) {
		struct servent *s;

		if (!inst->port_name) {
			cf_log_err(conf, "No 'port' was specified in the 'tcp' section");
			return -1;
		}

		s = getservbyname(inst->port_name, "tcp");
		if (!s) {
			cf_log_err(conf, "Unknown value for 'port_name = %s", inst->port_name);
			return -1;
		}

		inst->port = ntohs(s->s_port);
	}

	/*
	 *	Parse and create the trie for dynamic clients.
	 */
	num = talloc_array_length(inst->allow);
	if (!num) {
		if (inst->dynamic_clients) {
			cf_log_err(conf, "The 'allow' subsection MUST contain at least one 'network' entry when 'dynamic_clients = true'.");
			return -1;
		}
	} else {
		inst->trie = fr_master_io_network(inst, inst->ipaddr.af, inst->allow, inst->deny);
		if (!inst->trie) {
			cf_log_perr(conf, "Failed creating list of networks");
			return -1;
		}
	}

	ci = cf_section_to_item(mctx->mi->parent->conf); /* listen { ... } */
	fr_assert(ci != NULL);
	ci = cf_parent(ci);
	fr_assert(ci != NULL);

	server_cs = cf_item_to_section(ci);

	if (cf_section_find_next(server_cs, NULL, "client", CF_IDENT_ANY)) {
		inst->clients = client_list_parse_section(server_cs, IPPROTO_TCP, false);
		if (!inst->clients) {
			cf_log_err(conf, "Failed creating local clients");
			return -1;
		}
	}

	return 0;
}

static fr_client_t *mod_client_find(fr_listen_t *li, fr_ipaddr_t const *ipaddr, int ipproto)
{
	proto_http_tcp_t const *inst = talloc_get_type_abort_const(li->app_io_instance, proto_http_tcp_t);

	if (inst->clients) {
		fr_client_t *client;

		client = client_find(inst->clients, ipaddr, ipproto);
		if (client) return client;
	}

	return client_find(NULL, ipaddr, ipproto);
}

fr_app_io_t proto_http_tcp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "http_tcp",
		.config			= tcp_listen_config,
		.inst_size		= sizeof(proto_http_tcp_t),
		.thread_inst_size	= sizeof(proto_http_tcp_thread_t),
		.instantiate		= mod_instantiate,
	},
	.default_message_size	= 65536,
	.track_duplicates	= false,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
	.get_name		= mod_name,
	.hexdump_set		= mod_hexdump_set,
};
