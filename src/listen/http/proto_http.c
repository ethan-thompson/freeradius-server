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
 * @file proto_http.c
 * @brief HTTP protocol handler.
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Ethan Thompson (ethan.thompson@inkbridge.io)
 */

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/http/http.h>

#include "proto_http.h"

extern fr_app_t proto_http;

static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int type_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule);

static conf_parser_t const limit_config[] = {
	{ FR_CONF_OFFSET("idle_timeout", proto_http_t, io.idle_timeout), .dflt = "30.0" },
	{ FR_CONF_OFFSET("dynamic_timeout", proto_http_t, io.dynamic_timeout), .dflt = "600.0" },

	{ FR_CONF_OFFSET("max_connections", proto_http_t, io.max_connections), .dflt = "1024" },

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", proto_http_t, max_packet_size) },
	{ FR_CONF_OFFSET("num_messages", proto_http_t, num_messages) },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const priority_config[] = {
	{ FR_CONF_OFFSET("GET", proto_http_t, priorities[FR_HTTP_GET]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("POST", proto_http_t, priorities[FR_HTTP_POST]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("PUT", proto_http_t, priorities[FR_HTTP_PUT]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("DELETE", proto_http_t, priorities[FR_HTTP_DELETE]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("PATCH", proto_http_t, priorities[FR_HTTP_PATCH]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("HEAD", proto_http_t, priorities[FR_HTTP_HEAD]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("OPTIONS", proto_http_t, priorities[FR_HTTP_OPTIONS]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const proto_http_config[] = {
	{ FR_CONF_OFFSET_FLAGS("type", CONF_FLAG_NOT_EMPTY, proto_http_t, allowed_types), .func = type_parse },
	{ FR_CONF_OFFSET_TYPE_FLAGS("transport", FR_TYPE_VOID, 0, proto_http_t, io.submodule), .func = transport_parse },

	{ FR_CONF_POINTER("limit", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) limit_config },
	{ FR_CONF_POINTER("priority", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) priority_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_http;

extern fr_dict_autoload_t proto_http_dict[];
fr_dict_autoload_t proto_http_dict[] = {
	{ .out = &dict_http, .proto = "http" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_http_request;
static fr_dict_attr_t const *attr_http_request_method;

extern fr_dict_attr_autoload_t proto_http_dict_attr[];
fr_dict_attr_autoload_t proto_http_dict_attr[] = {
	{ .out = &attr_packet_type,		.name = "Packet-Type",		.type = FR_TYPE_UINT32, .dict = &dict_http },
	{ .out = &attr_http_request,	.name = "Request",		.type = FR_TYPE_STRUCT, .dict = &dict_http },
	{ .out = &attr_http_request_method,	.name = "Request.Method",	.type = FR_TYPE_UINT32, .dict = &dict_http },
	DICT_AUTOLOAD_TERMINATOR
};

static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	proto_http_t		*inst = talloc_get_type_abort(parent, proto_http_t);
	module_instance_t	*mi;

	if (unlikely(virtual_server_listen_transport_parse(ctx, out, parent, ci, rule) < 0)) {
		return -1;
	}

	mi = talloc_get_type_abort(*(void **)out, module_instance_t);
	inst->io.app_io = (fr_app_io_t const *)mi->exported;
	inst->io.app_io_instance = mi->data;
	inst->io.app_io_conf = mi->conf;

	return 0;
}

/** Translates the packet-type string into an entry in the allowed[] array
 *
 * @param[in] ctx	to allocate data in (instance of proto_http).
 * @param[out] out	Where to write a module_instance_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	proto_http_t			*inst = talloc_get_type_abort(parent, proto_http_t);
	fr_dict_enum_value_t const	*dv;
	CONF_PAIR			*cp;
	char const			*value;

	cp = cf_item_to_pair(ci);
	value = cf_pair_value(cp);

	dv = fr_dict_enum_by_name(attr_packet_type, value, -1);
	if (!dv || !FR_HTTP_PACKET_CODE_VALID(dv->value->vb_uint32) ||
	    dv->value->vb_uint32 >= FR_HTTP_CODE_MAX) {
		cf_log_err(ci, "Unknown HTTP packet type '%s'", value);
		return -1;
	}

	inst->allowed[dv->value->vb_uint32] = true;
	*((char const **) out) = value;

	return 0;
}

/** Decode the packet
 *
 */
static int mod_decode(UNUSED void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const	*address = track->address;
	fr_client_t const	*client;
	fr_pair_t		*request_vp, *method_vp;

	RHEXDUMP3(data, data_len, "proto_http decode packet");

	client = address->radclient;

	request->packet->id      = 0; /* HTTP has no packet ID */
	request->packet->data    = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	/*
	 *	Unlike encrypted protocols (e.g. TACACS+), HTTP is plaintext —
	 *	we can always decode the packet regardless of whether the client
	 *	is known yet.
	 */
	if (fr_http_decode(request->request_ctx, &request->request_pairs,
			   request->packet->data, request->packet->data_len, NULL) < 0) {
		RPEDEBUG("Failed decoding HTTP request from %s", client->longname);
		return -1;
	}

	/*
	 *	Synthesize Packet-Type from Request.Method.
	 *	The method enum values (GET=1..TRACE=9) are the same as
	 *	the fr_http_packet_code_t values.
	 */
	request_vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_http_request);
	if (!request_vp) {
		REDEBUG("Missing Request struct after decode");
		return -1;
	}

	method_vp = fr_pair_find_by_da(&request_vp->vp_group, NULL, attr_http_request_method);
	if (!method_vp) {
		REDEBUG("Missing Request.Method after decode");
		return -1;
	}

	request->packet->code = method_vp->vp_uint32;

	/*
	 *	If this is a dynamic client, let the framework know so it can
	 *	run the new-client virtual server section.  We still decoded
	 *	the full request above so the policy has something to work with.
	 */
	if (!client->active) {
		fr_assert(client->dynamic);
		request_set_dynamic_client(request);
	}

	request->client = UNCONST(fr_client_t *, client);

	request->packet->socket = address->socket;
	fr_socket_addr_swap(&request->reply->socket, &address->socket);

	REQUEST_VERIFY(request);

	if (RDEBUG_ENABLED) {
		uint32_t code = request->packet->code;

		RDEBUG("Received %s from %pV:%i to %pV:%i length %zu via socket %s",
		       (code < FR_HTTP_CODE_MAX && fr_http_packet_names[code]) ? fr_http_packet_names[code] : "unknown",
		       fr_box_ipaddr(request->packet->socket.inet.src_ipaddr),
		       request->packet->socket.inet.src_port,
		       fr_box_ipaddr(request->packet->socket.inet.dst_ipaddr),
		       request->packet->socket.inet.dst_port,
		       request->packet->data_len,
		       request->async->listen->name);

		log_request_pair_list(L_DBG_LVL_1, request, NULL, &request->request_pairs, NULL);
	}

	if (fr_packet_pairs_from_packet(request->request_ctx, &request->request_pairs, request->packet) < 0) {
		RPEDEBUG("Failed decoding 'Net.*' packet");
		return -1;
	}

	return 0;
}

static ssize_t mod_encode(UNUSED void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
	fr_io_track_t		*track = talloc_get_type_abort(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const	*address = track->address;
	fr_client_t const	*client;
	fr_dbuff_t		dbuff;
	ssize_t			data_len;
	fr_http_ctx_t		encode_ctx = {};

	/*
	 *	Process layer NAK, or "Do not respond".
	 *
	 *	Note: FR_HTTP_DO_NOT_RESPOND is considered a valid code by
	 *	FR_HTTP_PACKET_CODE_VALID (it is a legitimate dictionary value),
	 *	so we must check for it explicitly before the validity test.
	 */
	if ((buffer_len == 1) ||
	    (request->reply->code == FR_HTTP_DO_NOT_RESPOND) ||
	    !FR_HTTP_PACKET_CODE_VALID(request->reply->code)) {
		track->do_not_respond = true;
		return 1;
	}

	client = address->radclient;
	fr_assert(client);

	/*
	 *	Dynamic client stuff.
	 */
	if (client->dynamic && !client->active) {
		fr_client_t *new_client;

		fr_assert(buffer_len >= sizeof(client));

		new_client = client_afrom_request(NULL, request);
		if (!new_client) {
			PERROR("Failed creating new client");
			buffer[0] = true;
			return 1;
		}

		memcpy(buffer, &new_client, sizeof(new_client));
		return sizeof(new_client);
	}

	fr_dbuff_init(&dbuff, buffer, buffer_len);

	/*
	 *	Pass the request method to the encoder so it can suppress the
	 *	body for HEAD responses (RFC 9110 §9.3.2).
	 */
	{
		fr_pair_t *request_vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_http_request);
		if (request_vp) {
			fr_pair_t *method_vp = fr_pair_find_by_da(&request_vp->vp_group, NULL, attr_http_request_method);
			if (method_vp) encode_ctx.request_method = (fr_http_packet_code_t)method_vp->vp_uint32;
		}
	}

	data_len = fr_http_encode(&dbuff, &request->reply_pairs, &encode_ctx);
	if (data_len < 0) {
		RPEDEBUG("Failed encoding HTTP reply");
		return -1;
	}

	if (RDEBUG_ENABLED) {
		uint32_t code = request->reply->code;

		RDEBUG("Sending %s from %pV:%i to %pV:%i length %zu via socket %s",
		       (code < FR_HTTP_CODE_MAX && fr_http_packet_names[code]) ? fr_http_packet_names[code] : "response",
		       fr_box_ipaddr(request->reply->socket.inet.src_ipaddr),
		       request->reply->socket.inet.src_port,
		       fr_box_ipaddr(request->reply->socket.inet.dst_ipaddr),
		       request->reply->socket.inet.dst_port,
		       data_len,
		       request->async->listen->name);

		log_request_proto_pair_list(L_DBG_LVL_1, request, NULL, &request->reply_pairs, NULL);
	}

	RHEXDUMP3(buffer, data_len, "proto_http encode packet");

	return data_len;
}

static int mod_priority_set(void const *instance, uint8_t const *buffer, size_t buflen)
{
	proto_http_t const	*inst = talloc_get_type_abort_const(instance, proto_http_t);
	uint8_t const		*sp;
	fr_http_packet_code_t	 code;

	if (!buflen) return 0;

	/*
	 *	Peek at the first token (up to the first space) to get the method.
	 *	The longest method name is "OPTIONS" (7 bytes), so 16 is plenty.
	 */
	sp = memchr(buffer, ' ', buflen < 16 ? buflen : 16);
	if (!sp) return 0;

	code = fr_table_value_by_substr(fr_http_method_table, (char const *)buffer, sp - buffer, FR_HTTP_UNKNOWN);
	if (code == FR_HTTP_UNKNOWN || code >= FR_HTTP_CODE_MAX) return 0;

	if (!inst->priorities[code]) return 0;

	return inst->priorities[code];
}

/** Open listen sockets/connect to external event source
 *
 * @param[in] instance	Ctx data for this application.
 * @param[in] sc	to add our file descriptor to.
 * @param[in] conf	Listen section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_open(void *instance, fr_schedule_t *sc, UNUSED CONF_SECTION *conf)
{
	proto_http_t *inst = talloc_get_type_abort(instance, proto_http_t);

	inst->io.app = &proto_http;
	inst->io.app_instance = instance;

	return fr_master_io_listen(&inst->io, sc, inst->max_packet_size, inst->num_messages);
}

/** Instantiate the application
 *
 * Instantiate I/O and type submodules.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_http_t *inst = talloc_get_type_abort(mctx->mi->data, proto_http_t);

	inst->io.server_cs = cf_item_to_section(cf_parent(mctx->mi->conf));

	fr_assert(dict_http != NULL);

	if (!inst->io.submodule) return 0;

	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, <=, fr_time_delta_from_sec(600));

	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, <=, fr_time_delta_from_sec(600));

	inst->io.app = &proto_http;
	inst->io.app_instance = inst;

	inst->io.mi = mctx->mi;

	if (!inst->max_packet_size && inst->io.app_io) inst->max_packet_size = inst->io.app_io->default_message_size;

	if (!inst->num_messages) inst->num_messages = 256;

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 32);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 1024);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	if (module_instantiate(inst->io.submodule) < 0) return -1;

	return fr_master_app_io.common.instantiate(MODULE_INST_CTX(inst->io.mi));
}

static int mod_load(void)
{
	if (fr_http_global_init() < 0) {
		PERROR("Failed initialising HTTP");
		return -1;
	}

	return 0;
}

static void mod_unload(void)
{
	fr_http_global_free();
}

fr_app_t proto_http = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "http",
		.config			= proto_http_config,
		.inst_size		= sizeof(proto_http_t),

		.onload			= mod_load,
		.unload			= mod_unload,
		.instantiate		= mod_instantiate
	},
	.dict			= &dict_http,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.priority		= mod_priority_set
};
