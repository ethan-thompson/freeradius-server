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
 * @file src/process/http/base.c
 * @brief HTTP request processing.
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Ethan Thompson (ethan.thompson@inkbridge.io)
 */
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/http/http.h>
#include <freeradius-devel/unlang/interpret.h>

static fr_dict_t const *dict_http;

extern fr_dict_autoload_t process_http_dict[];
fr_dict_autoload_t process_http_dict[] = {
	{ .out = &dict_http, .proto = "http" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_http_response;
static fr_dict_attr_t const *attr_http_response_version;
static fr_dict_attr_t const *attr_http_response_status_code;
static fr_dict_attr_t const *attr_http_response_reason_phrase;

extern fr_dict_attr_autoload_t process_http_dict_attr[];
fr_dict_attr_autoload_t process_http_dict_attr[] = {
	{ .out = &attr_packet_type,                .name = "Packet-Type",            .type = FR_TYPE_UINT32, .dict = &dict_http },
	{ .out = &attr_http_response,              .name = "Response",                .type = FR_TYPE_STRUCT, .dict = &dict_http },
	{ .out = &attr_http_response_version,      .name = "Response.Version",        .type = FR_TYPE_UINT8,  .dict = &dict_http },
	{ .out = &attr_http_response_status_code,  .name = "Response.Status-Code",    .type = FR_TYPE_UINT16, .dict = &dict_http },
	{ .out = &attr_http_response_reason_phrase,.name = "Response.Reason-Phrase",  .type = FR_TYPE_STRING, .dict = &dict_http },
	DICT_AUTOLOAD_TERMINATOR
};

typedef struct {
	uint64_t		nothing;		// so that the next field isn't at offset 0

	/** Request sections — one per HTTP method
	 */
	CONF_SECTION		*recv_get;
	CONF_SECTION		*recv_post;
	CONF_SECTION		*recv_put;
	CONF_SECTION		*recv_delete;
	CONF_SECTION		*recv_patch;
	CONF_SECTION		*recv_head;
	CONF_SECTION		*recv_options;
	CONF_SECTION		*recv_connect;
	CONF_SECTION		*recv_trace;

	/** Response sections — one per method response type
	 */
	CONF_SECTION		*send_get_response;
	CONF_SECTION		*send_post_response;
	CONF_SECTION		*send_put_response;
	CONF_SECTION		*send_delete_response;
	CONF_SECTION		*send_patch_response;
	CONF_SECTION		*send_head_response;
	CONF_SECTION		*send_options_response;

	CONF_SECTION		*do_not_respond;
} process_http_sections_t;

typedef struct {
	process_http_sections_t	sections;
} process_http_t;

#define PROCESS_PACKET_TYPE		fr_http_packet_code_t
#define PROCESS_CODE_MAX		FR_HTTP_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_HTTP_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_HTTP_PACKET_CODE_VALID
#define PROCESS_INST			process_http_t
#include <freeradius-devel/server/process.h>

/** Automatic HTTP Status-Code to set based on rlm_rcode_t.
 *
 * Only set if the operator hasn't already set Response.Status-Code.
 * 0 means "no automatic value" — the operator is expected to set it.
 *
 * ok/noop/updated default to 200 (RFC-conventional success).
 * Operators can override by setting Response.Status-Code before returning.
 */
static uint16_t const http_auto_status[RLM_MODULE_NUMCODES] = {
	[RLM_MODULE_NOOP]	= FR_STATUS_CODE_VALUE_OK,			//!< OK (default success)
	[RLM_MODULE_OK]		= FR_STATUS_CODE_VALUE_OK,
	[RLM_MODULE_UPDATED]	= FR_STATUS_CODE_VALUE_OK,
	[RLM_MODULE_HANDLED]	= 0,					//!< Module handled it; operator controls status code
	[RLM_MODULE_REJECT]	= FR_STATUS_CODE_VALUE_FORBIDDEN,		//!< Forbidden
	[RLM_MODULE_DISALLOW]	= FR_STATUS_CODE_VALUE_FORBIDDEN,
	[RLM_MODULE_FAIL]	= FR_STATUS_CODE_VALUE_INTERNAL_SERVER_ERROR,	//!< Internal Server Error
	[RLM_MODULE_TIMEOUT]	= FR_STATUS_CODE_VALUE_SERVICE_UNAVAILABLE,	//!< Service Unavailable
	[RLM_MODULE_INVALID]	= FR_STATUS_CODE_VALUE_BAD_REQUEST,		//!< Bad Request
	[RLM_MODULE_NOTFOUND]	= FR_STATUS_CODE_VALUE_NOT_FOUND,		//!< Not Found
};

/** Default reason phrases for the status codes we auto-set from rlm_rcode_t.
 */
static fr_table_num_ordered_t const http_auto_reason_table[] = {
	{ L("OK"),			FR_STATUS_CODE_VALUE_OK },
	{ L("Bad Request"),		FR_STATUS_CODE_VALUE_BAD_REQUEST },
	{ L("Forbidden"),		FR_STATUS_CODE_VALUE_FORBIDDEN },
	{ L("Not Found"),		FR_STATUS_CODE_VALUE_NOT_FOUND },
	{ L("Internal Server Error"),	FR_STATUS_CODE_VALUE_INTERNAL_SERVER_ERROR },
	{ L("Service Unavailable"),	FR_STATUS_CODE_VALUE_SERVICE_UNAVAILABLE },
};
static size_t const http_auto_reason_table_len = NUM_ELEMENTS(http_auto_reason_table);

/** Set HTTP response defaults in the reply after a recv section completes.
 *
 * Always sets Response.Version to HTTP/1.1 if not already present (operators
 * rarely need to override this, and the encoder requires it).
 *
 * When `status_code` is non-zero (i.e. the rcode maps to an error), also sets
 * Response.Status-Code and Response.Reason-Phrase if not already present.
 * This covers the case where a module returns `fail` or `notfound` without the
 * operator explicitly providing a status line.
 */
static void http_response_defaults_set(request_t *request, uint16_t status_code)
{
	fr_pair_t	*response;
	fr_pair_t	*vp;

	MEM(pair_update_reply(&response, attr_http_response) >= 0);

	/*
	 *	Use explicit find+append rather than fr_pair_update_by_da_parent.
	 *	For depth > 1 attributes the slow path of that function always
	 *	returns 0 at the leaf, making it impossible to distinguish
	 *	"found existing" from "just created".  We need to know which case
	 *	we're in so we can avoid overwriting values the operator set.
	 */

	/* Always default Version to HTTP/1.1 if not already set */
	if (!fr_pair_find_by_da(&response->vp_group, NULL, attr_http_response_version)) {
		MEM(fr_pair_append_by_da(response, &vp, &response->vp_group, attr_http_response_version) == 0);
		vp->vp_uint8 = FR_VERSION_VALUE_HTTP_1_1;
	}

	if (!status_code) return;

	/* Set Status-Code only if not already provided by the operator */
	if (!fr_pair_find_by_da(&response->vp_group, NULL, attr_http_response_status_code)) {
		MEM(fr_pair_append_by_da(response, &vp, &response->vp_group, attr_http_response_status_code) == 0);
		vp->vp_uint16 = status_code;
	}

	/* Set a standard Reason-Phrase only if not already provided */
	if (!fr_pair_find_by_da(&response->vp_group, NULL, attr_http_response_reason_phrase)) {
		char const *reason = fr_table_str_by_value(http_auto_reason_table, status_code, NULL);
		if (reason) {
			MEM(fr_pair_append_by_da(response, &vp, &response->vp_group, attr_http_response_reason_phrase) == 0);
			MEM(fr_pair_value_strdup(vp, reason, false) == 0);
		}
	}
}

/** After a recv section completes, auto-set Status-Code based on rlm_rcode.
 *
 * This means a module returning `fail` in a recv GET section will automatically
 * produce a 500 response without any explicit policy.  Operators can override by
 * setting &reply.HTTP.Response.Status-Code before the module returns, or by
 * setting &reply.Packet-Type := Do-Not-Respond to suppress the response entirely.
 */
RESUME(recv_request)
{
	rlm_rcode_t			rcode = RESULT_RCODE;

	PROCESS_TRACE;

	/*
	 *	Auto-set a Status-Code based on the rlm_rcode.  This resume is
	 *	only registered for the seven methods that have real response types
	 *	(GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS), so we always want to set one.
	 *	A status_code of 0 (ok/noop/updated/handled) is a no-op in http_status_set.
	 */
	http_response_defaults_set(request, http_auto_status[rcode]);

	return CALL_RESUME(recv_generic);
}

static fr_process_state_t const process_state[] = {
	[ FR_HTTP_GET ] = {
		.default_reply		= FR_HTTP_GET_RESPONSE,
		.default_rcode		= RLM_MODULE_NOOP,
		.recv			= recv_generic,
		.resume			= resume_recv_request,
		.section_offset		= PROCESS_CONF_OFFSET(recv_get),
	},
	[ FR_HTTP_POST ] = {
		.default_reply		= FR_HTTP_POST_RESPONSE,
		.default_rcode		= RLM_MODULE_NOOP,
		.recv			= recv_generic,
		.resume			= resume_recv_request,
		.section_offset		= PROCESS_CONF_OFFSET(recv_post),
	},
	[ FR_HTTP_PUT ] = {
		.default_reply		= FR_HTTP_PUT_RESPONSE,
		.default_rcode		= RLM_MODULE_NOOP,
		.recv			= recv_generic,
		.resume			= resume_recv_request,
		.section_offset		= PROCESS_CONF_OFFSET(recv_put),
	},
	[ FR_HTTP_DELETE ] = {
		.default_reply		= FR_HTTP_DELETE_RESPONSE,
		.default_rcode		= RLM_MODULE_NOOP,
		.recv			= recv_generic,
		.resume			= resume_recv_request,
		.section_offset		= PROCESS_CONF_OFFSET(recv_delete),
	},
	[ FR_HTTP_PATCH ] = {
		.default_reply		= FR_HTTP_PATCH_RESPONSE,
		.default_rcode		= RLM_MODULE_NOOP,
		.recv			= recv_generic,
		.resume			= resume_recv_request,
		.section_offset		= PROCESS_CONF_OFFSET(recv_patch),
	},
	[ FR_HTTP_HEAD ] = {
		.default_reply		= FR_HTTP_HEAD_RESPONSE,
		.default_rcode		= RLM_MODULE_NOOP,
		.recv			= recv_generic,
		.resume			= resume_recv_request,
		.section_offset		= PROCESS_CONF_OFFSET(recv_head),
	},
	[ FR_HTTP_OPTIONS ] = {
		.default_reply		= FR_HTTP_OPTIONS_RESPONSE,
		.default_rcode		= RLM_MODULE_NOOP,
		.recv			= recv_generic,
		.resume			= resume_recv_request,
		.section_offset		= PROCESS_CONF_OFFSET(recv_options),
	},
	/*
	 *	@todo - CONNECT should respond with "200 Connection Established" on success,
	 *	or a 4xx/5xx on failure (RFC 9110 §9.3.6).  Requires adding CONNECT-Response
	 *	to the dictionary and a corresponding send section.
	 */
	[ FR_HTTP_CONNECT ] = {
		.default_reply		= FR_HTTP_DO_NOT_RESPOND,
		.default_rcode		= RLM_MODULE_NOOP,
		.recv			= recv_generic,
		.resume			= resume_recv_generic,
		.section_offset		= PROCESS_CONF_OFFSET(recv_connect),
	},
	/*
	 *	@todo - TRACE should echo the request back in the response body with
	 *	"200 OK" (RFC 9110 §9.3.8).  Requires adding TRACE-Response to the
	 *	dictionary and a corresponding send section.
	 */
	[ FR_HTTP_TRACE ] = {
		.default_reply		= FR_HTTP_DO_NOT_RESPOND,
		.default_rcode		= RLM_MODULE_NOOP,
		.recv			= recv_generic,
		.resume			= resume_recv_generic,
		.section_offset		= PROCESS_CONF_OFFSET(recv_trace),
	},

	[ FR_HTTP_GET_RESPONSE ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_HTTP_GET_RESPONSE,
			[RLM_MODULE_OK]		= FR_HTTP_GET_RESPONSE,
			[RLM_MODULE_UPDATED]	= FR_HTTP_GET_RESPONSE,
			[RLM_MODULE_HANDLED]	= FR_HTTP_GET_RESPONSE,
			[RLM_MODULE_REJECT]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_HTTP_DO_NOT_RESPOND,
		},
		.default_rcode		= RLM_MODULE_NOOP,
		.result_rcode		= RLM_MODULE_OK,
		.send			= send_generic,
		.resume			= resume_send_generic,
		.section_offset		= PROCESS_CONF_OFFSET(send_get_response),
	},
	[ FR_HTTP_POST_RESPONSE ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_HTTP_POST_RESPONSE,
			[RLM_MODULE_OK]		= FR_HTTP_POST_RESPONSE,
			[RLM_MODULE_UPDATED]	= FR_HTTP_POST_RESPONSE,
			[RLM_MODULE_HANDLED]	= FR_HTTP_POST_RESPONSE,
			[RLM_MODULE_REJECT]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_HTTP_DO_NOT_RESPOND,
		},
		.default_rcode		= RLM_MODULE_NOOP,
		.result_rcode		= RLM_MODULE_OK,
		.send			= send_generic,
		.resume			= resume_send_generic,
		.section_offset		= PROCESS_CONF_OFFSET(send_post_response),
	},
	[ FR_HTTP_PUT_RESPONSE ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_HTTP_PUT_RESPONSE,
			[RLM_MODULE_OK]		= FR_HTTP_PUT_RESPONSE,
			[RLM_MODULE_UPDATED]	= FR_HTTP_PUT_RESPONSE,
			[RLM_MODULE_HANDLED]	= FR_HTTP_PUT_RESPONSE,
			[RLM_MODULE_REJECT]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_HTTP_DO_NOT_RESPOND,
		},
		.default_rcode		= RLM_MODULE_NOOP,
		.result_rcode		= RLM_MODULE_OK,
		.send			= send_generic,
		.resume			= resume_send_generic,
		.section_offset		= PROCESS_CONF_OFFSET(send_put_response),
	},
	[ FR_HTTP_DELETE_RESPONSE ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_HTTP_DELETE_RESPONSE,
			[RLM_MODULE_OK]		= FR_HTTP_DELETE_RESPONSE,
			[RLM_MODULE_UPDATED]	= FR_HTTP_DELETE_RESPONSE,
			[RLM_MODULE_HANDLED]	= FR_HTTP_DELETE_RESPONSE,
			[RLM_MODULE_REJECT]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_HTTP_DO_NOT_RESPOND,
		},
		.default_rcode		= RLM_MODULE_NOOP,
		.result_rcode		= RLM_MODULE_OK,
		.send			= send_generic,
		.resume			= resume_send_generic,
		.section_offset		= PROCESS_CONF_OFFSET(send_delete_response),
	},
	[ FR_HTTP_PATCH_RESPONSE ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_HTTP_PATCH_RESPONSE,
			[RLM_MODULE_OK]		= FR_HTTP_PATCH_RESPONSE,
			[RLM_MODULE_UPDATED]	= FR_HTTP_PATCH_RESPONSE,
			[RLM_MODULE_HANDLED]	= FR_HTTP_PATCH_RESPONSE,
			[RLM_MODULE_REJECT]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_HTTP_DO_NOT_RESPOND,
		},
		.default_rcode		= RLM_MODULE_NOOP,
		.result_rcode		= RLM_MODULE_OK,
		.send			= send_generic,
		.resume			= resume_send_generic,
		.section_offset		= PROCESS_CONF_OFFSET(send_patch_response),
	},
	[ FR_HTTP_HEAD_RESPONSE ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_HTTP_HEAD_RESPONSE,
			[RLM_MODULE_OK]		= FR_HTTP_HEAD_RESPONSE,
			[RLM_MODULE_UPDATED]	= FR_HTTP_HEAD_RESPONSE,
			[RLM_MODULE_HANDLED]	= FR_HTTP_HEAD_RESPONSE,
			[RLM_MODULE_REJECT]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_HTTP_DO_NOT_RESPOND,
		},
		.default_rcode		= RLM_MODULE_NOOP,
		.result_rcode		= RLM_MODULE_OK,
		.send			= send_generic,
		.resume			= resume_send_generic,
		.section_offset		= PROCESS_CONF_OFFSET(send_head_response),
	},
	[ FR_HTTP_OPTIONS_RESPONSE ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_HTTP_OPTIONS_RESPONSE,
			[RLM_MODULE_OK]		= FR_HTTP_OPTIONS_RESPONSE,
			[RLM_MODULE_UPDATED]	= FR_HTTP_OPTIONS_RESPONSE,
			[RLM_MODULE_HANDLED]	= FR_HTTP_OPTIONS_RESPONSE,
			[RLM_MODULE_REJECT]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_HTTP_DO_NOT_RESPOND,
		},
		.default_rcode		= RLM_MODULE_NOOP,
		.result_rcode		= RLM_MODULE_OK,
		.send			= send_generic,
		.resume			= resume_send_generic,
		.section_offset		= PROCESS_CONF_OFFSET(send_options_response),
	},

	[ FR_HTTP_DO_NOT_RESPOND ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_OK]		= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_HANDLED]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_HTTP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_HTTP_DO_NOT_RESPOND,
		},
		.default_rcode		= RLM_MODULE_NOOP,
		.result_rcode		= RLM_MODULE_HANDLED,
		.send			= send_generic,
		.resume			= resume_send_generic,
		.section_offset		= PROCESS_CONF_OFFSET(do_not_respond),
	},
};

/*
 *	Debug the packet if requested.
 *
 *	fr_http_packet_names[] covers request codes 1-9 only.
 *	For response codes and Do-Not-Respond, look up the enum name from
 *	the dictionary so the log always shows a human-readable string.
 */
static void http_packet_debug(request_t *request, fr_packet_t const *packet, fr_pair_list_t const *list, bool received)
{
	char const *name;

	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

	if (packet->code < FR_HTTP_CODE_MAX) {
		name = fr_http_packet_names[packet->code];
	} else {
		name = fr_dict_enum_name_by_value(attr_packet_type, fr_box_uint32(packet->code));
		if (!name) name = "Unknown";
	}

	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s %s",
		    received ? "Received" : "Sending", name);

	if (received || request->parent) {
		log_request_pair_list(L_DBG_LVL_1, request, NULL, list, NULL);
	} else {
		log_request_proto_pair_list(L_DBG_LVL_1, request, NULL, list, NULL);
	}
}

static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->mi->data, process_http_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "http";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_http);

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_UNLANG_FAIL;
	}

	http_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}

static const virtual_server_compile_t compile_list[] = {
	{
		.section	= SECTION_NAME("recv", "GET"),
		.actions	= &mod_actions_authorize,
		.offset		= PROCESS_CONF_OFFSET(recv_get),
	},
	{
		.section	= SECTION_NAME("recv", "POST"),
		.actions	= &mod_actions_authorize,
		.offset		= PROCESS_CONF_OFFSET(recv_post),
	},
	{
		.section	= SECTION_NAME("recv", "PUT"),
		.actions	= &mod_actions_authorize,
		.offset		= PROCESS_CONF_OFFSET(recv_put),
	},
	{
		.section	= SECTION_NAME("recv", "DELETE"),
		.actions	= &mod_actions_authorize,
		.offset		= PROCESS_CONF_OFFSET(recv_delete),
	},
	{
		.section	= SECTION_NAME("recv", "PATCH"),
		.actions	= &mod_actions_authorize,
		.offset		= PROCESS_CONF_OFFSET(recv_patch),
	},
	{
		.section	= SECTION_NAME("recv", "HEAD"),
		.actions	= &mod_actions_authorize,
		.offset		= PROCESS_CONF_OFFSET(recv_head),
	},
	{
		.section	= SECTION_NAME("recv", "OPTIONS"),
		.actions	= &mod_actions_authorize,
		.offset		= PROCESS_CONF_OFFSET(recv_options),
	},
	{
		.section	= SECTION_NAME("recv", "CONNECT"),
		.actions	= &mod_actions_authorize,
		.offset		= PROCESS_CONF_OFFSET(recv_connect),
	},
	{
		.section	= SECTION_NAME("recv", "TRACE"),
		.actions	= &mod_actions_authorize,
		.offset		= PROCESS_CONF_OFFSET(recv_trace),
	},

	{
		.section	= SECTION_NAME("send", "GET-Response"),
		.actions	= &mod_actions_postauth,
		.offset		= PROCESS_CONF_OFFSET(send_get_response),
	},
	{
		.section	= SECTION_NAME("send", "POST-Response"),
		.actions	= &mod_actions_postauth,
		.offset		= PROCESS_CONF_OFFSET(send_post_response),
	},
	{
		.section	= SECTION_NAME("send", "PUT-Response"),
		.actions	= &mod_actions_postauth,
		.offset		= PROCESS_CONF_OFFSET(send_put_response),
	},
	{
		.section	= SECTION_NAME("send", "DELETE-Response"),
		.actions	= &mod_actions_postauth,
		.offset		= PROCESS_CONF_OFFSET(send_delete_response),
	},
	{
		.section	= SECTION_NAME("send", "PATCH-Response"),
		.actions	= &mod_actions_postauth,
		.offset		= PROCESS_CONF_OFFSET(send_patch_response),
	},
	{
		.section	= SECTION_NAME("send", "HEAD-Response"),
		.actions	= &mod_actions_postauth,
		.offset		= PROCESS_CONF_OFFSET(send_head_response),
	},
	{
		.section	= SECTION_NAME("send", "OPTIONS-Response"),
		.actions	= &mod_actions_postauth,
		.offset		= PROCESS_CONF_OFFSET(send_options_response),
	},
	{
		.section	= SECTION_NAME("send", "Do-Not-Respond"),
		.actions	= &mod_actions_postauth,
		.offset		= PROCESS_CONF_OFFSET(do_not_respond),
	},
	COMPILE_TERMINATOR
};

extern fr_process_module_t process_http;
fr_process_module_t process_http = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "http",
		MODULE_INST(process_http_t),
		MODULE_RCTX(process_rctx_t)
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_http,
	.packet_type	= &attr_packet_type
};
