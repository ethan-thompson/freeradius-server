/*
 * rlm_eap_peap.c  contains the interfaces that are called from eap
 *
 * Version:     $Id$
 *
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
 *
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/eap/tls.h>
#include "eap_peap.h"

typedef struct {
	SSL_CTX		*ssl_ctx;			//!< Thread local SSL_CTX.
} rlm_eap_peap_thread_t;

typedef struct {
	char const		*tls_conf_name;		//!< TLS configuration.
	fr_tls_conf_t		*tls_conf;

	bool			use_tunneled_reply;	//!< Use the reply attributes from the tunneled session in
							//!< the non-tunneled reply to the client.

	bool			copy_request_to_tunnel;	//!< Use SOME of the request attributes from outside of the
							//!< tunneled session in the tunneled request.

	char const		*virtual_server;	//!< Virtual server for inner tunnel session.
	CONF_SECTION		*server_cs;

	bool			req_client_cert;	//!< Do we do require a client cert?
} rlm_eap_peap_t;

static conf_parser_t submodule_config[] = {
	{ FR_CONF_OFFSET("tls", rlm_eap_peap_t, tls_conf_name) },

	{ FR_CONF_DEPRECATED("copy_request_to_tunnel", rlm_eap_peap_t, NULL), .dflt = "no" },

	{ FR_CONF_DEPRECATED("use_tunneled_reply", rlm_eap_peap_t, NULL), .dflt = "no" },

	{ FR_CONF_OFFSET_FLAGS("virtual_server", CONF_FLAG_REQUIRED | CONF_FLAG_NOT_EMPTY, rlm_eap_peap_t, virtual_server) },

	{ FR_CONF_OFFSET("require_client_cert", rlm_eap_peap_t, req_client_cert), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_eap_peap_dict[];
fr_dict_autoload_t rlm_eap_peap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_auth_type;
fr_dict_attr_t const *attr_eap_tls_require_client_cert;

fr_dict_attr_t const *attr_eap_message;
fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_eap_peap_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_peap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_tls_require_client_cert, .name = "EAP-TLS-Require-Client-Cert", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};


/*
 *	Allocate the PEAP per-session data
 */
static peap_tunnel_t *peap_alloc(TALLOC_CTX *ctx, rlm_eap_peap_t *inst)
{
	peap_tunnel_t *t;

	t = talloc_zero(ctx, peap_tunnel_t);

	t->server_cs = inst->server_cs;
	t->session_resumption_state = PEAP_RESUMPTION_MAYBE;

	return t;
}

/*
 *	Construct the reply appropriately based on the rcode from PEAP processing.
 */
static unlang_action_t process_rcode(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t		*eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;

	RDEBUG3("Tunneled request complete");

	switch (eap_session->submodule_result.rcode) {
	case RLM_MODULE_REJECT:
		eap_tls_fail(request, eap_session);
		break;

	case RLM_MODULE_HANDLED:
		eap_tls_request(request, eap_session);
		break;

	case RLM_MODULE_OK:
	{
		eap_tls_prf_label_t prf_label;

		eap_crypto_prf_label_init(&prf_label, eap_session,
					  "client EAP encryption",
					  sizeof("client EAP encryption") - 1);

		/*
		 *	Success: Automatically return MPPE keys.
		 */
		if (eap_tls_success(request, eap_session, &prf_label) > 0) RETURN_UNLANG_FAIL;
		p_result->rcode = RLM_MODULE_OK;

		/*
		 *	Write the session to the session cache
		 *
		 *	We do this here (instead of relying on OpenSSL to call the
		 *	session caching callback), because we only want to write
		 *	session data to the cache if all phases were successful.
		 *
		 *	If we wrote out the cache data earlier, and the server
		 *	exited whilst the session was in progress, the supplicant
		 *	could resume the session (and get access) even if phase2
		 *	never completed.
		 */
		return fr_tls_cache_pending_push(request, tls_session);
	}

	/*
	 *	No response packet, MUST be proxying it.
	 *	The main EAP module will take care of discovering
	 *	that the request now has a "proxy" packet, and
	 *	will proxy it, rather than returning an EAP packet.
	 */
	case RLM_MODULE_UPDATED:
		break;

	default:
		eap_tls_fail(request, eap_session);
		break;
	}

	RETURN_UNLANG_RCODE(eap_session->submodule_result.rcode);
}

static unlang_action_t mod_handshake_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_peap_t		*inst = talloc_get_type(mctx->mi->data, rlm_eap_peap_t);
	eap_session_t		*eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;
	peap_tunnel_t		*peap = talloc_get_type_abort(tls_session->opaque, peap_tunnel_t);

	if ((eap_tls_session->state == EAP_TLS_INVALID) || (eap_tls_session->state == EAP_TLS_FAIL)) {
		REDEBUG("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, eap_tls_session->state, "<INVALID>"));
	} else {
		RDEBUG2("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, eap_tls_session->state, "<INVALID>"));
	}

	switch (eap_tls_session->state) {
	/*
	 *	EAP-TLS handshake was successful, tell the
	 *	client to keep talking.
	 *
	 *	If this was EAP-TLS, we would just return
	 *	an EAP-TLS-Success packet here.
	 */
	case EAP_TLS_ESTABLISHED:
		peap->status = PEAP_STATUS_TUNNEL_ESTABLISHED;
		break;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case EAP_TLS_HANDLED:
		/*
		 *	FIXME: If the SSL session is established, grab the state
		 *	and EAP id from the inner tunnel, and update it with
		 *	the expected EAP id!
		 */
		RETURN_UNLANG_HANDLED;

	/*
	 *	Handshake is done, proceed with decoding tunneled
	 *	data.
	 */
	case EAP_TLS_RECORD_RECV_COMPLETE:
                /*
                 *     TLSv1.3 makes application data immediately
                 *     available when the handshake is finished.
                 */
		if (SSL_is_init_finished(tls_session->ssl) && (peap->status == PEAP_STATUS_INVALID)) {
			peap->status = PEAP_STATUS_TUNNEL_ESTABLISHED;
		}
		break;

	/*
	 *	Anything else: fail.
	 */
	default:
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Decoding tunneled data");

	/*
	 *	We may need PEAP data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!tls_session->opaque) tls_session->opaque = peap_alloc(tls_session, inst);

	/*
	 *	Setup the resume point to prepare the correct reply based on
	 *	the rcode coming back from PEAP processing.
	 */
	(void) unlang_module_yield(request, process_rcode, NULL, 0, eap_session);

	/*
	 *	Process the PEAP portion of the request.
	 */
	return eap_peap_process(&eap_session->submodule_result, request, eap_session, tls_session);
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static unlang_action_t mod_handshake_process(UNUSED unlang_result_t *p_result, UNUSED module_ctx_t const *mctx,
					     request_t *request)
{
	eap_session_t		*eap_session = eap_session_get(request->parent);

	/*
	 *	Setup the resumption frame to process the result
	 */
	(void)unlang_module_yield(request, mod_handshake_resume, NULL, 0, eap_session);

	/*
	 *	Process TLS layer until done.
	 */
	return eap_tls_process(request, eap_session);
}

static unlang_action_t mod_session_init_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_peap_t);
	rlm_eap_peap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_peap_thread_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_tls_session_t	*eap_tls_session;
	fr_tls_session_t	*tls_session;

	fr_pair_t		*vp;
	bool			client_cert;

	/*
	 *	EAP-TLS-Require-Client-Cert attribute will override
	 *	the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_eap_tls_require_client_cert);
	if (vp) {
		client_cert = vp->vp_uint32 ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	eap_session->opaque = eap_tls_session = eap_tls_session_init(request, eap_session, t->ssl_ctx, client_cert);
	if (!eap_tls_session) RETURN_UNLANG_FAIL;

 	tls_session = eap_tls_session->tls_session;

	/*
	 *	As it is a poorly designed protocol, PEAP uses
	 *	bits in the TLS header to indicate PEAP
	 *	version numbers.  For now, we only support
	 *	PEAP version 0, so it doesn't matter too much.
	 *	However, if we support later versions of PEAP,
	 *	we will need this flag to indicate which
	 *	version we're currently dealing with.
	 */
	eap_tls_session->base_flags = 0x00;

	/*
	 *	PEAP version 0 requires 'include_length = no',
	 *	so rather than hoping the user figures it out,
	 *	we force it here.
	 */
	eap_tls_session->include_length = false;

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	if (eap_tls_start(request, eap_session) < 0) {
		talloc_free(eap_tls_session);
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Session resumption requires the storage of data, so
	 *	allocate it if it doesn't already exist.
	 */
	tls_session->opaque = peap_alloc(tls_session, inst);

	eap_session->process = mod_handshake_process;

	RETURN_UNLANG_HANDLED;
}

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static unlang_action_t mod_session_init(UNUSED unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_peap_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	eap_session->tls = true;

	(void) unlang_module_yield(request, mod_session_init_resume, NULL, 0, NULL);

	if (inst->tls_conf->new_session) return fr_tls_new_session_push(request, inst->tls_conf);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_peap_t);
	rlm_eap_peap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_peap_thread_t);

	t->ssl_ctx = fr_tls_ctx_alloc(inst->tls_conf, false);
	if (!t->ssl_ctx) return -1;

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_peap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_peap_thread_t);

	if (likely(t->ssl_ctx != NULL)) SSL_CTX_free(t->ssl_ctx);
	t->ssl_ctx = NULL;

	return 0;
}

/*
 *	Attach the module.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_peap_t);
	CONF_SECTION		*conf = mctx->mi->conf;
	virtual_server_t const	*virtual_server = virtual_server_find(inst->virtual_server);

	if (!virtual_server) {
		cf_log_err_by_child(conf, "virtual_server", "Unknown virtual server '%s'", inst->virtual_server);
		return -1;
	}

	inst->server_cs = virtual_server_cs(virtual_server);
	if (!inst->server_cs) {
		cf_log_err_by_child(conf, "virtual_server", "Virtual server \"%s\" missing", inst->virtual_server);
		return -1;
	}

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eap_tls_conf_parse(conf);
	if (!inst->tls_conf) {
		cf_log_err(conf, "Failed initializing SSL context");
		return -1;
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_peap;
rlm_eap_submodule_t rlm_eap_peap = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "eap_peap",
		.inst_size		= sizeof(rlm_eap_peap_t),
		.config			= submodule_config,
		.instantiate		= mod_instantiate,

		.thread_inst_size	= sizeof(rlm_eap_peap_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},
	.provides		= { FR_EAP_METHOD_PEAP },
	.session_init		= mod_session_init,	/* Initialise a new EAP session */
};
