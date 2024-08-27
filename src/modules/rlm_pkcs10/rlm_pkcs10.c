/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

#include <freeradius-devel/server/module_rlm.h>
#include <openssl/pkcs7.h>

typedef struct {
    char const *pkcs10_name;
} rlm_pkcs10_t;

static const conf_parser_t module_config[] = {
    { FR_CONF_OFFSET("pkcs10", rlm_pkcs10_t, pkcs10_name) },
    CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_pkcs10_dict[];
fr_dict_autoload_t rlm_pkcs10_dict[] = {
    { .out = &dict_freeradius, .proto = "freeradius" },
    { NULL }
};

static fr_dict_attr_t const *attr_pkcs10;
static fr_dict_attr_t const *attr_pkcs7;

/**
 * Specified the PKCS10 CSR attribute (from request),
 * and the PKCS7 certificate attribute (to create response).
 */
extern fr_dict_attr_autoload_t rlm_pkcs10_dict_attr[];
fr_dict_attr_autoload_t rlm_pkcs10_dict_attr[] = {
    { .out = &attr_pkcs10, .name = "PKCS10", .type = FR_TYPE_PKCS10, .dict = &dict_freeradius },
    { .out = &attr_pkcs7, .name = "PKCS7", .type = FR_TYPE_PKCS7, .dict = &dict_freeradius },
    { NULL }
};

/** Instantiate the module.
 *
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
    rlm_pkcs10_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_pkcs10_t);

    // Do checks

    return 0;
}

/** Process the PKCS10 certificate request and return a PKCS7 certificate.
 *
 * @param[in] request The PKCS10 request to process.
 * @return The PKCS7 certificate response.
 */
static int mod_request()
{
    // Process the request

    return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_pkcs10;
module_rlm_t rlm_pkcs10 = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "pkcs10",
        .flags		= MODULE_TYPE_THREAD_UNSAFE,
		.inst_size		= sizeof(rlm_pkcs10_t),
		.config			= module_config,
		.instantiate		= mod_instantiate
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("recv", CF_IDENT_ANY), .method = mod_request },
			MODULE_BINDING_TERMINATOR
		}
	}
};
