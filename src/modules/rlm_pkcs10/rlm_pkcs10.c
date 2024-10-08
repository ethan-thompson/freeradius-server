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

#include "lib/util/dict.h"
#include "talloc.h"
#include <errno.h>

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/tls/log.h>
#include <freeradius-devel/tls/pkcs10.h>
// #include <freeradius-devel/tls/pkcs7.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/tls/utils.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/syserror.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdint.h>
#include <time.h>

/** The module context for the PKCS10 module.
 */
typedef struct {
    X509        *certificate;               //!< The CA certificate used to sign the certificate.
    EVP_PKEY    *private_key;               //!< The private key used to sign the certificate.
    char const  *private_key_password;      //!< Literal string used to decrypt the private key.
} rlm_pkcs10_t;

static int cf_parse_certificate_file(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
    X509 *ca_cert;
    CONF_PAIR *cp = cf_item_to_pair(ci);

    FILE *fp = fopen(cf_pair_value(cp), "r");
    if (fp == NULL) {
        cf_log_err(ci, "Error opening certificate file: %s", fr_syserror(errno));
        return -1;
    }
    ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (ca_cert == NULL) {
        fr_tls_strerror_drain();
        cf_log_perr(ci, "Error reading certificate file");
        return -1;
    }

    *(X509 **)out = ca_cert;

    return 0;
}

static int cf_parse_private_key_file(UNUSED TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
    rlm_pkcs10_t    *inst = talloc_get_type_abort(parent, rlm_pkcs10_t);
    EVP_PKEY        *ca_key;
    CONF_PAIR       *cp = cf_item_to_pair(ci);

    FILE *fp = fopen(cf_pair_value(cp), "r");
    if (fp == NULL) {
        cf_log_err(ci,"Error opening CA key file: %s", fr_syserror(errno));
        return -1;
    }
    ca_key = PEM_read_PrivateKey(fp, NULL, fr_utils_get_private_key_password, UNCONST(void *, inst->private_key_password));
    fclose(fp);
    if (ca_key == NULL) {
        fr_tls_strerror_drain();
        cf_log_perr(ci, "Error reading private key file");
        return -1;
    }

    if (!X509_check_private_key(inst->certificate, ca_key)) {
        fr_tls_strerror_drain();
        cf_log_perr(ci, "CA certificate and CA private key do not match");
        EVP_PKEY_free(ca_key);
        return -1;
    }

    *(EVP_PKEY **)out = ca_key;

    return 0;
}

static const conf_parser_t module_config[] = {
    { FR_CONF_OFFSET_TYPE_FLAGS("certificate_file", FR_TYPE_VOID, CONF_FLAG_REQUIRED, rlm_pkcs10_t, certificate), .func = cf_parse_certificate_file },

	{ FR_CONF_OFFSET_FLAGS("private_key_password", CONF_FLAG_SECRET, rlm_pkcs10_t, private_key_password) },	/* Must come before private_key */
    { FR_CONF_OFFSET_TYPE_FLAGS("private_key_file", FR_TYPE_VOID, CONF_FLAG_REQUIRED, rlm_pkcs10_t, private_key), .func = cf_parse_private_key_file },
    CONF_PARSER_TERMINATOR
};

typedef struct {
	fr_value_box_t	pkcs10;
	tmpl_t      	*pkcs7;
} pkcs10_call_env_t;

static const call_env_method_t csr_method_env = {
	FR_CALL_ENV_METHOD_OUT(pkcs10_call_env_t),
	.env = (call_env_parser_t[]) {
	    { FR_CALL_ENV_OFFSET("pkcs10-csr", FR_TYPE_OCTETS, CALL_ENV_FLAG_REQUIRED, pkcs10_call_env_t, pkcs10) },
        { FR_CALL_ENV_PARSE_ONLY_OFFSET("pkcs7", FR_TYPE_OCTETS, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, pkcs10_call_env_t, pkcs7)},
	    CALL_ENV_TERMINATOR
    }
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_pkcs10;

extern fr_dict_autoload_t rlm_pkcs10_dict[];
fr_dict_autoload_t rlm_pkcs10_dict[] = {
    { .out = &dict_freeradius, .proto = "freeradius" },
    { .out = &dict_pkcs10, .proto = "pkcs10" },
    { NULL }
};

static fr_dict_attr_t const *attr_pkcs10;
static fr_dict_attr_t const *attr_pkcs7;

static fr_dict_attr_t const *attr_csr_version;
static fr_dict_attr_t const *tls_pkcs10_attr_subject_pk_algorithm;

/**
 * Specified the PKCS10 CSR attribute (from request),
 * and the PKCS7 certificate attribute (to create response).
 */
extern fr_dict_attr_autoload_t rlm_pkcs10_dict_attr[];
fr_dict_attr_autoload_t rlm_pkcs10_dict_attr[] = {
    { .out = &attr_pkcs10, .name = "PKCS10-CSR", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
    { .out = &attr_pkcs7, .name = "PKCS7", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
    { .out = &attr_csr_version, .name = "Certificate-Request.Info.Version", .type = FR_TYPE_UINT8, .dict = &dict_pkcs10 },
	// { .out = &tls_pkcs10_attr_subject_pk_algorithm, .name = "Certificate-Request.Info.Subject-Pk-Info.Algorithm", .type = FR_TYPE_UINT8, .dict = &dict_pkcs10 },
    { NULL }
};

/** Process the PKCS10 certificate request and return a PKCS7 certificate.
 *
 * @param[in] request The PKCS10 request to process.
 * @return The PKCS7 certificate response.
 */
static unlang_action_t CC_HINT(nonnull) mod_request(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
    rlm_pkcs10_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_pkcs10_t);
    pkcs10_call_env_t *env = talloc_get_type_abort(mctx->env_data, pkcs10_call_env_t);

    const uint8_t *pkcs10_buf;

    X509_REQ *req;
    X509 *certificate = NULL;
    STACK_OF(X509_EXTENSION) *req_exts;
    EVP_PKEY *pkey = NULL;
    BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
    AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
    X509_EXTENSION *bc_ext = NULL, *akid_ext = NULL;;

    unsigned char *der = NULL, md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    int len;

    RHEXDUMP3(env->pkcs10.vb_octets, env->pkcs10.vb_length, "Signing Request");

    MEM(pkcs10_buf = talloc_memdup(unlang_interpret_frame_talloc_ctx(request), env->pkcs10.vb_octets, env->pkcs10.vb_length));
    req = d2i_X509_REQ(NULL, &pkcs10_buf, talloc_array_length(pkcs10_buf));

    // Check that the request was decoded correctly
    if (req == NULL) {
        fr_tls_strerror_drain();
        RPEDEBUG("Error decoding PKCS10 request");
    invalid:
        RETURN_MODULE_INVALID;
    }

    // Verify the request
    RDEBUG("Verifying request");
    if ((pkey = X509_REQ_get_pubkey(req)) == NULL) {
        fr_tls_strerror_drain();
        RPEDEBUG("Error getting public key from request");
        goto invalid;
    }

    if (X509_REQ_verify(req, pkey) <= 0) {
        fr_tls_strerror_drain();
        RDEBUG("Error verifying request");
        goto invalid;
    }

    // Convert request fields to attributes
    // fr_pair_list_t *out = NULL;
    fr_pair_list_t *out = NULL;
    fr_pair_t *vp = NULL;

    // MEM(vp = fr_pair_afrom_da(request->request_ctx, attr_pkcs10));
    MEM(out = fr_pair_list_alloc(request->request_ctx));

    if (fr_tls_attrs_from_pkcs10(vp, out, req) < 0) {
        RPEDEBUG("Error converting request fields to attributes");
        goto invalid;
    }

    // Get the version of the CSR
    vp = fr_pair_find_by_da(out, NULL, attr_csr_version);
    if (vp == NULL) {
        RPEDEBUG("Error getting CSR version");
        goto invalid;
    }
    RDEBUG("CSR version: %d", vp->vp_uint8);

    // Get the public key algorithm
    vp = fr_pair_find_by_da(out, NULL, tls_pkcs10_attr_subject_pk_algorithm);
    if (vp == NULL) {
        RPEDEBUG("Error getting public key algorithm");
        goto invalid;
    }
    RDEBUG("Public key algorithm: %d", vp->vp_uint8);

    // Create the certificate
    RDEBUG("Creating certificate");
    if ((certificate = X509_new()) == NULL) {
        RDEBUG("Error creating a new certificate");
        RETURN_MODULE_FAIL;
    }

    RDEBUG("Setting certificate fields");
    X509_set_subject_name(certificate, X509_REQ_get_subject_name(req)); // Set the subject name
    X509_set_issuer_name(certificate, X509_get_subject_name(inst->certificate)); // Set the issuer name

    X509_set_pubkey(certificate, pkey); // Set the public key

    ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1); // Set the serial number

    // Set the validity period
    X509_gmtime_adj(X509_get0_notBefore(certificate), 0);
    X509_gmtime_adj(X509_get0_notAfter(certificate), 31536000L);

    // Copy the extensions
    req_exts = X509_REQ_get_extensions(req);
    for (int i = 0; i < sk_X509_EXTENSION_num(req_exts); i++) {
        X509_EXTENSION *req_ext = sk_X509_EXTENSION_value(req_exts, i);
        X509_add_ext(certificate, req_ext, -1);
    }

    // Set/modify the Basic Constraints extension
    bc->ca = 0;
    bc_ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    X509_EXTENSION_free(X509_delete_ext(certificate, X509_get_ext_by_NID(certificate, NID_basic_constraints, -1))); // Remove existing extension
    X509_add_ext(certificate, bc_ext, -1);
    BASIC_CONSTRAINTS_free(bc);


    // Add more extensions
    // Add the Authority Key Identifier extension
    X509_pubkey_digest(inst->certificate, EVP_sha256(), md, &md_len);
    akid->keyid = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(akid->keyid, md, md_len);
    akid_ext = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid);
    X509_add_ext(certificate, akid_ext, -1);
    AUTHORITY_KEYID_free(akid);

    // Sign the CSR
    RDEBUG2("Signing certificate");
    if (!X509_sign(certificate, inst->private_key, EVP_sha256())) {
        REDEBUG("Error signing certificate");
        RETURN_MODULE_FAIL;
    }

    RDEBUG("Creating DER response");
    // Convert the X509 certificate to DER format and return the length of the DER data
    len = i2d_X509(certificate, &der);

    RHEXDUMP3(der, len, "Signing Response");

	{
        tmpl_t	match_rhs;
        map_t	match_map;

        match_map = (map_t) {
            .lhs = env->pkcs7,
            .op = T_OP_SET,
            .rhs = &match_rhs
        };

        tmpl_init_shallow(&match_rhs, TMPL_TYPE_DATA, T_BARE_WORD, "", 0, NULL);
        fr_value_box_memdup_shallow(&match_map.rhs->data.literal, NULL, der, len, false);
        if (map_to_request(request, &match_map, map_to_vp, NULL) < 0) {
            RERROR("Failed creating %s", env->pkcs7->name);
            RETURN_MODULE_FAIL;
        }
    }

    RETURN_MODULE_OK;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
    rlm_pkcs10_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_pkcs10_t);

    if (inst->certificate != NULL) {
        X509_free(inst->certificate);
    }
    if (inst->private_key != NULL) {
        EVP_PKEY_free(inst->private_key);
    }

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
		.inst_size		= sizeof(rlm_pkcs10_t),
		.config			= module_config,
        .detach         = mod_detach
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("recv", CF_IDENT_ANY), .method = mod_request, .method_env = &csr_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
