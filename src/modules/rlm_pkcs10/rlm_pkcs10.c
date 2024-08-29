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
#include <freeradius-devel/tls/log.h>
// #include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// #include <apps.h>

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
    { .out = &attr_pkcs10, .name = "PKCS10", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
    { .out = &attr_pkcs7, .name = "PKCS7", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
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
static unlang_action_t CC_HINT(nonnull) mod_request(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
    fr_pair_t *pkcs10;
    pkcs10 = fr_pair_find_by_da(&request->request_pairs, NULL, attr_pkcs10);

    RDEBUG("Decoding PKCS10 request");
    X509_REQ *req;
    req = d2i_X509_REQ(NULL, &pkcs10->vp_ptr, pkcs10->vp_length);

    // TODO: Do this in a friendlier way to the debugger
    if (req == NULL) {
        // Log error
        fprintf(stderr, "Error decoding PKCS10 request\n");
        exit(1);
    }

    // Verify the request
    RDEBUG("Verifying request");
    EVP_PKEY *pkey = NULL;
    if ((pkey = X509_REQ_get_pubkey(req)) == NULL) {
        // Log error
        fprintf(stderr, "Error getting public key from request\n");
        exit(1);
    }

    // STACK_OF(OPENSSL_STRING) *vfyopts = NULL;
    // vfyopts = sk_OPENSSL_STRING_new_null();

    if (X509_REQ_verify(req, pkey) <= 0) {
        // Log error
        fprintf(stderr, "Error verifying request\n");
        exit(1);
    }

    // Load the CA key
    RDEBUG("Loading CA key");
    char *CAkeyfile = "//Users/ethanthompson/devel/tests/key.pem";

    EVP_PKEY *CAkey = NULL;

    FILE *file = fopen(CAkeyfile, "r");
    CAkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);

    // Check the CA key and certificate
    RDEBUG("Checking CA key and certificate");
    X509 *CAcert = NULL;
    char *CAcertfile = "/Users/ethanthompson/devel/tests/cert.pem";

    // Load the CA certificate
    FILE *fp = fopen(CAcertfile, "r");
    CAcert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!X509_check_private_key(CAcert, CAkey)) {
        // Log error
        fprintf(stderr, "CA certificate and CA private key do not match\n");
        exit(1);
    }

    // Create the certificate
    RDEBUG("Creating certificate");
    X509 *certificate = NULL;
    if ((certificate = X509_new()) == NULL) {
        // Log error
        fprintf(stderr, "Error creating certificate\n");
        exit(1);
    }

    // Copy extensions here if desired
    // copy_extensions(x, request, ext_copy)

    RDEBUG("Setting certificate subject and public key");
    X509_set_subject_name(certificate, X509_REQ_get_subject_name(req));
    X509_set_pubkey(certificate, pkey);

    // Sign the CSR
    RDEBUG("Signing certificate");

    if (!X509_sign(certificate, CAkey, EVP_sha256())) {
        // Log error
        fprintf(stderr, "Error signing certificate\n");
        exit(1);
    }

    RDEBUG("Creating DER response");
    int len;
    unsigned char *der = NULL;
    len = i2d_X509(certificate, &der);

    // // Set the pem response
    // fr_pair_t *vp;
    // MEM(vp = fr_pair_afrom_da(request->request_ctx, attr_pkcs7));
    // // fr_pair_value_memdup(vp, "0xabcdf", sizeof("0xabcdf"), true);
    // fr_pair_value_strdup(vp, pemData, true);
    // fr_pair_append(&request->request_pairs, vp);


    // Set the pem response
    RDEBUG("Setting PKCS7 response");
    fr_pair_t *vp;
    MEM(vp = fr_pair_afrom_da(request->request_ctx, attr_pkcs7));
    // fr_pair_value_memdup(vp, "0xabcdf", sizeof("0xabcdf"), true);
    // fr_pair_value_strdup(vp, "0xabcdef", true);

    // fr_pair_value_strdup(vp, der, true);

    RDEBUG("DER length: %d", len);

    if (fr_pair_value_memdup(vp, der, sizeof(der), true) < 0) {
        // Log error
        fprintf(stderr, "Error setting PKCS7 response\n");
        exit(1);
    }

    fr_pair_append(&request->request_pairs, vp);

    RETURN_MODULE_OK;
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
