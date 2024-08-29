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
    { .out = &attr_pkcs10, .name = "PKCS10", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
    { .out = &attr_pkcs7, .name = "PKCS7", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
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
    // X509_REQ *req;

    // req = fr_pair_find_by_da(&request->request_pairs, NULL, attr_pkcs10);

    // Create a BIO from the request data
    // This is so we can read the request data and create a X509_REQ object
    fr_pair_t *pkcs10;
    pkcs10 = fr_pair_find_by_da(&request->request_pairs, NULL, attr_pkcs10);
    char *reqData = &pkcs10->data;

    // First, we need to decode the base64 encoded PKCS10 request
    BIO *b64, *bio, *reqBIO;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(reqData, -1); // -1 means read until null terminator

    // The following creates a base64 filter BIO
    // When read from, it will decode the base64 data
    bio = BIO_push(b64, bio);

    // reqBIO = BIO_new(BIO_s_mem());

    // RDEBUG("PKCS10 request: %s", reqData);

    // BIO_write(reqBIO, reqData, strlen(reqData));

    X509_REQ *req;
    // req = d2i_X509_REQ_bio(reqBIO, NULL); // This is where we get the CSR
    req = d2i_X509_REQ_bio(bio, NULL); // This is where we get the CSR

    BIO_free_all(bio);

    // BIO_free(reqBIO);

    /**
    // Verify the request
    EVP_PKEY *pkey;
    if ((pkey = X509_REQ_get0_pubkey(request)) == NULL) {
        // Log error
        fprintf(stderr, "Error getting public key from request\n");
        exit(1);
    }

    STACK_OF(OPENSSL_STRING) *vfyopts = NULL;
    vfyopts = sk_OPENSSL_STRING_new_null();
    if (do_X509_REQ_verify(request, pkey, vfyopts) <= 0) {
        // Log error
        fprintf(stderr, "Error verifying request\n");
        exit(1);
    }

    // Load the CA key
    char *CAkeyfile = "CAkey.pem";
    int CAkeyformat = FORMAT_PEM;

    EVP_PKEY *CAkey = NULL;
    char *passin = NULL;
    ENGINE *e = NULL;
    CAkey = load_key(CAkeyfile, CAkeyformat, 0, passin, e, "CA private key");

    // Check the CA key and certificate
    X509 *CAcert = NULL;
    char *CAcertfile = "CAcert.pem";
    int CAcertformat = FORMAT_PEM;

    // Load the CA certificate
    CAcert = load_cert_pass(CAcertfile, CAcertformat, 1, passin, "CA certificate");

    if (!X509_check_private_key(CAcert, CAkey)) {
        // Log error
        fprintf(stderr, "CA certificate and CA private key do not match\n");
        exit(1);
    }

    // Create the certificate
    X509 *x;
    if ((x = X509_new_ex(app_get0_libctx(), app_get0_propq())) == NULL) {
        // Log error
        fprintf(stderr, "Error creating certificate\n");
        exit(1);
    }

    // Copy extensions here if desired
    // copy_extensions(x, request, ext_copy)

    X509_set_subject_name(x, X509_REQ_get_subject_name(request));
    X509_set_pubkey(x, pkey);

    // Sign the CSR
    char *digest = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
    sigopts = sk_OPENSSL_STRING_new_null();
    X509V3_CTX ext_ctx;

    do_X509_sign(x, 0, CAkey, digest, sigopts, &ext_ctx);

    // Format the response
    BIO *out = NULL;
    out = bio_open_default(NULL, "w", FORMAT_PEM);

    PEM_write_bio_X509_AUX(out, x);

    */

    // char *pemData = NULL;
    // bio_to_mem(pemData, sizeof(out), out);

    // char *pemData = NULL;
    // bio_to_mem(pemData, sizeof(reqBIO), reqBIO);
    // pemData = BIO_new_mem_buf(

    // // Set the pem response
    // fr_pair_t *vp;
    // MEM(vp = fr_pair_afrom_da(request->request_ctx, attr_pkcs7));
    // // fr_pair_value_memdup(vp, "0xabcdf", sizeof("0xabcdf"), true);
    // fr_pair_value_strdup(vp, pemData, true);
    // fr_pair_append(&request->request_pairs, vp);


    // Set the pem response
    fr_pair_t *vp;
    MEM(vp = fr_pair_afrom_da(request->request_ctx, attr_pkcs7));
    // fr_pair_value_memdup(vp, "0xabcdf", sizeof("0xabcdf"), true);
    fr_pair_value_strdup(vp, "0xabcdef", true);
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
