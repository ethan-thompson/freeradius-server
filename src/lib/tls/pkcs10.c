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
 *
 * @file tls/attrs.c
 * @brief Convert fields in certificates represented by X509 to attributes and vice versa.
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include "lib/server/log.h"
#include "lib/util/dict.h"
#include "lib/util/types.h"
#include <stdio.h>
#include <string.h>
// #include <cstddef> // TODO: What was this supposed to be? C standard def?
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#include <freeradius-devel/util/pair.h>
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/objects.h"
#include "openssl/asn1.h"
#include "openssl/evp.h"
#include "openssl/types.h"
#include "pkcs10.h"

fr_dict_t const *tls_pkcs10_dict_pkcs10;

fr_dict_autoload_t tls_pkcs10_dict_autoload[] = {
	{ .out = &tls_pkcs10_dict_pkcs10, .proto = "pkcs10" },
	{ NULL }
};

fr_dict_attr_t const *tls_pkcs10_attr_version;
fr_dict_attr_t const *tls_pkcs10_attr_subject;
fr_dict_attr_t const *tls_pkcs10_attr_subject_pk_algorithm;
fr_dict_attr_t const *tls_pkcs10_attr_subject_pk_value;
fr_dict_attr_t const *tls_pkcs10_attr_attributes;
fr_dict_attr_t const *tls_pkcs10_attr_signature_algorithm;
fr_dict_attr_t const *tls_pkcs10_attr_signature_value;

fr_dict_attr_t const *tls_pkcs10_attr_ext_basic_constraints_oid;
fr_dict_attr_t const *tls_pkcs10_attr_ext_basic_constraints_critical;
fr_dict_attr_t const *tls_pkcs10_attr_ext_basic_constraints_ca;
fr_dict_attr_t const *tls_pkcs10_attr_ext_basic_constraints_pathlen;

fr_dict_attr_autoload_t tls_pkcs10_attr_autoload[] = {
	{ .out = &tls_pkcs10_attr_version, .name = "Certificate-Request.Info.Version", .type = FR_TYPE_UINT8, .dict = &tls_pkcs10_dict_pkcs10 },
	{ .out = &tls_pkcs10_attr_subject, .name = "Certificate-Request.Info.Name", .type = FR_TYPE_STRING, .dict = &tls_pkcs10_dict_pkcs10 },
	// { .out = &tls_pkcs10_attr_subject_pk_algorithm, .name = "Certificate-Request.Info.Subject-Pk-Info.Algorithm", .type = FR_TYPE_UINT8, .dict = &tls_pkcs10_dict_pkcs10 },
	// { .out = &tls_pkcs10_attr_subject_pk_value, .name = "Certificate-Request.Info.Subject-Pk-Info.Subject-Pk", .type = FR_TYPE_OCTETS, .dict = &tls_pkcs10_dict_pkcs10 },
	{ .out = &tls_pkcs10_attr_attributes, .name = "Certificate-Request.Info.Attributes", .type = FR_TYPE_GROUP, .dict = &tls_pkcs10_dict_pkcs10 },
	// { .out = &tls_pkcs10_attr_signature_algorithm, .name = "Certificate-Request.Signature-Algorithm", .type = FR_TYPE_UINT8, .dict = &tls_pkcs10_dict_pkcs10 },
	// { .out = &tls_pkcs10_attr_signature_value, .name = "Certificate-Request.Signature", .type = FR_TYPE_OCTETS, .dict = &tls_pkcs10_dict_pkcs10 },

	{ .out = &tls_pkcs10_attr_ext_basic_constraints_oid, .name = "Extension-Request.Basic-Constraints.Extension-ID", .type = FR_TYPE_STRING, .dict = &tls_pkcs10_dict_pkcs10 },
	// { .out = &tls_pkcs10_attr_ext_basic_constraints_critical, .name = "Extension-Request.Basic-Constraints.Critical", .type = FR_TYPE_BOOL, .dict = &tls_pkcs10_dict_pkcs10 },
	{ .out = &tls_pkcs10_attr_ext_basic_constraints_ca, .name = "Extension-Request.Basic-Constraints.Value.CA", .type = FR_TYPE_BOOL, .dict = &tls_pkcs10_dict_pkcs10 },
	{ .out = &tls_pkcs10_attr_ext_basic_constraints_pathlen, .name = "Extension-Request.Basic-Constraints.Value.Path-Len-Constraint", .type = FR_TYPE_UINT8, .dict = &tls_pkcs10_dict_pkcs10 },

	{ NULL }
};

/**
 * @brief Convert fields in certificates represented by X509 to attributes.
 *
 * @param[in] ctx Talloc context.
 * @param[out] out List of attributes.
 * @param[in] req Certificate request.
 * @return 0 on success, -1 on failure.
 */
// int fr_tls_attrs_from_pkcs10(TALLOC_CTX *ctx, fr_pair_list_t *out, X509_REQ *req)
int fr_tls_attrs_from_pkcs10(TALLOC_CTX *ctx, fr_pair_list_t *req_vp, X509_REQ *req)
{
	const STACK_OF(X509_EXTENSION) *exts;
	X509_ATTRIBUTE *attr;
	GENERAL_NAMES *names;
	fr_pair_t *vp, *attr_vp;
	int i, j, num_names;
	// fr_pair_list_t req_vp;

	// fr_pair_list_init(&req_vp);


	// Copy the extensions
	// exts = X509_REQ_get_extensions(req);
	// for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {

	// }

//	X509_REQ_get_version

	vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_version);
	vp->vp_uint8 = X509_REQ_get_version(req);
	// fr_pair_append(&req_vp, vp);
	fr_pair_append(req_vp, vp);


//	X509_REQ_get_subject_name

	// vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_subject);
	// vp->vp_strvalue = X509_NAME_oneline(X509_REQ_get_subject_name(req), NULL, 0);
	// fr_pair_append(&req_vp, vp);

//	X509_REQ_get_pubkey


	EVP_PKEY *pubkey = X509_REQ_get_pubkey(req);
	vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_subject_pk_algorithm);

	// This is a temporary approach for testing
	// In reality, we may want to change our internal values to match the OpenSSL values
	// Or use a different approach to get the key type

	int key_id = EVP_PKEY_id(pubkey);

	switch (key_id) {
		case EVP_PKEY_RSA:
			vp->vp_uint8 = 1;
			break;
		default:
			vp->vp_uint8 = 2;
			break;
	}

	// vp->vp_uint8 = EVP_PKEY_id(pubkey);
	// fr_pair_append(&req_vp, vp);
	fr_pair_append(req_vp, vp);

	vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_subject_pk_value);
	// vp->vp_octets = pubkey->pkey.ptr;

	// fr_pair_append(&req_vp, vp);
	fr_pair_append(req_vp, vp);

//	X509_REQ_get0_signature
//	X509_REQ_get_signature_nid

	// const ASN1_BIT_STRING **signature = NULL;
	// const X509_ALGOR **algorithm = NULL;
	// X509_REQ_get0_signature(req, signature, algorithm);

	// vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_signature_algorithm);
	// vp->vp_uint8 = OBJ_obj2nid((*algorithm)->algorithm);
	// fr_pair_append(&req_vp, vp);

	// vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_signature_value);
	// vp->vp_octets = ASN1_STRING_get0_data(*signature);
	// fr_pair_append(&req_vp, vp);

//	int X509_REQ_get_attr, X509_REQ_get_attr_count

	// exts = X509_REQ_get_extensions(req);

	// int num_exts = X509v3_get_ext_count(exts);

	// for (i = 0; i < num_exts; i++) {
	// 	X509_EXTENSION *ext = X509v3_get_ext(exts, i);
	// 	ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
	// 	ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(ext);

	// 	// Get the NID of the object
	// 	int nid = OBJ_obj2nid(obj);
	// 	const char *ln = OBJ_nid2ln(nid);
	// 	const char *sn = OBJ_nid2sn(nid);

	// 	// Get the data from the octet string
	// 	unsigned char *data_ptr = ASN1_STRING_get0_data(data);
	// 	int data_len = ASN1_STRING_length(data);

	// 	// Get the textual representation of the OID
	// 	char oid_str[256];
	// 	int len = OBJ_obj2txt(oid_str, sizeof(oid_str) - 1, obj, 1);

	// 	// ASN1_OBJECT *obj1 = OBJ_txt2obj(oid_str, 1);

	// 	// Encode the extension data
	// 	unsigned char *ext_out = NULL;
	// 	int ext_out_len = i2d_X509_EXTENSION(ext, &ext_out);

	// 	int lenny = sizeof(ext_out);

	// 	printf("foo");

	// 	// Decode the extension data
	// 	X509_EXTENSION *ext2 = d2i_X509_EXTENSION(NULL, &ext_out, ext_out_len);

	// 	if (nid == NID_subject_alt_name) {
	// 		// Get the subject alternative name
	// 		GENERAL_NAMES *names = X509V3_EXT_d2i(ext);
	// 		int num_names = sk_GENERAL_NAME_num(names);

	// 		for (j = 0; j < num_names; j++) {
	// 			GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);
	// 			ASN1_STRING *str = GENERAL_NAME_get0_value(name, NULL);
	// 			unsigned char *data = ASN1_STRING_get0_data(str);
	// 			int len = ASN1_STRING_length(str);

	// 			// vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_subject_alt_name);
	// 			// vp->vp_strvalue = talloc_strndup(ctx, (char *)data, len);
	// 			// fr_pair_append(&req_vp, vp);
	// 		}
	// 	}

	// 	if (nid == NID_basic_constraints) {
	// 		BASIC_CONSTRAINTS *bc = X509V3_EXT_d2i(ext);
	// 		int ca = bc->ca;
	// 		int pathlen = ASN1_INTEGER_get(bc->pathlen);

	// 		// vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_basic_constraints);
	// 		// vp->vp_group = fr_pair_list_init(ctx);
	// 		// fr_pair_list_append(vp->vp_group, fr_pair_afrom_da(ctx, tls_pkcs10_attr_basic_constraints_ca));
	// 		// vp->vp_group->vp_group->vp_bool = ca;
	// 		// fr_pair_list_append(vp->vp_group, fr_pair_afrom_da(ctx, tls_pkcs10_attr_basic_constraints_pathlen));
	// 		// vp->vp_group->vp_group->vp_int = pathlen;
	// 		// fr_pair_append(&req_vp, vp);
	// 	}

	// 	ASN1_ITEM *item = ASN1_SEQUENCE_ANY_it();

	// 	ASN1_TYPE *p;

	// 	p = ASN1_item_unpack(data, item);

	// 	printf("foo");
	// }

	attr_vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_attributes);
	fr_pair_list_init(&attr_vp->vp_group);

	int num_attrs = X509_REQ_get_attr_count(req);

	for (i = 0; i < num_attrs; i++) {
		fr_pair_t *vp2;

		attr = X509_REQ_get_attr(req, i);
		ASN1_OBJECT *object = X509_ATTRIBUTE_get0_object(attr);

		// Get the data from the object
		// const unsigned char *data_ptr3 = OBJ_get0_data(object);

		// unsigned char *out = NULL;
		// int len7 = i2d_ASN1_OBJECT(object, &out);

		// Get the NID of the object
		int nid = OBJ_obj2nid(object);
		const char *ln = OBJ_nid2ln(nid); // Useful for debugging
		const char *sn = OBJ_nid2sn(nid); // Useful for debugging

		if (nid == NID_ext_req) {
			// Get the extension request
			exts = X509_REQ_get_extensions(req);
			int num_exts = X509v3_get_ext_count(exts);

			for (j = 0; j < num_exts; j++) {
				X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, j);
				ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
				ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(ext);

				// Get the NID of the object
				int id = OBJ_obj2nid(obj);
				const char *lname = OBJ_nid2ln(id); // Useful for debugging
				const char *sname = OBJ_nid2sn(id); // Useful for debugging

				// Get the raw version of the extension
				unsigned char *ext_raw = NULL;
				int len_raw = i2d_X509_EXTENSION(ext, &ext_raw);

				// Get the data from the octet string
				unsigned char *data_ptr = ASN1_STRING_get0_data(data);
				// int data_len = ASN1_STRING_length(data);

				// Get the data from the object
				const unsigned char *data_ptr2 = OBJ_get0_data(obj);
				// int data_len2 = OBJ_length(obj);

				// Get the textual representation of the OID
				char oid_str[256];
				int len = OBJ_obj2txt(oid_str, sizeof(oid_str) - 1, obj, 1);

				printf("foo");

				switch (id) {
					// Extensions defined in RFC 5280
					case NID_authority_key_identifier:
						AUTHORITY_KEYID *akid = X509V3_EXT_d2i(ext);
						ASN1_OCTET_STRING *keyid = akid->keyid;
						ASN1_OCTET_STRING *issuer = akid->issuer;
						ASN1_INTEGER *serial = akid->serial;

						// vp2 = fr_pair_afrom_da(ctx, tls_pkcs10_attr_authority_key_identifier);
						// vp2->vp_group = fr_pair_list_init(ctx);
						// fr_pair_list_append(vp2->vp_group, fr_pair_afrom_da(ctx, tls_pkcs10_attr_authority_key_identifier_keyid));
						// vp2->vp_group->vp_group->vp_octets = talloc_memdup(ctx, ASN1_STRING_get0_data(keyid), ASN1_STRING_length(keyid));
						// fr_pair_list_append(vp2->vp_group, fr_pair_afrom_da(ctx, tls_pkcs10_attr_authority_key_identifier_issuer));
						// vp2->vp_group->vp_group->vp_octets = talloc_memdup(ctx, ASN1_STRING_get0_data(issuer), ASN1_STRING_length(issuer));
						// fr_pair_list_append(vp2->vp_group, fr_pair_afrom_da(ctx, tls_pkcs10_attr_authority_key_identifier_serial));
						// vp2->vp_group->vp_group->vp_int = ASN1_INTEGER_get(serial);

						break;

					case NID_subject_key_identifier:
						ASN1_OCTET_STRING *ski = X509V3_EXT_d2i(ext);

						// vp2 = fr_pair_afrom_da(ctx, tls_pkcs10_attr_subject_key_identifier);
						// vp2->vp_octets = talloc_memdup(ctx, ASN1_STRING_get0_data(ski), ASN1_STRING_length(ski));
						// fr_pair_append(&req_vp, vp2);
						break;

					case NID_key_usage:
						// Get the key usage
						ASN1_BIT_STRING *usage = X509V3_EXT_d2i(ext);
						unsigned char *usage_data = ASN1_STRING_get0_data(usage);
						int usage_len = ASN1_STRING_length(usage);

						// vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_key_usage);
						// vp->vp_octets = talloc_memdup(ctx, usage_data, usage_len);
						// vp->vp_octets_len = usage_len;
						// fr_pair_append(&req_vp, vp);
						break;

					case NID_certificate_policies:
						continue;

					case NID_policy_mappings:
						continue;

					case NID_subject_alt_name:
						// Get the subject alternative name
						names = X509V3_EXT_d2i(ext);
						num_names = sk_GENERAL_NAME_num(names);

						for (j = 0; j < num_names; j++) {
							GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);
							ASN1_STRING *str = GENERAL_NAME_get0_value(name, NULL);
							unsigned char *data = ASN1_STRING_get0_data(str);
							int len = ASN1_STRING_length(str);

							// vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_subject_alt_name);
							// vp->vp_strvalue = talloc_strndup(ctx, (char *)data, len);
							// fr_pair_append(&req_vp, vp);
						}
						break;

					case NID_issuer_alt_name:
						names = X509V3_EXT_d2i(ext);
						num_names = sk_GENERAL_NAME_num(names);

						for (j = 0; j < num_names; j++) {
							GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);
							ASN1_STRING *str = GENERAL_NAME_get0_value(name, NULL);
							unsigned char *data = ASN1_STRING_get0_data(str);
							int len = ASN1_STRING_length(str);

							// vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_issuer_alt_name);
							// vp->vp_strvalue = talloc_strndup(ctx, (char *)data, len);
							// fr_pair_append(&req_vp, vp);
						}

					case NID_subject_directory_attributes:
						continue;

					case NID_basic_constraints:
						BASIC_CONSTRAINTS *bc = X509V3_EXT_d2i(ext);
						int ca = bc->ca;
						int pathlen = ASN1_INTEGER_get(bc->pathlen);

						// vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_ext_basic_constraints_oid);
						// vp->vp_strvalue = oid_str;
						// fr_pair_append(&attr_vp->vp_group, vp);

						vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_ext_basic_constraints_critical);
						vp->vp_bool = ca;
						// fr_pair_append(&attr_vp->vp_group, vp);
						// fr_pair_append(&req_vp, vp);
						fr_pair_append(req_vp, vp);

						vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_ext_basic_constraints_ca);
						vp->vp_bool = ca;
						// fr_pair_append(&attr_vp->vp_group, vp);
						// fr_pair_append(&req_vp, vp);
						fr_pair_append(req_vp, vp);

						vp = fr_pair_afrom_da(ctx, tls_pkcs10_attr_ext_basic_constraints_pathlen);
						vp->vp_uint8 = pathlen;
						// fr_pair_append(&attr_vp->vp_group, vp);
						// fr_pair_append(&req_vp, vp);
						fr_pair_append(req_vp, vp);


						// vp->vp_group = fr_pair_list_init(ctx);
						// fr_pair_list_append(vp->vp_group, fr_pair_afrom_da(ctx, tls_pkcs10_attr_basic_constraints_ca));
						// vp->vp_group->vp_group->vp_bool = ca;
						// fr_pair_list_append(vp->vp_group, fr_pair_afrom_da(ctx, tls_pkcs10_attr_basic_constraints_pathlen));
						// vp->vp_group->vp_group->vp_int = pathlen;
						// fr_pair_append(&req_vp, vp);
						break;

					case NID_name_constraints:
						continue;

					case NID_policy_constraints:
						continue;

					case NID_ext_key_usage:
						continue;

					case NID_crl_distribution_points:
						continue;

					case NID_inhibit_any_policy:
						continue;

					case NID_freshest_crl:
						continue;

					default:
						//TODO: Meaningful error message
						break;
				}
			}
		}

		continue;

		// fr_pair_append(&attr_vp->vp_group, vp2); // This probably needs to be inside the switch statement...

	// for all things in attr
	//    get attr
// get vp from dict entry

		/*

		vp2 = fr_pair_afrom_da(attr_vp, tls_pkcs10_attr_attributes); //TODO: individual attributes

		// Get the X509 Attribute object
		X509_ATTRIBUTE *xattr = X509at_get_attr(attr, i);


		// Get the attribute type
		ASN1_TYPE *attr_type = X509_ATTRIBUTE_get0_type(attr, i);

		// Get the textual representation of the OID
		char oid_str[256];
		int len = OBJ_obj2txt(oid_str, sizeof(oid_str) - 1, object, 1);

		const unsigned char *data = OBJ_get0_data(object); // Get the data from the object
		size_t data_len = OBJ_length(object); // Get the length of the data

		// Get the type of the object
		// int type_a = OBJ_obj2nid(object);
		int type = ASN1_TYPE_get(attr_type);

		// Check if the type is a SEQUENCE
		if (type == V_ASN1_SEQUENCE) {
			// Get the sequence object from the attribute
			// int ret = ASN1_get_object(&data, (long *)&data_len, NULL, NULL, 0);

			// Try and get an object
			// const unsigned char *q = data;
			// ASN1_OBJECT *obj = d2i_ASN1_OBJECT(NULL, &q, data_len);

			// Get the textual representation of the OID
			// char oid_str3[256];
			// int len3 = OBJ_obj2txt(oid_str, sizeof(oid_str) - 1, obj, 1);

			// Get the ASN1_ITEM for a sequence
			const ASN1_ITEM *item = ASN1_SEQUENCE_ANY_it();
			// const ASN1_ITEM *item = ASN1_ITEM_lookup("ASN1_SEQUENCE");

			const char *name = ASN1_tag2str(type);

			// Unpack the sequence object
			// void *p;
			ASN1_TYPE *p;
			p = ASN1_TYPE_unpack_sequence(item, attr_type);

			char oid_str2[256];
			int len2 = OBJ_obj2txt(oid_str2, sizeof(oid_str2) - 1, p->value.object, 1);

			// const unsigned char *data2 = ASN1_STRING_get0_data(p->value.sequence);

			// Get the type of the string data
			int type2 = ASN1_STRING_type(p->value.sequence);

			// Check that the unpack was successful
			if (p == NULL) {
				// Print an error message
				printf("Error unpacking sequence object\n");
				// goto error;
			}

			// Create an ASN1 object from the sequence object
			// ASN1_OBJECT *obj = OBJ_txt2obj((const char*)p->value.sequence->data, 0);

			// Print the sequence object
			printf("Sequence object: %s\n", (char *)p);
		}

		*/

		// Get the string data
		// unsigned char *data2 = ASN1_STRING_data(attr_type->value.asn1_string);

		// Get the type of the string data
		// int type2 = ASN1_STRING_type(attr_type->value.asn1_string);

		// Get the ASN1 item
		// ASN1_ITEM *item = ASN1_ITEM_get(ASN1_TYPE_get(attr_type));

		// // Get the sequence object from the attribute
		// int ret = ASN1_get_object(&data, (long *)&data_len, NULL, NULL, 0);

		// Unpack the sequence object
		// void *p = ASN1_TYPE_unpack_sequence(item, attr_type);

		// reslve to dict attribute

		// Get the NID, long name, and short name of the OID
		// int nid = OBJ_obj2nid(oid);
		// const char *ln = OBJ_nid2ln(nid);
		// const char *sn = OBJ_nid2sn(nid);


// set value for vp from attr
		// Get the number of attributes in the attribute list (This seems to be how OpenSSL does it)
		// int num_attrs = X509_ATTRIBUTE_count(attr);

		// // Loop through all the attributes in the attribute list
		// for (j = 0; j < num_attrs; j++) {

		// 	// int size = ASN1_STRING_length(attr_type->value.asn1_string);
		// 	// unsigned char *data = ASN1_STRING_data(attr_type->value.asn1_string);

		// 	// Get the attribute

		// 	// Get the type of the attribute for the debug message
		// 	printf("Attribute type: %d\n", attr_type->type);
		// 	// Get the attribute value
		// 	// What type is this thing?
		// 	// vp2-> = X509_ATTRIBUTE_get0_data(attr, j, attr_type->type, NULL);
		// }

		// // Get the attribute value
		// X509_ATTRIBUTE_get0_data(attr, int idx, int atrtype, vp2->vp_strvalue)
//    add vp to attr_vp->vp_group
	}

	// fr_pair_list_free(&req_vp);

	// return 0;

	// fr_pair_list_append(&req_vp, &attr_vp->vp_group);
	// I think we actually want to append the group as a single thing to the req_vp
	// fr_pair_append(&req_vp, attr_vp);
	fr_pair_append(req_vp, attr_vp);


	// X509_EXTENSION *req_ext = sk_X509_EXTENSION_value(req_exts, i);
	// X509_add_ext(certificate, req_ext, -1);

// error:
	// fr_pair_list_free(&req_vp);

	// Now we need to set the output list to the req_vp
	// fr_pair_list_copy(ctx, out, &req_vp);

	// fr_pair_list
	return 0;
}



#endif /* WITH_TLS */
