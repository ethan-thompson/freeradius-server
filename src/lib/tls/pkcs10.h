#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifdef WITH_TLS
/**
 * $Id$
 *
 * @file lib/tls/pkcs10
 * @brief Prototypes for Certificate Signing Requests in PKCS10 format
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(tls_pkcs10_h, "$Id$")

#include <freeradius-devel/util/dict.h>
#include <openssl/x509.h> // Add this line to include the necessary header

extern fr_dict_autoload_t tls_pkcs10_dict_autoload[];
extern fr_dict_attr_autoload_t tls_pkcs10_attr_autoload[];

// fr_dict_t const *tls_pkcs10_dict_pkcs10;

// fr_dict_attr_t const *tls_pkcs10_attr_version;
// fr_dict_attr_t const *tls_pkcs10_attr_subject;
// fr_dict_attr_t const *tls_pkcs10_attr_subject_pk_algorithm;
// fr_dict_attr_t const *tls_pkcs10_attr_subject_pk_value;
// fr_dict_attr_t const *tls_pkcs10_attr_attributes;
// fr_dict_attr_t const *tls_pkcs10_attr_signature_algorithm;
// fr_dict_attr_t const *tls_pkcs10_attr_signature_value;

int fr_tls_attrs_from_pkcs10(TALLOC_CTX *ctx, fr_pair_list_t *out, X509_REQ *req);

#endif
