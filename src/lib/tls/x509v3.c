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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 0217-1301, USA
 */


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
#include "openssl/types.h"
#include "x509v3.h"

fr_dict_t const *tls_x509v3_dict_x509v3;

fr_dict_autoload_t tls_x509v3_dict_autoload[] = {
	{ .out = &tls_x509v3_dict_x509v3, .proto = "x509v3" },
	{ NULL }
};

fr_dict_attr_t const *tls_x509v3_attr_version;
fr_dict_attr_t const *tls_x509v3_attr_subject;
fr_dict_attr_t const *tls_x509v3_attr_subject_pk_algorithm;
fr_dict_attr_t const *tls_x509v3_attr_subject_pk_value;
fr_dict_attr_t const *tls_x509v3_attr_attributes;
fr_dict_attr_t const *tls_x509v3_attr_signature_algorithm;
fr_dict_attr_t const *tls_x509v3_attr_signature_value;

fr_dict_attr_autoload_t tls_x509v3_attr_autoload[] = {
	{ .out = &tls_x509v3_attr_version, .name = "Certificate.TBS-Certificate.Version", .type = FR_TYPE_UINT8, .dict = &tls_x509v3_dict_x509v3 },
	{ NULL }
};


#endif /* WITH_TLS */
