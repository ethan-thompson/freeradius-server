/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/der/decode.c
 * @brief Functions to decode DER encoded data.
 *
 * @author Ethan Thompson (ethan.thompson@inkbridge.io)
 *
 * @copyright 2024 Inkbridge Networks SAS.
 */

#include "include/build.h"
#include "der.h"
#include "lib/util/debug.h"
#include "lib/util/table.h"
#include "lib/util/types.h"
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/net.h>
#include <stdbool.h>

static uint32_t instance_count = 0;

fr_dict_t const *dict_der;

extern fr_dict_autoload_t libfreeradius_der_dict[];
fr_dict_autoload_t	  libfreeradius_der_dict[] = { { .out = &dict_der, .proto = "PKCS10" }, { NULL } };

// Define the dictionary attributes here
fr_dict_attr_t const *attr_der_foo;

extern fr_dict_attr_autoload_t libfreeradius_der_dict_attr[];
fr_dict_attr_autoload_t	       libfreeradius_der_dict_attr[] = {
	       { .out = &attr_der_foo, .name = "foo", .type = FR_TYPE_STRUCT, .dict = &dict_der },
	       { NULL }
};

fr_der_tag_constructed_t tag_labels[] = {
	[FR_DER_TAG_BOOLEAN]	      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_INTEGER]	      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_BITSTRING]	      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_OCTETSTRING]      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_NULL]	      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_OID]	      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_ENUMERATED]	      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_UTF8_STRING]      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_SEQUENCE]	      = FR_DER_TAG_CONSTRUCTED,
	[FR_DER_TAG_SET]	      = FR_DER_TAG_CONSTRUCTED,
	[FR_DER_TAG_PRINTABLE_STRING] = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_T61_STRING]	      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_IA5_STRING]	      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_UTC_TIME]	      = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_GENERALIZED_TIME] = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_VISIBLE_STRING]   = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_GENERAL_STRING]   = FR_DER_TAG_PRIMATIVE,
	[FR_DER_TAG_UNIVERSAL_STRING] = FR_DER_TAG_PRIMATIVE,
};

int fr_der_global_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(libfreeradius_der_dict) < 0) {
	fail:
		instance_count--;
		return -1;
	}

	if (fr_dict_attr_autoload(libfreeradius_der_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_der_dict);
		goto fail;
	}

	return 0;
}

void fr_der_global_free(void)
{
	fr_assert(instance_count > 0);

	if (--instance_count != 0) return;

	fr_dict_autofree(libfreeradius_der_dict);
}

static int dict_flag_tag_num(fr_dict_attr_t const **da_p, char const *value)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->tag_num = (uint8_t)atoi(value);

	return 0;
}

static int dict_flag_class(fr_dict_attr_t const **da_p, char const *value)
{
	static fr_table_num_sorted_t const table[] = {
		{ L("universal"), FR_DER_CLASS_UNIVERSAL },
		{ L("application"), FR_DER_CLASS_APPLICATION },
		{ L("context-specific"), FR_DER_CLASS_CONTEXT },
		{ L("private"), FR_DER_CLASS_PRIVATE },
	};

	static size_t table_len = NUM_ELEMENTS(table);

	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_class_t   tag_class;

	tag_class = fr_table_value_by_str(table, value, FR_DER_CLASS_INVALID);

	if (tag_class == FR_DER_CLASS_INVALID) {
		fr_strerror_printf("Invalid tag class '%s'", value);
		return -1;
	}

	flags->tag_class = tag_class;

	return 0;
}

static int dict_flag_sub_type(fr_dict_attr_t const **da_p, char const *value)
{
	static fr_table_num_sorted_t const table[] = {
		{ L("boolean"), FR_DER_TAG_BOOLEAN },
		{ L("integer"), FR_DER_TAG_INTEGER },
		{ L("bitstring"), FR_DER_TAG_BITSTRING },
		{ L("octetstring"), FR_DER_TAG_OCTETSTRING },
		{ L("null"), FR_DER_TAG_NULL },
		{ L("oid"), FR_DER_TAG_OID },
		{ L("enumerated"), FR_DER_TAG_ENUMERATED },
		{ L("utf8string"), FR_DER_TAG_UTF8_STRING },
		{ L("sequence"), FR_DER_TAG_SEQUENCE },
		{ L("set"), FR_DER_TAG_SET },
		{ L("printablestring"), FR_DER_TAG_PRINTABLE_STRING },
		{ L("t61string"), FR_DER_TAG_T61_STRING },
		{ L("ia5string"), FR_DER_TAG_IA5_STRING },
		{ L("utctime"), FR_DER_TAG_UTC_TIME },
		{ L("generalizedtime"), FR_DER_TAG_GENERALIZED_TIME },
		{ L("visiblestring"), FR_DER_TAG_VISIBLE_STRING },
		{ L("generalstring"), FR_DER_TAG_GENERAL_STRING },
		{ L("universalstring"), FR_DER_TAG_UNIVERSAL_STRING },
		{ L("bmpstring"), FR_DER_TAG_BMP_STRING },
	};

	static size_t table_len = NUM_ELEMENTS(table);

	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_num_t     sub_type;

	sub_type = fr_table_value_by_str(table, value, UINT8_MAX);

	if (sub_type == UINT8_MAX) {
		fr_strerror_printf("Invalid tag sub_type '%s'", value);
		return -1;
	}

	flags->sub_type = sub_type;

	return 0;
}

static fr_dict_flag_parser_t const der_flags[] = {
	{ L("tag_num"), dict_flag_tag_num },
	{ L("class"), dict_flag_class },
	{ L("sub_type"), dict_flag_sub_type },
};

static bool attr_valid(fr_dict_attr_t *da)
{
	return true;
}

extern fr_dict_protocol_t libfreeradius_der_dict_protocol;
fr_dict_protocol_t	  libfreeradius_der_dict_protocol = {
	       .name		    = "der",
	       .default_type_size   = 1,
	       .default_type_length = 1,
	       //        .subtype_table	    = subtype_table,
	       //        .subtype_table_len   = NUM_ELEMENTS(subtype_table),
	       //        .attr_valid	    = attr_valid,
	       .attr = {
		       .flags_table = der_flags,
		       .flags_table_len = NUM_ELEMENTS(der_flags),
		       .flags_len = sizeof(fr_der_attr_flags_t),
		       .valid = attr_valid,
	       },

		.init = fr_der_global_init,
	       .free		     = fr_der_global_free,

	       // .decode = fr_der_decode_foreign,
	       // .encode = fr_der_encode_foreign,
};
