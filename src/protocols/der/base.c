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

#include "lib/util/dict.h"
#include "der.h"
#include "lib/util/types.h"

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
	if (--instance_count != 0) return;

	fr_dict_autofree(libfreeradius_der_dict);
}

static fr_table_num_ordered_t const subtype_table[] = {
	{ L("tag=0"), FLAG_DER_TAG_0 },
	{ L("tag=1"), FLAG_DER_TAG_1 },
	{ L("tag=2"), FLAG_DER_TAG_2 },
	{ L("tag=3"), FLAG_DER_TAG_3 },
	{ L("tag=4"), FLAG_DER_TAG_4 },
	{ L("tag=5"), FLAG_DER_TAG_5 },
	{ L("tag=6"), FLAG_DER_TAG_6 },
	{ L("tag=7"), FLAG_DER_TAG_7 },
	{ L("tag=8"), FLAG_DER_TAG_8 },
	{ L("tag=9"), FLAG_DER_TAG_9 },
	{ L("tag=10"), FLAG_DER_TAG_10 },

	{ L("class=universal"), FLAG_DER_CLASS_UNIVERSAL },
	{ L("class=application"), FLAG_DER_CLASS_APPLICATION },
	{ L("class=context-specific"), FLAG_DER_CLASS_CONTEXT },
	{ L("class=private"), FLAG_DER_CLASS_PRIVATE },
};

static bool attr_valid(UNUSED fr_dict_t *dict, fr_dict_attr_t const *parent, UNUSED char const *name, UNUSED int attr,
		       fr_type_t type, fr_dict_attr_flags_t *flags)
{
}

extern fr_dict_protocol_t libfreeradius_der_dict_protocol;
fr_dict_protocol_t	  libfreeradius_der_dict_protocol = {
	       .name		    = "der",
	       .default_type_size   = 1,
	       .default_type_length = 1,
	       .subtype_table	    = subtype_table,
	       .subtype_table_len   = NUM_ELEMENTS(subtype_table),
	       .attr_valid	    = attr_valid,

	       .init = fr_der_global_init,
	       .free = fr_der_global_free,

	       // .decode = fr_der_decode_foreign,
	       // .encode = fr_der_encode_foreign,
};
