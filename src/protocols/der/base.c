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
fr_dict_autoload_t	  libfreeradius_der_dict[] = { { .out = &dict_der, .proto = "der" }, { NULL } };

// Define the dictionary attributes here
fr_dict_attr_t const *attr_der_boolean;
fr_dict_attr_t const *attr_der_integer;
fr_dict_attr_t const *attr_der_foo;
fr_dict_attr_t const *attr_der_foo_integer;
fr_dict_attr_t const *attr_der_bar;
fr_dict_attr_t const *attr_der_bar_boolean;
fr_dict_attr_t const *attr_der_foobar;
fr_dict_attr_t const *attr_der_foobar_integer;
fr_dict_attr_t const *attr_der_foobar_boolean;
fr_dict_attr_t const *attr_der_bitstring;
fr_dict_attr_t const *attr_der_seq_bitstring_octets;
fr_dict_attr_t const *attr_der_seq_bitstring;
fr_dict_attr_t const *attr_der_bitstring_struct;
fr_dict_attr_t const *attr_der_bitstring_struct_foo;
fr_dict_attr_t const *attr_der_bitstring_struct_bar;
fr_dict_attr_t const *attr_der_bitstring_struct_foobar;

fr_dict_attr_t const *attr_der_null;

fr_dict_attr_t const *attr_der_utf8;
fr_dict_attr_t const *attr_der_context_specific;
fr_dict_attr_t const *attr_der_subject;

extern fr_dict_attr_autoload_t libfreeradius_der_dict_attr[];
fr_dict_attr_autoload_t	       libfreeradius_der_dict_attr[] = {
	       { .out = &attr_der_boolean, .name = "Test-Boolean", .type = FR_TYPE_BOOL, .dict = &dict_der },
	       { .out = &attr_der_integer, .name = "Test-Integer", .type = FR_TYPE_INT64, .dict = &dict_der },
	       { .out = &attr_der_foo, .name = "Foo", .type = FR_TYPE_STRUCT, .dict = &dict_der },
	       { .out = &attr_der_foo_integer, .name = "Foo.Test-Integer", .type = FR_TYPE_INT64, .dict = &dict_der },
	       { .out = &attr_der_bar, .name = "Bar", .type = FR_TYPE_STRUCT, .dict = &dict_der },
	       { .out = &attr_der_bar_boolean, .name = "Bar.Test-Boolean", .type = FR_TYPE_BOOL, .dict = &dict_der },
	       { .out = &attr_der_foobar, .name = "Foo-Bar", .type = FR_TYPE_STRUCT, .dict = &dict_der },
	       { .out = &attr_der_foobar_integer, .name = "Foo-Bar.Test-Integer", .type = FR_TYPE_INT64, .dict = &dict_der },
	       { .out = &attr_der_foobar_boolean, .name = "Foo-Bar.Test-Boolean", .type = FR_TYPE_BOOL, .dict = &dict_der },
	       { .out = &attr_der_bitstring, .name = "Test-Bitstring", .type = FR_TYPE_OCTETS, .dict = &dict_der },
	       { .out = &attr_der_seq_bitstring_octets, .name = "Seq-Bitstring-Octets", .type = FR_TYPE_STRUCT, .dict = &dict_der },
	       { .out = &attr_der_seq_bitstring, .name = "Seq-Bitstring-Octets.Test-Bitstring", .type = FR_TYPE_OCTETS, .dict = &dict_der },
	       { .out = &attr_der_bitstring_struct, .name = "Bitstring-Struct", .type = FR_TYPE_STRUCT, .dict = &dict_der },
	       { .out = &attr_der_bitstring_struct_foo, .name = "Bitstring-Struct.Foo", .type = FR_TYPE_UINT8, .dict = &dict_der },
	       { .out = &attr_der_bitstring_struct_bar, .name = "Bitstring-Struct.Bar", .type = FR_TYPE_UINT8, .dict = &dict_der },
	       { .out = &attr_der_bitstring_struct_foobar, .name = "Bitstring-Struct.Foo-bar", .type = FR_TYPE_UINT8, .dict = &dict_der },

	       { .out = &attr_der_null, .name = "Test-Null", .type = FR_TYPE_BOOL, .dict = &dict_der },

	       { .out = &attr_der_utf8, .name = "Test-String-UTF8", .type = FR_TYPE_STRING, .dict = &dict_der },
	       { .out = &attr_der_context_specific, .name = "Test-Context-Specific", .type = FR_TYPE_BOOL, .dict = &dict_der },
	       { .out = &attr_der_subject, .name = "CertificationRequest.certificationRequestInfo.subject", .type = FR_TYPE_TLV, .dict = &dict_der },
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
	// fr_assert(instance_count > 0);

	if (--instance_count != 0) return;

	fr_dict_autofree(libfreeradius_der_dict);
}

static int dict_flag_tagnum(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->tagnum = (uint8_t)atoi(value);

	return 0;
}

static int dict_flag_class(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	static fr_table_num_sorted_t const table[] = {
		{ L("application"), FR_DER_CLASS_APPLICATION },
		{ L("context-specific"), FR_DER_CLASS_CONTEXT },
		{ L("private"), FR_DER_CLASS_PRIVATE },
		{ L("universal"), FR_DER_CLASS_UNIVERSAL },
	};

	static size_t table_len = NUM_ELEMENTS(table);

	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_class_t   tag_class;

	tag_class = fr_table_value_by_str(table, value, FR_DER_CLASS_INVALID);

	if (tag_class == FR_DER_CLASS_INVALID) {
		fr_strerror_printf("Invalid tag class '%s'", value);
		return -1;
	}

	flags->class = tag_class;

	return 0;
}

static int dict_flag_has_default(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->has_default = true;

	return 0;
}

static int dict_flag_subtype(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	static fr_table_num_sorted_t const table[] = {
		{ L("bitstring"), FR_DER_TAG_BITSTRING },
		{ L("boolean"), FR_DER_TAG_BOOLEAN },
		{ L("bmpstring"), FR_DER_TAG_BMP_STRING },
		{ L("enumerated"), FR_DER_TAG_ENUMERATED },
		{ L("generalizedtime"), FR_DER_TAG_GENERALIZED_TIME },
		{ L("generalstring"), FR_DER_TAG_GENERAL_STRING },
		{ L("ia5string"), FR_DER_TAG_IA5_STRING },
		{ L("integer"), FR_DER_TAG_INTEGER },
		{ L("null"), FR_DER_TAG_NULL },
		{ L("oid"), FR_DER_TAG_OID },
		{ L("octetstring"), FR_DER_TAG_OCTETSTRING },
		{ L("printablestring"), FR_DER_TAG_PRINTABLE_STRING },
		{ L("sequence"), FR_DER_TAG_SEQUENCE },
		{ L("set"), FR_DER_TAG_SET },
		{ L("t61string"), FR_DER_TAG_T61_STRING },
		{ L("universalstring"), FR_DER_TAG_UNIVERSAL_STRING },
		{ L("utctime"), FR_DER_TAG_UTC_TIME },
		{ L("utf8string"), FR_DER_TAG_UTF8_STRING },
		{ L("visiblestring"), FR_DER_TAG_VISIBLE_STRING },
	};

	static size_t table_len = NUM_ELEMENTS(table);

	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_num_t     subtype;

	subtype = fr_table_value_by_str(table, value, UINT8_MAX);

	if (subtype == UINT8_MAX) {
		fr_strerror_printf("Invalid tag subtype '%s'", value);
		return -1;
	}

	flags->subtype = subtype;

	return 0;
}

static int dict_flag_sequence_of(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	static fr_table_num_sorted_t const table[] = {
		{ L("bitstring"), FR_DER_TAG_BITSTRING },
		{ L("boolean"), FR_DER_TAG_BOOLEAN },
		{ L("bmpstring"), FR_DER_TAG_BMP_STRING },
		{ L("enumerated"), FR_DER_TAG_ENUMERATED },
		{ L("generalizedtime"), FR_DER_TAG_GENERALIZED_TIME },
		{ L("generalstring"), FR_DER_TAG_GENERAL_STRING },
		{ L("ia5string"), FR_DER_TAG_IA5_STRING },
		{ L("integer"), FR_DER_TAG_INTEGER },
		{ L("null"), FR_DER_TAG_NULL },
		{ L("oid"), FR_DER_TAG_OID },
		{ L("octetstring"), FR_DER_TAG_OCTETSTRING },
		{ L("printablestring"), FR_DER_TAG_PRINTABLE_STRING },
		{ L("sequence"), FR_DER_TAG_SEQUENCE },
		{ L("set"), FR_DER_TAG_SET },
		{ L("t61string"), FR_DER_TAG_T61_STRING },
		{ L("universalstring"), FR_DER_TAG_UNIVERSAL_STRING },
		{ L("utctime"), FR_DER_TAG_UTC_TIME },
		{ L("utf8string"), FR_DER_TAG_UTF8_STRING },
		{ L("visiblestring"), FR_DER_TAG_VISIBLE_STRING },
	};

	static size_t table_len = NUM_ELEMENTS(table);

	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_num_t     type;

	type = fr_table_value_by_str(table, value, UINT8_MAX);

	if (type == UINT8_MAX) {
		fr_strerror_printf("Invalid tag type '%s'", value);
		return -1;
	}

	flags->sequence_of = type;
	flags->is_sequence_of = true;

	return 0;
}

static int dict_flag_set_of(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	static fr_table_num_sorted_t const table[] = {
		{ L("bitstring"), FR_DER_TAG_BITSTRING },
		{ L("boolean"), FR_DER_TAG_BOOLEAN },
		{ L("bmpstring"), FR_DER_TAG_BMP_STRING },
		{ L("enumerated"), FR_DER_TAG_ENUMERATED },
		{ L("generalizedtime"), FR_DER_TAG_GENERALIZED_TIME },
		{ L("generalstring"), FR_DER_TAG_GENERAL_STRING },
		{ L("ia5string"), FR_DER_TAG_IA5_STRING },
		{ L("integer"), FR_DER_TAG_INTEGER },
		{ L("null"), FR_DER_TAG_NULL },
		{ L("oid"), FR_DER_TAG_OID },
		{ L("octetstring"), FR_DER_TAG_OCTETSTRING },
		{ L("printablestring"), FR_DER_TAG_PRINTABLE_STRING },
		{ L("sequence"), FR_DER_TAG_SEQUENCE },
		{ L("set"), FR_DER_TAG_SET },
		{ L("t61string"), FR_DER_TAG_T61_STRING },
		{ L("universalstring"), FR_DER_TAG_UNIVERSAL_STRING },
		{ L("utctime"), FR_DER_TAG_UTC_TIME },
		{ L("utf8string"), FR_DER_TAG_UTF8_STRING },
		{ L("visiblestring"), FR_DER_TAG_VISIBLE_STRING },
	};

	static size_t table_len = NUM_ELEMENTS(table);

	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_num_t     type;

	type = fr_table_value_by_str(table, value, UINT8_MAX);

	if (type == UINT8_MAX) {
		fr_strerror_printf("Invalid tag type '%s'", value);
		return -1;
	}

	flags->set_of = type;
	flags->is_set_of = true;

	return 0;
}

static int dict_flag_is_pair(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->is_pair = true;

	return 0;
}

static int dict_flag_is_extension(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->is_extension = true;

	return 0;
}

static int dict_flag_is_extensions(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->is_extensions = true;

	return 0;
}

static int dict_flag_is_pairs(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->is_pairs = true;

	return 0;
}

static int dict_flag_max(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->max = (uint64_t)atoll(value);

	return 0;
}

static fr_dict_flag_parser_t const der_flags[] = {
						   { L("class"), { .func = dict_flag_class } },
						   { L("has_default"), { .func = dict_flag_has_default } },
						   { L("is_extension"), { .func = dict_flag_is_extension } },
						   { L("is_extensions"), { .func = dict_flag_is_extensions } },
						   { L("is_pair"), { .func = dict_flag_is_pair } },
						   { L("is_pairs"), { .func = dict_flag_is_pairs } },
						   { L("max"), { .func = dict_flag_max } },
						   { L("sequence_of"), { .func = dict_flag_sequence_of } },
						   { L("set_of"), { .func = dict_flag_set_of } },
						   { L("subtype"), { .func = dict_flag_subtype } },
						    { L("tagnum"), { .func = dict_flag_tagnum } } };

static bool attr_valid(fr_dict_attr_t *da)
{
	if (da->flags.subtype && !fr_type_to_der_tag_valid(da->type, da->flags.subtype)) {
		return false;
	}

	if (fr_der_flag_is_sequence_of(da->parent) || fr_der_flag_is_set_of(da->parent)) {
		static fr_table_num_sorted_t const table[] = {
			{ L("bitstring"), FR_DER_TAG_BITSTRING },
			{ L("bmpstring"), FR_DER_TAG_BMP_STRING },
			{ L("boolean"), FR_DER_TAG_BOOLEAN },
			{ L("enumerated"), FR_DER_TAG_ENUMERATED },
			{ L("generalizedtime"), FR_DER_TAG_GENERALIZED_TIME },
			{ L("generalstring"), FR_DER_TAG_GENERAL_STRING },
			{ L("ia5string"), FR_DER_TAG_IA5_STRING },
			{ L("integer"), FR_DER_TAG_INTEGER },
			{ L("null"), FR_DER_TAG_NULL },
			{ L("octetstring"), FR_DER_TAG_OCTETSTRING },
			{ L("oid"), FR_DER_TAG_OID },
			{ L("printablestring"), FR_DER_TAG_PRINTABLE_STRING },
			{ L("sequence"), FR_DER_TAG_SEQUENCE },
			{ L("set"), FR_DER_TAG_SET },
			{ L("t61string"), FR_DER_TAG_T61_STRING },
			{ L("universalstring"), FR_DER_TAG_UNIVERSAL_STRING },
			{ L("utctime"), FR_DER_TAG_UTC_TIME },
			{ L("utf8string"), FR_DER_TAG_UTF8_STRING },
			{ L("visiblestring"), FR_DER_TAG_VISIBLE_STRING },
		};

		static size_t table_len = NUM_ELEMENTS(table);

		uint8_t of_type = fr_der_flag_is_sequence_of(da->parent) ? fr_der_flag_sequence_of(da->parent) : fr_der_flag_set_of(da->parent);

		if (unlikely(fr_type_to_der_tags[da->type][of_type] == false)) {
			fr_strerror_printf("Attribute %s of type %s is not allowed in a sequence/set-of %s",da->name, fr_type_to_str(da->type), fr_table_str_by_value(table, of_type, "<INVALID>"));
			return false;
		}
	}

	// if ((fr_der_flag_class(da) && !fr_der_flag_tagnum(da)) && unlikely(da->type != FR_TYPE_BOOL)) {
	// 	fr_strerror_printf("Attribute %s Non-Universal tag %u must have a tagnum.",da->name, fr_der_flag_tagnum(da));
	// 	return false;
	// }

	return true;
}

extern fr_dict_protocol_t libfreeradius_der_dict_protocol;
fr_dict_protocol_t	  libfreeradius_der_dict_protocol = {
	       .name		    = "der",
	       .default_type_size   = 1,
	       .default_type_length = 1,
	       .attr = {
		       .flags = {
			       .table    = der_flags,
			       .table_len = NUM_ELEMENTS(der_flags),
			       .len	   = sizeof(fr_der_attr_flags_t),
		       },
		       .valid = attr_valid
	       },

	       .init = fr_der_global_init,
	       .free		     = fr_der_global_free,

	       // .decode = fr_der_decode_foreign,
	       // .encode = fr_der_encode_foreign,
};