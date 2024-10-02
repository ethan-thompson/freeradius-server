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
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @author Ethan Thompson (ethan.thompson@inkbridge.io)
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2024 Inkbridge Networks SAS.
 */
#include "include/build.h"
#include "lib/util/proto.h"
#include "talloc.h"
#include <stdint.h>
#include <stddef.h>

#include <freeradius-devel/io/test_point.h>

#include <freeradius-devel/util/decode.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/types.h>

typedef struct {
	uint8_t		*tmp_ctx;
} fr_der_decode_ctx_t;

/** Enumeration describing the data types in a DER encoded structure
 */
typedef enum {
	FR_DER_TAG_BOOLEAN = 0x01,		//!< Boolean true/false
	FR_DER_TAG_INTEGER = 0x02,		//!< Arbitrary width signed integer.
	FR_DER_TAG_BIT_STRING = 0x03,		//!< String of bits (length field specifies bits).
	FR_DER_TAG_OCTET_STRING = 0x04,		//!< String of octets (length field specifies bytes).
	FR_DER_TAG_NULL = 0x05,			//!< An empty value.
	FR_DER_TAG_OID = 0x06,			//!< Reference to an OID based attribute.
	FR_DER_TAG_UTF8_STRING = 0x0c,		//!< String of UTF8 chars.
	FR_DER_TAG_SEQUENCE = 0x10,		//!< A sequence of DER encoded data (a structure).
	FR_DER_TAG_SET = 0x11,			//!< A set of DER encoded data (a structure).
	FR_DER_TAG_PRINTABLE_STRING = 0x13,	//!< String of printable chars.
	FR_DER_TAG_IA5_STRING = 0x16,		//!< String of IA5 (7bit) chars.
	FR_DER_TAG_UTC_TIME = 0x17,		//!< A time in UTC "YYMMDDhhmm[ss]Z" format.  "ss" is optional.
	FR_DER_TAG_GENERALIZED_TIME = 0x18	//!< A time in "YYYYMMDDHH[MM[SS[.fff]]]" format.
} fr_der_tag_t;

#define DER_TAG_CONTINUATION 0x1f 		//!< Mask to check if the tag is a continuation.

#define IS_DER_TAG_CONTINUATION(_tag)	(((_tag) & DER_TAG_CONTINUATION) == DER_TAG_CONTINUATION)
#define IS_DER_TAG_CONSTRUCTED(_tag)	((_tag) & 0x20)

typedef enum {
	FR_DER_TAG_PRIMATIVE = 0x00,		//!< This is a leaf value, it contains no children.
	FR_DER_TAG_CONSTRUCTED = 0x01		//!< This is a sequence or set, it contains children.
} fr_der_tag_constructed_t;

typedef enum {
	FR_DER_TAG_FLAG_UNIVERSAL = 0x00,	//!<
	FR_DER_TAG_FLAG_APPLICATION = 0x01,
	FR_DER_TAG_FLAG_CONTEXT = 0x02,
	FR_DER_TAG_FLAG_PRIVATE = 0x03
} fr_der_tag_flag_t;

/** Function signature for DER decode functions
 *
 * @param[in] ctx		Allocation context
 * @param[in] out		Where to store the decoded pairs.
 * @param[in] parent		Parent attribute.  This should be the root of the dictionary
 *				we're using to decode DER data initially, and then nested children.
 * @param[in] tag		The tag of the DER encoded data
 * @param[in] constructed	Whether the data is constructed (true) or primative (false).
 * @param[in] tag_flags		Flags describing the tag.  See #fr_der_tag_flag_t
 * @param[in] in		The DER encoded data.
 * @param[in] decode_ctx	Any decode specific data.
 * @return
 *	- > 0 on success.  How many bytes were decoded.
 *	- 0 no bytes decoded.
 *	- < 0 on error.  May be the offset (as a negative value) where the error occurred.
 */
typedef ssize_t (*fr_der_decode_t)(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				   fr_der_tag_t tag, fr_der_tag_constructed_t constructed, fr_der_tag_flag_t tag_flags,
				   fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_pair_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			   		fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_boolean(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				     fr_der_tag_t tag, fr_der_tag_constructed_t constructed, fr_der_tag_flag_t tag_flags,
				     fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_integer(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				     fr_der_tag_t tag, fr_der_tag_constructed_t constructed, fr_der_tag_flag_t tag_flags,
				     fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_sequence(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				      fr_der_tag_t tag, fr_der_tag_constructed_t constructed, fr_der_tag_flag_t tag_flags,
				      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);


static fr_der_decode_t tag_funcs[] = {
	[FR_DER_TAG_BOOLEAN] = fr_der_decode_boolean,
	[FR_DER_TAG_INTEGER] = fr_der_decode_integer,
	[FR_DER_TAG_SEQUENCE] = fr_der_decode_sequence
};

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_der_decode_ctx_t	*test_ctx;

	test_ctx = talloc_zero(ctx, fr_der_decode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_der_decode_boolean(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_der_tag_t tag,
				     fr_der_tag_constructed_t constructed, fr_der_tag_flag_t tag_flags,
				     fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t	*vp;
	uint8_t		val;

	if (unlikely(fr_dbuff_out(&val, in) < 0)) {
		fr_strerror_const("Insufficient data for boolean");
		return -1;
	}

	// Ensure the value conforms to DER standards where:
	// 1. False is represented by 0x00
	// 2. True is represented by 0xFF
	if (val != 0x00 && val != 0xFF) {
		fr_strerror_const("Boolean is not correctly DER encoded");
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);

	vp->vp_bool = val > 0;

	fr_pair_append(out, vp);

	return 1;
}

static ssize_t fr_der_decode_integer(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_der_tag_t tag,
				     fr_der_tag_constructed_t constructed, fr_der_tag_flag_t tag_flags,
				     fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t	*vp;
	int64_t		val = 0;
	uint8_t		sign = 0;
	static int64_t const		min[] = { INT8_MIN, INT16_MIN, INT32_MIN, INT32_MIN, INT64_MIN, INT64_MIN, INT64_MIN, INT64_MIN };
	static int64_t const		max[] = { INT8_MAX, INT16_MAX, INT32_MAX, INT32_MAX, INT64_MAX, INT64_MAX, INT64_MAX, INT64_MAX };

	size_t len = fr_dbuff_remaining(in);

	if (!fr_type_is_integer_except_bool(parent->type)) {
		fr_strerror_const("Integer found in non-integer attribute");
		return DECODE_FAIL_INVALID_ATTRIBUTE;
	}

	if (len > sizeof(val)) {
		fr_strerror_printf("Integer too large (%zu)", len);
		return -1;
	}

	if (unlikely(fr_dbuff_out(&sign, in) < 0)) {
		fr_strerror_const("Insufficient data for integer");
		return -1;
	}

	if (sign & 0x80) {
		// If the sign bit is set, this is a negative number.
		// This will fill the upper bits with 1s.
		// This is important for the case where the length of the integer is less than the length of the integer type.
		val = -1;
	}

	val = (val << 8) | sign;

	if (len > 1) {
		// If the length of the integer is greater than 1, we need to check that the first 9 bits:
		// 1. are not all 1s; and
		// 2. are not all 0s
		// These two conditions are necessary to ensure that the integer conforms to DER.
		uint8_t byte;
		if (unlikely(fr_dbuff_out(&byte, in) < 0)) {
			fr_strerror_const("Insufficient data for integer");
			return -1;
		}

		if ( (((val & 0xFF) == 0xFF) && (byte & 0x80)) || (((~val & 0xFF) == 0xFF) && !(byte & 0x80)) ) {
			fr_strerror_const("Integer is not correctly DER encoded");
			return -1;
		}

		val = (val << 8) | byte;
	}

	for (size_t i = 2; i < len; i++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, in) < 0)) {
			fr_strerror_const("Insufficient data for integer");
			return -1;
		}

		val = (val << 8) | byte;
	}

	if ( (val < min[len - 1 ]) || (val > max[len - 1]) ) {
		fr_strerror_printf("Integer out of range (%" PRId64 ")", val);
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);

	vp->vp_int64 = val;

	fr_pair_append(out, vp);

	return 1;
}

static ssize_t fr_der_decode_sequence(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_der_tag_t tag,
				 fr_der_tag_constructed_t constructed, fr_der_tag_flag_t tag_flags,
				      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t		*vp;
	fr_dict_attr_t const *child = NULL;
	fr_dbuff_t		our_in = FR_DBUFF(in);

	if (!fr_type_is_struct(parent->type)) {
		fr_strerror_const("Sequence found in non-struct attribute");
		return DECODE_FAIL_INVALID_ATTRIBUTE;
	}

	vp = fr_pair_afrom_da(ctx, parent);

	if (unlikely(vp == NULL)) {
		return DECODE_FAIL_UNKNOWN;
	};

	while ((child = fr_dict_attr_iterate_children(parent, &child))) {
		ssize_t ret;

		FR_PROTO_TRACE("decode context %s -> %s", parent->name, child->name);

		ret = fr_der_decode_pair_dbuff(vp, &vp->vp_group, child, &our_in, decode_ctx);
		if (unlikely(ret < 0)) {
			talloc_free(vp);
			return ret;
		}
	}

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_pair_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			   		fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_dbuff_t			our_in = FR_DBUFF(in);
	ssize_t				slen;
	uint8_t 			tag_byte;
	uint64_t 			tag;
	fr_der_tag_flag_t		tag_flags;
	fr_der_tag_constructed_t	constructed;

	uint8_t				len_byte;
	size_t				len = 0;
	fr_der_decode_t 		func;

	if (unlikely(fr_dbuff_out(&tag_byte, &our_in) < 0)) return 0;

	/*
	 *	Decode the tag flags
	 */
	tag_flags = (tag_byte >> 6) & 0x03;
	constructed = IS_DER_TAG_CONSTRUCTED(tag_byte);

	/*
	 *	Decode the tag
	 */
	if (IS_DER_TAG_CONTINUATION(tag_byte)) {
		/*
		 *	We have a multi-byte tag
		 */
		tag = 0;
		do {
			if (unlikely(fr_dbuff_out(&tag_byte, &our_in) < 0)) {
				fr_strerror_const("Insufficient data to satisfy multi-byte tag");
				return -1;
			}
			tag = (tag << 7) | (tag_byte & 0x7f);
		} while (tag_byte & 0x80);
	} else {
		tag = tag_byte & DER_TAG_CONTINUATION;
	}

	if ((tag > NUM_ELEMENTS(tag_funcs)) || (tag == 0)) {
		fr_strerror_printf("Unknown tag %" PRIu64 , tag);
	}

	func = tag_funcs[tag];
	if (unlikely(func == NULL)) {
		fr_strerror_printf("No decode function for tag %" PRIu64, tag);
		return -1;
	}

	if (unlikely(fr_dbuff_out(&len_byte, &our_in) < 0)) {
		fr_strerror_const("Missing length field");
		return -1;
	}

	if (len_byte & 0x80) {
		uint8_t len_len = len_byte & 0x7f;

		/*
		 *	Length bits of zero is an indeterminate length field where
		 *	the length is encoded in the data instead.
		 */
		if (len_len > 0) {
			if (unlikely(len_len > sizeof(len))) {
				fr_strerror_printf("Length field too large (%u)", len_len);
				return -1;
			}

			while (--len_len) {
				if (unlikely(fr_dbuff_out(&len_byte, &our_in) < 0)) {
					fr_strerror_const("Insufficient data to satisfy multi-byte length field");
					return -1;
				}
				len = (len << 8) | len_byte;
			}
		}

		if (!constructed) {
			fr_strerror_const("Primative data with indefinite form length field is invalid");
			return DECODE_FAIL_INVALID_ATTRIBUTE;
		}
	} else {
		len = len_byte;
	}

	fr_dbuff_set_end(&our_in, fr_dbuff_current(&our_in) + len);

	slen = func(ctx, out, parent, tag, constructed, tag_flags, &our_in, decode_ctx);

	if (unlikely(slen < 0)) return slen;

	return fr_dbuff_set(in, &our_in);
}

/** Decode a DER structure using the specific dictionary
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] out		where new VPs will be added
 * @param[in] parent		Parent attribute.  This should be the root of the dictionary
 *				we're using to decode DER data.  This only specifies structures
 *				like SEQUENCES.  OID based pairs are resolved using the global
 *				dictionary tree.
 *
 */
static ssize_t decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			   uint8_t const *data, size_t data_len, void *decode_ctx)
{
	// fr_assert(parent == fr_dict_root(dict_der));

	return fr_der_decode_pair_dbuff(ctx, out, parent, &FR_DBUFF_TMP(data, data_len), decode_ctx);
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t der_tp_decode_pair;
fr_test_point_pair_decode_t der_tp_decode_pair = {
	.test_ctx	= decode_test_ctx,
	.func		= decode_pair,
};
