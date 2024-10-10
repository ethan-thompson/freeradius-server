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
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <freeradius-devel/io/test_point.h>

#include <freeradius-devel/util/decode.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/types.h>

#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/time.h>

typedef struct {
	uint8_t *tmp_ctx;
} fr_der_decode_ctx_t;

/** Enumeration describing the data types in a DER encoded structure
 */
typedef enum {
	FR_DER_TAG_BOOLEAN	    = 0x01,	   //!< Boolean true/false
	FR_DER_TAG_INTEGER	    = 0x02,	   //!< Arbitrary width signed integer.
	FR_DER_TAG_BITSTRING	    = 0x03,	   //!< String of bits (length field specifies bits).
	FR_DER_TAG_OCTETSTRING	    = 0x04,	   //!< String of octets (length field specifies bytes).
	FR_DER_TAG_NULL		    = 0x05,	   //!< An empty value.
	FR_DER_TAG_OID		    = 0x06,	   //!< Reference to an OID based attribute.
	FR_DER_TAG_UTF8_STRING	    = 0x0c,	   //!< String of UTF8 chars.
	FR_DER_TAG_SEQUENCE	    = 0x10,	   //!< A sequence of DER encoded data (a structure).
	FR_DER_TAG_SET		    = 0x11,	   //!< A set of DER encoded data (a structure).
	FR_DER_TAG_PRINTABLE_STRING = 0x13,	   //!< String of printable chars.
	FR_DER_TAG_T61_STRING	    = 0x14,	   //!< String of T61 (8bit) chars.
	FR_DER_TAG_IA5_STRING	    = 0x16,	   //!< String of IA5 (7bit) chars.
	FR_DER_TAG_UTC_TIME	    = 0x17,	   //!< A time in UTC "YYMMDDhhmmssZ" format.
	FR_DER_TAG_GENERALIZED_TIME = 0x18,	   //!< A time in "YYYYMMDDHHMMSS[.fff]Z" format.
	FR_DER_TAG_VISIBLE_STRING   = 0x1a,	   //!< String of visible chars.
	FR_DER_TAG_GENERAL_STRING   = 0x1b,	   //!< String of general chars.
	FR_DER_TAG_UNIVERSAL_STRING = 0x1c,	   //!< String of universal chars.
	FR_DER_TAG_BMP_STRING	    = 0x1e	  //!< String of BMP chars.
} fr_der_tag_t;

#define DER_TAG_CONTINUATION 0x1f	 //!< Mask to check if the tag is a continuation.

#define IS_DER_TAG_CONTINUATION(_tag) (((_tag) & DER_TAG_CONTINUATION) == DER_TAG_CONTINUATION)
#define IS_DER_TAG_CONSTRUCTED(_tag) (((_tag) & 0x20) == 0x20)

#define DER_MAX_STR 16384

typedef enum {
	FR_DER_TAG_PRIMATIVE   = 0x00,	      //!< This is a leaf value, it contains no children.
	FR_DER_TAG_CONSTRUCTED = 0x01	     //!< This is a sequence or set, it contains children.
} fr_der_tag_constructed_t;

typedef enum {
	FR_DER_TAG_FLAG_UNIVERSAL   = 0x00,	   //!<
	FR_DER_TAG_FLAG_APPLICATION = 0x01,
	FR_DER_TAG_FLAG_CONTEXT	    = 0x02,
	FR_DER_TAG_FLAG_PRIVATE	    = 0x03
} fr_der_tag_flag_t;

/** Function signature for DER decode functions
 *
 * @param[in] ctx		Allocation context
 * @param[in] out		Where to store the decoded pairs.
 * @param[in] parent		Parent attribute.  This should be the root of the dictionary
 *				we're using to decode DER data initially, and then nested children.
 * @param[in] in		The DER encoded data.
 * @param[in] decode_ctx	Any decode specific data.
 * @return
 *	- > 0 on success.  How many bytes were decoded.
 *	- 0 no bytes decoded.
 *	- < 0 on error.  May be the offset (as a negative value) where the error occurred.
 */
typedef ssize_t (*fr_der_decode_t)(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				   fr_der_decode_ctx_t *decode_ctx);

typedef struct {
	fr_der_tag_constructed_t constructed;
	fr_der_decode_t		 decode;
} fr_der_tag_decode_t;

static ssize_t fr_der_decode_pair_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_boolean(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				     fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_integer(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				     fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_bitstring(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				       fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_octetstring(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					 fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_null(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				  fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_oid(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				 fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_utf8_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					 fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_sequence(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_set(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				 fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_printable_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_t61_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_ia5_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_utc_time(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_generalized_time(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_visible_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					    fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_general_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					    fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static ssize_t fr_der_decode_universal_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);

static fr_der_tag_decode_t tag_funcs[] = {
	[FR_DER_TAG_BOOLEAN]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_boolean },
	[FR_DER_TAG_INTEGER]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_integer },
	[FR_DER_TAG_BITSTRING]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_bitstring },
	[FR_DER_TAG_OCTETSTRING]      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_octetstring },
	[FR_DER_TAG_NULL]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_null },
	[FR_DER_TAG_OID]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_oid },
	[FR_DER_TAG_UTF8_STRING]      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_utf8_string },
	[FR_DER_TAG_SEQUENCE]	      = { .constructed = FR_DER_TAG_CONSTRUCTED, .decode = fr_der_decode_sequence },
	[FR_DER_TAG_SET]	      = { .constructed = FR_DER_TAG_CONSTRUCTED, .decode = fr_der_decode_set },
	[FR_DER_TAG_PRINTABLE_STRING] = { .constructed = FR_DER_TAG_PRIMATIVE,
					  .decode      = fr_der_decode_printable_string },
	[FR_DER_TAG_T61_STRING]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_t61_string },
	[FR_DER_TAG_IA5_STRING]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_ia5_string },
	[FR_DER_TAG_UTC_TIME]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_utc_time },
	[FR_DER_TAG_GENERALIZED_TIME] = { .constructed = FR_DER_TAG_PRIMATIVE,
					  .decode      = fr_der_decode_generalized_time },
	[FR_DER_TAG_VISIBLE_STRING]   = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_visible_string },
	[FR_DER_TAG_GENERAL_STRING]   = { .constructed = FR_DER_TAG_PRIMATIVE, .decode = fr_der_decode_general_string },
	[FR_DER_TAG_UNIVERSAL_STRING] = { .constructed = FR_DER_TAG_PRIMATIVE,
					  .decode      = fr_der_decode_universal_string },
};

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_der_decode_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_der_decode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_der_decode_boolean(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				     fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	uint8_t	   val;

	if (unlikely(fr_dbuff_out(&val, &our_in) < 0)) {
		fr_strerror_const("Insufficient data for boolean");
		return -1;
	}

	/*
	 * 	ISO/IEC 8825-1:2021
	 * 	8.2 Encoding of a boolean value
	 * 	8.2.1 The encoding of a boolean value shall be primitive.
	 *       	The contents octets shall consist of a single octet.
	 * 	8.2.2 If the boolean value is:
	 *       	FALSE the octet shall be zero [0x00].
	 *       	If the boolean value is TRUE the octet shall have any non-zero value, as a sender's option.
	 *
	 * 	11.1 Boolean values
	 * 		If the encoding represents the boolean value TRUE, its single contents octet shall have all
	 *		eight bits set to one [0xFF]. (Contrast with 8.2.2.)
	 */
	if (val != 0x00 && val != 0xFF) {
		fr_strerror_const("Boolean is not correctly DER encoded (cannot be constructed)");
		return -1;
	}

	if (val != 0x00 && val != 0xFF) {
		fr_strerror_const("Boolean is not correctly DER encoded (0x00 or 0xFF)");
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for boolean pair");
		return -1;
	}

	vp->vp_bool = val > 0;

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_integer(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				     fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	int64_t	   val	  = 0;
	uint8_t	   sign	  = 0;
	size_t	   i;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_integer_except_bool(parent->type)) {
		fr_strerror_printf("Integer found in non-integer attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	if (len > sizeof(val)) {
		fr_strerror_printf("Integer too large (%zu)", len);
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.3 Encoding of an integer value
	 *	8.3.1 The encoding of an integer value shall be primitive.
	 *	      The contents octets shall consist of one or more octets.
	 *	8.3.2 If the contents octets of an integer value encoding consist of more than one octet,
	 *	      then the bits of the first octet and bit 8 of the second octet:
	 *	      a) shall not all be ones; and
	 *	      b) shall not all be zero.
	 *	      NOTE – These rules ensure that an integer value is always encoded in the smallest possible number
	 *	      of octets. 8.3.3 The contents octets shall be a two's complement binary number equal to the
	 *	      integer value, and consisting of bits 8 to 1 of the first octet, followed by bits 8 to 1 of the
	 *	      second octet, followed by bits 8 to 1 of each octet in turn up to and including the last octet of
	 *	      the contents octets.
	 */
	if (unlikely(fr_dbuff_out(&sign, &our_in) < 0)) {
		fr_strerror_const("Insufficient data for integer. Missing first byte");
		return -1;
	}

	if (sign & 0x80) {
		/*
		 *	If the sign bit is set, this is a negative number.
		 *	This will fill the upper bits with 1s.
		 *	This is important for the case where the length of the integer is less than the length of the
		 *integer type.
		 */
		val = -1;
	}

	val = (val << 8) | sign;

	if (len > 1) {
		/*
		 *	If the length of the integer is greater than 1, we need to check that the first 9 bits:
		 *	1. are not all 0s; and
		 *	2. are not all 1s
		 *	These two conditions are necessary to ensure that the integer conforms to DER.
		 */
		uint8_t byte;
		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for integer. Missing second byte");
			return -1;
		}

		if ((((val & 0xFF) == 0xFF) && (byte & 0x80)) || (((~val & 0xFF) == 0xFF) && !(byte & 0x80))) {
			fr_strerror_const("Integer is not correctly DER encoded");
			return -1;
		}

		val = (val << 8) | byte;
	}

	for (i = 2; i < len; i++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for integer. Ran out of bytes");
			return -1;
		}

		val = (val << 8) | byte;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for integer pair");
		return -1;
	}

	vp->vp_int64 = val;

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_bitstring(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				       fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in      = FR_DBUFF(in);
	uint8_t	   unused_bits = 0;
	uint8_t	  *data;

	ssize_t data_len = 0, index = 0;
	size_t	len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_octets(parent->type) && !fr_type_is_struct(parent->type)) {
		fr_strerror_printf("Bitstring found in non-octets attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	Now we know that the parent is an octets attribute, we can decode the bitstring
	 */

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.6 Encoding of a bitstring value
	 *		8.6.1 The encoding of a bitstring value shall be either primitive or constructed at the option
	 *		      of the sender.
	 *			NOTE – Where it is necessary to transfer part of a bit string before the entire
	 *			       bitstring is available, the constructed encoding is used.
	 *		8.6.2 The contents octets for the primitive encoding shall contain an initial octet followed
	 *		      by zero, one or more subsequent octets.
	 *			8.6.2.1 The bits in the bitstring value, commencing with the leading bit and proceeding
	 *				to the trailing bit, shall be placed in bits 8 to 1 of the first subsequent
	 *				octet, followed by bits 8 to 1 of the second subsequent octet, followed by bits
	 *				8 to 1 of each octet in turn, followed by as many bits as are needed of the
	 *				final subsequent octet, commencing with bit 8.
	 *				NOTE – The terms "leading bit" and "trailing bit" are defined in
	 *				       Rec. ITU-T X.680 | ISO/IEC 8824-1, 22.2.
	 *			8.6.2.2 The initial octet shall encode, as an unsigned binary integer with bit 1 as the
	 *				least significant bit, the number of unused bits in the final subsequent octet.
	 *				The number shall be in the range zero to seven.
	 *			8.6.2.3 If the bitstring is empty, there shall be no subsequent octets, and the initial
	 *				octet shall be zero.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of
	 *		encoding shall not be used. (Contrast with 8.23.6.)
	 *
	 *	11.2 Unused bits 11.2.1 Each unused bit in the final octet of the encoding of a bit string value shall
	 *	     be set to zero.
	 */

	if (unlikely(fr_dbuff_out(&unused_bits, &our_in) < 0)) {
		fr_strerror_const("Insufficient data for bitstring");
		return -1;
	}

	if (unlikely(unused_bits > 7)) {
		fr_strerror_const("Invalid number of unused bits in bitstring");
		return -1;
	}

	if (len == 1 && unused_bits) {
		fr_strerror_const("Insufficient data for bitstring. Missing data bytes");
		return -1;
	}

	if (fr_type_is_struct(parent->type)) {
		/*
		 *	If the parent is a struct attribute, we will not be adding the unused bits count to the first
		 *	byte
		 */
		data_len = len - 1;
	} else {
		data_len = len;
	}

	data = talloc_array(ctx, uint8_t, data_len);
	if (unlikely(data == NULL)) {
		fr_strerror_const("Out of memory for bitstring");
		return -1;
	}

	if (fr_type_is_octets(parent->type)) {
		/*
		 *	If the parent is an octets attribute, we need to add the unused bits count to the first byte
		 */
		index	= 1;
		data[0] = unused_bits;
	}

	for (; index < data_len; index++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for bitstring. Ran out of bytes");
		error:
			talloc_free(data);
			return -1;
		}

		data[index] = byte;
	}

	/*
	 *	Remove the unused bits from the last byte
	 */
	if (unused_bits) {
		uint8_t mask = 0xff << unused_bits;

		data[data_len - 1] &= mask;
	}

	if (fr_type_is_struct(parent->type)) {
		ssize_t slen;

		slen = fr_struct_from_network(ctx, out, parent, data, data_len, true, decode_ctx, NULL, NULL);

		/*
		 *	If the structure decoder didn't consume all the data, we need to free the data and bail out
		 */
		if (unlikely(slen < data_len - 1)) {
			// fr_strerror_const("Bitstring structure decoder didn't consume all data");
			fr_strerror_printf(
				"Bitstring structure decoder didn't consume all data. Consumed %zu of %zu bytes", slen,
				data_len);
			goto error;
		}

		return fr_dbuff_set(in, &our_in);
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for bitstring pair");
		goto error;
	}

	/*
	 *	Add the bitstring to the pair value as octets
	 */
	fr_pair_value_memdup(vp, data, len, false);

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_octetstring(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					 fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	uint8_t	  *data	  = NULL;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_octets(parent->type)) {
		fr_strerror_printf("Octetstring found in non-octets attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.7 Encoding of an octetstring value
	 *		8.7.1 The encoding of an octetstring value shall be either primitive or constructed at the
	 *		      option of the sender.
	 *			NOTE – Where it is necessary to transfer part of an octet string before the entire
	 *			       octetstring is available, the constructed encoding is used.
	 *		8.7.2 The primitive encoding contains zero, one or more contents octets equal in value to the
	 *		      octets in the data value, in the order they appear in the data value, and with the most
	 *		      significant bit of an octet of the data value aligned with the most significant bit of an
	 *		      octet of the contents octets.
	 *		8.7.3 The contents octets for the constructed encoding shall consist of zero, one, or more
	 *		      encodings.
	 *			NOTE – Each such encoding includes identifier, length, and contents octets, and may
	 *			       include end-of-contents octets if it is constructed.
	 *			8.7.3.1 To encode an octetstring value in this way, it is segmented. Each segment shall
	 *			       consist of a series of consecutive octets of the value. There shall be no
	 *			       significance placed on the segment boundaries.
	 *				NOTE – A segment may be of size zero, i.e. contain no octets.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of
	 *		encoding shall not be used. (Contrast with 8.23.6.)
	 */

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for octetstring pair");
		return -1;
	}

	if (unlikely(fr_pair_value_mem_alloc(vp, &data, len, false) < 0)) {
		fr_strerror_const("Out of memory for octetstring");
		return -1;
	}

	fr_dbuff_out_memcpy(data, &our_in, len);

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_null(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				  fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);

	if (fr_dbuff_remaining(&our_in) != 0) {
		fr_strerror_const("Null has non-zero length");
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.8 Encoding of a null value 8.8.1 The encoding of a null value shall be primitive. 8.8.2 The contents
	 *	    octets shall not contain any octets. NOTE – The length octet is zero.
	 */

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for null pair");
		return -1;
	}

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_oid(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				 fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in	 = FR_DBUFF(in);
	uint64_t   subidentifier = 0;
	char	  *oid		 = NULL;

	size_t index = 1, magnitude = 1;
	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_string(parent->type)) {
		fr_strerror_printf("OID found in non-string attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.19 Encoding of an object identifier value
	 *	8.19.1 The encoding of an object identifier value shall be primitive.
	 *	8.19.2 The contents octets shall be an (ordered) list of encodings of subidentifiers (see 8.19.3
	 *	       and 8.19.4) concatenated together. Each subidentifier is represented as a series of
	 *	       (one or more) octets. Bit 8 of each octet indicates whether it is the last in the series: bit 8
	 *	       of the last octet is zero; bit 8 of each preceding octet is one. Bits 7 to 1 of the octets in
	 *	       the series collectively encode the subidentifier. Conceptually, these groups of bits are
	 *	       concatenated to form an unsigned binary number whose most significant bit is bit 7 of the first
	 *	       octet and whose least significant bit is bit 1 of the last octet. The subidentifier shall be
	 *	       encoded in the fewest possible octets, that is, the leading octet of the subidentifier shall not
	 *	       have the value 8016.
	 *	8.19.3 The number of subidentifiers (N) shall be one less than the number of object identifier
	 *		components in the object identifier value being encoded. 8.19.4 The numerical value of the
	 *		first subidentifier is derived from the values of the first two object identifier components in
	 *		the object identifier value being encoded, using the formula: (X*40) + Y where X is the value
	 *		of the first object identifier component and Y is the value of the second object identifier
	 *		component. NOTE – This packing of the first two object identifier components recognizes that
	 *		only three values are allocated from the root node, and at most 39 subsequent values from nodes
	 *		reached by X = 0 and X = 1. 8.19.5 The numerical value of the ith subidentifier, (2 ≤ i ≤ N) is
	 *		that of the (i + 1)th object identifier component.
	 */

	/*
	 *	The first subidentifier is the encoding of the first two object identifier components, encoded as:
	 *		(X * 40) + Y
	 *	where X is the first number and Y is the second number.
	 *	The first number is 0, 1, or 2.
	 */
	for (; index < len; index++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for OID subidentifier");
			return -1;
		}

		subidentifier = (subidentifier << 7) | (byte & 0x7f);

		if (!(byte & 0x80)) {
			/*
			 *	If the high bit is not set, this is the last byte of the subidentifier
			 */
			if (subidentifier < 40) {
				oid = talloc_asprintf(ctx, "%u", 0);
				oid = talloc_asprintf_append(oid, ".%llu", subidentifier);
			} else if (subidentifier < 80) {
				oid = talloc_asprintf(ctx, "%u", 1);
				oid = talloc_asprintf_append(oid, ".%llu", subidentifier - 40);
			} else {
				oid = talloc_asprintf(ctx, "%u", 2);
				oid = talloc_asprintf_append(oid, ".%llu", subidentifier - 80);
			}

			if (unlikely(oid == NULL)) {
				fr_strerror_const("Out of memory for OID");
				return -1;
			}

			subidentifier = 0;
			magnitude     = 1;
			break;
		}

		magnitude++;

		/*
		 *	We need to check that the subidentifier is not too large
		 *	Since the subidentifier is encoded using 7-bit "chunks", we can't have a subidentifier larger
		 *	than 9 chunks
		 */
		if (unlikely(magnitude > 9)) {
			fr_strerror_const("OID subidentifier too large (9 chunks)");
			return -1;
		}
	}

	/*
	 *	The remaining subidentifiers are encoded individually
	 */
	for (; index < len; index++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for remaining OID subidentifier(s)");
			return -1;
		}

		subidentifier = (subidentifier << 7) | (byte & 0x7f);

		if (!(byte & 0x80)) {
			oid = talloc_asprintf_append(oid, ".%llu", subidentifier);

			if (unlikely(oid == NULL)) {
				fr_strerror_const("Out of memory for OID subidentifier");
				return -1;
			}

			subidentifier = 0;
			magnitude     = 1;
			continue;
		}

		magnitude++;

		/*
		 *	We need to check that the subidentifier is not too large
		 *	Since the subidentifier is encoded using 7-bit "chunks", we can't have a subidentifier larger
		 *	than 9 chunks
		 */
		if (unlikely(magnitude > 9)) {
			fr_strerror_const("OID subidentifier too large (9 chunks)");
			return -1;
		}
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for OID pair");
		return -1;
	}

	fr_pair_value_strdup(vp, oid, false);

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_utf8_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					 fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	  *str	  = NULL;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_string(parent->type)) {
		fr_strerror_printf("UTF8 string found in non-string attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for UTF8 string pair");
		return -1;
	}

	if (unlikely(fr_pair_value_bstr_alloc(vp, &str, len, false) < 0)) {
		fr_strerror_const("Out of memory for UTF8 string");
		return -1;
	}

	fr_dbuff_out_memcpy((uint8_t *)str, &our_in, len);

	str[len] = '\0';

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_sequence(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t	     *vp;
	fr_dict_attr_t const *child  = NULL;
	fr_dbuff_t	      our_in = FR_DBUFF(in);

	if (!fr_type_is_struct(parent->type) && !fr_type_is_tlv(parent->type) && !fr_type_is_group(parent->type)) {
		fr_strerror_printf("Sequence found in incompatible attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.9 Encoding of a sequence value
	 *		8.9.1 The encoding of a sequence value shall be constructed.
	 *		8.9.2 The contents octets shall consist of the complete encoding of one data value from each of
	 *		      the types listed in the ASN.1 definition of the sequence type, in the order of their
	 *		      appearance in the definition, unless the type was referenced with the keyword OPTIONAL
	 *		      or the keyword DEFAULT.
	 *		8.9.3 The encoding of a data value may, but need not, be present for a type referenced with the
	 *		      keyword OPTIONAL or the keyword DEFAULT. If present, it shall appear in the order of
	 *		      appearance of the corresponding type in the ASN.1 definition.
	 *
	 *	11.5 Set and sequence components with default value
	 *		The encoding of a set value or sequence value shall not include an encoding for any component
	 *		value which is equal to its default value.
	 */

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for sequence pair");
		return -1;
	}

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

static ssize_t fr_der_decode_set(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				 fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t	     *vp;
	fr_dict_attr_t const *child	   = NULL;
	fr_dbuff_t	      our_in	   = FR_DBUFF(in);
	uint8_t		      previous_tag = 0x00;

	if (!fr_type_is_struct(parent->type) && !fr_type_is_tlv(parent->type) && !fr_type_is_group(parent->type)) {
		fr_strerror_printf("Set found in incompatible attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.11 Encoding of a set value
	 *		8.11.1 The encoding of a set value shall be constructed.
	 *		8.11.2 The contents octets shall consist of the complete encoding of one data value from each
	 *		       of the types listed in the ASN.1 definition of the set type, in an order chosen by the
	 *		       sender, unless the type was referenced with the keyword OPTIONAL or the keyword DEFAULT.
	 *		8.11.3 The encoding of a data value may, but need not, be present for a type referenced with the
	 *		       keyword OPTIONAL or the keyword DEFAULT.
	 *
	 *	11.5 Set and sequence components with default value
	 *		The encoding of a set value or sequence value shall not include an encoding for any component
	 *		value which is equal to its default value.
	 */

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for set pair");
		return -1;
	}

	while ((child = fr_dict_attr_iterate_children(parent, &child))) {
		ssize_t	 ret;
		uint8_t	 current_tag;
		uint8_t *current_marker = fr_dbuff_current(&our_in);

		FR_PROTO_TRACE("decode context %s -> %s", parent->name, child->name);

		/*
		 *	Check that the tag is in ascending order
		 */
		if (unlikely(fr_dbuff_out(&current_tag, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for set. Missing tag");
			talloc_free(vp);
			return -1;
		}

		if (unlikely(current_tag < previous_tag)) {
			fr_strerror_const("Set tags are not in ascending order");
			talloc_free(vp);
			return -1;
		}

		previous_tag = current_tag;

		/*
		 *	Reset the buffer to the start of the tag
		 */
		fr_dbuff_set(&our_in, current_marker);

		ret = fr_der_decode_pair_dbuff(vp, &vp->vp_group, child, &our_in, decode_ctx);
		if (unlikely(ret < 0)) {
			talloc_free(vp);
			return ret;
		}
	}

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_printable_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	  *str	  = NULL;

	static bool const allowed_chars[] = {
		[' '] = true, ['\''] = true, ['('] = true, [')'] = true, ['+'] = true,	     [','] = true, ['-'] = true,
		['.'] = true, ['/'] = true,  ['0'] = true, ['1'] = true, ['2'] = true,	     ['3'] = true, ['4'] = true,
		['5'] = true, ['6'] = true,  ['7'] = true, ['8'] = true, ['9'] = true,	     [':'] = true, ['='] = true,
		['?'] = true, ['A'] = true,  ['B'] = true, ['C'] = true, ['D'] = true,	     ['E'] = true, ['F'] = true,
		['G'] = true, ['H'] = true,  ['I'] = true, ['J'] = true, ['K'] = true,	     ['L'] = true, ['M'] = true,
		['N'] = true, ['O'] = true,  ['P'] = true, ['Q'] = true, ['R'] = true,	     ['S'] = true, ['T'] = true,
		['U'] = true, ['V'] = true,  ['W'] = true, ['X'] = true, ['Y'] = true,	     ['Z'] = true, ['a'] = true,
		['b'] = true, ['c'] = true,  ['d'] = true, ['e'] = true, ['f'] = true,	     ['g'] = true, ['h'] = true,
		['i'] = true, ['j'] = true,  ['k'] = true, ['l'] = true, ['m'] = true,	     ['n'] = true, ['o'] = true,
		['p'] = true, ['q'] = true,  ['r'] = true, ['s'] = true, ['t'] = true,	     ['u'] = true, ['v'] = true,
		['w'] = true, ['x'] = true,  ['y'] = true, ['z'] = true, [UINT8_MAX] = false
	};

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_string(parent->type)) {
		fr_strerror_printf("Printable string found in non-string attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for printable string pair");
		return -1;
	}

	if (unlikely(fr_pair_value_bstr_alloc(vp, &str, len, false) < 0)) {
		fr_strerror_const("Out of memory for printable string");
		return -1;
	}

	fr_dbuff_out_memcpy((uint8_t *)str, &our_in, len);

	for (size_t i = 0; i < len; i++) {
		/*
		 *	Check that the byte is a printable ASCII character allowed in a printable string
		 */
		if (allowed_chars[(uint8_t)str[i]] == false) {
			fr_strerror_printf("Invalid character in printable string (%d)", str[i]);
			return -1;
		}
	}

	str[len] = '\0';

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_t61_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	  *str	  = NULL;

	static bool const allowed_chars[] = {
		[0x08] = true, [0x0A] = true, [0x0C] = true,	  [0x0D] = true, [0x0E] = true, [0x0F] = true,
		[0x19] = true, [0x1A] = true, [0x1B] = true,	  [0x1D] = true, [' '] = true,	['!'] = true,
		['"'] = true,  ['%'] = true,  ['&'] = true,	  ['\''] = true, ['('] = true,	[')'] = true,
		['*'] = true,  ['+'] = true,  [','] = true,	  ['-'] = true,	 ['.'] = true,	['/'] = true,
		['0'] = true,  ['1'] = true,  ['2'] = true,	  ['3'] = true,	 ['4'] = true,	['5'] = true,
		['6'] = true,  ['7'] = true,  ['8'] = true,	  ['9'] = true,	 [':'] = true,	[';'] = true,
		['<'] = true,  ['='] = true,  ['>'] = true,	  ['?'] = true,	 ['@'] = true,	['A'] = true,
		['B'] = true,  ['C'] = true,  ['D'] = true,	  ['E'] = true,	 ['F'] = true,	['G'] = true,
		['H'] = true,  ['I'] = true,  ['J'] = true,	  ['K'] = true,	 ['L'] = true,	['M'] = true,
		['N'] = true,  ['O'] = true,  ['P'] = true,	  ['Q'] = true,	 ['R'] = true,	['S'] = true,
		['T'] = true,  ['U'] = true,  ['V'] = true,	  ['W'] = true,	 ['X'] = true,	['Y'] = true,
		['Z'] = true,  ['['] = true,  [']'] = true,	  ['_'] = true,	 ['a'] = true,	['b'] = true,
		['c'] = true,  ['d'] = true,  ['e'] = true,	  ['f'] = true,	 ['g'] = true,	['h'] = true,
		['i'] = true,  ['j'] = true,  ['k'] = true,	  ['l'] = true,	 ['m'] = true,	['n'] = true,
		['o'] = true,  ['p'] = true,  ['q'] = true,	  ['r'] = true,	 ['s'] = true,	['t'] = true,
		['u'] = true,  ['v'] = true,  ['w'] = true,	  ['x'] = true,	 ['y'] = true,	['z'] = true,
		['|'] = true,  [0x7F] = true, [0x8B] = true,	  [0x8C] = true, [0x9B] = true, [0xA0] = true,
		[0xA1] = true, [0xA2] = true, [0xA3] = true,	  [0xA4] = true, [0xA5] = true, [0xA6] = true,
		[0xA7] = true, [0xA8] = true, [0xAB] = true,	  [0xB0] = true, [0xB1] = true, [0xB2] = true,
		[0xB3] = true, [0xB4] = true, [0xB5] = true,	  [0xB6] = true, [0xB7] = true, [0xB8] = true,
		[0xBB] = true, [0xBC] = true, [0xBD] = true,	  [0xBE] = true, [0xBF] = true, [0xC1] = true,
		[0xC2] = true, [0xC3] = true, [0xC4] = true,	  [0xC5] = true, [0xC6] = true, [0xC7] = true,
		[0xC8] = true, [0xC9] = true, [0xCA] = true,	  [0xCB] = true, [0xCC] = true, [0xCD] = true,
		[0xCE] = true, [0xCF] = true, [0xE0] = true,	  [0xE1] = true, [0xE2] = true, [0xE3] = true,
		[0xE4] = true, [0xE5] = true, [0xE7] = true,	  [0xE8] = true, [0xE9] = true, [0xEA] = true,
		[0xEB] = true, [0xEC] = true, [0xED] = true,	  [0xEE] = true, [0xEF] = true, [0xF0] = true,
		[0xF1] = true, [0xF2] = true, [0xF3] = true,	  [0xF4] = true, [0xF5] = true, [0xF6] = true,
		[0xF7] = true, [0xF8] = true, [0xF9] = true,	  [0xFA] = true, [0xFB] = true, [0xFC] = true,
		[0xFD] = true, [0xFE] = true, [UINT8_MAX] = false
	};

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_string(parent->type)) {
		fr_strerror_printf("T61 string found in non-string attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for T61 string pair");
		return -1;
	}

	if (unlikely(fr_pair_value_bstr_alloc(vp, &str, len, false) < 0)) {
		fr_strerror_const("Out of memory for T61 string");
		return -1;
	}

	fr_dbuff_out_memcpy((uint8_t *)str, &our_in, len);

	for (size_t i = 0; i < len; i++) {
		/*
		 *	Check that the byte is a printable ASCII character allowed in a T61 string
		 */
		if (allowed_chars[(uint8_t)str[i]] == false) {
			fr_strerror_printf("Invalid character in T61 string (%d)", str[i]);
			return -1;
		}
	}

	str[len] = '\0';

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}
static ssize_t fr_der_decode_ia5_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	  *str	  = NULL;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_string(parent->type)) {
		fr_strerror_printf("IA5 string found in non-string attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for IA5 string pair");
		return -1;
	}

	if (unlikely(fr_pair_value_bstr_alloc(vp, &str, len, false) < 0)) {
		fr_strerror_const("Out of memory for IA5 string");
		return -1;
	}

	fr_dbuff_out_memcpy((uint8_t *)str, &our_in, len);

	str[len] = '\0';

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_utc_time(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
#define DER_UTC_TIME_LEN 13
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	   timestr[DER_UTC_TIME_LEN + 1];
	char	  *p;
	struct tm  tm = {};

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_date(parent->type)) {
		fr_strerror_printf("UTC time found in non-date attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	if (len != DER_UTC_TIME_LEN) {
		fr_strerror_const("Insufficient data for UTC time or incorrect length");
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.25 Encoding for values of the useful types
	 *		The following "useful types" shall be encoded as if they had been replaced by their definitions
	 *		given in clauses 46-48 of Rec. ITU-T X.680 | ISO/IEC 8824-1:
	 *			– generalized time;
	 *			– universal time;
	 *			– object descriptor.
	 *
	 *	8.26 Encoding for values of the TIME type and the useful time types
	 *		8.26 Encoding for values of the TIME type and the useful time types 8.26.1 Encoding for values
	 *		of the TIME type NOTE – The defined time types are subtypes of the TIME type, with the same
	 *		tag, and have the same encoding as the TIME type. 8.26.1.1 The encoding of the TIME type shall
	 *		be primitive. 8.26.1.2 The contents octets shall be the UTF-8 encoding of the value notation,
	 *		after the removal of initial and final QUOTATION MARK (34) characters.
	 *
	 *	11.8 UTCTime
	 *		11.8.1 The encoding shall terminate with "Z", as described in the ITU-T X.680 | ISO/IEC 8824-1
	 *		       clause on UTCTime.
	 *		11.8.2 The seconds element shall always be present.
	 *		11.8.3 Midnight (GMT) shall be represented as "YYMMDD000000Z", where "YYMMDD" represents the
	 *		       day following the midnight in question.
	 */

	/*
	 *	The format of a UTC time is "YYMMDDhhmmssZ"
	 *	Where:
	 *	1. YY is the year
	 *	2. MM is the month
	 *	3. DD is the day
	 *	4. hh is the hour
	 *	5. mm is the minute
	 *	6. ss is the second (not optional in DER)
	 *	7. Z is the timezone (UTC)
	 */

	if (fr_dbuff_out_memcpy((uint8_t *)timestr, &our_in, len) < 0) {
		fr_strerror_const("Insufficient data for UTC time. Missing data bytes");
		return -1;
	}

	if (memchr(timestr, '\0', len) != NULL) {
		fr_strerror_const("UTC time contains null byte");
		return -1;
	}

	timestr[len] = '\0';

	p = strptime(timestr, "%y%m%d%H%M%SZ", &tm);

	if (unlikely(p == NULL) || *p != '\0') {
		fr_strerror_const("Invalid UTC time format");
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for UTC time pair");
		return -1;
	}

	vp->vp_date = fr_unix_time_from_tm(&tm);

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_generalized_time(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
#define DER_GENERALIZED_TIME_LEN_MIN 15
#define DER_GENERALIZED_TIME_PRECISION_MAX 4
	fr_pair_t    *vp;
	fr_dbuff_t    our_in = FR_DBUFF(in);
	char	      timestr[DER_GENERALIZED_TIME_LEN_MIN + 1];
	char	     *p;
	unsigned long subseconds = 0;
	struct tm     tm	 = {};

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_date(parent->type)) {
		fr_strerror_printf("Generalized time found in non-date attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	if (len < DER_GENERALIZED_TIME_LEN_MIN) {
		fr_strerror_const("Insufficient data for generalized time or incorrect length");
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.25 Encoding for values of the useful types
	 *		The following "useful types" shall be encoded as if they had been replaced by their definitions
	 *		given in clauses 46-48 of Rec. ITU-T X.680 | ISO/IEC 8824-1:
	 *			– generalized time;
	 *			– universal time;
	 *			– object descriptor.
	 *
	 *	8.26 Encoding for values of the TIME type and the useful time types
	 *		8.26 Encoding for values of the TIME type and the useful time types 8.26.1 Encoding for values
	 *		of the TIME type NOTE – The defined time types are subtypes of the TIME type, with the same
	 *		tag, and have the same encoding as the TIME type. 8.26.1.1 The encoding of the TIME type shall
	 *		be primitive. 8.26.1.2 The contents octets shall be the UTF-8 encoding of the value notation,
	 *		after the removal of initial and final QUOTATION MARK (34) characters.
	 *
	 *	11.7 GeneralizedTime
	 *		11.7.1 The encoding shall terminate with a "Z", as described in the Rec. ITU-T X.680 | ISO/IEC
	 *		       8824-1 clause on GeneralizedTime.
	 *		11.7.2 The seconds element shall always be present.
	 *		11.7.3 The fractional-seconds elements, if present, shall omit all trailing zeros; if the
	 *		       elements correspond to 0, they shall be wholly omitted, and the decimal point element
	 *		       also shall be omitted.
	 */

	/*
	 *	The format of a generalized time is "YYYYMMDDHHMMSS[.fff]Z"
	 *	Where:
	 *	1. YYYY is the year
	 *	2. MM is the month
	 *	3. DD is the day
	 *	4. HH is the hour
	 *	5. MM is the minute
	 *	6. SS is the second
	 *	7. fff is the fraction of a second (optional)
	 *	8. Z is the timezone (UTC)
	 */

	if (fr_dbuff_out_memcpy((uint8_t *)timestr, &our_in, DER_GENERALIZED_TIME_LEN_MIN) < 0) {
		fr_strerror_const("Insufficient data for generalized time. Missing data bytes");
		return -1;
	}

	if (memchr(timestr, '\0', DER_GENERALIZED_TIME_LEN_MIN) != NULL) {
		fr_strerror_const("Generalized time contains null byte");
		return -1;
	}

	if (timestr[DER_GENERALIZED_TIME_LEN_MIN - 1] != 'Z' && timestr[DER_GENERALIZED_TIME_LEN_MIN - 1] != '.') {
		fr_strerror_const("Incorrect format for generalized time. Missing timezone");
		return -1;
	}

	/*
	 *	Check if the fractional seconds are present
	 */
	if (timestr[DER_GENERALIZED_TIME_LEN_MIN - 1] == '.') {
		/*
		 *	We only support subseconds up to 4 decimal places
		 */
		char subsecstring[DER_GENERALIZED_TIME_PRECISION_MAX + 1];

		uint8_t precision = DER_GENERALIZED_TIME_PRECISION_MAX;

		if (unlikely(fr_dbuff_remaining(&our_in) - 1 < DER_GENERALIZED_TIME_PRECISION_MAX)) {
			precision = fr_dbuff_remaining(&our_in) - 1;
		}

		if (unlikely(precision == 0)) {
			fr_strerror_const("Insufficient data for subseconds");
			return -1;
		}

		if (fr_dbuff_out_memcpy((uint8_t *)subsecstring, &our_in, precision) < 0) {
			fr_strerror_const("Insufficient data for subseconds. Missing data bytes");
			return -1;
		}

		if (memchr(subsecstring, '\0', precision) != NULL) {
			fr_strerror_const("Generalized time contains null byte in subseconds");
			return -1;
		}

		subsecstring[DER_GENERALIZED_TIME_PRECISION_MAX] = '\0';

		/*
		 *	Convert the subseconds to an unsigned long
		 */
		subseconds = strtoul(subsecstring, NULL, 10);

		/*
		 *	Scale to nanoseconds
		 */
		subseconds *= 1000000;
	}

	/*
	 *	Make sure the timezone is UTC (Z)
	 */
	timestr[DER_GENERALIZED_TIME_LEN_MIN - 1] = 'Z';

	timestr[DER_GENERALIZED_TIME_LEN_MIN] = '\0';

	p = strptime(timestr, "%Y%m%d%H%M%SZ", &tm);

	if (unlikely(p == NULL)) {
		fr_strerror_const("Invalid generalized time format (strptime)");
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for generalized time pair");
		return -1;
	}

	vp->vp_date = fr_unix_time_add(fr_unix_time_from_tm(&tm), fr_time_delta_wrap(subseconds));

	fr_pair_append(out, vp);

	/*
	 *	Move to the end of the buffer
	 *	This is necessary because the fractional seconds are being ignored
	 */
	fr_dbuff_advance(&our_in, fr_dbuff_remaining(&our_in));

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_visible_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					    fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	  *str	  = NULL;

	static bool const allowed_chars[] = {
		[' '] = true,  ['!'] = true,  ['"'] = true, ['#'] = true, ['$'] = true,	      ['%'] = true,
		['&'] = true,  ['\''] = true, ['('] = true, [')'] = true, ['*'] = true,	      ['+'] = true,
		[','] = true,  ['-'] = true,  ['.'] = true, ['/'] = true, ['0'] = true,	      ['1'] = true,
		['2'] = true,  ['3'] = true,  ['4'] = true, ['5'] = true, ['6'] = true,	      ['7'] = true,
		['8'] = true,  ['9'] = true,  [':'] = true, [';'] = true, ['<'] = true,	      ['='] = true,
		['>'] = true,  ['?'] = true,  ['@'] = true, ['A'] = true, ['B'] = true,	      ['C'] = true,
		['D'] = true,  ['E'] = true,  ['F'] = true, ['G'] = true, ['H'] = true,	      ['I'] = true,
		['J'] = true,  ['K'] = true,  ['L'] = true, ['M'] = true, ['N'] = true,	      ['O'] = true,
		['P'] = true,  ['Q'] = true,  ['R'] = true, ['S'] = true, ['T'] = true,	      ['U'] = true,
		['V'] = true,  ['W'] = true,  ['X'] = true, ['Y'] = true, ['Z'] = true,	      ['['] = true,
		['\\'] = true, [']'] = true,  ['^'] = true, ['_'] = true, ['`'] = true,	      ['a'] = true,
		['b'] = true,  ['c'] = true,  ['d'] = true, ['e'] = true, ['f'] = true,	      ['g'] = true,
		['h'] = true,  ['i'] = true,  ['j'] = true, ['k'] = true, ['l'] = true,	      ['m'] = true,
		['n'] = true,  ['o'] = true,  ['p'] = true, ['q'] = true, ['r'] = true,	      ['s'] = true,
		['t'] = true,  ['u'] = true,  ['v'] = true, ['w'] = true, ['x'] = true,	      ['y'] = true,
		['z'] = true,  ['{'] = true,  ['|'] = true, ['}'] = true, [UINT8_MAX] = false
	};

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_string(parent->type)) {
		fr_strerror_printf("Visible string found in non-string attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for visible string pair");
		return -1;
	}

	if (unlikely(fr_pair_value_bstr_alloc(vp, &str, len, false) < 0)) {
		fr_strerror_const("Out of memory for visible string");
		return -1;
	}

	fr_dbuff_out_memcpy((uint8_t *)str, &our_in, len);

	for (size_t i = 0; i < len; i++) {
		/*
		 *	Check that the byte is a printable ASCII character allowed in a printable string
		 */
		if (allowed_chars[(uint8_t)str[i]] == false) {
			fr_strerror_printf("Invalid character in visible string (%d)", str[i]);
			return -1;
		}
	}

	str[len] = '\0';

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_general_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					    fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	  *str	  = NULL;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_string(parent->type)) {
		fr_strerror_printf("General string found in non-string attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for general string pair");
		return -1;
	}

	if (unlikely(fr_pair_value_bstr_alloc(vp, &str, len, false) < 0)) {
		fr_strerror_const("Out of memory for general string");
		return -1;
	}

	fr_dbuff_out_memcpy((uint8_t *)str, &our_in, len);

	str[len] = '\0';

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_universal_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	  *str	  = NULL;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_string(parent->type)) {
		fr_strerror_printf("Universal string found in non-string attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory for universal string pair");
		return -1;
	}

	if (unlikely(fr_pair_value_bstr_alloc(vp, &str, len, false) < 0)) {
		fr_strerror_const("Out of memory for universal string");
		return -1;
	}

	fr_dbuff_out_memcpy((uint8_t *)str, &our_in, len);

	str[len] = '\0';

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_pair_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_dbuff_t		 our_in = FR_DBUFF(in);
	ssize_t			 slen;
	uint8_t			 tag_byte;
	uint64_t		 tag;
	fr_der_tag_flag_t	 tag_flags;
	fr_der_tag_constructed_t constructed;

	uint8_t		     len_byte;
	size_t		     len = 0;
	fr_der_tag_decode_t *func;

	if (unlikely(fr_dbuff_out(&tag_byte, &our_in) < 0)) return 0;

	/*
	 *	Decode the tag flags
	 */
	tag_flags   = (tag_byte >> 6) & 0x03;
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

	/*
	 *	Check if the tag is not universal
	 */
	if (tag_flags != FR_DER_TAG_FLAG_UNIVERSAL) {
		/*
		 *	The data type will need to be resolved using the dictionary and the tag value
		 */

		tag = FR_DER_TAG_SEQUENCE;
		// fr_strerror_printf("Non-universal tag %" PRIu64, tag);
		// return -1;
	}

	if ((tag > NUM_ELEMENTS(tag_funcs)) || (tag == 0)) {
		fr_strerror_printf("Unknown tag %" PRIu64, tag);
	}

	func = &tag_funcs[tag];
	if (unlikely(func->decode == NULL)) {
		fr_strerror_printf("No decode function for tag %" PRIu64, tag);
		return -1;
	}

	if (func->constructed != constructed) {
		fr_strerror_printf("Constructed flag mismatch for tag %" PRIu64, tag);
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

			while (len_len--) {
				if (unlikely(fr_dbuff_out(&len_byte, &our_in) < 0)) {
					fr_strerror_const("Insufficient data to satisfy multi-byte length field");
					return -1;
				}
				len = (len << 8) | len_byte;
			}
		}

		else if (!constructed) {
			fr_strerror_const("Primative data with indefinite form length field is invalid");
			return DECODE_FAIL_INVALID_ATTRIBUTE;
		}
	} else {
		len = len_byte;
	}

	/*
	 *	Check if the length is valid for our buffer
	 */
	if (unlikely(len > fr_dbuff_remaining(&our_in))) {
		fr_strerror_printf("Insufficient data for length field (%zu)", len);
		return -1;
	}

	/*
	 *	Make sure the data length is less than the maximum allowed
	 */
	switch (tag) {
	case FR_DER_TAG_SEQUENCE:
	case FR_DER_TAG_SET:
		break;
	default:
		if (unlikely(len > DER_MAX_STR)) {
			fr_strerror_printf("Data length too large (%zu)", len);
			return -1;
		}
		break;
	}

	fr_dbuff_set_end(&our_in, fr_dbuff_current(&our_in) + len);

	slen = func->decode(ctx, out, parent, &our_in, decode_ctx);

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
static ssize_t decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, uint8_t const *data,
			   size_t data_len, void *decode_ctx)
{
	// fr_assert(parent == fr_dict_root(dict_der));

	return fr_der_decode_pair_dbuff(ctx, out, parent, &FR_DBUFF_TMP(data, data_len), decode_ctx);
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t der_tp_decode_pair;
fr_test_point_pair_decode_t	   der_tp_decode_pair = {
	       .test_ctx = decode_test_ctx,
	       .func	 = decode_pair,
};
