#include "include/build.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "der.h"
#include "lib/util/dcursor.h"
#include "lib/util/dict_ext.h"
#include "lib/util/sbuff.h"
#include "lib/util/value.h"
#include "talloc.h"

#include <freeradius-devel/io/test_point.h>

#include <freeradius-devel/util/encode.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/types.h>

#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/time.h>
#include <string.h>
#include <sys/types.h>

typedef struct {
	uint8_t *tmp_ctx;
	uint8_t *encoding_start; //!< This is the start of the encoding. It is NOT the same as the start of the encoded value. It is the position of the tag.
	size_t encoding_length; //!< This is the length of the entire encoding. It is NOT the same as the length of the encoded value. It includes the tag, length, and value.
	ssize_t	 length_of_encoding;	//!< This is the number of bytes used by the encoded value. It is NOT the same as the encoded length field.
	uint8_t *encoded_value;		//!< This is a pointer to the start of the encoded value.
} fr_der_encode_ctx_t;

#define DER_MAX_STR 16384

/** Function signature for DER encode functions
 *
 * @param[in] dbuff	Where to encode the data.
 * @param[in] cursor	Where to encode the data from.
 * @param[in] encode_ctx	Any encode specific data.
 * @return
 *	- > 0 on success.  How many bytes were encoded.
 *	- 0 no bytes encoded.
 *	- < 0 on error.  May be the offset (as a negative value) where the error occurred.
 */
typedef ssize_t (*fr_der_encode_t)(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);

typedef struct {
	fr_der_tag_constructed_t constructed;
	fr_der_encode_t encode;
} fr_der_tag_encode_t;

static ssize_t fr_der_encode_boolean(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_integer(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_bitstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_octetstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_null(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_oid(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_enumerated(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_utf8_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_sequence(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_set(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_printable_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_t61_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_ia5_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_utc_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_generalized_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_visible_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_general_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_universal_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);

static ssize_t fr_der_encode_oid_value_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);

static ssize_t fr_der_encode_len(UNUSED fr_dbuff_t *dbuff, fr_dbuff_marker_t *length_start, ssize_t len);
static inline CC_HINT(always_inline) ssize_t
	fr_der_encode_tag(fr_dbuff_t *dbuff, fr_der_tag_num_t tag_num, fr_der_tag_class_t tag_class,
			  fr_der_tag_constructed_t constructed);
static ssize_t encode_value(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth, fr_dcursor_t *cursor,
			    void *encode_ctx);
static ssize_t encode_pair(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth, fr_dcursor_t *cursor,
			   void *encode_ctx);
static ssize_t der_encode_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx);

static fr_der_tag_encode_t tag_funcs[] = {
	[FR_DER_TAG_BOOLEAN]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_boolean },
	[FR_DER_TAG_INTEGER]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_integer },
	[FR_DER_TAG_BITSTRING]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_bitstring },
	[FR_DER_TAG_OCTETSTRING]      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_octetstring },
	[FR_DER_TAG_NULL]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_null },
	[FR_DER_TAG_OID]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_oid },
	[FR_DER_TAG_ENUMERATED]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_enumerated },
	[FR_DER_TAG_UTF8_STRING]      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_utf8_string },
	[FR_DER_TAG_SEQUENCE]	      = { .constructed = FR_DER_TAG_CONSTRUCTED, .encode = fr_der_encode_sequence },
	[FR_DER_TAG_SET]	      = { .constructed = FR_DER_TAG_CONSTRUCTED, .encode = fr_der_encode_set },
	[FR_DER_TAG_PRINTABLE_STRING] = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_printable_string },
	[FR_DER_TAG_T61_STRING]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_t61_string },
	[FR_DER_TAG_IA5_STRING]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_ia5_string },
	[FR_DER_TAG_UTC_TIME]	      = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_utc_time },
	[FR_DER_TAG_GENERALIZED_TIME] = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_generalized_time },
	[FR_DER_TAG_VISIBLE_STRING]   = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_visible_string },
	[FR_DER_TAG_GENERAL_STRING]   = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_general_string },
	[FR_DER_TAG_UNIVERSAL_STRING] = { .constructed = FR_DER_TAG_PRIMATIVE, .encode = fr_der_encode_universal_string },
};

static int encode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict)
{
	fr_der_encode_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_der_encode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);
	test_ctx->encoding_start = NULL;
	test_ctx->encoding_length = 0;
	test_ctx->length_of_encoding = 0;
	test_ctx->encoded_value = NULL;

	*out = test_ctx;

	return 0;
}

static inline CC_HINT(always_inline) int8_t fr_der_pair_cmp_by_da_tag(void const *a, void const *b)
{
	fr_pair_t const *my_a = a;
	fr_pair_t const *my_b = b;

	return CMP_PREFER_SMALLER(fr_der_flag_subtype(my_a->da), fr_der_flag_subtype(my_b->da));
}

static ssize_t fr_der_encode_boolean(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	uint8_t		 value;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode boolean");
		return -1;
	}

	PAIR_VERIFY(vp);

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
	value = vp->vp_bool;

	fr_dbuff_in(dbuff, (uint8_t)(value ? 0xff : 0x00));

	return 1;
}

static ssize_t fr_der_encode_integer(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	int64_t		 value;
	uint8_t		 first_octet = 0;
	ssize_t		 slen	     = 0;
	size_t		 i	     = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode integer");
		return -1;
	}

	PAIR_VERIFY(vp);

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
	value = vp->vp_int64;

	for (; i < sizeof(value); i++) {
		uint8_t byte = (uint8_t)(value >> (((sizeof(value) * 8) - 8) - (i * 8)));

		if (slen == 0) {
			first_octet = byte;
			slen++;
			continue;
		} else if (slen == 1) {
			/*
			 *	8.3.2 If the contents octets of an integer value encoding consist of more than one
			 *octet, then the bits of the first octet and bit 8 of the second octet: a) shall not all be
			 *ones; and b) shall not all be zero.
			 */
			if ((first_octet == 0xff && (byte & 0x80)) || (first_octet == 0x00 && byte >> 7 == 0)) {
				if (i == sizeof(value) - 1) {
					/*
					 * If this is the only byte, then we can encode it as a single byte.
					 */
					fr_dbuff_in(dbuff, byte);
					continue;
				}

				first_octet = byte;
				continue;
			} else {
				fr_dbuff_in(dbuff, first_octet);
				fr_dbuff_in(dbuff, byte);
				slen++;
				continue;
			}
		}

		fr_dbuff_in(dbuff, byte);
		slen++;
	}

	return slen;
}

static ssize_t fr_der_encode_bitstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	uint8_t const	*value = NULL;
	size_t		 len;
	uint8_t		 unused_bits = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode bitstring");
		return -1;
	}

	PAIR_VERIFY(vp);

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

	if (fr_type_is_struct(vp->vp_type)) {
		ssize_t		  slen;
		unsigned int	  depth = 0;
		fr_da_stack_t	  da_stack;
		fr_dbuff_t	  work_dbuff = FR_DBUFF(dbuff);
		fr_dbuff_marker_t unused_bits_marker;

		fr_dbuff_marker(&unused_bits_marker, &work_dbuff);
		fr_dbuff_advance(&work_dbuff, 1);

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		slen = fr_struct_to_network(&work_dbuff, &da_stack, depth, cursor, encode_ctx, NULL, NULL);
		if (slen < 0) {
			fr_strerror_printf("Failed to encode struct: %s", fr_strerror());
			return -1;
		}

		/*
		 *	We need to trim any empty trailing octets
		 */
		while (slen > 1 && fr_dbuff_current(&work_dbuff) != fr_dbuff_start(&work_dbuff)) {
			uint8_t byte;

			/*
			 *	Move the dbuff cursor back by one byte
			 */
			fr_dbuff_set(&work_dbuff, fr_dbuff_current(&work_dbuff) - sizeof(byte));

			if (fr_dbuff_out(&byte, &work_dbuff) < 0) {
				fr_strerror_const("Failed to read byte");
				return -1;
			}

			if (byte == 0) {
				/*
				 *	Trim this byte from the buff
				 */
				fr_dbuff_set_end(&work_dbuff, fr_dbuff_current(&work_dbuff) - sizeof(byte));
				fr_dbuff_set(&work_dbuff, fr_dbuff_current(&work_dbuff) - (sizeof(byte) * 2));
				slen--;
			} else {
				break;
			}
		}

		/*
		 *	Write the unused bits
		 */
		fr_dbuff_set(dbuff, fr_dbuff_current(&unused_bits_marker));
		fr_dbuff_in(dbuff, unused_bits);

		/*
		 *	Copy the work dbuff to the output dbuff
		 */
		fr_dbuff_set(&work_dbuff, dbuff);
		if (fr_dbuff_in_memcpy(dbuff, &work_dbuff, slen) <= 0) {
			fr_strerror_const("Failed to copy bitstring value");
			return -1;
		}

		return slen + 1;
	}

	/*
	 *	For octets type, we do not need to write the unused bits portion
	 *	because this information should be retained when encoding/decoding.
	 */

	value = vp->vp_octets;
	len   = vp->vp_length;

	if (len == 0) {
		fr_dbuff_in(dbuff, 0x00);
		return 1;
	}

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy bitstring value");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_octetstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					 UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	uint8_t const	*value = NULL;
	size_t		 len;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode octet string");
		return -1;
	}

	PAIR_VERIFY(vp);

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

	value = vp->vp_octets;
	len   = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy octet string value");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_null(UNUSED fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
				  UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode null");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.8 Encoding of a null value
	 *	8.8.1 The encoding of a null value shall be primitive.
	 *	8.8.2 The contents octets shall not contain any octets.
	 * 		NOTE – The length octet is zero.
	 */
	if (vp->vp_length != 0) {
		fr_strerror_printf("Null has non-zero length %zu", vp->vp_length);
		return -1;
	}

	return 0;
}

static ssize_t fr_der_encode_oid_to_str(fr_dbuff_t *dbuff, const char* oid_str)
{
	char		 buffer[21];
	uint64_t	 subidentifier	 = 0;
	uint8_t		 first_component = 0;
	size_t		 len = 0, buffer_len = 0;
	size_t		 index		       = 0, bit_index;
	bool		 started_subidentifier = false, subsequent = false;

	/*
	 *	The first subidentifier is the encoding of the first two object identifier components, encoded as:
	 *		(X * 40) + Y
	 *	where X is the first number and Y is the second number.
	 *	The first number is 0, 1, or 2.
	 */

	first_component = (uint8_t)(strtol(&oid_str[0], NULL, 10));

	oid_str += 2;

	for (; index < strlen(oid_str) + 1; index++) {
		uint8_t byte = 0;
		if (oid_str[index] == '.' || oid_str[index] == '\0') {
			/*
			 *	We have a subidentifier
			 */
			started_subidentifier = false;
			bit_index	      = sizeof(subidentifier) * 8;

			if (buffer_len == 0) {
				fr_strerror_const("Empty buffer for final subidentifier");
				return -1;
			}

			if (!subsequent) {
				subidentifier = (first_component * 40) + (uint64_t)strtol(buffer, NULL, 10);
				subsequent    = true;
			} else {
				subidentifier = (uint64_t)strtol(buffer, NULL, 10);
			}

			/*
			 *	We will be reading the subidentifier 7 bits at a time
			 */
			while (bit_index > 7) {
				if (!started_subidentifier && ((uint8_t)(subidentifier >> (bit_index - 8)) == 0)) {
					bit_index -= 8;
					continue;
				}

				byte = 0;

				if (!started_subidentifier) {
					started_subidentifier = true;
					byte = (uint8_t)(subidentifier >> (bit_index -= (bit_index % 7)));

					if (byte == 0) {
						if (bit_index <= 7) {
							break;
						}

						byte = (uint8_t)(subidentifier >> (bit_index -= 7));

						if (byte == 0) {
							byte = (uint8_t)(subidentifier >> (bit_index -= 7));
						}
					}

				} else {
					byte = (uint8_t)(subidentifier >> (bit_index -= 7));
				}

				byte = byte | 0x80;

				fr_dbuff_in(dbuff, byte);
				started_subidentifier = true;
				len++;
			}

			/*
			 *	Tack on the last byte
			 */
			byte = (uint8_t)(subidentifier);

			byte = byte & 0x7f;

			fr_dbuff_in(dbuff, byte);
			memset(buffer, 0, sizeof(buffer));
			buffer_len = 0;
			len++;

			continue;
		}

		buffer[buffer_len++] = oid_str[index];
	}

	return len;
}

static ssize_t fr_der_encode_oid(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	char const	*value;
	size_t		 len = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode OID");
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

	PAIR_VERIFY(vp);

	value = vp->vp_strvalue;

	len = fr_der_encode_oid_to_str(dbuff, value);

	return len;
}

static ssize_t fr_der_encode_enumerated(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	int64_t		 value;
	uint8_t		 first_octet = 0;
	ssize_t		 slen	     = 0;
	size_t		 i	     = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode enumerated");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.4 Encoding of an enumerated value
	 *		The encoding of an enumerated value shall be that of the integer value with which it is
	 *		associated.
	 *			NOTE – It is primitive.
	 */
	value = vp->vp_int64;

	for (; i < sizeof(value); i++) {
		uint8_t byte = (uint8_t)(value >> (((sizeof(value) * 8) - 8) - (i * 8)));

		if (slen == 0) {
			first_octet = byte;
			slen++;
			continue;
		} else if (slen == 1) {
			/*
			 *	8.3.2 If the contents octets of an integer value encoding consist of more than one
			 *octet, then the bits of the first octet and bit 8 of the second octet: a) shall not all be
			 *ones; and b) shall not all be zero.
			 */
			if ((first_octet == 0xff && (byte & 0x80)) || (first_octet == 0x00 && byte >> 7 == 0)) {
				if (i == sizeof(value) - 1) {
					/*
					 * If this is the only byte, then we can encode it as a single byte.
					 */
					fr_dbuff_in(dbuff, byte);
					continue;
				}

				first_octet = byte;
				continue;
			} else {
				fr_dbuff_in(dbuff, first_octet);
				fr_dbuff_in(dbuff, byte);
				slen++;
				continue;
			}
		}

		fr_dbuff_in(dbuff, byte);
		slen++;
	}

	return slen;
}

static ssize_t fr_der_encode_utf8_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					 UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	char const	*value = NULL;
	size_t		 len;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode UTF8 string");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	8.23 Encoding for values of the restricted character string types 8.23.1 The data value consists of a
	 *	     string of characters from the character set specified in the ASN.1 type definition. 8.23.2 Each data value
	 *	     shall be encoded independently of other data values of the same type.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of encoding shall
	 *		not be used. (Contrast with 8.23.6.)
	 */
	value = vp->vp_strvalue;
	len   = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for UTF8 string");
		fr_strerror_printf("Failed to copy string value with error number %ld",
				   fr_dbuff_in_memcpy(dbuff, value, len));
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_sequence(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const	     *vp;
	fr_da_stack_t	      da_stack;
	fr_dcursor_t	      child_cursor;
	fr_dict_attr_t const *ref   = NULL;
	ssize_t		      slen  = 0;
	unsigned int	      depth = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode sequence");
		return -1;
	}

	PAIR_VERIFY(vp);

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

	switch (vp->vp_type) {
	default:
		fr_strerror_printf("Unknown type %d", vp->vp_type);
		return -1;
	case FR_TYPE_STRUCT:
		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		slen = fr_struct_to_network(dbuff, &da_stack, depth, cursor, encode_ctx, encode_value, encode_pair);

		if (slen < 0) {
			fr_strerror_printf("Failed to encode struct: %s", fr_strerror());
			return -1;
		}

		return slen;
	case FR_TYPE_TLV:
		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

		do {
			ssize_t len_count;

			len_count = fr_pair_cursor_to_network(dbuff, &da_stack, depth, &child_cursor, encode_ctx,
							      encode_pair);
			if (unlikely(len_count < 0)) {
				fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
				return -1;
			}

			slen += len_count;

		} while (fr_dcursor_next(&child_cursor));

		return slen;
	case FR_TYPE_GROUP:
		if (fr_der_flag_is_pair(vp->da)) {
			if (unlikely((slen = fr_der_encode_oid_value_pair(dbuff, cursor, encode_ctx)) < 0)) {
				fr_strerror_printf("Failed to encode OID value pair: %s", fr_strerror());
				return -1;
			}

			return slen;
		}
		ref = fr_dict_attr_ref(vp->da);

		if (ref && (ref->dict != dict_der)) {
			fr_strerror_printf("Group %s is not a DER group", ref->name);
			return -1;
		}

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		if (!fr_pair_list_empty(&vp->vp_group)) {
			(void)fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

			while (fr_dcursor_current(&child_cursor)) {
				ssize_t len_count;

				len_count = fr_pair_cursor_to_network(dbuff, &da_stack, depth, &child_cursor,
								      encode_ctx, encode_pair);
				if (unlikely(len_count < 0)) {
					fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
					return -1;
				}

				slen += len_count;
			}

			return slen;
		}
	}

	return -1;
}

typedef struct {
	uint8_t *item_ptr;	//!< Pointer to the start of the encoded item (beginning of the tag)
	size_t	 item_len;	//!< Length of the encoded item (tag + length + value)
	uint8_t *octet_ptr;	//!< Pointer to the current octet
	size_t  remaining;	//!< Remaining octets
} fr_der_encode_set_of_ptr_pairs_t;

/*
 *	Lexicographically sort the set of pairs
 */
static int fr_der_encode_set_of_cmp(void const *a, void const *b)
{
	fr_der_encode_set_of_ptr_pairs_t const *my_a = a;
	fr_der_encode_set_of_ptr_pairs_t const *my_b = b;

	if (my_a->item_len > my_b->item_len) {
		return memcmp(my_a->item_ptr, my_b->item_ptr, my_a->item_len);
	}

	return memcmp(my_a->item_ptr, my_b->item_ptr, my_b->item_len);
}

static ssize_t fr_der_encode_set(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t	     *vp;
	fr_da_stack_t	      da_stack;
	fr_dcursor_t	      child_cursor;
	fr_dict_attr_t const *ref   = NULL;
	ssize_t		      slen  = 0;
	unsigned int	      depth = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode set");
		return -1;
	}

	PAIR_VERIFY(vp);

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

	switch (vp->vp_type) {
	default:
		fr_strerror_printf("Unknown type %d", vp->vp_type);
		return -1;
	case FR_TYPE_STRUCT:
		/*
		 * 	Note: Structures should be in the correct order in the dictionary.
		 *	if they are not, the dictionary loader should complain.
		 */

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		slen = fr_struct_to_network(dbuff, &da_stack, depth, cursor, encode_ctx, encode_value, encode_pair);

		if (slen < 0) {
			fr_strerror_printf("Failed to encode struct: %s", fr_strerror());
			return -1;
		}

		break;
	case FR_TYPE_TLV:
		if (fr_der_flag_is_set_of(vp->da)) {
			fr_dbuff_t	 work_dbuff;
			uint8_t *buff;
			fr_der_encode_set_of_ptr_pairs_t *ptr_pairs;
			size_t				  i = 0, count;

			buff = talloc_array(vp, uint8_t, fr_dbuff_remaining(dbuff));

			fr_dbuff_init(&work_dbuff, buff, fr_dbuff_remaining(dbuff));

			fr_proto_da_stack_build(&da_stack, vp->da);

			FR_PROTO_STACK_PRINT(&da_stack, depth);

			fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

			count = fr_pair_list_num_elements(&vp->children);

			ptr_pairs = talloc_array(vp, fr_der_encode_set_of_ptr_pairs_t, count);
			if (unlikely(ptr_pairs == NULL)) {
				fr_strerror_const("Failed to allocate memory for set of pointers");
				return -1;
			}

			for (i = 0; i < count; i++) {
				ssize_t len_count;

				if (unlikely(fr_dcursor_current(&child_cursor) == NULL)) {
					fr_strerror_const("No pair to encode set of");
					return -1;
				}

				len_count = encode_value(&work_dbuff, NULL, depth, &child_cursor, encode_ctx);

				if (unlikely(len_count < 0)) {
					fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
					return -1;
				}

				ptr_pairs[i].item_ptr = encode_ctx->encoding_start;
				ptr_pairs[i].item_len = encode_ctx->encoding_length;
				ptr_pairs[i].octet_ptr = encode_ctx->encoded_value;
				ptr_pairs[i].remaining = encode_ctx->length_of_encoding;

				slen += len_count;
			}

			if (unlikely(fr_dcursor_current(&child_cursor) != NULL)) {
				fr_strerror_const("Failed to encode all pairs");
				talloc_free(ptr_pairs);
				return -1;
			}

			qsort(ptr_pairs, count, sizeof(fr_der_encode_set_of_ptr_pairs_t), fr_der_encode_set_of_cmp);

			for (i = 0; i < count; i++) {
				fr_dbuff_set(&work_dbuff, ptr_pairs[i].item_ptr);

				FR_PROTO_TRACE("Copying %zu bytes from %p to %p", ptr_pairs[i].item_len, ptr_pairs[i].item_ptr,
					       fr_dbuff_current(dbuff));

				if (fr_dbuff_in_memcpy(dbuff, fr_dbuff_current(&work_dbuff), ptr_pairs[i].item_len) <= 0) {
					fr_strerror_const("Failed to copy set of value");
					talloc_free(ptr_pairs);
					talloc_free(buff);
					return -1;
				}
			}

			talloc_free(ptr_pairs);
			talloc_free(buff);
			return slen;
		}

		fr_pair_list_sort(&vp->children, fr_der_pair_cmp_by_da_tag);

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

		while (fr_dcursor_current(&child_cursor)){
			ssize_t len_count;

			len_count = fr_pair_cursor_to_network(dbuff, &da_stack, depth, &child_cursor, encode_ctx,
							      encode_pair);
			if (unlikely(len_count < 0)) {
				fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
				return -1;
			}

			slen += len_count;

		}
		break;
	case FR_TYPE_GROUP:
		if (fr_der_flag_is_pair(vp->da)) {
			if (unlikely((slen = fr_der_encode_oid_value_pair(dbuff, cursor, encode_ctx)) < 0)) {
				fr_strerror_printf("Failed to encode OID value pair: %s", fr_strerror());
				return -1;
			}

			return slen;
		}
		if (fr_der_flag_is_set_of(vp->da)) {
			fr_dbuff_t	 work_dbuff;
			uint8_t *buff;
			fr_der_encode_set_of_ptr_pairs_t *ptr_pairs;
			size_t				  i = 0, count;

			buff = talloc_array(vp, uint8_t, fr_dbuff_remaining(dbuff));

			fr_dbuff_init(&work_dbuff, buff, fr_dbuff_remaining(dbuff));

			ref = fr_dict_attr_ref(vp->da);

			if (ref && (ref->dict != dict_der)) {
				fr_strerror_printf("Group %s is not a DER group", ref->name);
				return -1;
			}

			fr_proto_da_stack_build(&da_stack, vp->da);

			FR_PROTO_STACK_PRINT(&da_stack, depth);

			if (!fr_pair_list_empty(&vp->vp_group)) {
				fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

				count = fr_pair_list_num_elements(&vp->children);

				ptr_pairs = talloc_array(vp, fr_der_encode_set_of_ptr_pairs_t, count);
				if (unlikely(ptr_pairs == NULL)) {
					fr_strerror_const("Failed to allocate memory for set of pointers");
					return -1;
				}

				for (i = 0; i < count; i++) {
					ssize_t len_count;

					if (unlikely(fr_dcursor_current(&child_cursor) == NULL)) {
						fr_strerror_const("No pair to encode set of");
						return -1;
					}

					len_count = encode_value(&work_dbuff, NULL, depth, &child_cursor, encode_ctx);

					if (unlikely(len_count < 0)) {
						fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
						return -1;
					}

					ptr_pairs[i].item_ptr = encode_ctx->encoding_start;
					ptr_pairs[i].item_len = encode_ctx->encoding_length;
					ptr_pairs[i].octet_ptr = encode_ctx->encoded_value;
					ptr_pairs[i].remaining = encode_ctx->length_of_encoding;

					slen += len_count;
				}

				if (unlikely(fr_dcursor_current(&child_cursor) != NULL)) {
					fr_strerror_const("Failed to encode all pairs");
					talloc_free(ptr_pairs);
					return -1;
				}

				qsort(ptr_pairs, count, sizeof(fr_der_encode_set_of_ptr_pairs_t), fr_der_encode_set_of_cmp);

				for (i = 0; i < count; i++) {
					fr_dbuff_set(&work_dbuff, ptr_pairs[i].item_ptr);

					FR_PROTO_TRACE("Copying %zu bytes from %p to %p", ptr_pairs[i].item_len, ptr_pairs[i].item_ptr,
						fr_dbuff_current(dbuff));

					if (fr_dbuff_in_memcpy(dbuff, fr_dbuff_current(&work_dbuff), ptr_pairs[i].item_len) <= 0) {
						fr_strerror_const("Failed to copy set of value");
						talloc_free(ptr_pairs);
						talloc_free(buff);
						return -1;
					}
				}

				talloc_free(ptr_pairs);
				talloc_free(buff);
				return slen;
			}
		}

		fr_pair_list_sort(&vp->children, fr_der_pair_cmp_by_da_tag);

		ref = fr_dict_attr_ref(vp->da);

		if (ref && (ref->dict != dict_der)) {
			fr_strerror_printf("Group %s is not a DER group", ref->name);
			return -1;
		}

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		if (!fr_pair_list_empty(&vp->vp_group)) {
			fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

			while (fr_dcursor_current(&child_cursor)) {
				ssize_t len_count;

				len_count = fr_pair_cursor_to_network(dbuff, &da_stack, depth, &child_cursor,
								      encode_ctx, encode_pair);
				if (unlikely(len_count < 0)) {
					fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
					return -1;
				}

				slen += len_count;
			}
		}
	}

	return slen;
}

static ssize_t fr_der_encode_printable_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					      UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	char const	*value = NULL;
	size_t		 len;

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

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode printable string");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	8.23 Encoding for values of the restricted character string types 8.23.1 The data value consists of a
	 *	     string of characters from the character set specified in the ASN.1 type definition. 8.23.2 Each data value
	 *	     shall be encoded independently of other data values of the same type.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of encoding shall
	 *		not be used. (Contrast with 8.23.6.)
	 */
	value = vp->vp_strvalue;
	len   = vp->vp_length;

	for (size_t i = 0; i < len; i++) {
		/*
		 *	Check that the byte is a printable ASCII character allowed in a printable string
		 */
		if (allowed_chars[(uint8_t)value[i]] == false) {
			fr_strerror_printf("Invalid character in printable string (%d)", value[i]);
			return -1;
		}
	}

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for printable string");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_t61_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	char const	*value = NULL;
	size_t		 len;

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

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode T61 string");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	8.23 Encoding for values of the restricted character string types 8.23.1 The data value consists of a
	 *	     string of characters from the character set specified in the ASN.1 type definition. 8.23.2 Each data value
	 *	     shall be encoded independently of other data values of the same type.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of encoding shall
	 *		not be used. (Contrast with 8.23.6.)
	 */
	value = vp->vp_strvalue;
	len   = vp->vp_length;

	for (size_t i = 0; i < len; i++) {
		/*
		 *	Check that the byte is a printable ASCII character allowed in a printable string
		 */
		if (allowed_chars[(uint8_t)value[i]] == false) {
			fr_strerror_printf("Invalid character in T61 string (%d)", value[i]);
			return -1;
		}
	}

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for T61 string");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_ia5_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	char const	*value = NULL;
	size_t		 len;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode IA5 string");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	8.23 Encoding for values of the restricted character string types 8.23.1 The data value consists of a
	 *	     string of characters from the character set specified in the ASN.1 type definition. 8.23.2 Each data value
	 *	     shall be encoded independently of other data values of the same type.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of encoding shall
	 *		not be used. (Contrast with 8.23.6.)
	 */
	value = vp->vp_strvalue;
	len   = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for IA5 string");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_utc_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	fr_sbuff_t	 time_sbuff;
	char		 fmt_time[50];
	size_t		 i = 0;

	fmt_time[0] = '\0';
	time_sbuff  = FR_SBUFF_OUT(fmt_time, sizeof(fmt_time));

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode UTC time");
		return -1;
	}

	PAIR_VERIFY(vp);


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
	fr_unix_time_to_str(&time_sbuff, vp->vp_date, FR_TIME_RES_SEC, true);

	/*
	 *	Remove the century from the year
	 */
	fr_sbuff_shift(&time_sbuff, 2);

	/*
	 *	Trim the time string of any unwanted characters
	 */
	for (; i < sizeof(fmt_time); i++) {
		if (fmt_time[i] == '\0') {
			break;
		}

		if (fmt_time[i] == '-' || fmt_time[i] == 'T' || fmt_time[i] == ':') {
			size_t j = i;

			while (fmt_time[j] != '\0') {
				fmt_time[j] = fmt_time[j + 1];
				j++;
			}

			fmt_time[j] = '\0';

			continue;
		}
	}

	if (fr_dbuff_in_memcpy(dbuff, fmt_time, DER_UTC_TIME_LEN) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for UTC time");
		return -1;
	}

	return DER_UTC_TIME_LEN;
}

static ssize_t fr_der_encode_generalized_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					      UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	fr_sbuff_t	 time_sbuff;
	char		 fmt_time[50];
	size_t		 i = 0;

	fmt_time[0] = '\0';
	time_sbuff  = FR_SBUFF_OUT(fmt_time, sizeof(fmt_time));

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode generalized time");
		return -1;
	}

	PAIR_VERIFY(vp);

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

	fr_unix_time_to_str(&time_sbuff, vp->vp_date, FR_TIME_RES_USEC, true);

	/*
	 *	Trim the time string of any unwanted characters
	 */
	for (; i < sizeof(fmt_time); i++) {
		if (fmt_time[i] == '\0') {
			break;
		}

		if (fmt_time[i] == '-' || fmt_time[i] == 'T' || fmt_time[i] == ':') {
			size_t j = i;

			while (fmt_time[j] != '\0') {
				fmt_time[j] = fmt_time[j + 1];
				j++;
			}

			fmt_time[j] = '\0';

			continue;
		}

		if (fmt_time[i] == '.') {
			/*
			 *	Remove any trailing zeros
			 */
			size_t j = strlen(fmt_time) - 2;

			while (fmt_time[j] == '0') {
				fmt_time[j]	= fmt_time[j + 1];
				fmt_time[j + 1] = '\0';
				j--;
			}

			/*
			 *	Remove the decimal point if there are no fractional seconds
			 */
			if (j == i) {
				fmt_time[i]	= fmt_time[i + 1];
				fmt_time[i + 1] = '\0';
			}
		}
	}

	if (fr_dbuff_in_memcpy(dbuff, fmt_time, i) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for generalized time");
		return -1;
	}

	return i;
}

static ssize_t fr_der_encode_visible_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					    UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	char const	*value = NULL;
	size_t		 len;

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

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode visible string");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	8.23 Encoding for values of the restricted character string types 8.23.1 The data value consists of a
	 *	     string of characters from the character set specified in the ASN.1 type definition. 8.23.2 Each data value
	 *	     shall be encoded independently of other data values of the same type.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of encoding shall
	 *		not be used. (Contrast with 8.23.6.)
	 */
	value = vp->vp_strvalue;
	len   = vp->vp_length;

	for (size_t i = 0; i < len; i++) {
		/*
		 *	Check that the byte is a printable ASCII character allowed in a printable string
		 */
		if (allowed_chars[(uint8_t)value[i]] == false) {
			fr_strerror_printf("Invalid character in visible string (%d)", value[i]);
			return -1;
		}
	}

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for visible string");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_general_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					    UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	char const	*value = NULL;
	size_t		 len;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode general string");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	8.23 Encoding for values of the restricted character string types 8.23.1 The data value consists of a
	 *	     string of characters from the character set specified in the ASN.1 type definition. 8.23.2 Each data value
	 *	     shall be encoded independently of other data values of the same type.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of encoding shall
	 *		not be used. (Contrast with 8.23.6.)
	 */
	value = vp->vp_strvalue;
	len   = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for general string");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_universal_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					      UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;
	char const	*value = NULL;
	size_t		 len;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode universal string");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	8.23 Encoding for values of the restricted character string types 8.23.1 The data value consists of a
	 *	     string of characters from the character set specified in the ASN.1 type definition. 8.23.2 Each data value
	 *	     shall be encoded independently of other data values of the same type.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of encoding shall
	 *		not be used. (Contrast with 8.23.6.)
	 */
	value = vp->vp_strvalue;
	len   = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for universal string");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_X509_extensions(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_marker_t marker, outer_seq_len_start;
	fr_dcursor_t child_cursor, root_cursor, parent_cursor;
	fr_pair_t const *vp;
	ssize_t		 slen = 0;
	size_t is_critical = 0;
	uint64_t max;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode pair");
		return -1;
	}

	PAIR_VERIFY(vp);

	if (unlikely(!fr_type_is_group(vp->vp_type))) {
		fr_strerror_printf("Pair %s is not a group", vp->da->name);
		return -1;
	}

	max = fr_der_flag_max(vp->da);

	fr_dbuff_marker(&marker, dbuff);

	slen = fr_der_encode_tag(dbuff, FR_DER_TAG_SEQUENCE, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_CONSTRUCTED);
	if (slen < 0) return slen;

	fr_dbuff_marker(&outer_seq_len_start, dbuff);
	fr_dbuff_advance(dbuff, 1);

	FR_PROTO_HEX_DUMP(fr_dbuff_start(dbuff), fr_dbuff_behind(&outer_seq_len_start) - 1,
				  "BEFORE encoded X509 extension");

	fr_pair_dcursor_child_iter_init(&root_cursor, &vp->children, cursor);
	fr_dcursor_copy(&parent_cursor, &root_cursor);
	while (fr_dcursor_current(&parent_cursor)) {
		fr_sbuff_t	 oid_sbuff;
		fr_dbuff_marker_t length_start, inner_seq_len_start;
		char oid_buff[1024];
		bool is_raw = false;

		/*
		*	Extensions are sequences or sets containing 2 items:
		*	1. The first item is the OID
		*	2. The second item is the value
		*
		*	Note: The value may be a constructed or primitive type
		*/

		if (max < 0) {
			fr_strerror_printf("Too many X509 extensions (%llu)", max);
			break;
		}

		oid_sbuff = FR_SBUFF_OUT(oid_buff, sizeof(oid_buff));
		oid_buff[0] = '\0';

		// fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, &parent_cursor);
		fr_dcursor_copy(&child_cursor, &parent_cursor);
		while (fr_dcursor_current(&child_cursor)) {
			fr_pair_t const *child_vp = fr_dcursor_current(&child_cursor);

			PAIR_VERIFY(child_vp);

			FR_PROTO_TRACE("Child: %s", child_vp->da->name);

			// if (child_vp->da->name == "Critical") {
			if (!is_critical && (strcmp(child_vp->da->name, "Critical") == 0)) {
				/*
				*	We don't encode the critical flag
				*/
				is_critical = fr_pair_list_num_elements(&child_vp->children);
				FR_PROTO_TRACE("Critical flag: %lu", is_critical);
				// parent_cursor = child_cursor;
				// fr_dcursor_copy(&parent_cursor, &child_cursor);
				fr_pair_dcursor_child_iter_init(&parent_cursor, &child_vp->children, &child_cursor);
				goto next;
			}

			if (!fr_type_is_structural(child_vp->vp_type) && !fr_der_flag_is_extension(child_vp->da)) {
				FR_PROTO_TRACE("Found non-structural child %s", child_vp->da->name);

				if(child_vp->da->flags.is_raw) {
					/*
					*	This was an unknown oid
					*/
					if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, ".%d", child_vp->da->attr) <= 0)) goto error;
					is_raw = true;
					break;
				}

				// child_cursor = parent_cursor;
				fr_dcursor_copy(&child_cursor, &parent_cursor);
				break;
			}

			if (oid_buff[0] == '\0') {
				if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, "%d", child_vp->da->attr) <= 0)) {
				error:
					fr_strerror_const("Failed to copy OID to buffer");
					return -1;
				}

				goto next;
			}

			if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, ".%d", child_vp->da->attr) <= 0)) goto error;

			if (fr_pair_list_num_elements(&child_vp->children) > 1) break;

		next:
			FR_PROTO_TRACE("OID: %s", oid_buff);
			if (fr_der_flag_is_extension(child_vp->da)) break;
			fr_pair_dcursor_child_iter_init(&child_cursor, &child_vp->children, &child_cursor);
		}

		fr_sbuff_terminate(&oid_sbuff);
		FR_PROTO_TRACE("OID: %s", oid_buff);

		slen = fr_der_encode_tag(dbuff, FR_DER_TAG_SEQUENCE, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_CONSTRUCTED);
		if (slen < 0) return slen;

		fr_dbuff_marker(&inner_seq_len_start, dbuff);
		fr_dbuff_advance(dbuff, 1);

		/*
		 *	Encode the OID portion of the extension
		 */
		slen = fr_der_encode_tag(dbuff, FR_DER_TAG_OID, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
		if (slen < 0) return slen;

		fr_dbuff_marker(&length_start, dbuff);
		fr_dbuff_advance(dbuff, 1);

		slen = fr_der_encode_oid_to_str(dbuff, oid_buff);
		if (slen < 0) return slen;

		slen = fr_der_encode_len(dbuff, &length_start, slen);
		if (slen < 0) return slen;

		if (is_critical){
			/*
			 *	Encode the critical flag
			 */
			slen = fr_der_encode_tag(dbuff, FR_DER_TAG_BOOLEAN, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
			if (slen < 0) return slen;

			fr_dbuff_marker(&length_start, dbuff);
			fr_dbuff_advance(dbuff, 1);

			fr_dbuff_in(dbuff, (uint8_t)(0xff));
			slen = 1;

			slen = fr_der_encode_len(dbuff, &length_start, slen);
			if (slen < 0) return slen;

			is_critical--;
		}

		/*
		 *	Encode the value portion of the extension
		 */
		slen = fr_der_encode_tag(dbuff, FR_DER_TAG_OCTETSTRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
		if (slen < 0) return slen;

		fr_dbuff_marker(&length_start, dbuff);
		fr_dbuff_advance(dbuff, 1);

		if (is_raw) {
			slen = fr_der_encode_octetstring(dbuff, &child_cursor, encode_ctx);
		} else {
			slen = fr_der_encode_sequence(dbuff, &child_cursor, encode_ctx);
		}
		if (slen < 0) return slen;

		slen = fr_der_encode_len(dbuff, &length_start, slen);
		if (slen < 0) return slen;

		slen = fr_der_encode_len(dbuff, &inner_seq_len_start, fr_dbuff_behind(&inner_seq_len_start) - 1);
		if (slen < 0) return slen;

		if (is_critical) {
			fr_dcursor_next(&parent_cursor);
			max --;
			continue;
		}

		FR_PROTO_HEX_DUMP(fr_dbuff_start(dbuff), fr_dbuff_behind(&outer_seq_len_start) - 1,
				  "Encoded X509 extension");

		fr_dcursor_next(&root_cursor);
		// parent_cursor = root_cursor;
		fr_dcursor_copy(&parent_cursor, &root_cursor);
		max --;
	}

	slen = fr_der_encode_len(dbuff, &outer_seq_len_start, fr_dbuff_behind(&outer_seq_len_start) - 1);
	if (slen < 0) return slen;

	slen = fr_dbuff_marker_release_behind(&marker);

	FR_PROTO_HEX_DUMP(fr_dbuff_start(dbuff), slen,
				  "Encoded X509 extensions");

	return slen;
}

static ssize_t fr_der_encode_oid_value_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_sbuff_t	 oid_sbuff;
	fr_dbuff_marker_t marker, length_start;
	fr_dcursor_t child_cursor, parent_cursor = *cursor;
	fr_pair_t const *vp;
	char oid_buff[1024];
	ssize_t		 slen = 0;
	bool is_raw = false;

	vp = fr_dcursor_current(&parent_cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode pair");
		return -1;
	}

	PAIR_VERIFY(vp);

	if (unlikely(!fr_type_is_group(vp->vp_type))) {
		fr_strerror_printf("Pair %s is not a group", vp->da->name);
		return -1;
	}

	fr_dbuff_marker(&marker, dbuff);

	/*
	 *	Pairs are sequences or sets containing 2 items:
	 *	1. The first item is the OID
	 *	2. The second item is the value
	 *
	 *	Note: The value may be a constructed or primitive type
	 */

	oid_sbuff = FR_SBUFF_OUT(oid_buff, sizeof(oid_buff));
	oid_buff[0] = '\0';

	fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, &parent_cursor);
	while (fr_dcursor_current(&child_cursor)) {
		fr_pair_t const *child_vp = fr_dcursor_current(&child_cursor);

		PAIR_VERIFY(child_vp);

		if (!fr_type_is_structural(child_vp->vp_type) && !fr_der_flag_is_oid_leaf(child_vp->da)) {
			FR_PROTO_TRACE("Found non-structural child %s", child_vp->da->name);

			if(child_vp->da->flags.is_raw) {
				/*
				 *	This was an unknown oid
				 */
				if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, ".%d", child_vp->da->attr) <= 0)) goto error;
				is_raw = true;
				break;
			}

			fr_dcursor_copy(&child_cursor, &parent_cursor);
			break;
		}

		if (oid_buff[0] == '\0') {
			if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, "%d", child_vp->da->attr) <= 0)) {
			error:
				fr_strerror_const("Failed to copy OID to buffer");
				return -1;
			}

			goto next;
		}

		if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, ".%d", child_vp->da->attr) <= 0)) goto error;

		if (fr_pair_list_num_elements(&child_vp->children) > 1) break;

	next:
		FR_PROTO_TRACE("OID: %s", oid_buff);
		if (fr_der_flag_is_oid_leaf(child_vp->da)) break;
		fr_pair_dcursor_child_iter_init(&child_cursor, &child_vp->children, &child_cursor);
	}

	fr_sbuff_terminate(&oid_sbuff);
	FR_PROTO_TRACE("OID: %s", oid_buff);

	slen = fr_der_encode_tag(dbuff, FR_DER_TAG_OID, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
	if (slen < 0) return slen;

	fr_dbuff_marker(&length_start, dbuff);
	fr_dbuff_advance(dbuff, 1);

	slen = fr_der_encode_oid_to_str(dbuff, oid_buff);
	if (slen < 0) return slen;

	slen = fr_der_encode_len(dbuff, &length_start, slen);
	if (slen < 0) return slen;


	if (is_raw) {
		slen = fr_der_encode_octetstring(dbuff, &child_cursor, encode_ctx);
	} else {
		slen = der_encode_pair(dbuff, &child_cursor, encode_ctx);
	}
	if (slen < 0) return slen;

	return (ssize_t)fr_dbuff_marker_release_behind(&marker);
}

static ssize_t fr_der_encode_len(UNUSED fr_dbuff_t *dbuff, fr_dbuff_marker_t *length_start, ssize_t len)
{
	fr_dbuff_marker_t value_start;
	fr_dbuff_t	  value_field;
	uint8_t		  len_len = 0;
	ssize_t		  i = 0, our_len = len;

	/*
	 * If the length can fit in a single byte, we don't need to extend the size of the length field
	 */
	if (len < 0x7f) {
		fr_dbuff_in(length_start, (uint8_t)len);
		return 1;
	}

	/*
	 * Calculate the number of bytes needed to encode the length
	 */
	while (our_len > 0) {
		our_len >>= 8;
		len_len++;
	}

	if (len_len > 0x7f) {
		fr_strerror_printf("Length %zd is too large to encode", len);
		return -1;
	}

	value_field = FR_DBUFF(length_start);

	fr_dbuff_set(&value_field, fr_dbuff_current(length_start));

	fr_dbuff_marker(&value_start, &value_field);

	fr_dbuff_set(dbuff, fr_dbuff_start(length_start) + len_len + 1);

	fr_dbuff_move(dbuff, fr_dbuff_ptr(&value_start), len + 1);

	fr_dbuff_set(dbuff, length_start);

	fr_dbuff_in(dbuff, (uint8_t)(0x80 | len_len));

	for (; i < len_len; i++) {
		fr_dbuff_in(dbuff, (uint8_t)((len) >> ((len_len - i - 1) * 8)));
	}

	fr_dbuff_set(dbuff, fr_dbuff_current(length_start) + len_len + 1 + len);

	fr_dbuff_marker_release(&value_start);

	return len_len + 1;
}

static inline CC_HINT(always_inline) ssize_t
	fr_der_encode_tag(fr_dbuff_t *dbuff, fr_der_tag_num_t tag_num, fr_der_tag_class_t tag_class,
			  fr_der_tag_constructed_t constructed)
{
	uint8_t tag_byte;

	tag_byte = (tag_class & DER_TAG_CLASS_MASK) | (constructed & DER_TAG_CONSTRUCTED_MASK) |
		   (tag_num & DER_TAG_NUM_MASK);

	fr_dbuff_in(dbuff, tag_byte);

	return 1;
}

/** Encode a DER structure
 */
static ssize_t encode_value(fr_dbuff_t *dbuff, UNUSED fr_da_stack_t *da_stack, UNUSED unsigned int depth,
			    fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_pair_t const	 *vp;
	ssize_t		  slen	    = 0;
	fr_dbuff_t	  our_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker_t marker;
	fr_der_tag_encode_t *tag_encode;
	fr_der_tag_num_t tag_num;
	fr_der_tag_class_t tag_class;
	fr_der_encode_ctx_t *uctx = encode_ctx;

	if (unlikely(cursor == NULL)) {
		fr_strerror_const("No cursor to encode");
		return -1;
	}

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode");
		return -1;
	}

	FR_PROTO_TRACE("Encoding %s", vp->da->name);

	PAIR_VERIFY(vp);

	if (fr_der_flag_has_default(vp->da)) {
		fr_dict_enum_value_t const *evp;

		evp = fr_dict_enum_by_name(vp->da, "DEFAULT", strlen("DEFAULT"));
		if (unlikely(evp == NULL)) {
			fr_strerror_printf("No default value for %s", vp->da->name);
			return -1;
		}

		if (fr_value_box_cmp(&vp->data, evp->value) == 0) {
			FR_PROTO_TRACE("Skipping default value");
			fr_dcursor_next(cursor);
			return 0;
		}
	}

	tag_num   = fr_der_flag_subtype(vp->da) ? fr_der_flag_subtype(vp->da) : fr_type_to_der_tag_default(vp->vp_type);

	tag_encode = &tag_funcs[tag_num];
	if (tag_encode->encode == NULL) {
		fr_strerror_printf("No encoding function for type %d", vp->vp_type);
		return -1;
	}

	tag_class = fr_der_flag_class(vp->da) ? fr_der_flag_class(vp->da) : FR_DER_CLASS_UNIVERSAL;

	uctx->encoding_start = fr_dbuff_current(&our_dbuff);

	slen = fr_der_encode_tag(&our_dbuff, tag_class ? fr_der_flag_tagnum(vp->da) : tag_num, tag_class, tag_encode->constructed);
	if (slen < 0) return slen;

	uctx->encoding_length = slen;

	/*
	 * Mark and reserve space in the buffer for the length field
	 */
	fr_dbuff_marker(&marker, &our_dbuff);
	fr_dbuff_advance(&our_dbuff, 1);

	if (fr_der_flag_is_extensions(vp->da)) {
		slen = fr_der_encode_X509_extensions(&our_dbuff, cursor, uctx);
	} else {
		slen = tag_encode->encode(&our_dbuff, cursor, uctx);
	}
	if (slen < 0) return slen;

	uctx->encoding_length += slen;
	uctx->length_of_encoding = slen;

	slen = fr_der_encode_len(&our_dbuff, &marker, slen);
	if (slen < 0) return slen;

	uctx->encoded_value = fr_dbuff_start(&marker) + slen + 1;
	uctx->encoding_length += slen;

	fr_dcursor_next(cursor);
	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t encode_pair(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth, fr_dcursor_t *cursor,
			   void *encode_ctx)
{
	return encode_value(dbuff, da_stack, depth, cursor, encode_ctx);
}

static ssize_t der_encode_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx)
{
	return encode_pair(dbuff, NULL, 0, cursor, encode_ctx);
}

static ssize_t fr_der_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len,
				   void *encode_ctx)
{
	fr_dbuff_t   dbuff;
	fr_dcursor_t cursor;
	ssize_t	     slen;

	fr_dbuff_init(&dbuff, data, data_len);

	fr_pair_dcursor_init(&cursor, vps);

	slen = der_encode_pair(&dbuff, &cursor, encode_ctx);

	if (slen < 0) {
		fr_strerror_printf("Failed to encode data: %s", fr_strerror());
		return -1;
	}

	return slen;
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t der_tp_encode_pair;
fr_test_point_pair_encode_t	   der_tp_encode_pair = {
	       .test_ctx = encode_test_ctx,
	       .func	 = der_encode_pair,
};

extern fr_test_point_proto_encode_t der_tp_encode_proto;
fr_test_point_proto_encode_t	    der_tp_encode_proto = {
	       .test_ctx = encode_test_ctx,
	       .func	 = fr_der_encode_proto,
};
