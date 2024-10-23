#include "include/build.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "der.h"
#include "lib/util/dcursor.h"

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

typedef struct {
	uint8_t *tmp_ctx;
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
	fr_der_encode_t		 encode;
} fr_der_tag_encode_t;

static ssize_t fr_der_encode_boolean(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_integer(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_bitstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_octetstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_null(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_oid(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_enumerated(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_utf8_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_sequence(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_set(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_printable_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_t61_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_ia5_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_utc_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_generalized_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_visible_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_general_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_universal_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);



static fr_der_encode_t tag_funcs[] = {
	[FR_DER_TAG_BOOLEAN]	      = fr_der_encode_boolean,
	[FR_DER_TAG_INTEGER]	      = fr_der_encode_integer,
	// [FR_DER_TAG_BITSTRING]	      = fr_der_encode_bitstring,
	// [FR_DER_TAG_OCTETSTRING]      = fr_der_encode_octetstring,
	// [FR_DER_TAG_NULL]	      = fr_der_encode_null,
	// [FR_DER_TAG_OID]	      = fr_der_encode_oid,
	// [FR_DER_TAG_ENUMERATED]	      = fr_der_encode_enumerated,
	// [FR_DER_TAG_UTF8_STRING]      = fr_der_encode_utf8_string,
	// [FR_DER_TAG_SEQUENCE]	      = fr_der_encode_sequence,
	// [FR_DER_TAG_SET]	      = fr_der_encode_set,
	// [FR_DER_TAG_PRINTABLE_STRING] = fr_der_encode_printable_string,
	// [FR_DER_TAG_T61_STRING]	      = fr_der_encode_t61_string,
	// [FR_DER_TAG_IA5_STRING]	      = fr_der_encode_ia5_string,
	// [FR_DER_TAG_UTC_TIME]	      = fr_der_encode_utc_time,
	// [FR_DER_TAG_GENERALIZED_TIME] = fr_der_encode_generalized_time,
	// [FR_DER_TAG_VISIBLE_STRING]   = fr_der_encode_visible_string,
	// [FR_DER_TAG_GENERAL_STRING]   = fr_der_encode_general_string,
	// [FR_DER_TAG_UNIVERSAL_STRING] = fr_der_encode_universal_string,
};

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_der_encode_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_der_encode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_der_encode_boolean(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;
	uint8_t			value;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode");
		return -1;
	}

	PAIR_VERIFY(vp);

	value = vp->vp_bool;

	fr_dbuff_in(dbuff, (uint8_t)(value ? 0xff : 0x00));

	return 1;
}

// static ssize_t calculate_integer_len(int64_t value)
// {
// 	uint8_t		first_octet = 0;
// 	ssize_t		slen = 0;
// 	size_t		i = 0;

// 	for (; i < sizeof(value); i++) {
// 		uint8_t byte = (uint8_t)(value >> (((sizeof(value) * 8) - 8) - (i * 8)));

// 		if (slen == 0) {
// 			first_octet = byte;
// 			slen++;
// 			continue;
// 		} else if (slen == 1) {
// 			/*
// 			 *	8.3.2 If the contents octets of an integer value encoding consist of more than one octet,
// 	 		 *	      then the bits of the first octet and bit 8 of the second octet:
// 	 		 *	      a) shall not all be ones; and
// 	 		 *	      b) shall not all be zero.
// 			 */
// 			if ((first_octet == 0xff && (byte & 0x80)) || (first_octet == 0x00 && byte >> 7 == 0)) {
// 				first_octet = byte;
// 				continue;
// 			} else {
// 				slen ++;
// 				continue;
// 			}
// 		}

// 		slen++;
// 	}

// 	return slen;
// }

static ssize_t fr_der_encode_integer(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;
	int64_t			value;
	uint8_t			first_octet = 0;
	ssize_t			slen = 0;
	size_t			i = 0;

	// Get the current pair
	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode");
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
		// uint8_t byte = (uint8_t)(value << ((i) * 8));

		if (slen == 0) {
			first_octet = byte;
			slen++;
			continue;
		} else if (slen == 1) {
			/*
			 *	8.3.2 If the contents octets of an integer value encoding consist of more than one octet,
	 		 *	      then the bits of the first octet and bit 8 of the second octet:
	 		 *	      a) shall not all be ones; and
	 		 *	      b) shall not all be zero.
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
				slen ++;
				continue;
			}
		}

		fr_dbuff_in(dbuff, byte);
		slen++;
	}

	return slen;
}

static ssize_t fr_der_encode_sequence(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode");
		return -1;
	}

	PAIR_VERIFY(vp);

	fr_dbuff_in(dbuff, 0x0101FF);

	return 1;
}

static ssize_t fr_der_encode_len(UNUSED fr_dbuff_t *dbuff, fr_dbuff_marker_t *length_start, ssize_t len)
{
	// fr_dbuff_marker_t dst, tmp;
	// fr_dbuff_t	value_field = FR_DBUFF(marker);
	// uint8_t		len_len;
	// ssize_t		i = 0;

	// fr_dbuff_marker(&dst, dbuff);
	// fr_dbuff_marker(&tmp, dbuff);

	// fr_dbuff_set(&tmp, marker);

	// if (len < 0x7f) {
	// 	fr_dbuff_set(dbuff, fr_dbuff_current(marker) + 1);

	// 	fr_dbuff_move(dbuff, &value_field, len);

	// 	// fr_dbuff_in(&tmp, (uint8_t)len);

	// 	fr_dbuff_set(dbuff, fr_dbuff_current(marker));
	// 	fr_dbuff_in(dbuff, (uint8_t)len);

	// 	fr_dbuff_set(dbuff, fr_dbuff_current(marker) + 1 + len);
	// 	fr_dbuff_marker_release(&tmp);
	// 	return 1;
	// }

	// len_len = len / 0x80;

	// if (len_len > 0x7f) {
	// 	fr_strerror_printf("Length %zd is too large to encode", len);
	// 	return -1;
	// }

	// fr_dbuff_move(dbuff, marker, len_len + 1);

	// fr_dbuff_in(&tmp, (uint8_t)(0x80 | len_len));

	// for (; i < len_len; i++) {
	// 	fr_dbuff_in(&tmp, (uint8_t)(len));
	// 	len >>= 8;
	// }

	// fr_dbuff_set(dbuff, fr_dbuff_current(marker) + len_len + 1);

	// fr_dbuff_marker_release(&tmp);

	// return len_len + 1;

	fr_dbuff_marker_t value_start, value_end, length_end;
	uint8_t		len_len;
	ssize_t		i = 0;

	/*
	 * If the length can fit in a single byte, we don't need to extend the size of the length field
	 */
	if (len < 0x7f) {
		fr_dbuff_in(length_start, (uint8_t)len);
		return 1;
	}

	len_len = len / 0x80;

	if (len_len > 0x7f) {
		fr_strerror_printf("Length %zd is too large to encode", len);
		return -1;
	}

	fr_dbuff_set(&value_start, fr_dbuff_current(length_start) + 1);
	fr_dbuff_set(&value_end, fr_dbuff_current(length_start) + 1 + len);
	fr_dbuff_set(&length_end, fr_dbuff_current(length_start) + len_len + 1);

	fr_dbuff_move(&length_end, &value_start, len);

	fr_dbuff_in(length_start, (uint8_t)(0x80 | len_len));

	for (; i < len_len; i++) {
		fr_dbuff_in(length_start, (uint8_t)(len));
		len >>= 8;
	}

	fr_dbuff_marker_release(&value_start);
	fr_dbuff_marker_release(&value_end);
	fr_dbuff_marker_release(&length_end);

	return len_len + 1;
}

static inline CC_HINT(always_inline)
ssize_t fr_der_encode_tag(fr_dbuff_t *dbuff, fr_der_tag_num_t tag_num, fr_der_tag_class_t tag_class, fr_der_tag_constructed_t constructed)
{
	uint8_t		tag_byte;

	tag_byte = (tag_class & DER_TAG_CLASS_MASK) | (constructed & DER_TAG_CONSTRUCTED_MASK) | (tag_num & DER_TAG_NUM_MASK);

	fr_dbuff_in(dbuff, tag_byte);

	return 1;
}

/** Encode a DER structure
 */
static ssize_t encode_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_pair_t const		*vp;
	ssize_t			slen = 0;
	fr_dbuff_t		our_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker_t	marker;

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

	switch (vp->vp_type) {
	default:
		fr_strerror_printf("Unknown type %d", vp->vp_type);
		//return -1;
		break;
	case FR_TYPE_BOOL:
		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_BOOLEAN, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
	error:
		if (slen < 0) return slen;

		/*
		 * Mark and reserve space in the buffer for the length field
		 */
		fr_dbuff_marker(&marker, &our_dbuff);
		fr_dbuff_advance(&our_dbuff, 1);

		slen = fr_der_encode_boolean(&our_dbuff, cursor, encode_ctx);
		if (slen < 0) goto error;

		slen = fr_der_encode_len(&our_dbuff, &marker, 1);
		if (slen < 0) goto error;

		break;

	case FR_TYPE_INTEGER_EXCEPT_BOOL:
		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_INTEGER, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
		if (slen < 0) goto error;

		/*
		 * Mark and reserve space in the buffer for the length field
		 */
		fr_dbuff_marker(&marker, &our_dbuff);
		fr_dbuff_advance(&our_dbuff, 1);

		slen = fr_der_encode_integer(&our_dbuff, cursor, encode_ctx);
		if (slen < 0) goto error;

		slen = fr_der_encode_len(&our_dbuff, &marker, slen);
		if (slen < 0) goto error;

		break;
	case FR_TYPE_STRUCT:
		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_SEQUENCE, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_CONSTRUCTED);
		if (slen < 0) goto error;

		fr_dbuff_marker(&marker, &our_dbuff);

		slen = fr_der_encode_len(&our_dbuff, &marker, 3);
		if (slen < 0) goto error;

		slen = fr_der_encode_sequence(&our_dbuff, cursor, encode_ctx);
		if (slen < 0) goto error;

		break;
	}

	if (slen < 0) goto error;

	fr_dcursor_next(cursor);

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len, void *encode_ctx)
{
	fr_dbuff_t		dbuff;
	fr_dcursor_t		cursor;
	ssize_t			slen;

	fr_dbuff_init(&dbuff, data, data_len);

	fr_pair_dcursor_init(&cursor, vps);

	slen = encode_pair(&dbuff, &cursor, encode_ctx);

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
fr_test_point_pair_encode_t der_tp_encode_pair = {
	.test_ctx	= encode_test_ctx,
	.func		= encode_pair,
};

extern fr_test_point_proto_encode_t der_tp_encode_proto;
fr_test_point_proto_encode_t der_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_der_encode_proto,
};
