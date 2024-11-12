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
static ssize_t fr_der_encode_octetstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_null(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_oid(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_enumerated(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_utf8_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_sequence(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_set(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_printable_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_t61_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_ia5_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_utc_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
// static ssize_t fr_der_encode_generalized_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_visible_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_general_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);
static ssize_t fr_der_encode_universal_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);


/*
 *	TODO: Use this to simplify the code
 */
static fr_der_encode_t tag_funcs[] = {
	[FR_DER_TAG_BOOLEAN]	      = fr_der_encode_boolean,
	[FR_DER_TAG_INTEGER]	      = fr_der_encode_integer,
	// [FR_DER_TAG_BITSTRING]	      = fr_der_encode_bitstring,
	[FR_DER_TAG_OCTETSTRING]      = fr_der_encode_octetstring,
	[FR_DER_TAG_NULL]	      = fr_der_encode_null,
	// [FR_DER_TAG_OID]	      = fr_der_encode_oid,
	// [FR_DER_TAG_ENUMERATED]	      = fr_der_encode_enumerated,
	[FR_DER_TAG_UTF8_STRING]      = fr_der_encode_utf8_string,
	// [FR_DER_TAG_SEQUENCE]	      = fr_der_encode_sequence,
	// [FR_DER_TAG_SET]	      = fr_der_encode_set,
	[FR_DER_TAG_PRINTABLE_STRING] = fr_der_encode_printable_string,
	[FR_DER_TAG_T61_STRING]	      = fr_der_encode_t61_string,
	[FR_DER_TAG_IA5_STRING]	      = fr_der_encode_ia5_string,
	// [FR_DER_TAG_UTC_TIME]	      = fr_der_encode_utc_time,
	// [FR_DER_TAG_GENERALIZED_TIME] = fr_der_encode_generalized_time,
	[FR_DER_TAG_VISIBLE_STRING]   = fr_der_encode_visible_string,
	[FR_DER_TAG_GENERAL_STRING]   = fr_der_encode_general_string,
	[FR_DER_TAG_UNIVERSAL_STRING] = fr_der_encode_universal_string,
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

static ssize_t fr_der_encode_octetstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;
	uint8_t const		*value = NULL;
	size_t			len;

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
	len = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy octet string value");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_null(UNUSED fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;

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
	 *	8.8.2 The contents octets shall be zero.
	 */
	if (vp->vp_length != 0) {
		fr_strerror_printf("Null has non-zero length %zu", vp->vp_length);
		return -1;
	}

	return 0;
}

static ssize_t fr_der_encode_utf8_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;
	char const		*value = NULL;
	size_t			len;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode");
		return -1;
	}

	PAIR_VERIFY(vp);

	value = vp->vp_strvalue;
	len = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for UTF8 string");
		fr_strerror_printf("Failed to copy string value with error number %ld", fr_dbuff_in_memcpy(dbuff, value, len));
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_sequence(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode sequence");
		return -1;
	}

	PAIR_VERIFY(vp);

	fr_dbuff_in(dbuff, 0x0101FF);

	return 1;
}

static ssize_t fr_der_encode_printable_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;
	char const		*value = NULL;
	size_t			len;

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

	value = vp->vp_strvalue;
	len = vp->vp_length;

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
	fr_pair_t const		*vp;
	char const		*value = NULL;
	size_t			len;

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

	value = vp->vp_strvalue;
	len = vp->vp_length;

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
	fr_pair_t const		*vp;
	char const		*value = NULL;
	size_t			len;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode IA5 string");
		return -1;
	}

	PAIR_VERIFY(vp);

	value = vp->vp_strvalue;
	len = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for IA5 string");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_visible_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;
	char const		*value = NULL;
	size_t			len;

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

	value = vp->vp_strvalue;
	len = vp->vp_length;

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

static ssize_t fr_der_encode_general_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;
	char const		*value = NULL;
	size_t			len;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode general string");
		return -1;
	}

	PAIR_VERIFY(vp);

	value = vp->vp_strvalue;
	len = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for general string");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_universal_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const		*vp;
	char const		*value = NULL;
	size_t			len;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode universal string");
		return -1;
	}

	PAIR_VERIFY(vp);

	value = vp->vp_strvalue;
	len = vp->vp_length;

	if (fr_dbuff_in_memcpy(dbuff, value, len) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for universal string");
		return -1;
	}

	return len;
}

static ssize_t fr_der_encode_len(UNUSED fr_dbuff_t *dbuff, fr_dbuff_marker_t *length_start, ssize_t len)
{
	fr_dbuff_marker_t value_start;
	fr_dbuff_t value_field;
	uint8_t		len_len = 0;
	ssize_t		i = 0, our_len = len;

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

	value_field = FR_DBUFF(length_start + 1);
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
		break;
	case FR_TYPE_BOOL:
		switch (fr_der_flag_subtype(vp->da)) {
		default:
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
		case FR_DER_TAG_NULL:
			slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_NULL, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
			if (slen < 0) goto error;

			/*
			 * Mark and reserve space in the buffer for the length field
			 */
			fr_dbuff_marker(&marker, &our_dbuff);
			fr_dbuff_advance(&our_dbuff, 1);

			slen = fr_der_encode_null(&our_dbuff, cursor, encode_ctx);
			if (slen < 0) goto error;

			slen = fr_der_encode_len(&our_dbuff, &marker, 0);
			if (slen < 0) goto error;

			break;
		}

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

	case FR_TYPE_OCTETS:
		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_OCTETSTRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
		if (slen < 0) goto error;

		/*
		 * Mark and reserve space in the buffer for the length field
		 */
		fr_dbuff_marker(&marker, &our_dbuff);
		fr_dbuff_advance(&our_dbuff, 1);

		slen = fr_der_encode_octetstring(&our_dbuff, cursor, encode_ctx);
		if (slen < 0) goto error;

		slen = fr_der_encode_len(&our_dbuff, &marker, slen);
		if (slen < 0) goto error;

		break;

	case FR_TYPE_NULL:
		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_NULL, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
		if (slen < 0) goto error;

		/*
		 * Mark and reserve space in the buffer for the length field
		 */
		fr_dbuff_marker(&marker, &our_dbuff);
		fr_dbuff_advance(&our_dbuff, 1);

		slen = fr_der_encode_null(&our_dbuff, cursor, encode_ctx);
		if (slen < 0) goto error;

		slen = fr_der_encode_len(&our_dbuff, &marker, slen);
		if (slen < 0) goto error;

		break;

	case FR_TYPE_STRING:
		switch (fr_der_flag_subtype(vp->da)) {
		default:
			fr_strerror_printf("Unknown string sub-type %d", fr_der_flag_subtype(vp->da));
			return -1;
		case FR_DER_TAG_UTF8_STRING:
			slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_UTF8_STRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
			if (slen < 0) goto error;

			/*
			* Mark and reserve space in the buffer for the length field
			*/
			fr_dbuff_marker(&marker, &our_dbuff);
			fr_dbuff_advance(&our_dbuff, 1);

			slen = fr_der_encode_utf8_string(&our_dbuff, cursor, encode_ctx);
			if (slen < 0) goto error;
			break;

		case FR_DER_TAG_PRINTABLE_STRING:
			slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_PRINTABLE_STRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
			if (slen < 0) goto error;

			/*
			* Mark and reserve space in the buffer for the length field
			*/
			fr_dbuff_marker(&marker, &our_dbuff);
			fr_dbuff_advance(&our_dbuff, 1);

			slen = fr_der_encode_printable_string(&our_dbuff, cursor, encode_ctx);
			if (slen < 0) goto error;
			break;

		case FR_DER_TAG_T61_STRING:
			slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_T61_STRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
			if (slen < 0) goto error;

			/*
			* Mark and reserve space in the buffer for the length field
			*/
			fr_dbuff_marker(&marker, &our_dbuff);
			fr_dbuff_advance(&our_dbuff, 1);

			slen = fr_der_encode_t61_string(&our_dbuff, cursor, encode_ctx);
			if (slen < 0) goto error;
			break;

		case FR_DER_TAG_IA5_STRING:
			slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_IA5_STRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
			if (slen < 0) goto error;

			/*
			* Mark and reserve space in the buffer for the length field
			*/
			fr_dbuff_marker(&marker, &our_dbuff);
			fr_dbuff_advance(&our_dbuff, 1);

			slen = fr_der_encode_ia5_string(&our_dbuff, cursor, encode_ctx);
			if (slen < 0) goto error;
			break;

		case FR_DER_TAG_VISIBLE_STRING:
			slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_VISIBLE_STRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
			if (slen < 0) goto error;

			/*
			* Mark and reserve space in the buffer for the length field
			*/
			fr_dbuff_marker(&marker, &our_dbuff);
			fr_dbuff_advance(&our_dbuff, 1);

			slen = fr_der_encode_visible_string(&our_dbuff, cursor, encode_ctx);
			if (slen < 0) goto error;
			break;

		case FR_DER_TAG_GENERAL_STRING:
			slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_GENERAL_STRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
			if (slen < 0) goto error;

			/*
			* Mark and reserve space in the buffer for the length field
			*/
			fr_dbuff_marker(&marker, &our_dbuff);
			fr_dbuff_advance(&our_dbuff, 1);

			slen = fr_der_encode_general_string(&our_dbuff, cursor, encode_ctx);
			if (slen < 0) goto error;
			break;

		case FR_DER_TAG_UNIVERSAL_STRING:
			slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_UNIVERSAL_STRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMATIVE);
			if (slen < 0) goto error;

			/*
			* Mark and reserve space in the buffer for the length field
			*/
			fr_dbuff_marker(&marker, &our_dbuff);
			fr_dbuff_advance(&our_dbuff, 1);

			slen = fr_der_encode_universal_string(&our_dbuff, cursor, encode_ctx);
			if (slen < 0) goto error;
			break;
		}

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
