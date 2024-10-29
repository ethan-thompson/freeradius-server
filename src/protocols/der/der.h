#include <freeradius-devel/util/dict.h>

extern HIDDEN fr_dict_t const *dict_der;

/** Enumeration describing the data types in a DER encoded structure
 */
typedef enum {
	FR_DER_TAG_BOOLEAN	    = 0x01,	   //!< Boolean true/false
	FR_DER_TAG_INTEGER	    = 0x02,	   //!< Arbitrary width signed integer.
	FR_DER_TAG_BITSTRING	    = 0x03,	   //!< String of bits (length field specifies bits).
	FR_DER_TAG_OCTETSTRING	    = 0x04,	   //!< String of octets (length field specifies bytes).
	FR_DER_TAG_NULL		    = 0x05,	   //!< An empty value.
	FR_DER_TAG_OID		    = 0x06,	   //!< Reference to an OID based attribute.
	FR_DER_TAG_ENUMERATED	    = 0x0a,	   //!< An enumerated value.
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
} fr_der_tag_num_t;

typedef enum {
	FR_DER_TAG_PRIMATIVE   = 0x00,	      //!< This is a leaf value, it contains no children.
	FR_DER_TAG_CONSTRUCTED = 0x01	     //!< This is a sequence or set, it contains children.
} fr_der_tag_constructed_t;

typedef enum {
	FR_DER_CLASS_UNIVERSAL   = 0x00,
	FR_DER_CLASS_APPLICATION = 0x01,
	FR_DER_CLASS_CONTEXT	    = 0x02,
	FR_DER_CLASS_PRIVATE	    = 0x03,
	FR_DER_CLASS_INVALID	    = 0x04
} fr_der_tag_class_t;

extern fr_der_tag_constructed_t tag_labels[];

#define DER_MAX_STR 16384

#define DER_TAG_CLASS_MASK 0xc0	 //!< Mask to extract the class from the tag.
#define DER_TAG_CONSTRUCTED_MASK 0x20	 //!< Mask to check if the tag is constructed.
#define DER_TAG_NUM_MASK 0x1f	 //!< Mask to extract the tag number from the tag.

#define DER_MAX_TAG_NUM 0xfe * 8	 //!< Maximum tag number that can be encoded in a single byte.

#define DER_TAG_CONTINUATION 0x1f	 //!< Mask to check if the tag is a continuation.

#define DER_BOOLEAN_FALSE 0x00	 //!< DER encoded boolean false value.
#define DER_BOOLEAN_TRUE 0xff	 //!< DER encoded boolean true value.

typedef struct {
	uint8_t tag_num;
	fr_der_tag_class_t tag_class;
	fr_der_tag_num_t sub_type;
} fr_der_attr_flags_t;

static inline fr_der_attr_flags_t const *fr_der_attr_flags(fr_dict_attr_t const *da)
{
	return fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
}

#define fr_der_flag_tag_num(_da) 	(fr_der_attr_flags(_da)->tag_num)
#define fr_der_flag_tag_class(_da) 	(fr_der_attr_flags(_da)->tag_class)
#define fr_der_flag_sub_type(_da) 		(fr_der_attr_flags(_da)->sub_type)

/*
 * 	base.c
 */
int fr_der_global_init(void);
void fr_der_global_free(void);
