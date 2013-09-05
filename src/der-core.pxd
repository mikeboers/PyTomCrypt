# encoding: utf8

cdef extern from "tomcrypt.h" nogil:
    
    ctypedef struct ltc_asn1_list:
        int type
        void *data
        unsigned long size
        int used
        ltc_asn1_list *prev
        ltc_asn1_list *next
        ltc_asn1_list *child
        ltc_asn1_list *parent

    int der_decode_sequence_flexi(
        unsigned char *input,
        unsigned long *inlen,
        ltc_asn1_list **out
    )

    void der_sequence_free(ltc_asn1_list *input)

    unsigned int LTC_ASN1_EOL # End of a ASN.1 list structure.
    unsigned int LTC_ASN1_BOOLEAN # BOOLEAN type
    unsigned int LTC_ASN1_INTEGER # INTEGER (uses mp int)
    unsigned int LTC_ASN1_SHORT_INTEGER # INTEGER (32-bit using unsigned long)
    unsigned int LTC_ASN1_BIT_STRING # BIT STRING (one bit per char)
    unsigned int LTC_ASN1_OCTET_STRING # OCTET STRING (one octet per char)
    unsigned int LTC_ASN1_NULL # NULL
    unsigned int LTC_ASN1_OBJECT_IDENTIFIER # OBJECT IDENTIFIER
    unsigned int LTC_ASN1_IA5_STRING # IA5 STRING (one octet per char)
    unsigned int LTC_ASN1_UTF8_STRING # UTF8 STRING (one wchar t per char)
    unsigned int LTC_ASN1_PRINTABLE_STRING # PRINTABLE STRING (one octet per char)
    unsigned int LTC_ASN1_UTCTIME # UTCTIME (see ltc utctime structure)
    unsigned int LTC_ASN1_SEQUENCE # SEQUENCE (and SEQUENCE OF)
    unsigned int LTC_ASN1_SET # SET
    unsigned int LTC_ASN1_SETOF # SET OF
    unsigned int LTC_ASN1_CHOICE #CHOICE
