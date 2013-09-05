from tomcrypt._core cimport *
from tomcrypt._core import Error


cdef type_to_str = {
    LTC_ASN1_EOL: 'eol',
    LTC_ASN1_BOOLEAN: 'boolean',
    LTC_ASN1_INTEGER: 'integer',
    LTC_ASN1_SHORT_INTEGER: 'short_integer',
    LTC_ASN1_BIT_STRING: 'bit_string',
    LTC_ASN1_OCTET_STRING: 'octet_string',
    LTC_ASN1_NULL: 'null',
    LTC_ASN1_OBJECT_IDENTIFIER: 'object_identifier',
    LTC_ASN1_IA5_STRING: 'ia5_string',
    LTC_ASN1_UTF8_STRING: 'utf8_string',
    LTC_ASN1_PRINTABLE_STRING: 'printable_string',
    LTC_ASN1_UTCTIME: 'utctime',
    LTC_ASN1_SEQUENCE: 'sequence',
    LTC_ASN1_SET: 'set',
    LTC_ASN1_SETOF: 'setof',
    LTC_ASN1_CHOICE: 'choice',
}



def pprint(bytes encoded):

    cdef ltc_asn1_list *value
    cdef unsigned long inlen = len(encoded)
    check_for_error(der_decode_sequence_flexi(
        encoded,
        &inlen,
        &value
    ))

    _pprint(value, 0)

    der_sequence_free(value)


cdef indent(int depth):
    return '  ' * depth


cdef void _pprint(ltc_asn1_list *value, int depth):
    
    # TODO: Figure out ideal size for this.
    cdef char buf[1024]

    type_str = type_to_str.get(value.type, 'unknown (%d)' % value.type).upper()

    if value.type == LTC_ASN1_SEQUENCE:
        print '%s%s: {' % (indent(depth), type_str)
        if value.child:
            _pprint(value.child, depth + 1)
        print '%s}' % (indent(depth), )

    elif value.type == LTC_ASN1_INTEGER:
        check_for_error(mp.write_radix(value.data, buf, 16))
        print '%s%s: 0x%s' % (indent(depth), type_str, buf)

    elif value.type == LTC_ASN1_OBJECT_IDENTIFIER:
        longs = []
        for i in range(value.size):
            longs.append(int((<unsigned long *>value.data)[i]))
        print '%s%s: %r' % (indent(depth), type_str, tuple(longs))

    elif value.type == LTC_ASN1_BIT_STRING:
        bools = []
        for i in range(value.size):
            bools.append(int((<unsigned char *>value.data)[i]))
        print '%s%s: %r' % (indent(depth), type_str, tuple(bools))

    elif value.type == LTC_ASN1_NULL:
        print '%s%s' % (indent(depth), type_str)

    else:
        print '%s%s: Not decodable.' % (indent(depth), type_str)

    if value.next:
        _pprint(value.next, depth)






