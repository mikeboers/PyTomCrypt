import os
import datetime

from distutils.core import setup
from distutils.extension import Extension
# from Cython.Distutils import build_ext


# Allow us to specify a single extension to build.
ext_names = ['_core', 'cipher', 'hash', 'mac', 'prng', 'rsa', 'pkcs1', 'pkcs5', 'ecc']
ext_name = os.environ.get('PyTomCrypt_ext_name')
if ext_name:
    if ext_name not in ext_names:
        raise ValueError('unknown extension %r' % ext_name)
    ext_names = [ext_name]

ext_sources = {'_core': '''

### LIBTOMCRYPT
# lib/libtomcrypt-1.17/demos/encrypt.c
# lib/libtomcrypt-1.17/demos/hashsum.c
# lib/libtomcrypt-1.17/demos/multi.c
# lib/libtomcrypt-1.17/demos/small.c
# lib/libtomcrypt-1.17/demos/test.c
# lib/libtomcrypt-1.17/demos/timing.c
# lib/libtomcrypt-1.17/demos/tv_gen.c
# lib/libtomcrypt-1.17/notes/etc/saferp_optimizer.c
# lib/libtomcrypt-1.17/notes/etc/whirlgen.c
# lib/libtomcrypt-1.17/notes/etc/whirltest.c
lib/libtomcrypt-1.17/src/ciphers/aes/aes.c
# lib/libtomcrypt-1.17/src/ciphers/aes/aes_tab.c
lib/libtomcrypt-1.17/src/ciphers/anubis.c
lib/libtomcrypt-1.17/src/ciphers/blowfish.c
lib/libtomcrypt-1.17/src/ciphers/cast5.c
lib/libtomcrypt-1.17/src/ciphers/des.c
lib/libtomcrypt-1.17/src/ciphers/kasumi.c
lib/libtomcrypt-1.17/src/ciphers/khazad.c
lib/libtomcrypt-1.17/src/ciphers/kseed.c
lib/libtomcrypt-1.17/src/ciphers/noekeon.c
lib/libtomcrypt-1.17/src/ciphers/rc2.c
lib/libtomcrypt-1.17/src/ciphers/rc5.c
lib/libtomcrypt-1.17/src/ciphers/rc6.c
lib/libtomcrypt-1.17/src/ciphers/safer/safer.c
lib/libtomcrypt-1.17/src/ciphers/safer/safer_tab.c
lib/libtomcrypt-1.17/src/ciphers/safer/saferp.c
lib/libtomcrypt-1.17/src/ciphers/skipjack.c
lib/libtomcrypt-1.17/src/ciphers/twofish/twofish.c
lib/libtomcrypt-1.17/src/ciphers/twofish/twofish_tab.c
lib/libtomcrypt-1.17/src/ciphers/xtea.c
lib/libtomcrypt-1.17/src/encauth/ccm/ccm_memory.c
lib/libtomcrypt-1.17/src/encauth/ccm/ccm_test.c
lib/libtomcrypt-1.17/src/encauth/eax/eax_addheader.c
lib/libtomcrypt-1.17/src/encauth/eax/eax_decrypt.c
lib/libtomcrypt-1.17/src/encauth/eax/eax_decrypt_verify_memory.c
lib/libtomcrypt-1.17/src/encauth/eax/eax_done.c
lib/libtomcrypt-1.17/src/encauth/eax/eax_encrypt.c
lib/libtomcrypt-1.17/src/encauth/eax/eax_encrypt_authenticate_memory.c
lib/libtomcrypt-1.17/src/encauth/eax/eax_init.c
lib/libtomcrypt-1.17/src/encauth/eax/eax_test.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_add_aad.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_add_iv.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_done.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_gf_mult.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_init.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_memory.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_mult_h.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_process.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_reset.c
lib/libtomcrypt-1.17/src/encauth/gcm/gcm_test.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_decrypt.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_decrypt_verify_memory.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_done_decrypt.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_done_encrypt.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_encrypt.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_encrypt_authenticate_memory.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_init.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_ntz.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_shift_xor.c
lib/libtomcrypt-1.17/src/encauth/ocb/ocb_test.c
lib/libtomcrypt-1.17/src/encauth/ocb/s_ocb_done.c
lib/libtomcrypt-1.17/src/hashes/chc/chc.c
lib/libtomcrypt-1.17/src/hashes/helper/hash_file.c
lib/libtomcrypt-1.17/src/hashes/helper/hash_filehandle.c
lib/libtomcrypt-1.17/src/hashes/helper/hash_memory.c
lib/libtomcrypt-1.17/src/hashes/helper/hash_memory_multi.c
lib/libtomcrypt-1.17/src/hashes/md2.c
lib/libtomcrypt-1.17/src/hashes/md4.c
lib/libtomcrypt-1.17/src/hashes/md5.c
lib/libtomcrypt-1.17/src/hashes/rmd128.c
lib/libtomcrypt-1.17/src/hashes/rmd160.c
lib/libtomcrypt-1.17/src/hashes/rmd256.c
lib/libtomcrypt-1.17/src/hashes/rmd320.c
lib/libtomcrypt-1.17/src/hashes/sha1.c
# lib/libtomcrypt-1.17/src/hashes/sha2/sha224.c
lib/libtomcrypt-1.17/src/hashes/sha2/sha256.c
# lib/libtomcrypt-1.17/src/hashes/sha2/sha384.c
lib/libtomcrypt-1.17/src/hashes/sha2/sha512.c
lib/libtomcrypt-1.17/src/hashes/tiger.c
lib/libtomcrypt-1.17/src/hashes/whirl/whirl.c
# lib/libtomcrypt-1.17/src/hashes/whirl/whirltab.c
lib/libtomcrypt-1.17/src/mac/f9/f9_done.c
lib/libtomcrypt-1.17/src/mac/f9/f9_file.c
lib/libtomcrypt-1.17/src/mac/f9/f9_init.c
lib/libtomcrypt-1.17/src/mac/f9/f9_memory.c
lib/libtomcrypt-1.17/src/mac/f9/f9_memory_multi.c
lib/libtomcrypt-1.17/src/mac/f9/f9_process.c
lib/libtomcrypt-1.17/src/mac/f9/f9_test.c
lib/libtomcrypt-1.17/src/mac/hmac/hmac_done.c
lib/libtomcrypt-1.17/src/mac/hmac/hmac_file.c
lib/libtomcrypt-1.17/src/mac/hmac/hmac_init.c
lib/libtomcrypt-1.17/src/mac/hmac/hmac_memory.c
lib/libtomcrypt-1.17/src/mac/hmac/hmac_memory_multi.c
lib/libtomcrypt-1.17/src/mac/hmac/hmac_process.c
lib/libtomcrypt-1.17/src/mac/hmac/hmac_test.c
lib/libtomcrypt-1.17/src/mac/omac/omac_done.c
lib/libtomcrypt-1.17/src/mac/omac/omac_file.c
lib/libtomcrypt-1.17/src/mac/omac/omac_init.c
lib/libtomcrypt-1.17/src/mac/omac/omac_memory.c
lib/libtomcrypt-1.17/src/mac/omac/omac_memory_multi.c
lib/libtomcrypt-1.17/src/mac/omac/omac_process.c
lib/libtomcrypt-1.17/src/mac/omac/omac_test.c
lib/libtomcrypt-1.17/src/mac/pelican/pelican.c
lib/libtomcrypt-1.17/src/mac/pelican/pelican_memory.c
lib/libtomcrypt-1.17/src/mac/pelican/pelican_test.c
lib/libtomcrypt-1.17/src/mac/pmac/pmac_done.c
lib/libtomcrypt-1.17/src/mac/pmac/pmac_file.c
lib/libtomcrypt-1.17/src/mac/pmac/pmac_init.c
lib/libtomcrypt-1.17/src/mac/pmac/pmac_memory.c
lib/libtomcrypt-1.17/src/mac/pmac/pmac_memory_multi.c
lib/libtomcrypt-1.17/src/mac/pmac/pmac_ntz.c
lib/libtomcrypt-1.17/src/mac/pmac/pmac_process.c
lib/libtomcrypt-1.17/src/mac/pmac/pmac_shift_xor.c
lib/libtomcrypt-1.17/src/mac/pmac/pmac_test.c
lib/libtomcrypt-1.17/src/mac/xcbc/xcbc_done.c
lib/libtomcrypt-1.17/src/mac/xcbc/xcbc_file.c
lib/libtomcrypt-1.17/src/mac/xcbc/xcbc_init.c
lib/libtomcrypt-1.17/src/mac/xcbc/xcbc_memory.c
lib/libtomcrypt-1.17/src/mac/xcbc/xcbc_memory_multi.c
lib/libtomcrypt-1.17/src/mac/xcbc/xcbc_process.c
lib/libtomcrypt-1.17/src/mac/xcbc/xcbc_test.c
lib/libtomcrypt-1.17/src/math/fp/ltc_ecc_fp_mulmod.c
# lib/libtomcrypt-1.17/src/math/gmp_desc.c
lib/libtomcrypt-1.17/src/math/ltm_desc.c
lib/libtomcrypt-1.17/src/math/multi.c
lib/libtomcrypt-1.17/src/math/rand_prime.c
lib/libtomcrypt-1.17/src/math/tfm_desc.c
lib/libtomcrypt-1.17/src/misc/base64/base64_decode.c
lib/libtomcrypt-1.17/src/misc/base64/base64_encode.c
lib/libtomcrypt-1.17/src/misc/burn_stack.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_argchk.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_cipher_descriptor.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_cipher_is_valid.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_find_cipher.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_find_cipher_any.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_find_cipher_id.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_find_hash.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_find_hash_any.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_find_hash_id.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_find_hash_oid.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_find_prng.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_fsa.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_hash_descriptor.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_hash_is_valid.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_ltc_mp_descriptor.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_prng_descriptor.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_prng_is_valid.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_register_cipher.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_register_hash.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_register_prng.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_unregister_cipher.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_unregister_hash.c
lib/libtomcrypt-1.17/src/misc/crypt/crypt_unregister_prng.c
lib/libtomcrypt-1.17/src/misc/error_to_string.c
lib/libtomcrypt-1.17/src/misc/pkcs5/pkcs_5_1.c
lib/libtomcrypt-1.17/src/misc/pkcs5/pkcs_5_2.c
lib/libtomcrypt-1.17/src/misc/zeromem.c
lib/libtomcrypt-1.17/src/modes/cbc/cbc_decrypt.c
lib/libtomcrypt-1.17/src/modes/cbc/cbc_done.c
lib/libtomcrypt-1.17/src/modes/cbc/cbc_encrypt.c
lib/libtomcrypt-1.17/src/modes/cbc/cbc_getiv.c
lib/libtomcrypt-1.17/src/modes/cbc/cbc_setiv.c
lib/libtomcrypt-1.17/src/modes/cbc/cbc_start.c
lib/libtomcrypt-1.17/src/modes/cfb/cfb_decrypt.c
lib/libtomcrypt-1.17/src/modes/cfb/cfb_done.c
lib/libtomcrypt-1.17/src/modes/cfb/cfb_encrypt.c
lib/libtomcrypt-1.17/src/modes/cfb/cfb_getiv.c
lib/libtomcrypt-1.17/src/modes/cfb/cfb_setiv.c
lib/libtomcrypt-1.17/src/modes/cfb/cfb_start.c
lib/libtomcrypt-1.17/src/modes/ctr/ctr_decrypt.c
lib/libtomcrypt-1.17/src/modes/ctr/ctr_done.c
lib/libtomcrypt-1.17/src/modes/ctr/ctr_encrypt.c
lib/libtomcrypt-1.17/src/modes/ctr/ctr_getiv.c
lib/libtomcrypt-1.17/src/modes/ctr/ctr_setiv.c
lib/libtomcrypt-1.17/src/modes/ctr/ctr_start.c
lib/libtomcrypt-1.17/src/modes/ctr/ctr_test.c
lib/libtomcrypt-1.17/src/modes/ecb/ecb_decrypt.c
lib/libtomcrypt-1.17/src/modes/ecb/ecb_done.c
lib/libtomcrypt-1.17/src/modes/ecb/ecb_encrypt.c
lib/libtomcrypt-1.17/src/modes/ecb/ecb_start.c
lib/libtomcrypt-1.17/src/modes/f8/f8_decrypt.c
lib/libtomcrypt-1.17/src/modes/f8/f8_done.c
lib/libtomcrypt-1.17/src/modes/f8/f8_encrypt.c
lib/libtomcrypt-1.17/src/modes/f8/f8_getiv.c
lib/libtomcrypt-1.17/src/modes/f8/f8_setiv.c
lib/libtomcrypt-1.17/src/modes/f8/f8_start.c
lib/libtomcrypt-1.17/src/modes/f8/f8_test_mode.c
lib/libtomcrypt-1.17/src/modes/lrw/lrw_decrypt.c
lib/libtomcrypt-1.17/src/modes/lrw/lrw_done.c
lib/libtomcrypt-1.17/src/modes/lrw/lrw_encrypt.c
lib/libtomcrypt-1.17/src/modes/lrw/lrw_getiv.c
lib/libtomcrypt-1.17/src/modes/lrw/lrw_process.c
lib/libtomcrypt-1.17/src/modes/lrw/lrw_setiv.c
lib/libtomcrypt-1.17/src/modes/lrw/lrw_start.c
lib/libtomcrypt-1.17/src/modes/lrw/lrw_test.c
lib/libtomcrypt-1.17/src/modes/ofb/ofb_decrypt.c
lib/libtomcrypt-1.17/src/modes/ofb/ofb_done.c
lib/libtomcrypt-1.17/src/modes/ofb/ofb_encrypt.c
lib/libtomcrypt-1.17/src/modes/ofb/ofb_getiv.c
lib/libtomcrypt-1.17/src/modes/ofb/ofb_setiv.c
lib/libtomcrypt-1.17/src/modes/ofb/ofb_start.c
lib/libtomcrypt-1.17/src/pk/asn1/der/bit/der_decode_bit_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/bit/der_encode_bit_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/bit/der_length_bit_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/boolean/der_decode_boolean.c
lib/libtomcrypt-1.17/src/pk/asn1/der/boolean/der_encode_boolean.c
lib/libtomcrypt-1.17/src/pk/asn1/der/boolean/der_length_boolean.c
lib/libtomcrypt-1.17/src/pk/asn1/der/choice/der_decode_choice.c
lib/libtomcrypt-1.17/src/pk/asn1/der/ia5/der_decode_ia5_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/ia5/der_encode_ia5_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/ia5/der_length_ia5_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/integer/der_decode_integer.c
lib/libtomcrypt-1.17/src/pk/asn1/der/integer/der_encode_integer.c
lib/libtomcrypt-1.17/src/pk/asn1/der/integer/der_length_integer.c
lib/libtomcrypt-1.17/src/pk/asn1/der/object_identifier/der_decode_object_identifier.c
lib/libtomcrypt-1.17/src/pk/asn1/der/object_identifier/der_encode_object_identifier.c
lib/libtomcrypt-1.17/src/pk/asn1/der/object_identifier/der_length_object_identifier.c
lib/libtomcrypt-1.17/src/pk/asn1/der/octet/der_decode_octet_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/octet/der_encode_octet_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/octet/der_length_octet_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/printable_string/der_decode_printable_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/printable_string/der_encode_printable_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/printable_string/der_length_printable_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_decode_sequence_ex.c
lib/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_decode_sequence_flexi.c
lib/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_decode_sequence_multi.c
lib/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_encode_sequence_ex.c
lib/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_encode_sequence_multi.c
lib/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_length_sequence.c
lib/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_sequence_free.c
lib/libtomcrypt-1.17/src/pk/asn1/der/set/der_encode_set.c
lib/libtomcrypt-1.17/src/pk/asn1/der/set/der_encode_setof.c
lib/libtomcrypt-1.17/src/pk/asn1/der/short_integer/der_decode_short_integer.c
lib/libtomcrypt-1.17/src/pk/asn1/der/short_integer/der_encode_short_integer.c
lib/libtomcrypt-1.17/src/pk/asn1/der/short_integer/der_length_short_integer.c
lib/libtomcrypt-1.17/src/pk/asn1/der/utctime/der_decode_utctime.c
lib/libtomcrypt-1.17/src/pk/asn1/der/utctime/der_encode_utctime.c
lib/libtomcrypt-1.17/src/pk/asn1/der/utctime/der_length_utctime.c
lib/libtomcrypt-1.17/src/pk/asn1/der/utf8/der_decode_utf8_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/utf8/der_encode_utf8_string.c
lib/libtomcrypt-1.17/src/pk/asn1/der/utf8/der_length_utf8_string.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_decrypt_key.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_encrypt_key.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_export.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_free.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_import.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_make_key.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_shared_secret.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_sign_hash.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_verify_hash.c
lib/libtomcrypt-1.17/src/pk/dsa/dsa_verify_key.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_ansi_x963_export.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_ansi_x963_import.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_decrypt_key.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_encrypt_key.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_export.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_free.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_get_size.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_import.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_make_key.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_shared_secret.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_sign_hash.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_sizes.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_test.c
lib/libtomcrypt-1.17/src/pk/ecc/ecc_verify_hash.c
lib/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_is_valid_idx.c
lib/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_map.c
lib/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_mul2add.c
lib/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_mulmod.c
lib/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_mulmod_timing.c
lib/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_points.c
lib/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_projective_add_point.c
lib/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_projective_dbl_point.c
lib/libtomcrypt-1.17/src/pk/katja/katja_decrypt_key.c
lib/libtomcrypt-1.17/src/pk/katja/katja_encrypt_key.c
lib/libtomcrypt-1.17/src/pk/katja/katja_export.c
lib/libtomcrypt-1.17/src/pk/katja/katja_exptmod.c
lib/libtomcrypt-1.17/src/pk/katja/katja_free.c
lib/libtomcrypt-1.17/src/pk/katja/katja_import.c
lib/libtomcrypt-1.17/src/pk/katja/katja_make_key.c
lib/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_i2osp.c
lib/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_mgf1.c
lib/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_oaep_decode.c
lib/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_oaep_encode.c
lib/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_os2ip.c
lib/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_pss_decode.c
lib/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_pss_encode.c
lib/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_v1_5_decode.c
lib/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_v1_5_encode.c
lib/libtomcrypt-1.17/src/pk/rsa/rsa_decrypt_key.c
lib/libtomcrypt-1.17/src/pk/rsa/rsa_encrypt_key.c
lib/libtomcrypt-1.17/src/pk/rsa/rsa_export.c
lib/libtomcrypt-1.17/src/pk/rsa/rsa_exptmod.c
lib/libtomcrypt-1.17/src/pk/rsa/rsa_free.c
lib/libtomcrypt-1.17/src/pk/rsa/rsa_import.c
lib/libtomcrypt-1.17/src/pk/rsa/rsa_make_key.c
lib/libtomcrypt-1.17/src/pk/rsa/rsa_sign_hash.c
lib/libtomcrypt-1.17/src/pk/rsa/rsa_verify_hash.c
lib/libtomcrypt-1.17/src/prngs/fortuna.c
lib/libtomcrypt-1.17/src/prngs/rc4.c
lib/libtomcrypt-1.17/src/prngs/rng_get_bytes.c
lib/libtomcrypt-1.17/src/prngs/rng_make_prng.c
lib/libtomcrypt-1.17/src/prngs/sober128.c
# lib/libtomcrypt-1.17/src/prngs/sober128tab.c
lib/libtomcrypt-1.17/src/prngs/sprng.c
lib/libtomcrypt-1.17/src/prngs/yarrow.c
# lib/libtomcrypt-1.17/testprof/base64_test.c
# lib/libtomcrypt-1.17/testprof/cipher_hash_test.c
# lib/libtomcrypt-1.17/testprof/der_tests.c
# lib/libtomcrypt-1.17/testprof/dsa_test.c
# lib/libtomcrypt-1.17/testprof/ecc_test.c
# lib/libtomcrypt-1.17/testprof/katja_test.c
# lib/libtomcrypt-1.17/testprof/mac_test.c
# lib/libtomcrypt-1.17/testprof/modes_test.c
# lib/libtomcrypt-1.17/testprof/pkcs_1_test.c
# lib/libtomcrypt-1.17/testprof/rsa_test.c
# lib/libtomcrypt-1.17/testprof/store_test.c
# lib/libtomcrypt-1.17/testprof/test_driver.c
# lib/libtomcrypt-1.17/testprof/x86_prof.c


### TOMSFASTMATH
lib/libtommath-0.41/bn_error.c
lib/libtommath-0.41/bn_fast_mp_invmod.c
lib/libtommath-0.41/bn_fast_mp_montgomery_reduce.c
lib/libtommath-0.41/bn_fast_s_mp_mul_digs.c
lib/libtommath-0.41/bn_fast_s_mp_mul_high_digs.c
lib/libtommath-0.41/bn_fast_s_mp_sqr.c
lib/libtommath-0.41/bn_mp_2expt.c
lib/libtommath-0.41/bn_mp_abs.c
lib/libtommath-0.41/bn_mp_add.c
lib/libtommath-0.41/bn_mp_add_d.c
lib/libtommath-0.41/bn_mp_addmod.c
lib/libtommath-0.41/bn_mp_and.c
lib/libtommath-0.41/bn_mp_clamp.c
lib/libtommath-0.41/bn_mp_clear.c
lib/libtommath-0.41/bn_mp_clear_multi.c
lib/libtommath-0.41/bn_mp_cmp.c
lib/libtommath-0.41/bn_mp_cmp_d.c
lib/libtommath-0.41/bn_mp_cmp_mag.c
lib/libtommath-0.41/bn_mp_cnt_lsb.c
lib/libtommath-0.41/bn_mp_copy.c
lib/libtommath-0.41/bn_mp_count_bits.c
lib/libtommath-0.41/bn_mp_div.c
lib/libtommath-0.41/bn_mp_div_2.c
lib/libtommath-0.41/bn_mp_div_2d.c
lib/libtommath-0.41/bn_mp_div_3.c
lib/libtommath-0.41/bn_mp_div_d.c
lib/libtommath-0.41/bn_mp_dr_is_modulus.c
lib/libtommath-0.41/bn_mp_dr_reduce.c
lib/libtommath-0.41/bn_mp_dr_setup.c
lib/libtommath-0.41/bn_mp_exch.c
lib/libtommath-0.41/bn_mp_expt_d.c
lib/libtommath-0.41/bn_mp_exptmod.c
lib/libtommath-0.41/bn_mp_exptmod_fast.c
lib/libtommath-0.41/bn_mp_exteuclid.c
lib/libtommath-0.41/bn_mp_fread.c
lib/libtommath-0.41/bn_mp_fwrite.c
lib/libtommath-0.41/bn_mp_gcd.c
lib/libtommath-0.41/bn_mp_get_int.c
lib/libtommath-0.41/bn_mp_grow.c
lib/libtommath-0.41/bn_mp_init.c
lib/libtommath-0.41/bn_mp_init_copy.c
lib/libtommath-0.41/bn_mp_init_multi.c
lib/libtommath-0.41/bn_mp_init_set.c
lib/libtommath-0.41/bn_mp_init_set_int.c
lib/libtommath-0.41/bn_mp_init_size.c
lib/libtommath-0.41/bn_mp_invmod.c
lib/libtommath-0.41/bn_mp_invmod_slow.c
lib/libtommath-0.41/bn_mp_is_square.c
lib/libtommath-0.41/bn_mp_jacobi.c
lib/libtommath-0.41/bn_mp_karatsuba_mul.c
lib/libtommath-0.41/bn_mp_karatsuba_sqr.c
lib/libtommath-0.41/bn_mp_lcm.c
lib/libtommath-0.41/bn_mp_lshd.c
lib/libtommath-0.41/bn_mp_mod.c
lib/libtommath-0.41/bn_mp_mod_2d.c
lib/libtommath-0.41/bn_mp_mod_d.c
lib/libtommath-0.41/bn_mp_montgomery_calc_normalization.c
lib/libtommath-0.41/bn_mp_montgomery_reduce.c
lib/libtommath-0.41/bn_mp_montgomery_setup.c
lib/libtommath-0.41/bn_mp_mul.c
lib/libtommath-0.41/bn_mp_mul_2.c
lib/libtommath-0.41/bn_mp_mul_2d.c
lib/libtommath-0.41/bn_mp_mul_d.c
lib/libtommath-0.41/bn_mp_mulmod.c
lib/libtommath-0.41/bn_mp_n_root.c
lib/libtommath-0.41/bn_mp_neg.c
lib/libtommath-0.41/bn_mp_or.c
lib/libtommath-0.41/bn_mp_prime_fermat.c
lib/libtommath-0.41/bn_mp_prime_is_divisible.c
lib/libtommath-0.41/bn_mp_prime_is_prime.c
lib/libtommath-0.41/bn_mp_prime_miller_rabin.c
lib/libtommath-0.41/bn_mp_prime_next_prime.c
lib/libtommath-0.41/bn_mp_prime_rabin_miller_trials.c
lib/libtommath-0.41/bn_mp_prime_random_ex.c
lib/libtommath-0.41/bn_mp_radix_size.c
lib/libtommath-0.41/bn_mp_radix_smap.c
lib/libtommath-0.41/bn_mp_rand.c
lib/libtommath-0.41/bn_mp_read_radix.c
lib/libtommath-0.41/bn_mp_read_signed_bin.c
lib/libtommath-0.41/bn_mp_read_unsigned_bin.c
lib/libtommath-0.41/bn_mp_reduce.c
lib/libtommath-0.41/bn_mp_reduce_2k.c
lib/libtommath-0.41/bn_mp_reduce_2k_l.c
lib/libtommath-0.41/bn_mp_reduce_2k_setup.c
lib/libtommath-0.41/bn_mp_reduce_2k_setup_l.c
lib/libtommath-0.41/bn_mp_reduce_is_2k.c
lib/libtommath-0.41/bn_mp_reduce_is_2k_l.c
lib/libtommath-0.41/bn_mp_reduce_setup.c
lib/libtommath-0.41/bn_mp_rshd.c
lib/libtommath-0.41/bn_mp_set.c
lib/libtommath-0.41/bn_mp_set_int.c
lib/libtommath-0.41/bn_mp_shrink.c
lib/libtommath-0.41/bn_mp_signed_bin_size.c
lib/libtommath-0.41/bn_mp_sqr.c
lib/libtommath-0.41/bn_mp_sqrmod.c
lib/libtommath-0.41/bn_mp_sqrt.c
lib/libtommath-0.41/bn_mp_sub.c
lib/libtommath-0.41/bn_mp_sub_d.c
lib/libtommath-0.41/bn_mp_submod.c
lib/libtommath-0.41/bn_mp_to_signed_bin.c
lib/libtommath-0.41/bn_mp_to_signed_bin_n.c
lib/libtommath-0.41/bn_mp_to_unsigned_bin.c
lib/libtommath-0.41/bn_mp_to_unsigned_bin_n.c
lib/libtommath-0.41/bn_mp_toom_mul.c
lib/libtommath-0.41/bn_mp_toom_sqr.c
lib/libtommath-0.41/bn_mp_toradix.c
lib/libtommath-0.41/bn_mp_toradix_n.c
lib/libtommath-0.41/bn_mp_unsigned_bin_size.c
lib/libtommath-0.41/bn_mp_xor.c
lib/libtommath-0.41/bn_mp_zero.c
lib/libtommath-0.41/bn_prime_tab.c
lib/libtommath-0.41/bn_reverse.c
lib/libtommath-0.41/bn_s_mp_add.c
lib/libtommath-0.41/bn_s_mp_exptmod.c
lib/libtommath-0.41/bn_s_mp_mul_digs.c
lib/libtommath-0.41/bn_s_mp_mul_high_digs.c
lib/libtommath-0.41/bn_s_mp_sqr.c
lib/libtommath-0.41/bn_s_mp_sub.c
lib/libtommath-0.41/bncore.c
# lib/libtommath-0.41/demo/demo.c
# lib/libtommath-0.41/demo/timing.c
# lib/libtommath-0.41/etc/2kprime.c
# lib/libtommath-0.41/etc/drprime.c
# lib/libtommath-0.41/etc/mersenne.c
# lib/libtommath-0.41/etc/mont.c
# lib/libtommath-0.41/etc/pprime.c
# lib/libtommath-0.41/etc/tune.c
# lib/libtommath-0.41/mtest/mpi.c
# lib/libtommath-0.41/mtest/mtest.c
# lib/libtommath-0.41/pre_gen/mpi.c


'''.strip().splitlines()}

for name, sources in ext_sources.items():
	ext_sources[name] = [x.strip() for x in sources if x.strip() and not x.lstrip().startswith('#')]

# print '\n'.join(sources)

# Define the extensions
ext_modules = [Extension(
    'tomcrypt.%s' % name, ["tomcrypt/%s.c" % name] + ext_sources.get(name, []),
    include_dirs=[
                '.', # Buh?
                './src',
                './lib/libtomcrypt-1.17/src/headers',
                './lib/libtommath-0.41',
    ],
    define_macros=list(dict(
    
        # These macros are needed for the math library.
        LTM_DESC=None,
        LTC_SOURCE=None,
        # TFM_NO_ASM=None,
    
    ).items()),
) for name in ext_names]


# Go!
if __name__ == '__main__':
    setup(

        name='PyTomCrypt',
            description='Python+Cython wrapper around LibTomCrypt',
            version='0.6.1',
            license='BSD-3',
            platforms=['any'],
            packages=['tomcrypt'],
            
            author='Mike Boers',
            author_email='pytomcrypt@mikeboers.com',
            maintainer='Mike Boers',
            maintainer_email='pytomcrypt@mikeboers.com',
            url='http://github.com/mikeboers/PyTomCrypt',
            

            classifiers = [
                'Development Status :: 4 - Beta',
                'Intended Audience :: Developers',
                'License :: OSI Approved :: BSD License',
                'Natural Language :: English',
                'Operating System :: OS Independent',
                'Programming Language :: C',
                'Programming Language :: Python :: 2',
                'Programming Language :: Python :: 3',
                'Topic :: Security :: Cryptography',
                'Topic :: Software Development :: Libraries :: Python Modules',
            ],

        ext_modules=ext_modules,
    )
