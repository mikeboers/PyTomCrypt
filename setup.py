import os
import datetime

from distutils.core import setup
from distutils.extension import Extension
# from Cython.Distutils import build_ext


# Allow us to specify a single extension to build.
ext_names = ['_main']
ext_name = os.environ.get('PyTomCrypt_ext_name')
if ext_name:
    if ext_name not in ext_names:
        raise ValueError('unknown extension %r' % ext_name)
    ext_names = [ext_name]


sources = '''

### LIBTOMCRYPT
# src/libtomcrypt-1.16/demos/encrypt.c
# src/libtomcrypt-1.16/demos/hashsum.c
# src/libtomcrypt-1.16/demos/multi.c
# src/libtomcrypt-1.16/demos/small.c
# src/libtomcrypt-1.16/demos/test.c
# src/libtomcrypt-1.16/demos/timing.c
# src/libtomcrypt-1.16/demos/tv_gen.c
# src/libtomcrypt-1.16/notes/etc/saferp_optimizer.c
# src/libtomcrypt-1.16/notes/etc/whirlgen.c
# src/libtomcrypt-1.16/notes/etc/whirltest.c
src/libtomcrypt-1.16/src/ciphers/aes/aes.c
# src/libtomcrypt-1.16/src/ciphers/aes/aes_tab.c
src/libtomcrypt-1.16/src/ciphers/anubis.c
src/libtomcrypt-1.16/src/ciphers/blowfish.c
src/libtomcrypt-1.16/src/ciphers/cast5.c
src/libtomcrypt-1.16/src/ciphers/des.c
src/libtomcrypt-1.16/src/ciphers/kasumi.c
src/libtomcrypt-1.16/src/ciphers/khazad.c
src/libtomcrypt-1.16/src/ciphers/kseed.c
src/libtomcrypt-1.16/src/ciphers/noekeon.c
src/libtomcrypt-1.16/src/ciphers/rc2.c
src/libtomcrypt-1.16/src/ciphers/rc5.c
src/libtomcrypt-1.16/src/ciphers/rc6.c
src/libtomcrypt-1.16/src/ciphers/safer/safer.c
src/libtomcrypt-1.16/src/ciphers/safer/safer_tab.c
src/libtomcrypt-1.16/src/ciphers/safer/saferp.c
src/libtomcrypt-1.16/src/ciphers/skipjack.c
src/libtomcrypt-1.16/src/ciphers/twofish/twofish.c
src/libtomcrypt-1.16/src/ciphers/twofish/twofish_tab.c
src/libtomcrypt-1.16/src/ciphers/xtea.c
src/libtomcrypt-1.16/src/encauth/ccm/ccm_memory.c
src/libtomcrypt-1.16/src/encauth/ccm/ccm_test.c
src/libtomcrypt-1.16/src/encauth/eax/eax_addheader.c
src/libtomcrypt-1.16/src/encauth/eax/eax_decrypt.c
src/libtomcrypt-1.16/src/encauth/eax/eax_decrypt_verify_memory.c
src/libtomcrypt-1.16/src/encauth/eax/eax_done.c
src/libtomcrypt-1.16/src/encauth/eax/eax_encrypt.c
src/libtomcrypt-1.16/src/encauth/eax/eax_encrypt_authenticate_memory.c
src/libtomcrypt-1.16/src/encauth/eax/eax_init.c
src/libtomcrypt-1.16/src/encauth/eax/eax_test.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_add_aad.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_add_iv.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_done.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_gf_mult.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_init.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_memory.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_mult_h.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_process.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_reset.c
src/libtomcrypt-1.16/src/encauth/gcm/gcm_test.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_decrypt.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_decrypt_verify_memory.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_done_decrypt.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_done_encrypt.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_encrypt.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_encrypt_authenticate_memory.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_init.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_ntz.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_shift_xor.c
src/libtomcrypt-1.16/src/encauth/ocb/ocb_test.c
src/libtomcrypt-1.16/src/encauth/ocb/s_ocb_done.c
src/libtomcrypt-1.16/src/hashes/chc/chc.c
src/libtomcrypt-1.16/src/hashes/helper/hash_file.c
src/libtomcrypt-1.16/src/hashes/helper/hash_filehandle.c
src/libtomcrypt-1.16/src/hashes/helper/hash_memory.c
src/libtomcrypt-1.16/src/hashes/helper/hash_memory_multi.c
src/libtomcrypt-1.16/src/hashes/md2.c
src/libtomcrypt-1.16/src/hashes/md4.c
src/libtomcrypt-1.16/src/hashes/md5.c
src/libtomcrypt-1.16/src/hashes/rmd128.c
src/libtomcrypt-1.16/src/hashes/rmd160.c
src/libtomcrypt-1.16/src/hashes/rmd256.c
src/libtomcrypt-1.16/src/hashes/rmd320.c
src/libtomcrypt-1.16/src/hashes/sha1.c
# src/libtomcrypt-1.16/src/hashes/sha2/sha224.c
src/libtomcrypt-1.16/src/hashes/sha2/sha256.c
# src/libtomcrypt-1.16/src/hashes/sha2/sha384.c
src/libtomcrypt-1.16/src/hashes/sha2/sha512.c
src/libtomcrypt-1.16/src/hashes/tiger.c
src/libtomcrypt-1.16/src/hashes/whirl/whirl.c
# src/libtomcrypt-1.16/src/hashes/whirl/whirltab.c
src/libtomcrypt-1.16/src/mac/f9/f9_done.c
src/libtomcrypt-1.16/src/mac/f9/f9_file.c
src/libtomcrypt-1.16/src/mac/f9/f9_init.c
src/libtomcrypt-1.16/src/mac/f9/f9_memory.c
src/libtomcrypt-1.16/src/mac/f9/f9_memory_multi.c
src/libtomcrypt-1.16/src/mac/f9/f9_process.c
src/libtomcrypt-1.16/src/mac/f9/f9_test.c
src/libtomcrypt-1.16/src/mac/hmac/hmac_done.c
src/libtomcrypt-1.16/src/mac/hmac/hmac_file.c
src/libtomcrypt-1.16/src/mac/hmac/hmac_init.c
src/libtomcrypt-1.16/src/mac/hmac/hmac_memory.c
src/libtomcrypt-1.16/src/mac/hmac/hmac_memory_multi.c
src/libtomcrypt-1.16/src/mac/hmac/hmac_process.c
src/libtomcrypt-1.16/src/mac/hmac/hmac_test.c
src/libtomcrypt-1.16/src/mac/omac/omac_done.c
src/libtomcrypt-1.16/src/mac/omac/omac_file.c
src/libtomcrypt-1.16/src/mac/omac/omac_init.c
src/libtomcrypt-1.16/src/mac/omac/omac_memory.c
src/libtomcrypt-1.16/src/mac/omac/omac_memory_multi.c
src/libtomcrypt-1.16/src/mac/omac/omac_process.c
src/libtomcrypt-1.16/src/mac/omac/omac_test.c
src/libtomcrypt-1.16/src/mac/pelican/pelican.c
src/libtomcrypt-1.16/src/mac/pelican/pelican_memory.c
src/libtomcrypt-1.16/src/mac/pelican/pelican_test.c
src/libtomcrypt-1.16/src/mac/pmac/pmac_done.c
src/libtomcrypt-1.16/src/mac/pmac/pmac_file.c
src/libtomcrypt-1.16/src/mac/pmac/pmac_init.c
src/libtomcrypt-1.16/src/mac/pmac/pmac_memory.c
src/libtomcrypt-1.16/src/mac/pmac/pmac_memory_multi.c
src/libtomcrypt-1.16/src/mac/pmac/pmac_ntz.c
src/libtomcrypt-1.16/src/mac/pmac/pmac_process.c
src/libtomcrypt-1.16/src/mac/pmac/pmac_shift_xor.c
src/libtomcrypt-1.16/src/mac/pmac/pmac_test.c
src/libtomcrypt-1.16/src/mac/xcbc/xcbc_done.c
src/libtomcrypt-1.16/src/mac/xcbc/xcbc_file.c
src/libtomcrypt-1.16/src/mac/xcbc/xcbc_init.c
src/libtomcrypt-1.16/src/mac/xcbc/xcbc_memory.c
src/libtomcrypt-1.16/src/mac/xcbc/xcbc_memory_multi.c
src/libtomcrypt-1.16/src/mac/xcbc/xcbc_process.c
src/libtomcrypt-1.16/src/mac/xcbc/xcbc_test.c
src/libtomcrypt-1.16/src/math/fp/ltc_ecc_fp_mulmod.c
# src/libtomcrypt-1.16/src/math/gmp_desc.c
# src/libtomcrypt-1.16/src/math/ltm_desc.c
src/libtomcrypt-1.16/src/math/multi.c
src/libtomcrypt-1.16/src/math/rand_prime.c
src/libtomcrypt-1.16/src/math/tfm_desc.c
src/libtomcrypt-1.16/src/misc/base64/base64_decode.c
src/libtomcrypt-1.16/src/misc/base64/base64_encode.c
src/libtomcrypt-1.16/src/misc/burn_stack.c
src/libtomcrypt-1.16/src/misc/crypt/crypt.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_argchk.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_cipher_descriptor.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_cipher_is_valid.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_find_cipher.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_find_cipher_any.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_find_cipher_id.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_find_hash.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_find_hash_any.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_find_hash_id.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_find_hash_oid.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_find_prng.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_fsa.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_hash_descriptor.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_hash_is_valid.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_ltc_mp_descriptor.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_prng_descriptor.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_prng_is_valid.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_register_cipher.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_register_hash.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_register_prng.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_unregister_cipher.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_unregister_hash.c
src/libtomcrypt-1.16/src/misc/crypt/crypt_unregister_prng.c
src/libtomcrypt-1.16/src/misc/error_to_string.c
src/libtomcrypt-1.16/src/misc/pkcs5/pkcs_5_1.c
src/libtomcrypt-1.16/src/misc/pkcs5/pkcs_5_2.c
src/libtomcrypt-1.16/src/misc/zeromem.c
src/libtomcrypt-1.16/src/modes/cbc/cbc_decrypt.c
src/libtomcrypt-1.16/src/modes/cbc/cbc_done.c
src/libtomcrypt-1.16/src/modes/cbc/cbc_encrypt.c
src/libtomcrypt-1.16/src/modes/cbc/cbc_getiv.c
src/libtomcrypt-1.16/src/modes/cbc/cbc_setiv.c
src/libtomcrypt-1.16/src/modes/cbc/cbc_start.c
src/libtomcrypt-1.16/src/modes/cfb/cfb_decrypt.c
src/libtomcrypt-1.16/src/modes/cfb/cfb_done.c
src/libtomcrypt-1.16/src/modes/cfb/cfb_encrypt.c
src/libtomcrypt-1.16/src/modes/cfb/cfb_getiv.c
src/libtomcrypt-1.16/src/modes/cfb/cfb_setiv.c
src/libtomcrypt-1.16/src/modes/cfb/cfb_start.c
src/libtomcrypt-1.16/src/modes/ctr/ctr_decrypt.c
src/libtomcrypt-1.16/src/modes/ctr/ctr_done.c
src/libtomcrypt-1.16/src/modes/ctr/ctr_encrypt.c
src/libtomcrypt-1.16/src/modes/ctr/ctr_getiv.c
src/libtomcrypt-1.16/src/modes/ctr/ctr_setiv.c
src/libtomcrypt-1.16/src/modes/ctr/ctr_start.c
src/libtomcrypt-1.16/src/modes/ctr/ctr_test.c
src/libtomcrypt-1.16/src/modes/ecb/ecb_decrypt.c
src/libtomcrypt-1.16/src/modes/ecb/ecb_done.c
src/libtomcrypt-1.16/src/modes/ecb/ecb_encrypt.c
src/libtomcrypt-1.16/src/modes/ecb/ecb_start.c
src/libtomcrypt-1.16/src/modes/f8/f8_decrypt.c
src/libtomcrypt-1.16/src/modes/f8/f8_done.c
src/libtomcrypt-1.16/src/modes/f8/f8_encrypt.c
src/libtomcrypt-1.16/src/modes/f8/f8_getiv.c
src/libtomcrypt-1.16/src/modes/f8/f8_setiv.c
src/libtomcrypt-1.16/src/modes/f8/f8_start.c
src/libtomcrypt-1.16/src/modes/f8/f8_test_mode.c
src/libtomcrypt-1.16/src/modes/lrw/lrw_decrypt.c
src/libtomcrypt-1.16/src/modes/lrw/lrw_done.c
src/libtomcrypt-1.16/src/modes/lrw/lrw_encrypt.c
src/libtomcrypt-1.16/src/modes/lrw/lrw_getiv.c
src/libtomcrypt-1.16/src/modes/lrw/lrw_process.c
src/libtomcrypt-1.16/src/modes/lrw/lrw_setiv.c
src/libtomcrypt-1.16/src/modes/lrw/lrw_start.c
src/libtomcrypt-1.16/src/modes/lrw/lrw_test.c
src/libtomcrypt-1.16/src/modes/ofb/ofb_decrypt.c
src/libtomcrypt-1.16/src/modes/ofb/ofb_done.c
src/libtomcrypt-1.16/src/modes/ofb/ofb_encrypt.c
src/libtomcrypt-1.16/src/modes/ofb/ofb_getiv.c
src/libtomcrypt-1.16/src/modes/ofb/ofb_setiv.c
src/libtomcrypt-1.16/src/modes/ofb/ofb_start.c
src/libtomcrypt-1.16/src/pk/asn1/der/bit/der_decode_bit_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/bit/der_encode_bit_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/bit/der_length_bit_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/boolean/der_decode_boolean.c
src/libtomcrypt-1.16/src/pk/asn1/der/boolean/der_encode_boolean.c
src/libtomcrypt-1.16/src/pk/asn1/der/boolean/der_length_boolean.c
src/libtomcrypt-1.16/src/pk/asn1/der/choice/der_decode_choice.c
src/libtomcrypt-1.16/src/pk/asn1/der/ia5/der_decode_ia5_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/ia5/der_encode_ia5_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/ia5/der_length_ia5_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/integer/der_decode_integer.c
src/libtomcrypt-1.16/src/pk/asn1/der/integer/der_encode_integer.c
src/libtomcrypt-1.16/src/pk/asn1/der/integer/der_length_integer.c
src/libtomcrypt-1.16/src/pk/asn1/der/object_identifier/der_decode_object_identifier.c
src/libtomcrypt-1.16/src/pk/asn1/der/object_identifier/der_encode_object_identifier.c
src/libtomcrypt-1.16/src/pk/asn1/der/object_identifier/der_length_object_identifier.c
src/libtomcrypt-1.16/src/pk/asn1/der/octet/der_decode_octet_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/octet/der_encode_octet_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/octet/der_length_octet_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/printable_string/der_decode_printable_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/printable_string/der_encode_printable_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/printable_string/der_length_printable_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/sequence/der_decode_sequence_ex.c
src/libtomcrypt-1.16/src/pk/asn1/der/sequence/der_decode_sequence_flexi.c
src/libtomcrypt-1.16/src/pk/asn1/der/sequence/der_decode_sequence_multi.c
src/libtomcrypt-1.16/src/pk/asn1/der/sequence/der_encode_sequence_ex.c
src/libtomcrypt-1.16/src/pk/asn1/der/sequence/der_encode_sequence_multi.c
src/libtomcrypt-1.16/src/pk/asn1/der/sequence/der_length_sequence.c
src/libtomcrypt-1.16/src/pk/asn1/der/sequence/der_sequence_free.c
src/libtomcrypt-1.16/src/pk/asn1/der/set/der_encode_set.c
src/libtomcrypt-1.16/src/pk/asn1/der/set/der_encode_setof.c
src/libtomcrypt-1.16/src/pk/asn1/der/short_integer/der_decode_short_integer.c
src/libtomcrypt-1.16/src/pk/asn1/der/short_integer/der_encode_short_integer.c
src/libtomcrypt-1.16/src/pk/asn1/der/short_integer/der_length_short_integer.c
src/libtomcrypt-1.16/src/pk/asn1/der/utctime/der_decode_utctime.c
src/libtomcrypt-1.16/src/pk/asn1/der/utctime/der_encode_utctime.c
src/libtomcrypt-1.16/src/pk/asn1/der/utctime/der_length_utctime.c
src/libtomcrypt-1.16/src/pk/asn1/der/utf8/der_decode_utf8_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/utf8/der_encode_utf8_string.c
src/libtomcrypt-1.16/src/pk/asn1/der/utf8/der_length_utf8_string.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_decrypt_key.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_encrypt_key.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_export.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_free.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_import.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_make_key.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_shared_secret.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_sign_hash.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_verify_hash.c
src/libtomcrypt-1.16/src/pk/dsa/dsa_verify_key.c
src/libtomcrypt-1.16/src/pk/ecc/ecc.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_ansi_x963_export.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_ansi_x963_import.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_decrypt_key.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_encrypt_key.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_export.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_free.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_get_size.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_import.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_make_key.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_shared_secret.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_sign_hash.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_sizes.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_test.c
src/libtomcrypt-1.16/src/pk/ecc/ecc_verify_hash.c
src/libtomcrypt-1.16/src/pk/ecc/ltc_ecc_is_valid_idx.c
src/libtomcrypt-1.16/src/pk/ecc/ltc_ecc_map.c
src/libtomcrypt-1.16/src/pk/ecc/ltc_ecc_mul2add.c
src/libtomcrypt-1.16/src/pk/ecc/ltc_ecc_mulmod.c
src/libtomcrypt-1.16/src/pk/ecc/ltc_ecc_mulmod_timing.c
src/libtomcrypt-1.16/src/pk/ecc/ltc_ecc_points.c
src/libtomcrypt-1.16/src/pk/ecc/ltc_ecc_projective_add_point.c
src/libtomcrypt-1.16/src/pk/ecc/ltc_ecc_projective_dbl_point.c
src/libtomcrypt-1.16/src/pk/katja/katja_decrypt_key.c
src/libtomcrypt-1.16/src/pk/katja/katja_encrypt_key.c
src/libtomcrypt-1.16/src/pk/katja/katja_export.c
src/libtomcrypt-1.16/src/pk/katja/katja_exptmod.c
src/libtomcrypt-1.16/src/pk/katja/katja_free.c
src/libtomcrypt-1.16/src/pk/katja/katja_import.c
src/libtomcrypt-1.16/src/pk/katja/katja_make_key.c
src/libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_i2osp.c
src/libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_mgf1.c
src/libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_oaep_decode.c
src/libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_oaep_encode.c
src/libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_os2ip.c
src/libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_pss_decode.c
src/libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_pss_encode.c
src/libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_v1_5_decode.c
src/libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_v1_5_encode.c
src/libtomcrypt-1.16/src/pk/rsa/rsa_decrypt_key.c
src/libtomcrypt-1.16/src/pk/rsa/rsa_encrypt_key.c
src/libtomcrypt-1.16/src/pk/rsa/rsa_export.c
src/libtomcrypt-1.16/src/pk/rsa/rsa_exptmod.c
src/libtomcrypt-1.16/src/pk/rsa/rsa_free.c
src/libtomcrypt-1.16/src/pk/rsa/rsa_import.c
src/libtomcrypt-1.16/src/pk/rsa/rsa_make_key.c
src/libtomcrypt-1.16/src/pk/rsa/rsa_sign_hash.c
src/libtomcrypt-1.16/src/pk/rsa/rsa_verify_hash.c
src/libtomcrypt-1.16/src/prngs/fortuna.c
src/libtomcrypt-1.16/src/prngs/rc4.c
src/libtomcrypt-1.16/src/prngs/rng_get_bytes.c
src/libtomcrypt-1.16/src/prngs/rng_make_prng.c
src/libtomcrypt-1.16/src/prngs/sober128.c
# src/libtomcrypt-1.16/src/prngs/sober128tab.c
src/libtomcrypt-1.16/src/prngs/sprng.c
src/libtomcrypt-1.16/src/prngs/yarrow.c
# src/libtomcrypt-1.16/testprof/base64_test.c
# src/libtomcrypt-1.16/testprof/cipher_hash_test.c
# src/libtomcrypt-1.16/testprof/der_tests.c
# src/libtomcrypt-1.16/testprof/dsa_test.c
# src/libtomcrypt-1.16/testprof/ecc_test.c
# src/libtomcrypt-1.16/testprof/katja_test.c
# src/libtomcrypt-1.16/testprof/mac_test.c
# src/libtomcrypt-1.16/testprof/modes_test.c
# src/libtomcrypt-1.16/testprof/pkcs_1_test.c
# src/libtomcrypt-1.16/testprof/rsa_test.c
# src/libtomcrypt-1.16/testprof/store_test.c
# src/libtomcrypt-1.16/testprof/test_driver.c
# src/libtomcrypt-1.16/testprof/x86_prof.c


### TOMSFASTMATH
# src/tomsfastmath-0.10/comba_mont_gen.c
# src/tomsfastmath-0.10/comba_mult_gen.c
# src/tomsfastmath-0.10/comba_mult_smallgen.c
# src/tomsfastmath-0.10/comba_sqr_gen.c
# src/tomsfastmath-0.10/comba_sqr_smallgen.c
# src/tomsfastmath-0.10/demo/rsa.c
# src/tomsfastmath-0.10/demo/stest.c
# src/tomsfastmath-0.10/demo/test.c
src/tomsfastmath-0.10/fp_2expt.c
src/tomsfastmath-0.10/fp_add.c
src/tomsfastmath-0.10/fp_add_d.c
src/tomsfastmath-0.10/fp_addmod.c
src/tomsfastmath-0.10/fp_cmp.c
src/tomsfastmath-0.10/fp_cmp_d.c
src/tomsfastmath-0.10/fp_cmp_mag.c
src/tomsfastmath-0.10/fp_cnt_lsb.c
src/tomsfastmath-0.10/fp_count_bits.c
src/tomsfastmath-0.10/fp_div.c
src/tomsfastmath-0.10/fp_div_2.c
src/tomsfastmath-0.10/fp_div_2d.c
src/tomsfastmath-0.10/fp_div_d.c
src/tomsfastmath-0.10/fp_exptmod.c
src/tomsfastmath-0.10/fp_gcd.c
src/tomsfastmath-0.10/fp_ident.c
src/tomsfastmath-0.10/fp_invmod.c
src/tomsfastmath-0.10/fp_isprime.c
src/tomsfastmath-0.10/fp_lcm.c
src/tomsfastmath-0.10/fp_lshd.c
src/tomsfastmath-0.10/fp_mod.c
src/tomsfastmath-0.10/fp_mod_2d.c
src/tomsfastmath-0.10/fp_mod_d.c
src/tomsfastmath-0.10/fp_mont_small.c
src/tomsfastmath-0.10/fp_montgomery_calc_normalization.c
src/tomsfastmath-0.10/fp_montgomery_reduce.c
src/tomsfastmath-0.10/fp_montgomery_setup.c
src/tomsfastmath-0.10/fp_mul.c
src/tomsfastmath-0.10/fp_mul_2.c
src/tomsfastmath-0.10/fp_mul_2d.c
src/tomsfastmath-0.10/fp_mul_comba.c
src/tomsfastmath-0.10/fp_mul_d.c
src/tomsfastmath-0.10/fp_mulmod.c
src/tomsfastmath-0.10/fp_prime_miller_rabin.c
src/tomsfastmath-0.10/fp_prime_random_ex.c
src/tomsfastmath-0.10/fp_radix_size.c
src/tomsfastmath-0.10/fp_read_radix.c
src/tomsfastmath-0.10/fp_read_signed_bin.c
src/tomsfastmath-0.10/fp_read_unsigned_bin.c
src/tomsfastmath-0.10/fp_reverse.c
src/tomsfastmath-0.10/fp_rshd.c
src/tomsfastmath-0.10/fp_s_rmap.c
src/tomsfastmath-0.10/fp_set.c
src/tomsfastmath-0.10/fp_signed_bin_size.c
src/tomsfastmath-0.10/fp_sqr.c
src/tomsfastmath-0.10/fp_sqr_comba.c
# src/tomsfastmath-0.10/fp_sqr_comba_generic.c
src/tomsfastmath-0.10/fp_sqrmod.c
src/tomsfastmath-0.10/fp_sub.c
src/tomsfastmath-0.10/fp_sub_d.c
src/tomsfastmath-0.10/fp_submod.c
src/tomsfastmath-0.10/fp_to_signed_bin.c
src/tomsfastmath-0.10/fp_to_unsigned_bin.c
src/tomsfastmath-0.10/fp_toradix.c
src/tomsfastmath-0.10/fp_unsigned_bin_size.c
# src/tomsfastmath-0.10/mtest/mtest.c
# src/tomsfastmath-0.10/pre_gen/mpi.c
src/tomsfastmath-0.10/s_fp_add.c
src/tomsfastmath-0.10/s_fp_sub.c


### CUSTOM
src/aes_enc.c

'''.strip().splitlines()

sources = [x.strip() for x in sources if x.strip() and not x.lstrip().startswith('#')]

# print '\n'.join(sources)

# Define the extensions
ext_modules = [Extension(
    'tomcrypt.%s' % name, ["src/%s.c" % name] + sources,
    include_dirs=[
                './src',
                './src/libtomcrypt-1.16/src/headers',
                './src/tomsfastmath-0.10',
    ],
    define_macros=dict(
    
        # These two macros are needed for the math library.
        TFM_DESC=None,
        LTC_SOURCE=None,
    
    ).items(),
) for name in ext_names]


# Go!
if __name__ == '__main__':
    setup(

        name='PyTomCrypt',
            description='Python+Cython wrapper around LibTomCrypt',
            # version='1.0a.dev%s' % datetime.datetime.utcnow().strftime('%Y%m%dT%H%M'),
            version='0.5a',
            license='New BSD',
            platforms=['any'],
            author='Mike Boers',
            author_email='pytomcrypt@mikeboers.com',
            maintainer='Mike Boers',
            maintainer_email='pytomcrypt@mikeboers.com',
            packages=['tomcrypt'],
    url='http://github.com/mikeboers/PyTomCrypt',

            classifiers = [
                'Development Status :: 3 - Alpha',
                'Intended Audience :: Developers',
                'Operating System :: OS Independent',
                'Programming Language :: C',
                'Programming Language :: Python',
                'Topic :: Security :: Cryptography',
                'Topic :: Software Development :: Libraries :: Python Modules',
            ],

        # cmdclass = {'build_ext': build_ext},
        ext_modules=ext_modules,
    )
