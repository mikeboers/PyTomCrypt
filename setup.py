import os
import datetime

from distutils.core import setup
from distutils.extension import Extension
# from Cython.Distutils import build_ext


# Allow us to specify a single extension to build.
ext_names = ['_core', 'cipher', 'hash', 'mac', 'prng', 'rsa', 'pkcs1', 'pkcs5']
ext_name = os.environ.get('PyTomCrypt_ext_name')
if ext_name:
    if ext_name not in ext_names:
        raise ValueError('unknown extension %r' % ext_name)
    ext_names = [ext_name]

ext_sources = {'_core': '''

### LIBTOMCRYPT
# src/libtomcrypt-1.17/demos/encrypt.c
# src/libtomcrypt-1.17/demos/hashsum.c
# src/libtomcrypt-1.17/demos/multi.c
# src/libtomcrypt-1.17/demos/small.c
# src/libtomcrypt-1.17/demos/test.c
# src/libtomcrypt-1.17/demos/timing.c
# src/libtomcrypt-1.17/demos/tv_gen.c
# src/libtomcrypt-1.17/notes/etc/saferp_optimizer.c
# src/libtomcrypt-1.17/notes/etc/whirlgen.c
# src/libtomcrypt-1.17/notes/etc/whirltest.c
src/libtomcrypt-1.17/src/ciphers/aes/aes.c
# src/libtomcrypt-1.17/src/ciphers/aes/aes_tab.c
src/libtomcrypt-1.17/src/ciphers/anubis.c
src/libtomcrypt-1.17/src/ciphers/blowfish.c
src/libtomcrypt-1.17/src/ciphers/cast5.c
src/libtomcrypt-1.17/src/ciphers/des.c
src/libtomcrypt-1.17/src/ciphers/kasumi.c
src/libtomcrypt-1.17/src/ciphers/khazad.c
src/libtomcrypt-1.17/src/ciphers/kseed.c
src/libtomcrypt-1.17/src/ciphers/noekeon.c
src/libtomcrypt-1.17/src/ciphers/rc2.c
src/libtomcrypt-1.17/src/ciphers/rc5.c
src/libtomcrypt-1.17/src/ciphers/rc6.c
src/libtomcrypt-1.17/src/ciphers/safer/safer.c
src/libtomcrypt-1.17/src/ciphers/safer/safer_tab.c
src/libtomcrypt-1.17/src/ciphers/safer/saferp.c
src/libtomcrypt-1.17/src/ciphers/skipjack.c
src/libtomcrypt-1.17/src/ciphers/twofish/twofish.c
src/libtomcrypt-1.17/src/ciphers/twofish/twofish_tab.c
src/libtomcrypt-1.17/src/ciphers/xtea.c
src/libtomcrypt-1.17/src/encauth/ccm/ccm_memory.c
src/libtomcrypt-1.17/src/encauth/ccm/ccm_test.c
src/libtomcrypt-1.17/src/encauth/eax/eax_addheader.c
src/libtomcrypt-1.17/src/encauth/eax/eax_decrypt.c
src/libtomcrypt-1.17/src/encauth/eax/eax_decrypt_verify_memory.c
src/libtomcrypt-1.17/src/encauth/eax/eax_done.c
src/libtomcrypt-1.17/src/encauth/eax/eax_encrypt.c
src/libtomcrypt-1.17/src/encauth/eax/eax_encrypt_authenticate_memory.c
src/libtomcrypt-1.17/src/encauth/eax/eax_init.c
src/libtomcrypt-1.17/src/encauth/eax/eax_test.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_add_aad.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_add_iv.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_done.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_gf_mult.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_init.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_memory.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_mult_h.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_process.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_reset.c
src/libtomcrypt-1.17/src/encauth/gcm/gcm_test.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_decrypt.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_decrypt_verify_memory.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_done_decrypt.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_done_encrypt.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_encrypt.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_encrypt_authenticate_memory.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_init.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_ntz.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_shift_xor.c
src/libtomcrypt-1.17/src/encauth/ocb/ocb_test.c
src/libtomcrypt-1.17/src/encauth/ocb/s_ocb_done.c
src/libtomcrypt-1.17/src/hashes/chc/chc.c
src/libtomcrypt-1.17/src/hashes/helper/hash_file.c
src/libtomcrypt-1.17/src/hashes/helper/hash_filehandle.c
src/libtomcrypt-1.17/src/hashes/helper/hash_memory.c
src/libtomcrypt-1.17/src/hashes/helper/hash_memory_multi.c
src/libtomcrypt-1.17/src/hashes/md2.c
src/libtomcrypt-1.17/src/hashes/md4.c
src/libtomcrypt-1.17/src/hashes/md5.c
src/libtomcrypt-1.17/src/hashes/rmd128.c
src/libtomcrypt-1.17/src/hashes/rmd160.c
src/libtomcrypt-1.17/src/hashes/rmd256.c
src/libtomcrypt-1.17/src/hashes/rmd320.c
src/libtomcrypt-1.17/src/hashes/sha1.c
# src/libtomcrypt-1.17/src/hashes/sha2/sha224.c
src/libtomcrypt-1.17/src/hashes/sha2/sha256.c
# src/libtomcrypt-1.17/src/hashes/sha2/sha384.c
src/libtomcrypt-1.17/src/hashes/sha2/sha512.c
src/libtomcrypt-1.17/src/hashes/tiger.c
src/libtomcrypt-1.17/src/hashes/whirl/whirl.c
# src/libtomcrypt-1.17/src/hashes/whirl/whirltab.c
src/libtomcrypt-1.17/src/mac/f9/f9_done.c
src/libtomcrypt-1.17/src/mac/f9/f9_file.c
src/libtomcrypt-1.17/src/mac/f9/f9_init.c
src/libtomcrypt-1.17/src/mac/f9/f9_memory.c
src/libtomcrypt-1.17/src/mac/f9/f9_memory_multi.c
src/libtomcrypt-1.17/src/mac/f9/f9_process.c
src/libtomcrypt-1.17/src/mac/f9/f9_test.c
src/libtomcrypt-1.17/src/mac/hmac/hmac_done.c
src/libtomcrypt-1.17/src/mac/hmac/hmac_file.c
src/libtomcrypt-1.17/src/mac/hmac/hmac_init.c
src/libtomcrypt-1.17/src/mac/hmac/hmac_memory.c
src/libtomcrypt-1.17/src/mac/hmac/hmac_memory_multi.c
src/libtomcrypt-1.17/src/mac/hmac/hmac_process.c
src/libtomcrypt-1.17/src/mac/hmac/hmac_test.c
src/libtomcrypt-1.17/src/mac/omac/omac_done.c
src/libtomcrypt-1.17/src/mac/omac/omac_file.c
src/libtomcrypt-1.17/src/mac/omac/omac_init.c
src/libtomcrypt-1.17/src/mac/omac/omac_memory.c
src/libtomcrypt-1.17/src/mac/omac/omac_memory_multi.c
src/libtomcrypt-1.17/src/mac/omac/omac_process.c
src/libtomcrypt-1.17/src/mac/omac/omac_test.c
src/libtomcrypt-1.17/src/mac/pelican/pelican.c
src/libtomcrypt-1.17/src/mac/pelican/pelican_memory.c
src/libtomcrypt-1.17/src/mac/pelican/pelican_test.c
src/libtomcrypt-1.17/src/mac/pmac/pmac_done.c
src/libtomcrypt-1.17/src/mac/pmac/pmac_file.c
src/libtomcrypt-1.17/src/mac/pmac/pmac_init.c
src/libtomcrypt-1.17/src/mac/pmac/pmac_memory.c
src/libtomcrypt-1.17/src/mac/pmac/pmac_memory_multi.c
src/libtomcrypt-1.17/src/mac/pmac/pmac_ntz.c
src/libtomcrypt-1.17/src/mac/pmac/pmac_process.c
src/libtomcrypt-1.17/src/mac/pmac/pmac_shift_xor.c
src/libtomcrypt-1.17/src/mac/pmac/pmac_test.c
src/libtomcrypt-1.17/src/mac/xcbc/xcbc_done.c
src/libtomcrypt-1.17/src/mac/xcbc/xcbc_file.c
src/libtomcrypt-1.17/src/mac/xcbc/xcbc_init.c
src/libtomcrypt-1.17/src/mac/xcbc/xcbc_memory.c
src/libtomcrypt-1.17/src/mac/xcbc/xcbc_memory_multi.c
src/libtomcrypt-1.17/src/mac/xcbc/xcbc_process.c
src/libtomcrypt-1.17/src/mac/xcbc/xcbc_test.c
src/libtomcrypt-1.17/src/math/fp/ltc_ecc_fp_mulmod.c
# src/libtomcrypt-1.17/src/math/gmp_desc.c
src/libtomcrypt-1.17/src/math/ltm_desc.c
src/libtomcrypt-1.17/src/math/multi.c
src/libtomcrypt-1.17/src/math/rand_prime.c
src/libtomcrypt-1.17/src/math/tfm_desc.c
src/libtomcrypt-1.17/src/misc/base64/base64_decode.c
src/libtomcrypt-1.17/src/misc/base64/base64_encode.c
src/libtomcrypt-1.17/src/misc/burn_stack.c
src/libtomcrypt-1.17/src/misc/crypt/crypt.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_argchk.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_cipher_descriptor.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_cipher_is_valid.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_find_cipher.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_find_cipher_any.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_find_cipher_id.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_find_hash.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_find_hash_any.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_find_hash_id.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_find_hash_oid.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_find_prng.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_fsa.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_hash_descriptor.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_hash_is_valid.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_ltc_mp_descriptor.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_prng_descriptor.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_prng_is_valid.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_register_cipher.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_register_hash.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_register_prng.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_unregister_cipher.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_unregister_hash.c
src/libtomcrypt-1.17/src/misc/crypt/crypt_unregister_prng.c
src/libtomcrypt-1.17/src/misc/error_to_string.c
src/libtomcrypt-1.17/src/misc/pkcs5/pkcs_5_1.c
src/libtomcrypt-1.17/src/misc/pkcs5/pkcs_5_2.c
src/libtomcrypt-1.17/src/misc/zeromem.c
src/libtomcrypt-1.17/src/modes/cbc/cbc_decrypt.c
src/libtomcrypt-1.17/src/modes/cbc/cbc_done.c
src/libtomcrypt-1.17/src/modes/cbc/cbc_encrypt.c
src/libtomcrypt-1.17/src/modes/cbc/cbc_getiv.c
src/libtomcrypt-1.17/src/modes/cbc/cbc_setiv.c
src/libtomcrypt-1.17/src/modes/cbc/cbc_start.c
src/libtomcrypt-1.17/src/modes/cfb/cfb_decrypt.c
src/libtomcrypt-1.17/src/modes/cfb/cfb_done.c
src/libtomcrypt-1.17/src/modes/cfb/cfb_encrypt.c
src/libtomcrypt-1.17/src/modes/cfb/cfb_getiv.c
src/libtomcrypt-1.17/src/modes/cfb/cfb_setiv.c
src/libtomcrypt-1.17/src/modes/cfb/cfb_start.c
src/libtomcrypt-1.17/src/modes/ctr/ctr_decrypt.c
src/libtomcrypt-1.17/src/modes/ctr/ctr_done.c
src/libtomcrypt-1.17/src/modes/ctr/ctr_encrypt.c
src/libtomcrypt-1.17/src/modes/ctr/ctr_getiv.c
src/libtomcrypt-1.17/src/modes/ctr/ctr_setiv.c
src/libtomcrypt-1.17/src/modes/ctr/ctr_start.c
src/libtomcrypt-1.17/src/modes/ctr/ctr_test.c
src/libtomcrypt-1.17/src/modes/ecb/ecb_decrypt.c
src/libtomcrypt-1.17/src/modes/ecb/ecb_done.c
src/libtomcrypt-1.17/src/modes/ecb/ecb_encrypt.c
src/libtomcrypt-1.17/src/modes/ecb/ecb_start.c
src/libtomcrypt-1.17/src/modes/f8/f8_decrypt.c
src/libtomcrypt-1.17/src/modes/f8/f8_done.c
src/libtomcrypt-1.17/src/modes/f8/f8_encrypt.c
src/libtomcrypt-1.17/src/modes/f8/f8_getiv.c
src/libtomcrypt-1.17/src/modes/f8/f8_setiv.c
src/libtomcrypt-1.17/src/modes/f8/f8_start.c
src/libtomcrypt-1.17/src/modes/f8/f8_test_mode.c
src/libtomcrypt-1.17/src/modes/lrw/lrw_decrypt.c
src/libtomcrypt-1.17/src/modes/lrw/lrw_done.c
src/libtomcrypt-1.17/src/modes/lrw/lrw_encrypt.c
src/libtomcrypt-1.17/src/modes/lrw/lrw_getiv.c
src/libtomcrypt-1.17/src/modes/lrw/lrw_process.c
src/libtomcrypt-1.17/src/modes/lrw/lrw_setiv.c
src/libtomcrypt-1.17/src/modes/lrw/lrw_start.c
src/libtomcrypt-1.17/src/modes/lrw/lrw_test.c
src/libtomcrypt-1.17/src/modes/ofb/ofb_decrypt.c
src/libtomcrypt-1.17/src/modes/ofb/ofb_done.c
src/libtomcrypt-1.17/src/modes/ofb/ofb_encrypt.c
src/libtomcrypt-1.17/src/modes/ofb/ofb_getiv.c
src/libtomcrypt-1.17/src/modes/ofb/ofb_setiv.c
src/libtomcrypt-1.17/src/modes/ofb/ofb_start.c
src/libtomcrypt-1.17/src/pk/asn1/der/bit/der_decode_bit_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/bit/der_encode_bit_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/bit/der_length_bit_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/boolean/der_decode_boolean.c
src/libtomcrypt-1.17/src/pk/asn1/der/boolean/der_encode_boolean.c
src/libtomcrypt-1.17/src/pk/asn1/der/boolean/der_length_boolean.c
src/libtomcrypt-1.17/src/pk/asn1/der/choice/der_decode_choice.c
src/libtomcrypt-1.17/src/pk/asn1/der/ia5/der_decode_ia5_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/ia5/der_encode_ia5_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/ia5/der_length_ia5_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/integer/der_decode_integer.c
src/libtomcrypt-1.17/src/pk/asn1/der/integer/der_encode_integer.c
src/libtomcrypt-1.17/src/pk/asn1/der/integer/der_length_integer.c
src/libtomcrypt-1.17/src/pk/asn1/der/object_identifier/der_decode_object_identifier.c
src/libtomcrypt-1.17/src/pk/asn1/der/object_identifier/der_encode_object_identifier.c
src/libtomcrypt-1.17/src/pk/asn1/der/object_identifier/der_length_object_identifier.c
src/libtomcrypt-1.17/src/pk/asn1/der/octet/der_decode_octet_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/octet/der_encode_octet_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/octet/der_length_octet_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/printable_string/der_decode_printable_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/printable_string/der_encode_printable_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/printable_string/der_length_printable_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_decode_sequence_ex.c
src/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_decode_sequence_flexi.c
src/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_decode_sequence_multi.c
src/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_encode_sequence_ex.c
src/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_encode_sequence_multi.c
src/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_length_sequence.c
src/libtomcrypt-1.17/src/pk/asn1/der/sequence/der_sequence_free.c
src/libtomcrypt-1.17/src/pk/asn1/der/set/der_encode_set.c
src/libtomcrypt-1.17/src/pk/asn1/der/set/der_encode_setof.c
src/libtomcrypt-1.17/src/pk/asn1/der/short_integer/der_decode_short_integer.c
src/libtomcrypt-1.17/src/pk/asn1/der/short_integer/der_encode_short_integer.c
src/libtomcrypt-1.17/src/pk/asn1/der/short_integer/der_length_short_integer.c
src/libtomcrypt-1.17/src/pk/asn1/der/utctime/der_decode_utctime.c
src/libtomcrypt-1.17/src/pk/asn1/der/utctime/der_encode_utctime.c
src/libtomcrypt-1.17/src/pk/asn1/der/utctime/der_length_utctime.c
src/libtomcrypt-1.17/src/pk/asn1/der/utf8/der_decode_utf8_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/utf8/der_encode_utf8_string.c
src/libtomcrypt-1.17/src/pk/asn1/der/utf8/der_length_utf8_string.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_decrypt_key.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_encrypt_key.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_export.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_free.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_import.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_make_key.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_shared_secret.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_sign_hash.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_verify_hash.c
src/libtomcrypt-1.17/src/pk/dsa/dsa_verify_key.c
src/libtomcrypt-1.17/src/pk/ecc/ecc.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_ansi_x963_export.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_ansi_x963_import.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_decrypt_key.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_encrypt_key.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_export.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_free.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_get_size.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_import.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_make_key.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_shared_secret.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_sign_hash.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_sizes.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_test.c
src/libtomcrypt-1.17/src/pk/ecc/ecc_verify_hash.c
src/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_is_valid_idx.c
src/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_map.c
src/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_mul2add.c
src/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_mulmod.c
src/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_mulmod_timing.c
src/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_points.c
src/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_projective_add_point.c
src/libtomcrypt-1.17/src/pk/ecc/ltc_ecc_projective_dbl_point.c
src/libtomcrypt-1.17/src/pk/katja/katja_decrypt_key.c
src/libtomcrypt-1.17/src/pk/katja/katja_encrypt_key.c
src/libtomcrypt-1.17/src/pk/katja/katja_export.c
src/libtomcrypt-1.17/src/pk/katja/katja_exptmod.c
src/libtomcrypt-1.17/src/pk/katja/katja_free.c
src/libtomcrypt-1.17/src/pk/katja/katja_import.c
src/libtomcrypt-1.17/src/pk/katja/katja_make_key.c
src/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_i2osp.c
src/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_mgf1.c
src/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_oaep_decode.c
src/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_oaep_encode.c
src/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_os2ip.c
src/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_pss_decode.c
src/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_pss_encode.c
src/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_v1_5_decode.c
src/libtomcrypt-1.17/src/pk/pkcs1/pkcs_1_v1_5_encode.c
src/libtomcrypt-1.17/src/pk/rsa/rsa_decrypt_key.c
src/libtomcrypt-1.17/src/pk/rsa/rsa_encrypt_key.c
src/libtomcrypt-1.17/src/pk/rsa/rsa_export.c
src/libtomcrypt-1.17/src/pk/rsa/rsa_exptmod.c
src/libtomcrypt-1.17/src/pk/rsa/rsa_free.c
src/libtomcrypt-1.17/src/pk/rsa/rsa_import.c
src/libtomcrypt-1.17/src/pk/rsa/rsa_make_key.c
src/libtomcrypt-1.17/src/pk/rsa/rsa_sign_hash.c
src/libtomcrypt-1.17/src/pk/rsa/rsa_verify_hash.c
src/libtomcrypt-1.17/src/prngs/fortuna.c
src/libtomcrypt-1.17/src/prngs/rc4.c
src/libtomcrypt-1.17/src/prngs/rng_get_bytes.c
src/libtomcrypt-1.17/src/prngs/rng_make_prng.c
src/libtomcrypt-1.17/src/prngs/sober128.c
# src/libtomcrypt-1.17/src/prngs/sober128tab.c
src/libtomcrypt-1.17/src/prngs/sprng.c
src/libtomcrypt-1.17/src/prngs/yarrow.c
# src/libtomcrypt-1.17/testprof/base64_test.c
# src/libtomcrypt-1.17/testprof/cipher_hash_test.c
# src/libtomcrypt-1.17/testprof/der_tests.c
# src/libtomcrypt-1.17/testprof/dsa_test.c
# src/libtomcrypt-1.17/testprof/ecc_test.c
# src/libtomcrypt-1.17/testprof/katja_test.c
# src/libtomcrypt-1.17/testprof/mac_test.c
# src/libtomcrypt-1.17/testprof/modes_test.c
# src/libtomcrypt-1.17/testprof/pkcs_1_test.c
# src/libtomcrypt-1.17/testprof/rsa_test.c
# src/libtomcrypt-1.17/testprof/store_test.c
# src/libtomcrypt-1.17/testprof/test_driver.c
# src/libtomcrypt-1.17/testprof/x86_prof.c


### TOMSFASTMATH
src/libtommath-0.41/bn_error.c
src/libtommath-0.41/bn_fast_mp_invmod.c
src/libtommath-0.41/bn_fast_mp_montgomery_reduce.c
src/libtommath-0.41/bn_fast_s_mp_mul_digs.c
src/libtommath-0.41/bn_fast_s_mp_mul_high_digs.c
src/libtommath-0.41/bn_fast_s_mp_sqr.c
src/libtommath-0.41/bn_mp_2expt.c
src/libtommath-0.41/bn_mp_abs.c
src/libtommath-0.41/bn_mp_add.c
src/libtommath-0.41/bn_mp_add_d.c
src/libtommath-0.41/bn_mp_addmod.c
src/libtommath-0.41/bn_mp_and.c
src/libtommath-0.41/bn_mp_clamp.c
src/libtommath-0.41/bn_mp_clear.c
src/libtommath-0.41/bn_mp_clear_multi.c
src/libtommath-0.41/bn_mp_cmp.c
src/libtommath-0.41/bn_mp_cmp_d.c
src/libtommath-0.41/bn_mp_cmp_mag.c
src/libtommath-0.41/bn_mp_cnt_lsb.c
src/libtommath-0.41/bn_mp_copy.c
src/libtommath-0.41/bn_mp_count_bits.c
src/libtommath-0.41/bn_mp_div.c
src/libtommath-0.41/bn_mp_div_2.c
src/libtommath-0.41/bn_mp_div_2d.c
src/libtommath-0.41/bn_mp_div_3.c
src/libtommath-0.41/bn_mp_div_d.c
src/libtommath-0.41/bn_mp_dr_is_modulus.c
src/libtommath-0.41/bn_mp_dr_reduce.c
src/libtommath-0.41/bn_mp_dr_setup.c
src/libtommath-0.41/bn_mp_exch.c
src/libtommath-0.41/bn_mp_expt_d.c
src/libtommath-0.41/bn_mp_exptmod.c
src/libtommath-0.41/bn_mp_exptmod_fast.c
src/libtommath-0.41/bn_mp_exteuclid.c
src/libtommath-0.41/bn_mp_fread.c
src/libtommath-0.41/bn_mp_fwrite.c
src/libtommath-0.41/bn_mp_gcd.c
src/libtommath-0.41/bn_mp_get_int.c
src/libtommath-0.41/bn_mp_grow.c
src/libtommath-0.41/bn_mp_init.c
src/libtommath-0.41/bn_mp_init_copy.c
src/libtommath-0.41/bn_mp_init_multi.c
src/libtommath-0.41/bn_mp_init_set.c
src/libtommath-0.41/bn_mp_init_set_int.c
src/libtommath-0.41/bn_mp_init_size.c
src/libtommath-0.41/bn_mp_invmod.c
src/libtommath-0.41/bn_mp_invmod_slow.c
src/libtommath-0.41/bn_mp_is_square.c
src/libtommath-0.41/bn_mp_jacobi.c
src/libtommath-0.41/bn_mp_karatsuba_mul.c
src/libtommath-0.41/bn_mp_karatsuba_sqr.c
src/libtommath-0.41/bn_mp_lcm.c
src/libtommath-0.41/bn_mp_lshd.c
src/libtommath-0.41/bn_mp_mod.c
src/libtommath-0.41/bn_mp_mod_2d.c
src/libtommath-0.41/bn_mp_mod_d.c
src/libtommath-0.41/bn_mp_montgomery_calc_normalization.c
src/libtommath-0.41/bn_mp_montgomery_reduce.c
src/libtommath-0.41/bn_mp_montgomery_setup.c
src/libtommath-0.41/bn_mp_mul.c
src/libtommath-0.41/bn_mp_mul_2.c
src/libtommath-0.41/bn_mp_mul_2d.c
src/libtommath-0.41/bn_mp_mul_d.c
src/libtommath-0.41/bn_mp_mulmod.c
src/libtommath-0.41/bn_mp_n_root.c
src/libtommath-0.41/bn_mp_neg.c
src/libtommath-0.41/bn_mp_or.c
src/libtommath-0.41/bn_mp_prime_fermat.c
src/libtommath-0.41/bn_mp_prime_is_divisible.c
src/libtommath-0.41/bn_mp_prime_is_prime.c
src/libtommath-0.41/bn_mp_prime_miller_rabin.c
src/libtommath-0.41/bn_mp_prime_next_prime.c
src/libtommath-0.41/bn_mp_prime_rabin_miller_trials.c
src/libtommath-0.41/bn_mp_prime_random_ex.c
src/libtommath-0.41/bn_mp_radix_size.c
src/libtommath-0.41/bn_mp_radix_smap.c
src/libtommath-0.41/bn_mp_rand.c
src/libtommath-0.41/bn_mp_read_radix.c
src/libtommath-0.41/bn_mp_read_signed_bin.c
src/libtommath-0.41/bn_mp_read_unsigned_bin.c
src/libtommath-0.41/bn_mp_reduce.c
src/libtommath-0.41/bn_mp_reduce_2k.c
src/libtommath-0.41/bn_mp_reduce_2k_l.c
src/libtommath-0.41/bn_mp_reduce_2k_setup.c
src/libtommath-0.41/bn_mp_reduce_2k_setup_l.c
src/libtommath-0.41/bn_mp_reduce_is_2k.c
src/libtommath-0.41/bn_mp_reduce_is_2k_l.c
src/libtommath-0.41/bn_mp_reduce_setup.c
src/libtommath-0.41/bn_mp_rshd.c
src/libtommath-0.41/bn_mp_set.c
src/libtommath-0.41/bn_mp_set_int.c
src/libtommath-0.41/bn_mp_shrink.c
src/libtommath-0.41/bn_mp_signed_bin_size.c
src/libtommath-0.41/bn_mp_sqr.c
src/libtommath-0.41/bn_mp_sqrmod.c
src/libtommath-0.41/bn_mp_sqrt.c
src/libtommath-0.41/bn_mp_sub.c
src/libtommath-0.41/bn_mp_sub_d.c
src/libtommath-0.41/bn_mp_submod.c
src/libtommath-0.41/bn_mp_to_signed_bin.c
src/libtommath-0.41/bn_mp_to_signed_bin_n.c
src/libtommath-0.41/bn_mp_to_unsigned_bin.c
src/libtommath-0.41/bn_mp_to_unsigned_bin_n.c
src/libtommath-0.41/bn_mp_toom_mul.c
src/libtommath-0.41/bn_mp_toom_sqr.c
src/libtommath-0.41/bn_mp_toradix.c
src/libtommath-0.41/bn_mp_toradix_n.c
src/libtommath-0.41/bn_mp_unsigned_bin_size.c
src/libtommath-0.41/bn_mp_xor.c
src/libtommath-0.41/bn_mp_zero.c
src/libtommath-0.41/bn_prime_tab.c
src/libtommath-0.41/bn_reverse.c
src/libtommath-0.41/bn_s_mp_add.c
src/libtommath-0.41/bn_s_mp_exptmod.c
src/libtommath-0.41/bn_s_mp_mul_digs.c
src/libtommath-0.41/bn_s_mp_mul_high_digs.c
src/libtommath-0.41/bn_s_mp_sqr.c
src/libtommath-0.41/bn_s_mp_sub.c
src/libtommath-0.41/bncore.c
# src/libtommath-0.41/demo/demo.c
# src/libtommath-0.41/demo/timing.c
# src/libtommath-0.41/etc/2kprime.c
# src/libtommath-0.41/etc/drprime.c
# src/libtommath-0.41/etc/mersenne.c
# src/libtommath-0.41/etc/mont.c
# src/libtommath-0.41/etc/pprime.c
# src/libtommath-0.41/etc/tune.c
# src/libtommath-0.41/mtest/mpi.c
# src/libtommath-0.41/mtest/mtest.c
# src/libtommath-0.41/pre_gen/mpi.c


'''.strip().splitlines()}

for name, sources in ext_sources.items():
	ext_sources[name] = [x.strip() for x in sources if x.strip() and not x.lstrip().startswith('#')]

# print '\n'.join(sources)

# Define the extensions
ext_modules = [Extension(
    'tomcrypt.%s' % name, ["src/%s.c" % name] + ext_sources.get(name, []),
    include_dirs=[
                '.', # Buh?
                './src',
                './src/libtomcrypt-1.17/src/headers',
                './src/libtommath-0.41',
    ],
    define_macros=dict(
    
        # These macros are needed for the math library.
        LTM_DESC=None,
        LTC_SOURCE=None,
        # TFM_NO_ASM=None,
    
    ).items(),
    extra_link_args=['-rdynamic'],
) for name in ext_names]


# Go!
if __name__ == '__main__':
    setup(

        name='PyTomCrypt',
            description='Python+Cython wrapper around LibTomCrypt',
            version='0.5.5',
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
                'Topic :: Security :: Cryptography',
                'Topic :: Software Development :: Libraries :: Python Modules',
            ],

        ext_modules=ext_modules,
    )
