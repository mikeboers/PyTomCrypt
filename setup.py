import os

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext


# Allow us to specify a single extension to build.
ext_names = ['_main']
ext_name = os.environ.get('PyTomCrypt_ext_name')
if ext_name:
	if ext_name not in ext_names:
		raise ValueError('unknown extension %r' % ext_name)
	ext_names = [ext_name]


sources = '''

# libtomcrypt-1.16/demos/encrypt.c
# libtomcrypt-1.16/demos/hashsum.c
# libtomcrypt-1.16/demos/multi.c
# libtomcrypt-1.16/demos/small.c
# libtomcrypt-1.16/demos/test.c
# libtomcrypt-1.16/demos/timing.c
# libtomcrypt-1.16/demos/tv_gen.c
# libtomcrypt-1.16/notes/etc/saferp_optimizer.c
# libtomcrypt-1.16/notes/etc/whirlgen.c
# libtomcrypt-1.16/notes/etc/whirltest.c
libtomcrypt-1.16/src/ciphers/aes/aes.c
# libtomcrypt-1.16/src/ciphers/aes/aes_tab.c
libtomcrypt-1.16/src/ciphers/anubis.c
libtomcrypt-1.16/src/ciphers/blowfish.c
libtomcrypt-1.16/src/ciphers/cast5.c
libtomcrypt-1.16/src/ciphers/des.c
libtomcrypt-1.16/src/ciphers/kasumi.c
libtomcrypt-1.16/src/ciphers/khazad.c
libtomcrypt-1.16/src/ciphers/kseed.c
libtomcrypt-1.16/src/ciphers/noekeon.c
libtomcrypt-1.16/src/ciphers/rc2.c
libtomcrypt-1.16/src/ciphers/rc5.c
libtomcrypt-1.16/src/ciphers/rc6.c
libtomcrypt-1.16/src/ciphers/safer/safer.c
libtomcrypt-1.16/src/ciphers/safer/safer_tab.c
libtomcrypt-1.16/src/ciphers/safer/saferp.c
libtomcrypt-1.16/src/ciphers/skipjack.c
libtomcrypt-1.16/src/ciphers/twofish/twofish.c
libtomcrypt-1.16/src/ciphers/twofish/twofish_tab.c
libtomcrypt-1.16/src/ciphers/xtea.c
libtomcrypt-1.16/src/encauth/ccm/ccm_memory.c
libtomcrypt-1.16/src/encauth/ccm/ccm_test.c
libtomcrypt-1.16/src/encauth/eax/eax_addheader.c
libtomcrypt-1.16/src/encauth/eax/eax_decrypt.c
libtomcrypt-1.16/src/encauth/eax/eax_decrypt_verify_memory.c
libtomcrypt-1.16/src/encauth/eax/eax_done.c
libtomcrypt-1.16/src/encauth/eax/eax_encrypt.c
libtomcrypt-1.16/src/encauth/eax/eax_encrypt_authenticate_memory.c
libtomcrypt-1.16/src/encauth/eax/eax_init.c
libtomcrypt-1.16/src/encauth/eax/eax_test.c
libtomcrypt-1.16/src/encauth/gcm/gcm_add_aad.c
libtomcrypt-1.16/src/encauth/gcm/gcm_add_iv.c
libtomcrypt-1.16/src/encauth/gcm/gcm_done.c
libtomcrypt-1.16/src/encauth/gcm/gcm_gf_mult.c
libtomcrypt-1.16/src/encauth/gcm/gcm_init.c
libtomcrypt-1.16/src/encauth/gcm/gcm_memory.c
libtomcrypt-1.16/src/encauth/gcm/gcm_mult_h.c
libtomcrypt-1.16/src/encauth/gcm/gcm_process.c
libtomcrypt-1.16/src/encauth/gcm/gcm_reset.c
libtomcrypt-1.16/src/encauth/gcm/gcm_test.c
libtomcrypt-1.16/src/encauth/ocb/ocb_decrypt.c
libtomcrypt-1.16/src/encauth/ocb/ocb_decrypt_verify_memory.c
libtomcrypt-1.16/src/encauth/ocb/ocb_done_decrypt.c
libtomcrypt-1.16/src/encauth/ocb/ocb_done_encrypt.c
libtomcrypt-1.16/src/encauth/ocb/ocb_encrypt.c
libtomcrypt-1.16/src/encauth/ocb/ocb_encrypt_authenticate_memory.c
libtomcrypt-1.16/src/encauth/ocb/ocb_init.c
libtomcrypt-1.16/src/encauth/ocb/ocb_ntz.c
libtomcrypt-1.16/src/encauth/ocb/ocb_shift_xor.c
libtomcrypt-1.16/src/encauth/ocb/ocb_test.c
libtomcrypt-1.16/src/encauth/ocb/s_ocb_done.c
libtomcrypt-1.16/src/hashes/chc/chc.c
libtomcrypt-1.16/src/hashes/helper/hash_file.c
libtomcrypt-1.16/src/hashes/helper/hash_filehandle.c
libtomcrypt-1.16/src/hashes/helper/hash_memory.c
libtomcrypt-1.16/src/hashes/helper/hash_memory_multi.c
libtomcrypt-1.16/src/hashes/md2.c
libtomcrypt-1.16/src/hashes/md4.c
libtomcrypt-1.16/src/hashes/md5.c
libtomcrypt-1.16/src/hashes/rmd128.c
libtomcrypt-1.16/src/hashes/rmd160.c
libtomcrypt-1.16/src/hashes/rmd256.c
libtomcrypt-1.16/src/hashes/rmd320.c
libtomcrypt-1.16/src/hashes/sha1.c
# libtomcrypt-1.16/src/hashes/sha2/sha224.c
libtomcrypt-1.16/src/hashes/sha2/sha256.c
# libtomcrypt-1.16/src/hashes/sha2/sha384.c
libtomcrypt-1.16/src/hashes/sha2/sha512.c
libtomcrypt-1.16/src/hashes/tiger.c
libtomcrypt-1.16/src/hashes/whirl/whirl.c
# libtomcrypt-1.16/src/hashes/whirl/whirltab.c
libtomcrypt-1.16/src/mac/f9/f9_done.c
libtomcrypt-1.16/src/mac/f9/f9_file.c
libtomcrypt-1.16/src/mac/f9/f9_init.c
libtomcrypt-1.16/src/mac/f9/f9_memory.c
libtomcrypt-1.16/src/mac/f9/f9_memory_multi.c
libtomcrypt-1.16/src/mac/f9/f9_process.c
libtomcrypt-1.16/src/mac/f9/f9_test.c
libtomcrypt-1.16/src/mac/hmac/hmac_done.c
libtomcrypt-1.16/src/mac/hmac/hmac_file.c
libtomcrypt-1.16/src/mac/hmac/hmac_init.c
libtomcrypt-1.16/src/mac/hmac/hmac_memory.c
libtomcrypt-1.16/src/mac/hmac/hmac_memory_multi.c
libtomcrypt-1.16/src/mac/hmac/hmac_process.c
libtomcrypt-1.16/src/mac/hmac/hmac_test.c
libtomcrypt-1.16/src/mac/omac/omac_done.c
libtomcrypt-1.16/src/mac/omac/omac_file.c
libtomcrypt-1.16/src/mac/omac/omac_init.c
libtomcrypt-1.16/src/mac/omac/omac_memory.c
libtomcrypt-1.16/src/mac/omac/omac_memory_multi.c
libtomcrypt-1.16/src/mac/omac/omac_process.c
libtomcrypt-1.16/src/mac/omac/omac_test.c
libtomcrypt-1.16/src/mac/pelican/pelican.c
libtomcrypt-1.16/src/mac/pelican/pelican_memory.c
libtomcrypt-1.16/src/mac/pelican/pelican_test.c
libtomcrypt-1.16/src/mac/pmac/pmac_done.c
libtomcrypt-1.16/src/mac/pmac/pmac_file.c
libtomcrypt-1.16/src/mac/pmac/pmac_init.c
libtomcrypt-1.16/src/mac/pmac/pmac_memory.c
libtomcrypt-1.16/src/mac/pmac/pmac_memory_multi.c
libtomcrypt-1.16/src/mac/pmac/pmac_ntz.c
libtomcrypt-1.16/src/mac/pmac/pmac_process.c
libtomcrypt-1.16/src/mac/pmac/pmac_shift_xor.c
libtomcrypt-1.16/src/mac/pmac/pmac_test.c
libtomcrypt-1.16/src/mac/xcbc/xcbc_done.c
libtomcrypt-1.16/src/mac/xcbc/xcbc_file.c
libtomcrypt-1.16/src/mac/xcbc/xcbc_init.c
libtomcrypt-1.16/src/mac/xcbc/xcbc_memory.c
libtomcrypt-1.16/src/mac/xcbc/xcbc_memory_multi.c
libtomcrypt-1.16/src/mac/xcbc/xcbc_process.c
libtomcrypt-1.16/src/mac/xcbc/xcbc_test.c
libtomcrypt-1.16/src/math/fp/ltc_ecc_fp_mulmod.c
# libtomcrypt-1.16/src/math/gmp_desc.c
# libtomcrypt-1.16/src/math/ltm_desc.c
# libtomcrypt-1.16/src/math/multi.c
# libtomcrypt-1.16/src/math/rand_prime.c
# libtomcrypt-1.16/src/math/tfm_desc.c
libtomcrypt-1.16/src/misc/base64/base64_decode.c
libtomcrypt-1.16/src/misc/base64/base64_encode.c
libtomcrypt-1.16/src/misc/burn_stack.c
libtomcrypt-1.16/src/misc/crypt/crypt.c
libtomcrypt-1.16/src/misc/crypt/crypt_argchk.c
libtomcrypt-1.16/src/misc/crypt/crypt_cipher_descriptor.c
libtomcrypt-1.16/src/misc/crypt/crypt_cipher_is_valid.c
libtomcrypt-1.16/src/misc/crypt/crypt_find_cipher.c
libtomcrypt-1.16/src/misc/crypt/crypt_find_cipher_any.c
libtomcrypt-1.16/src/misc/crypt/crypt_find_cipher_id.c
libtomcrypt-1.16/src/misc/crypt/crypt_find_hash.c
libtomcrypt-1.16/src/misc/crypt/crypt_find_hash_any.c
libtomcrypt-1.16/src/misc/crypt/crypt_find_hash_id.c
libtomcrypt-1.16/src/misc/crypt/crypt_find_hash_oid.c
libtomcrypt-1.16/src/misc/crypt/crypt_find_prng.c
libtomcrypt-1.16/src/misc/crypt/crypt_fsa.c
libtomcrypt-1.16/src/misc/crypt/crypt_hash_descriptor.c
libtomcrypt-1.16/src/misc/crypt/crypt_hash_is_valid.c
libtomcrypt-1.16/src/misc/crypt/crypt_ltc_mp_descriptor.c
libtomcrypt-1.16/src/misc/crypt/crypt_prng_descriptor.c
libtomcrypt-1.16/src/misc/crypt/crypt_prng_is_valid.c
libtomcrypt-1.16/src/misc/crypt/crypt_register_cipher.c
libtomcrypt-1.16/src/misc/crypt/crypt_register_hash.c
libtomcrypt-1.16/src/misc/crypt/crypt_register_prng.c
libtomcrypt-1.16/src/misc/crypt/crypt_unregister_cipher.c
libtomcrypt-1.16/src/misc/crypt/crypt_unregister_hash.c
libtomcrypt-1.16/src/misc/crypt/crypt_unregister_prng.c
libtomcrypt-1.16/src/misc/error_to_string.c
libtomcrypt-1.16/src/misc/pkcs5/pkcs_5_1.c
libtomcrypt-1.16/src/misc/pkcs5/pkcs_5_2.c
libtomcrypt-1.16/src/misc/zeromem.c
libtomcrypt-1.16/src/modes/cbc/cbc_decrypt.c
libtomcrypt-1.16/src/modes/cbc/cbc_done.c
libtomcrypt-1.16/src/modes/cbc/cbc_encrypt.c
libtomcrypt-1.16/src/modes/cbc/cbc_getiv.c
libtomcrypt-1.16/src/modes/cbc/cbc_setiv.c
libtomcrypt-1.16/src/modes/cbc/cbc_start.c
libtomcrypt-1.16/src/modes/cfb/cfb_decrypt.c
libtomcrypt-1.16/src/modes/cfb/cfb_done.c
libtomcrypt-1.16/src/modes/cfb/cfb_encrypt.c
libtomcrypt-1.16/src/modes/cfb/cfb_getiv.c
libtomcrypt-1.16/src/modes/cfb/cfb_setiv.c
libtomcrypt-1.16/src/modes/cfb/cfb_start.c
libtomcrypt-1.16/src/modes/ctr/ctr_decrypt.c
libtomcrypt-1.16/src/modes/ctr/ctr_done.c
libtomcrypt-1.16/src/modes/ctr/ctr_encrypt.c
libtomcrypt-1.16/src/modes/ctr/ctr_getiv.c
libtomcrypt-1.16/src/modes/ctr/ctr_setiv.c
libtomcrypt-1.16/src/modes/ctr/ctr_start.c
libtomcrypt-1.16/src/modes/ctr/ctr_test.c
libtomcrypt-1.16/src/modes/ecb/ecb_decrypt.c
libtomcrypt-1.16/src/modes/ecb/ecb_done.c
libtomcrypt-1.16/src/modes/ecb/ecb_encrypt.c
libtomcrypt-1.16/src/modes/ecb/ecb_start.c
libtomcrypt-1.16/src/modes/f8/f8_decrypt.c
libtomcrypt-1.16/src/modes/f8/f8_done.c
libtomcrypt-1.16/src/modes/f8/f8_encrypt.c
libtomcrypt-1.16/src/modes/f8/f8_getiv.c
libtomcrypt-1.16/src/modes/f8/f8_setiv.c
libtomcrypt-1.16/src/modes/f8/f8_start.c
libtomcrypt-1.16/src/modes/f8/f8_test_mode.c
libtomcrypt-1.16/src/modes/lrw/lrw_decrypt.c
libtomcrypt-1.16/src/modes/lrw/lrw_done.c
libtomcrypt-1.16/src/modes/lrw/lrw_encrypt.c
libtomcrypt-1.16/src/modes/lrw/lrw_getiv.c
libtomcrypt-1.16/src/modes/lrw/lrw_process.c
libtomcrypt-1.16/src/modes/lrw/lrw_setiv.c
libtomcrypt-1.16/src/modes/lrw/lrw_start.c
libtomcrypt-1.16/src/modes/lrw/lrw_test.c
libtomcrypt-1.16/src/modes/ofb/ofb_decrypt.c
libtomcrypt-1.16/src/modes/ofb/ofb_done.c
libtomcrypt-1.16/src/modes/ofb/ofb_encrypt.c
libtomcrypt-1.16/src/modes/ofb/ofb_getiv.c
libtomcrypt-1.16/src/modes/ofb/ofb_setiv.c
libtomcrypt-1.16/src/modes/ofb/ofb_start.c
# libtomcrypt-1.16/src/pk/asn1/der/bit/der_decode_bit_string.c
# libtomcrypt-1.16/src/pk/asn1/der/bit/der_encode_bit_string.c
# libtomcrypt-1.16/src/pk/asn1/der/bit/der_length_bit_string.c
# libtomcrypt-1.16/src/pk/asn1/der/boolean/der_decode_boolean.c
# libtomcrypt-1.16/src/pk/asn1/der/boolean/der_encode_boolean.c
# libtomcrypt-1.16/src/pk/asn1/der/boolean/der_length_boolean.c
# libtomcrypt-1.16/src/pk/asn1/der/choice/der_decode_choice.c
# libtomcrypt-1.16/src/pk/asn1/der/ia5/der_decode_ia5_string.c
# libtomcrypt-1.16/src/pk/asn1/der/ia5/der_encode_ia5_string.c
# libtomcrypt-1.16/src/pk/asn1/der/ia5/der_length_ia5_string.c
# libtomcrypt-1.16/src/pk/asn1/der/integer/der_decode_integer.c
# libtomcrypt-1.16/src/pk/asn1/der/integer/der_encode_integer.c
# libtomcrypt-1.16/src/pk/asn1/der/integer/der_length_integer.c
# libtomcrypt-1.16/src/pk/asn1/der/object_identifier/der_decode_object_identifier.c
# libtomcrypt-1.16/src/pk/asn1/der/object_identifier/der_encode_object_identifier.c
# libtomcrypt-1.16/src/pk/asn1/der/object_identifier/der_length_object_identifier.c
# libtomcrypt-1.16/src/pk/asn1/der/octet/der_decode_octet_string.c
# libtomcrypt-1.16/src/pk/asn1/der/octet/der_encode_octet_string.c
# libtomcrypt-1.16/src/pk/asn1/der/octet/der_length_octet_string.c
# libtomcrypt-1.16/src/pk/asn1/der/printable_string/der_decode_printable_string.c
# libtomcrypt-1.16/src/pk/asn1/der/printable_string/der_encode_printable_string.c
# libtomcrypt-1.16/src/pk/asn1/der/printable_string/der_length_printable_string.c
# libtomcrypt-1.16/src/pk/asn1/der/sequence/der_decode_sequence_ex.c
# libtomcrypt-1.16/src/pk/asn1/der/sequence/der_decode_sequence_flexi.c
# libtomcrypt-1.16/src/pk/asn1/der/sequence/der_decode_sequence_multi.c
# libtomcrypt-1.16/src/pk/asn1/der/sequence/der_encode_sequence_ex.c
# libtomcrypt-1.16/src/pk/asn1/der/sequence/der_encode_sequence_multi.c
# libtomcrypt-1.16/src/pk/asn1/der/sequence/der_length_sequence.c
# libtomcrypt-1.16/src/pk/asn1/der/sequence/der_sequence_free.c
# libtomcrypt-1.16/src/pk/asn1/der/set/der_encode_set.c
# libtomcrypt-1.16/src/pk/asn1/der/set/der_encode_setof.c
# libtomcrypt-1.16/src/pk/asn1/der/short_integer/der_decode_short_integer.c
# libtomcrypt-1.16/src/pk/asn1/der/short_integer/der_encode_short_integer.c
# libtomcrypt-1.16/src/pk/asn1/der/short_integer/der_length_short_integer.c
# libtomcrypt-1.16/src/pk/asn1/der/utctime/der_decode_utctime.c
# libtomcrypt-1.16/src/pk/asn1/der/utctime/der_encode_utctime.c
# libtomcrypt-1.16/src/pk/asn1/der/utctime/der_length_utctime.c
# libtomcrypt-1.16/src/pk/asn1/der/utf8/der_decode_utf8_string.c
# libtomcrypt-1.16/src/pk/asn1/der/utf8/der_encode_utf8_string.c
# libtomcrypt-1.16/src/pk/asn1/der/utf8/der_length_utf8_string.c
# libtomcrypt-1.16/src/pk/dsa/dsa_decrypt_key.c
# libtomcrypt-1.16/src/pk/dsa/dsa_encrypt_key.c
# libtomcrypt-1.16/src/pk/dsa/dsa_export.c
# libtomcrypt-1.16/src/pk/dsa/dsa_free.c
# libtomcrypt-1.16/src/pk/dsa/dsa_import.c
# libtomcrypt-1.16/src/pk/dsa/dsa_make_key.c
# libtomcrypt-1.16/src/pk/dsa/dsa_shared_secret.c
# libtomcrypt-1.16/src/pk/dsa/dsa_sign_hash.c
# libtomcrypt-1.16/src/pk/dsa/dsa_verify_hash.c
# libtomcrypt-1.16/src/pk/dsa/dsa_verify_key.c
# libtomcrypt-1.16/src/pk/ecc/ecc.c
# libtomcrypt-1.16/src/pk/ecc/ecc_ansi_x963_export.c
# libtomcrypt-1.16/src/pk/ecc/ecc_ansi_x963_import.c
# libtomcrypt-1.16/src/pk/ecc/ecc_decrypt_key.c
# libtomcrypt-1.16/src/pk/ecc/ecc_encrypt_key.c
# libtomcrypt-1.16/src/pk/ecc/ecc_export.c
# libtomcrypt-1.16/src/pk/ecc/ecc_free.c
# libtomcrypt-1.16/src/pk/ecc/ecc_get_size.c
# libtomcrypt-1.16/src/pk/ecc/ecc_import.c
# libtomcrypt-1.16/src/pk/ecc/ecc_make_key.c
# libtomcrypt-1.16/src/pk/ecc/ecc_shared_secret.c
# libtomcrypt-1.16/src/pk/ecc/ecc_sign_hash.c
# libtomcrypt-1.16/src/pk/ecc/ecc_sizes.c
# libtomcrypt-1.16/src/pk/ecc/ecc_test.c
# libtomcrypt-1.16/src/pk/ecc/ecc_verify_hash.c
# libtomcrypt-1.16/src/pk/ecc/ltc_ecc_is_valid_idx.c
# libtomcrypt-1.16/src/pk/ecc/ltc_ecc_map.c
# libtomcrypt-1.16/src/pk/ecc/ltc_ecc_mul2add.c
# libtomcrypt-1.16/src/pk/ecc/ltc_ecc_mulmod.c
# libtomcrypt-1.16/src/pk/ecc/ltc_ecc_mulmod_timing.c
# libtomcrypt-1.16/src/pk/ecc/ltc_ecc_points.c
# libtomcrypt-1.16/src/pk/ecc/ltc_ecc_projective_add_point.c
# libtomcrypt-1.16/src/pk/ecc/ltc_ecc_projective_dbl_point.c
# libtomcrypt-1.16/src/pk/katja/katja_decrypt_key.c
# libtomcrypt-1.16/src/pk/katja/katja_encrypt_key.c
# libtomcrypt-1.16/src/pk/katja/katja_export.c
# libtomcrypt-1.16/src/pk/katja/katja_exptmod.c
# libtomcrypt-1.16/src/pk/katja/katja_free.c
# libtomcrypt-1.16/src/pk/katja/katja_import.c
# libtomcrypt-1.16/src/pk/katja/katja_make_key.c
# libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_i2osp.c
# libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_mgf1.c
# libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_oaep_decode.c
# libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_oaep_encode.c
# libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_os2ip.c
# libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_pss_decode.c
# libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_pss_encode.c
# libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_v1_5_decode.c
# libtomcrypt-1.16/src/pk/pkcs1/pkcs_1_v1_5_encode.c
# libtomcrypt-1.16/src/pk/rsa/rsa_decrypt_key.c
# libtomcrypt-1.16/src/pk/rsa/rsa_encrypt_key.c
# libtomcrypt-1.16/src/pk/rsa/rsa_export.c
# libtomcrypt-1.16/src/pk/rsa/rsa_exptmod.c
# libtomcrypt-1.16/src/pk/rsa/rsa_free.c
# libtomcrypt-1.16/src/pk/rsa/rsa_import.c
# libtomcrypt-1.16/src/pk/rsa/rsa_make_key.c
# libtomcrypt-1.16/src/pk/rsa/rsa_sign_hash.c
# libtomcrypt-1.16/src/pk/rsa/rsa_verify_hash.c
# libtomcrypt-1.16/src/prngs/fortuna.c
# libtomcrypt-1.16/src/prngs/rc4.c
# libtomcrypt-1.16/src/prngs/rng_get_bytes.c
# libtomcrypt-1.16/src/prngs/rng_make_prng.c
# libtomcrypt-1.16/src/prngs/sober128.c
# libtomcrypt-1.16/src/prngs/sober128tab.c
# libtomcrypt-1.16/src/prngs/sprng.c
# libtomcrypt-1.16/src/prngs/yarrow.c
# libtomcrypt-1.16/testprof/base64_test.c
# libtomcrypt-1.16/testprof/cipher_hash_test.c
# libtomcrypt-1.16/testprof/der_tests.c
# libtomcrypt-1.16/testprof/dsa_test.c
# libtomcrypt-1.16/testprof/ecc_test.c
# libtomcrypt-1.16/testprof/katja_test.c
# libtomcrypt-1.16/testprof/mac_test.c
# libtomcrypt-1.16/testprof/modes_test.c
# libtomcrypt-1.16/testprof/pkcs_1_test.c
# libtomcrypt-1.16/testprof/rsa_test.c
# libtomcrypt-1.16/testprof/store_test.c
# libtomcrypt-1.16/testprof/test_driver.c
# libtomcrypt-1.16/testprof/x86_prof.c

'''.strip().splitlines()

sources = [x.strip() for x in sources if not x.lstrip().startswith('#')]

# print '\n'.join(sources)

# Define the extensions
ext_modules = [Extension(
    'tomcrypt.%s' % name, ["tomcrypt/%s.pyx" % name] + sources,
    include_dirs=['./libtomcrypt-1.16/src/headers'],
    # extra_objects=['./libtomcrypt-1.16/libtomcrypt.a'],
) for name in ext_names]


# Go!
if __name__ == '__main__':
	setup(
	  name = 'PyTomCrypt',
	  cmdclass = {'build_ext': build_ext},
	  ext_modules = ext_modules,
	)
