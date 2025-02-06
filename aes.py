import sys
from Crypto.Cipher import _create_cipher
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib, VoidPointer, SmartPointer, c_size_t, c_uint8_ptr)
from Crypto.Util import _cpu_features
from Crypto.Random import get_random_bytes

MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_OPENPGP, MODE_CCM, MODE_EAX, MODE_SIV, MODE_GCM, MODE_OCB = range(1, 13)

_cproto = """
        int AES_start_operation(const uint8_t key[], size_t key_len, void **pResult);
        int AES_encrypt(const void *state, const uint8_t *in, uint8_t *out, size_t data_len);
        int AES_decrypt(const void *state, const uint8_t *in, uint8_t *out, size_t data_len);
        int AES_stop_operation(void *state);
        """

_raw_aes_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_aes", _cproto)
_raw_aesni_lib = None
if _cpu_features.have_aes_ni():
    try:
        _raw_aesni_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_aesni", _cproto.replace("AES", "AESNI"))
    except OSError:
        pass

def _create_base_cipher(dict_parameters):
    use_aesni = dict_parameters.pop("use_aesni", True)
    key = dict_parameters.pop("key", None)
    if key is None or len(key) not in key_size:
        raise ValueError("Incorrect AES key length")

    start_operation = (_raw_aesni_lib.AESNI_start_operation if use_aesni and _raw_aesni_lib else _raw_aes_lib.AES_start_operation)
    stop_operation = (_raw_aesni_lib.AESNI_stop_operation if use_aesni and _raw_aesni_lib else _raw_aes_lib.AES_stop_operation)
    
    cipher = VoidPointer()
    result = start_operation(c_uint8_ptr(key), c_size_t(len(key)), cipher.address_of())
    if result:
        raise ValueError(f"Error {result:X} while instantiating the AES cipher")
    
    return SmartPointer(cipher.get(), stop_operation)

def _derive_Poly1305_key_pair(key, nonce):
    if len(key) != 32:
        raise ValueError("Poly1305 with AES requires a 32-byte key")
    if nonce is None:
        nonce = get_random_bytes(16)
    elif len(nonce) != 16:
        raise ValueError("Poly1305 with AES requires a 16-byte nonce")
    s = new(key[:16], MODE_ECB).encrypt(nonce)
    return key[16:], s, nonce

def new(key, mode, *args, **kwargs):
    kwargs["add_aes_modes"] = True
    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)

block_size = 16
key_size = (16, 24, 32)
