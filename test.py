import pyftdi.serialext as ft
import serial

from os import urandom
from crypto import *

def kyber_pke_test(s: serial.Serial, k: int):
    print(f'Kyber({k}) - PKE')

    pk, sk = kyber_pke_key_gen(s, urandom(32), k)

    m = urandom(32)

    c = kyber_pke_enc(s, pk, m, urandom(32), k)

    m2 = kyber_pke_dec(s, sk, c, k)

    print(m.hex(), m2.hex())

def kyber_kem_test(s: serial.Serial, k: int):
    print(f'Kyber({k}) - KEM')

    pk, sk = kyber_kem_key_gen(s, urandom(32), urandom(32), k)

    m = urandom(32)

    K, c = kyber_kem_enc(s, pk, m, k)

    K2 = kyber_kem_dec(s, sk, c, k)

    print(K.hex(), K2.hex())

def dilithium_test(s: serial.Serial, sec: int):
    print(f'Dilithium({sec})')

    pk, sk = dilithium_key_gen(s, urandom(32), sec)

    m = urandom(32)

    sig = dilithium_sign(s, sk, m, sec)

    print(dilithium_verify(s, pk, sig, m, sec))

if __name__ == '__main__':
    s = ft.serial_for_url('ftdi://ftdi:2232:FT15CC7B/1', baudrate=3000000)

    for k in [2, 3, 4]:
        kyber_pke_test(s, k)

    for k in [2, 3, 4]:
        kyber_kem_test(s, k)

    for sec in [2, 3, 5]:
        dilithium_test(s, sec)

    s.close()