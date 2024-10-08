from typing import TypeVar, Tuple

import serial

T = TypeVar("T")

def kyber_value(k: int, a: T, b: T, c: T) -> T:
    return a if k == 2 else b if k == 3 else c

def kyber_mode(k: int) -> int:
    return kyber_value(k, 0x00, 0x10, 0x20)

def dilithium_value(sec: int, a: T, b: T, c: T) -> T:
    return a if sec == 2 else b if sec == 3 else c

def dilithium_mode(sec: int) -> int:
    return dilithium_value(sec, 0x00, 0x10, 0x20)

def dilithium_k(sec: int) -> int:
    return dilithium_value(sec, 4, 6, 8)

def dilithium_l(sec: int) -> int:
    return dilithium_value(sec, 4, 5, 7)

def write_mode(s: serial.Serial, mode: int):
    s.write(b'\x01')
    s.write(mode.to_bytes(1, 'big'))


def kyber_pke_key_gen(s: serial.Serial, seed: bytes, k: int) -> Tuple[bytes, bytes]:
    write_mode(s, (kyber_mode(k) + 0x01))
    s.write(seed)

    pk = s.read(k * 384 + 32)
    sk = s.read(k * 384)

    return (pk, sk)

def kyber_pke_enc(s: serial.Serial, pk: bytes, m: bytes, r: bytes, k: int) -> bytes:
    write_mode(s, (kyber_mode(k) + 0x02))

    s.write(pk)
    s.write(m)
    s.write(r)

    u_len = kyber_value(k, 320, 320, 352)
    v_len = kyber_value(k, 128, 128, 160)

    c = s.read(k * u_len + v_len)

    return c

def kyber_pke_dec(s: serial.Serial, sk: bytes, c: bytes, k: int) -> bytes:
    write_mode(s, (kyber_mode(k) + 0x03))

    s.write(sk)
    s.write(c)

    m = s.read(32)

    return m

def kyber_kem_key_gen(s: serial.Serial, seed: bytes, z: bytes, k: int) -> Tuple[bytes, bytes]:
    write_mode(s, (kyber_mode(k) + 0x04))
    s.write(seed)
    s.write(z)

    pk = s.read(k * 384 + 32)
    sk = s.read(k * 384 + k * 384 + 32 + 32 + 32)

    return (pk, sk)

def kyber_kem_enc(s: serial.Serial, pk: bytes, m: bytes, k: int) -> Tuple[bytes, bytes]:
    write_mode(s, (kyber_mode(k) + 0x05))

    s.write(pk)
    s.write(m)

    u_len = kyber_value(k, 320, 320, 352)
    v_len = kyber_value(k, 128, 128, 160)

    K = s.read(32)
    c = s.read(k * u_len + v_len)

    return (K, c)

def kyber_kem_dec(s: serial.Serial, sk: bytes, c: bytes, k: int) -> bytes:
    write_mode(s, (kyber_mode(k) + 0x06))

    s.write(sk)
    s.write(c)

    return s.read(32)

def dilithium_key_gen(s: serial.Serial, seed: bytes, sec: int) -> Tuple[bytes, bytes]:
    k, l = dilithium_k(sec), dilithium_l(sec)

    write_mode(s, (dilithium_mode(sec) + 0x07))
    s.write(seed)

    eta_len = dilithium_value(sec, 96, 128, 96)

    pk = s.read(32 + k * 320)
    sk = s.read(32 + 32 + 64 + l * eta_len + k * eta_len + k * 416)

    return (pk, sk)

def dilithium_sign(s: serial.Serial, sk: bytes, m: bytes, sec: int) -> bytes:
    k, l = dilithium_k(sec), dilithium_l(sec)

    write_mode(s, (dilithium_mode(sec) + 0x08))

    s.write(sk)
    s.write(m)

    c_len = dilithium_value(sec, 32, 48, 64)
    z_len = dilithium_value(sec, 576, 640, 640)
    omega = dilithium_value(sec, 80, 55, 75)

    sig_len = c_len + l * z_len + omega + k

    sig = s.read(sig_len)
    # read padding to multiply of 8B
    s.read((8 - sig_len) % 8)

    return sig

def dilithium_verify(s: serial.Serial, pk: bytes, sig: bytes, m: bytes, sec: int) -> bool:
    write_mode(s, (dilithium_mode(sec) + 0x09))

    s.write(pk)
    s.write(sig)
    # pad to multiply of 8B
    s.write((8 - len(sig)) % 8 * b'\x00')
    s.write(m)

    return int.from_bytes(s.read(8)) != 0