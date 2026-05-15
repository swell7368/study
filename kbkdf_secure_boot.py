import hashlib
from Crypto.Hash import CMAC
from Crypto.Cipher import AES


def aes_cmac_prf_128(key: bytes, data: bytes) -> bytes:
    """
    RFC 4615 AES-CMAC-PRF-128
    키 길이가 16바이트가 아닌 경우, 먼저 zero-key AES-CMAC으로 16바이트 키를 유도한 뒤 사용.
    """
    if len(key) == 16:
        k = key
    else:
        # zero key(16B)로 AES-CMAC 수행해 16바이트 키 유도
        c = CMAC.new(b'\x00' * 16, ciphermod=AES)
        c.update(key)
        k = c.digest()

    c = CMAC.new(k, ciphermod=AES)
    c.update(data)
    return c.digest()


def derive_wrap_key(base_key: bytes, label: str, fw_code_hash: bytes) -> bytes:
    """
    WrapKey(128b) = AES-CMAC-PRF-128(
        KI  = base_key,
        Din = 0x00000001 || label || 0x00 || fw_code_hash || 0x00000080
    )
    """
    din = (
        (1).to_bytes(4, byteorder='big') +        # counter: 0x00000001
        label.encode('ascii') +                    # label string
        b'\x00' +                                  # separator
        fw_code_hash +                             # FW_code_hash (32 bytes)
        (128).to_bytes(4, byteorder='big')         # L: 0x00000080 = 128 bits
    )
    return aes_cmac_prf_128(base_key, din)


def main():
    print("=== Secure Boot Key Generation Modeling (AES-CMAC-PRF-128) ===\n")

    # ---------------------------------------------------------
    # 1. 초기 데이터 셋업
    # ---------------------------------------------------------
    abc_base_key  = bytes.fromhex("99FF887766554433221100AABBCCDDEEFF99887766554433221100AABBCCDDEE")
    fw_code       = b"B80000008ED88EC0E801000000E9452301"
    abc_fw_salt   = bytes.fromhex("A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90")

    print("[Setup]")
    print(f"  ABCBaseKey : {abc_base_key.hex().upper()}")
    print(f"  ABCFwSalt  : {abc_fw_salt.hex().upper()}\n")

    # ---------------------------------------------------------
    # 2. 펌웨어 측정: SHA-256(fw_code || fw_salt)
    # ---------------------------------------------------------
    print("[1] 펌웨어 무결성 측정 (Hashing)...")
    fw_code_hash = hashlib.sha256(fw_code + abc_fw_salt).digest()
    print(f"  FW Code (hex)     : {fw_code.hex().upper()}")
    print(f"  FW_code_hash      : {fw_code_hash.hex().upper()}\n")

    # ---------------------------------------------------------
    # 3. WrapKey1 도출
    # ---------------------------------------------------------
    print("[2] WrapKey1 도출 (AES-CMAC-PRF-128)...")
    label = "WrapKey1"
    din = (
        (1).to_bytes(4, byteorder='big') +
        label.encode('ascii') +
        b'\x00' +
        fw_code_hash +
        (128).to_bytes(4, byteorder='big')
    )

    wrap_key_1 = derive_wrap_key(abc_base_key, label, fw_code_hash)

    print(f"  Label     : {label}")
    print(f"  Din       : {din.hex().upper()}")
    print(f"  WrapKey1  : {wrap_key_1.hex().upper()}  (128-bit)\n")

    # ---------------------------------------------------------
    # 4. 공격 시뮬레이션: 펌웨어 1바이트 변조
    # ---------------------------------------------------------
    print("=== 공격 시뮬레이션: 펌웨어 1바이트 변조 ('B' → 'C') ===")
    hacked_fw_code  = b"C80000008ED88EC0E801000000E9452301"
    hacked_fw_hash  = hashlib.sha256(hacked_fw_code + abc_fw_salt).digest()
    hacked_wrap_key = derive_wrap_key(abc_base_key, label, hacked_fw_hash)

    print(f"  원본  FW_code_hash : {fw_code_hash.hex().upper()}")
    print(f"  변조  FW_code_hash : {hacked_fw_hash.hex().upper()}")
    print(f"  원본  WrapKey1     : {wrap_key_1.hex().upper()}")
    print(f"  변조  WrapKey1     : {hacked_wrap_key.hex().upper()}")
    match = wrap_key_1 == hacked_wrap_key
    print(f"  키 일치 여부: {'일치 (보안 실패!)' if match else '불일치 → 부팅/복호화 실패 (보안 유지!)'}\n")

    # ---------------------------------------------------------
    # 5. Avalanche Effect 정량 분석
    # ---------------------------------------------------------
    print("=== Avalanche Effect 정량 분석 ===")
    diff_hash = bin(int(fw_code_hash.hex(), 16) ^ int(hacked_fw_hash.hex(), 16)).count('1')
    diff_key  = bin(int(wrap_key_1.hex(), 16) ^ int(hacked_wrap_key.hex(), 16)).count('1')
    print(f"  FW Hash  비트 차이 : {diff_hash} / 256 bits ({diff_hash / 256 * 100:.1f}%)")
    print(f"  WrapKey1 비트 차이 : {diff_key} / 128 bits ({diff_key / 128 * 100:.1f}%)")
    print("  (이상적인 눈사태 효과 = ~50% 비트 반전)")


if __name__ == "__main__":
    main()
