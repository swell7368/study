import hashlib
import hmac

def kbkdf_hmac_sha256(key_in: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """
    NIST SP 800-108 기반의 KBKDF (Counter Mode) 구현체 (HMAC-SHA256 사용)
    - key_in: 최상위 마스터 키 (예: OTP Key)
    - label: 키의 용도를 나타내는 문자열
    - context: 키 유도에 결합될 부가 정보 (예: 펌웨어 해시)
    - length: 도출할 키의 바이트 길이 (예: 32바이트 = 256비트)
    """
    derived_key = b""
    counter = 1

    # 요구하는 길이(length)를 채울 때까지 반복 (SHA-256은 한 번에 32바이트 생성)
    while len(derived_key) < length:
        # 입력 데이터 구성: [Counter(4바이트, NIST SP 800-108)] || [Label] || [0x00] || [Context] || [Length(4바이트)]
        msg = (
            counter.to_bytes(4, byteorder='big') +  # NIST 표준: 32-bit counter
            label +
            b'\x00' +
            context +
            (length * 8).to_bytes(4, byteorder='big')
        )

        # HMAC-SHA256 수행
        h = hmac.new(key_in, msg, hashlib.sha256)
        derived_key += h.digest()
        counter += 1

    return derived_key[:length]

def main():
    print("=== Secure Boot Key Generation Modeling ===\n")

    # ---------------------------------------------------------
    # 1. 초기 데이터 셋업 (Provisioning & Build Time)
    # ---------------------------------------------------------
    global_otp_key   = bytes.fromhex("99FF887766554433221100AABBCCDDEEFF99887766554433221100AABBCCDDEE")
    fw_code          = b"B80000008ED88EC0E801000000E9452301"
    global_fw_salt   = bytes.fromhex("A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90")

    print(f"[Setup]")
    print(f"  OTP Key : {global_otp_key.hex().upper()}")
    print(f"  FW Salt : {global_fw_salt.hex().upper()}\n")

    # ---------------------------------------------------------
    # 2. Bootloader 단계: 펌웨어 측정 (Hash Computation)
    # ---------------------------------------------------------
    print("[1] 펌웨어 무결성 측정 (Hashing)...")
    # fw_code + salt 연결 후 SHA-256 (의도된 설계: salt가 measurement에 포함)
    fw_memory_image = fw_code + global_fw_salt
    fw_hash = hashlib.sha256(fw_memory_image).digest()
    print(f"  FW Code (hex) : {fw_code.hex().upper()}")
    print(f"  FW Hash (SHA-256) : {fw_hash.hex().upper()}\n")

    # ---------------------------------------------------------
    # 3. KBKDF 단계: 최종 Wrapping Key 도출
    # ---------------------------------------------------------
    print("[2] KBKDF를 이용한 Wrapping Key 도출...")
    kdf_context = fw_hash
    kdf_label   = b"SECURE_BOOT_WRAPPING_KEY"

    wrapping_key = kbkdf_hmac_sha256(
        key_in=global_otp_key,
        label=kdf_label,
        context=kdf_context,
        length=32
    )
    print(f"  KDF Label   : {kdf_label.decode()}")
    print(f"  KDF Context : {kdf_context.hex().upper()}")
    print(f"  Wrapping Key: {wrapping_key.hex().upper()}")
    print("  (이 키로 하위 세션/페이로드 키를 AES-KeyWrap으로 래핑/언래핑)\n")

    # ---------------------------------------------------------
    # 4. Avalanche Effect (눈사태 효과) 테스트
    # ---------------------------------------------------------
    print("=== 공격 시뮬레이션: 펌웨어 1바이트 변조 ===")
    hacked_fw_code = b"C80000008ED88EC0E801000000E9452301"  # 'B' → 'C'

    hacked_fw_hash = hashlib.sha256(hacked_fw_code + global_fw_salt).digest()
    hacked_wrapping_key = kbkdf_hmac_sha256(
        key_in=global_otp_key,
        label=kdf_label,
        context=hacked_fw_hash,
        length=32
    )

    print(f"  원본  FW Hash   : {fw_hash.hex().upper()}")
    print(f"  변조  FW Hash   : {hacked_fw_hash.hex().upper()}")
    print(f"  원본  Wrapping Key: {wrapping_key.hex().upper()}")
    print(f"  변조  Wrapping Key: {hacked_wrapping_key.hex().upper()}")
    print(f"  키 일치 여부: {'일치 (보안 실패!)' if wrapping_key == hacked_wrapping_key else '불일치 → 부팅/복호화 실패 (보안 유지!)'}\n")

    # ---------------------------------------------------------
    # 5. 비트 차이 통계 (Avalanche 정량 분석)
    # ---------------------------------------------------------
    print("=== Avalanche Effect 정량 분석 ===")
    diff_hash = bin(int(fw_hash.hex(), 16) ^ int(hacked_fw_hash.hex(), 16)).count('1')
    diff_key  = bin(int(wrapping_key.hex(), 16) ^ int(hacked_wrapping_key.hex(), 16)).count('1')
    print(f"  FW Hash 비트 차이    : {diff_hash} / 256 bits ({diff_hash/256*100:.1f}%)")
    print(f"  Wrapping Key 비트 차이: {diff_key} / 256 bits ({diff_key/256*100:.1f}%)")
    print("  (이상적인 눈사태 효과 = ~50% 비트 반전)")

if __name__ == "__main__":
    main()
