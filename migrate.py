import hashlib
import hmac

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError


password_hasher = PasswordHasher(type=Type.ID)


def store_password(password: str) -> str:
    return password_hasher.hash(password)


def _is_legacy_md5(stored_hash: str) -> bool:
    return len(stored_hash) == 32 and all(
        character in "0123456789abcdefABCDEF" for character in stored_hash
    )


def authenticate_and_migrate(stored_hash: str, password: str) -> tuple[bool, str]:
    if _is_legacy_md5(stored_hash):
        candidate = hashlib.md5(password.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(candidate, stored_hash.lower()):
            return False, stored_hash
        return True, store_password(password)

    try:
        return password_hasher.verify(stored_hash, password), stored_hash
    except (InvalidHashError, VerificationError):
        return False, stored_hash


def _self_test() -> None:
    password = "correct horse battery staple"
    legacy_hash = hashlib.md5(password.encode("utf-8")).hexdigest()

    authenticated, migrated_hash = authenticate_and_migrate(legacy_hash, password)
    assert authenticated and migrated_hash.startswith("$argon2id$")
    print("PASS - successful login upgrades legacy MD5 to Argon2id")

    authenticated, unchanged_hash = authenticate_and_migrate(legacy_hash, "wrong password")
    assert not authenticated and unchanged_hash == legacy_hash
    print("PASS - wrong password is refused")

    authenticated, unchanged_hash = authenticate_and_migrate(migrated_hash, password)
    assert authenticated and unchanged_hash == migrated_hash
    print("PASS - upgraded Argon2id password still authenticates")
    print("ALL PASS")


if __name__ == "__main__":
    _self_test()
