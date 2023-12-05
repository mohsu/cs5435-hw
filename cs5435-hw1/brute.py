from csv import reader
from app.util.hash import hash_sha256, hash_pbkdf2
import json
from multiprocessing.pool import ThreadPool

COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"


def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert (header[0] == 'username')
        return list(r)


def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    pws = [pw for [pw] in pws]
    return pws


def brute_force_attack(target_hash, target_salt):
    def try_pw(pw):
        salted_pw = hash_pbkdf2(pw, target_salt)
        if target_hash == salted_pw:
            return pw
        return None

    pws = load_common_passwords()

    with ThreadPool(processes=32) as pool:
        results = pool.map(try_pw, pws)
    for result in results:
        if result:
            return result
    return None


def create_hash_table(pws):
    hashed_dict = {}
    for pw in pws:
        hashed_pw = hash_sha256(pw)
        hashed_dict[pw] = hashed_pw

    with open("common_passwords.txt", "w") as f:
        json.dump(hashed_dict, f)


def main():
    # create hashes
    # pws = load_common_passwords()
    # create_hash_table(pws)

    salted_creds = load_breach(SALTED_BREACH_PATH)
    for salt_cred in salted_creds:
        _, hash, salt = salt_cred
        brute_force_attack(hash, salt)


if __name__ == "__main__":
    main()
