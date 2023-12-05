import siphash
from collections import defaultdict


def callhash(hashkey, inval):
    return siphash.SipHash_2_4(hashkey, inval).hash()


def ht_hash(hashkey, inval, htsize):
    return callhash(hashkey, inval) % htsize

# Put your collision-finding code here.
# Your function should output the colliding strings in a list.


def find_collisions(key, n=20, size=2**16):
    table = defaultdict(list)
    i = 0
    while True:
        encoded = str(i).encode("utf-8")
        hashed = ht_hash(key, encoded, size)
        table[hashed].append(encoded)
        if len(table[hashed]) == n:
            return table[hashed]
        i += 1

# Implement this function, which takes the list of
# collisions and verifies they all have the same
# SipHash output under the given key.


def check_collisions(key, colls):
    hashed = ht_hash(key, colls[0], 2**16)
    for coll in colls[1:]:
        if ht_hash(key, coll, 2**16) != hashed:
            return False
    return True


if __name__ == '__main__':
    # Look in the source code of the app to
    # find the key used for hashing.
    key = b'\x00'*16
    colls = find_collisions(key)
    print(colls)
    checked = check_collisions(key, colls)
    print(checked)
