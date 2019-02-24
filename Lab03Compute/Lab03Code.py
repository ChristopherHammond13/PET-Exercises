#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 03
#
# Basics of Privacy Friendly Computations through
#         Additive Homomorphic Encryption.
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Setup, key derivation, log
#           Encryption and Decryption
#

###########################
# Group Members: TODO
###########################

from petlib.bn import Bn
from petlib.ec import EcGroup


def setup():
    """Generates the Cryptosystem Parameters."""
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()
    return (G, g, h, o)

def keyGen(params):
   """ Generate a private / public key pair """
   (G, g, h, o) = params
   
   priv = o.random()
   pub = priv * g

   return (priv, pub)

def encrypt(params, pub, m):
    """ Encrypt a message under the public key """
    if not -100 < m < 100:
        raise Exception("Message value to low or high.")

    (G, g, h, o) = params
    k = o.random()                  # Private Key
    g_pow_k = k * g                 # g^k
    pk_pow_k = k * pub              # g^(xk)
    h_pow_m = m * h                 # h^m

    message = pk_pow_k + h_pow_m

    c = (g_pow_k, message)

    return c

def isCiphertext(params, ciphertext):
    """ Check a ciphertext """
    (G, g, h, o) = params
    ret = len(ciphertext) == 2
    a, b = ciphertext
    ret &= G.check_point(a)
    ret &= G.check_point(b)
    return ret

_logh = None
def logh(params, hm):
    """ Compute a discrete log, for small number only """
    global _logh
    (G, g, h, o) = params

    # Initialize the map of logh
    if _logh == None:
        _logh = {}
        for m in range (-1000, 1000):
            _logh[(m * h)] = m

    if hm not in _logh:
        raise Exception("No decryption found.")

    return _logh[hm]

def decrypt(params, priv, ciphertext):
    """ Decrypt a message using the private key """
    assert isCiphertext(params, ciphertext)
    a , b = ciphertext

    (G, g, h, o) = params

    hm = b - (priv * a)

    return logh(params, hm)

#####################################################
# TASK 2 -- Define homomorphic addition and
#           multiplication with a public value
# 

def add(params, pub, c1, c2):
    """ Given two ciphertexts compute the ciphertext of the 
        sum of their plaintexts.
    """

    # Adding to none returns the other parameter
    if c1 is None:
        assert isCiphertext(params, c2)
        return c2
    if c2 is None:
        assert isCiphertext(params, c1)
        return c1

    # Expect both parameters to be cipher texts that can be added
    assert isCiphertext(params, c1)
    assert isCiphertext(params, c2)

    (a1, b1) = c1
    (a2, b2) = c2

    c3 = (a1 + a2, b1 + b2)

    return c3

def mul(params, pub, c1, alpha):
    """ Given a ciphertext compute the ciphertext of the 
        product of the plaintext time alpha """
    assert isCiphertext(params, c1)

    (a, b) = c1
    c3 = (Bn(alpha) * a, Bn(alpha) * b)

    return c3

#####################################################
# TASK 3 -- Define Group key derivation & Threshold
#           decryption. Assume an honest but curious 
#           set of authorities.

def groupKey(params, pubKeys=[]):
    """ Generate a group public key from a list of public keys """
    (G, g, h, o) = params

    pub = None
    for pub_key in pubKeys:
        if pub is None:
            pub = pub_key
        else:
            pub = pub + pub_key

    # pub = pub.mod(o)

    return pub

def partialDecrypt(params, priv, ciphertext, final=False):
    """ Given a ciphertext and a private key, perform partial decryption. 
        If final is True, then return the plaintext. """
    assert isCiphertext(params, ciphertext)
    
    (G, g, h, o) = params

    a1, b = ciphertext

    b1 = b - (priv * a1)

    if final:
        return logh(params, b1)
    else:
        return a1, b1

#####################################################
# TASK 4 -- Actively corrupt final authority, derives
#           a public key with a known private key.
#

def corruptPubKey(params, priv, OtherPubKeys=[]):
    """ Simulate the operation of a corrupt decryption authority. 
        Given a set of public keys from other authorities return a
        public key for the corrupt authority that leads to a group
        public key corresponding to a private key known to the
        corrupt authority. """
    (G, g, h, o) = params

    my_priv_key = priv * g

    pub = None

    for k in OtherPubKeys:
        if pub is None:
            pub = -k
        else:
            pub -= k

    pub += my_priv_key

    return pub

#####################################################
# TASK 5 -- Implement operations to support a simple
#           private poll.
#

def encode_vote(params, pub, vote):
    """ Given a vote 0 or 1 encode the vote as two
        ciphertexts representing the count of votes for
        zero and the votes for one."""
    assert vote in [0, 1]

    v0 = encrypt(params, pub, (1 - vote))
    v1 = encrypt(params, pub, vote)

    return (v0, v1)

def process_votes(params, pub, encrypted_votes):
    """ Given a list of encrypted votes tally them
        to sum votes for zeros and votes for ones. """
    assert isinstance(encrypted_votes, list)

    tv0 = None
    tv1 = None

    for (v0, v1) in encrypted_votes:
        tv0 = add(params, pub, v0, tv0)
        tv1 = add(params, pub, v1, tv1)

    return tv0, tv1

def simulate_poll(votes):
    """ Simulates the full process of encrypting votes,
        tallying them, and then decrypting the total. """

    # Generate parameters for the crypto-system
    params = setup()

    # Make keys for 3 authorities
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    priv3, pub3 = keyGen(params)
    pub = groupKey(params, [pub1, pub2, pub3])

    # Simulate encrypting votes
    encrypted_votes = []
    for v in votes:
        encrypted_votes.append(encode_vote(params, pub, v))

    # Tally the votes
    total_v0, total_v1 = process_votes(params, pub, encrypted_votes)

    # Simulate threshold decryption
    privs = [priv1, priv2, priv3]
    for priv in privs[:-1]:
        total_v0 = partialDecrypt(params, priv, total_v0)
        total_v1 = partialDecrypt(params, priv, total_v1)

    total_v0 = partialDecrypt(params, privs[-1], total_v0, True)
    total_v1 = partialDecrypt(params, privs[-1], total_v1, True)

    # Return the plaintext values
    return total_v0, total_v1

###########################################################
# TASK Q1 -- Answer questions regarding your implementation
#
# Consider the following game between an adversary A and honest users H1 and H2: 
# 1) H1 picks 3 plaintext integers Pa, Pb, Pc arbitrarily, and encrypts them to the public
#    key of H2 using the scheme you defined in TASK 1.
# 2) H1 provides the ciphertexts Ca, Cb and Cc to H2 who flips a fair coin b.
#    In case b=0 then H2 homomorphically computes C as the encryption of Pa plus Pb.
#    In case b=1 then H2 homomorphically computes C as the encryption of Pb plus Pc.
# 3) H2 provides the adversary A, with Ca, Cb, Cc and C.
#
# What is the advantage of the adversary in guessing b given your implementation of 
# Homomorphic addition? What are the security implications of this?

"""
Although the cipher texts may not be decryptable themselves, as they were encrypted
in the public key of H2, it is possible for A to determine which cipher texts
Ca, Cb and Cc were combined (as they are added together homomorphically), and
from this it is possible to calculate the value of b.

In the case of b = 0 => C = E(Pa + Pb) = Ca + Cb
In the case of b = 1 => C = E(Pb + Pc) = Cb + Cc

Since homomorphic encryption is inherently malleable, and ElGamal, RSA and others
are vulnerable to this, it is possible to compute all encrypted combinations of
Ca, Cb and Cc even without the source messages as there are no measures such
as CBC in place to prevent this. Therefore, A can just generate all permutations
of Ca, Cb and Cc and then match against C. If A knows the rules for combining
Pa, Pb and Pc in the case of b, A will then be able to infer the value of b.
"""

###########################################################
# TASK Q2 -- Answer questions regarding your implementation
#
# Given your implementation of the private poll in TASK 5, how
# would a malicious user implement encode_vote to (a) distrupt the
# poll so that it yields no result, or (b) manipulate the poll so 
# that it yields an arbitrary result. Can those malicious actions 
# be detected given your implementation?

"""
There is no sanity checking on the data coming into the voting function.
For example, process_votes is quite happy to add the votes together
regardless of the vote value. It also does not check the number of
votes cast (e.g. to ensure it matches the number of voters), nor does
it check how many times each person has voted.
The following attacks could work quite reasonably if an attacker could
control encode_vote:
a) The attacker could keep state and submit votes in pairs, one for each
   candidate after each pair of votes, ignoring what each voter actually
   wrote. That way, there would be no result because the votes would
   be split exactly 50/50.
b) The attacker could manipulate the result so that instead of submitting
   one vote for each candidate, one candidate is given multiple votes by
   changing the value that is encoded.
   For example, if the attacker wanted candidate 1 to win, they could
   encrypt 2 * vote for each time candidate 1 is voted for so that when
   process_votes is run the number 2 will be added to the vote tally
   instead of 1 each time candidate 1 is voted for, doubling their votes.
   In addition, the number of encrypted messages would be consistent with
   the number of voters, making the bug quite difficult to spot.
"""
