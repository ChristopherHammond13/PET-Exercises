#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py 

###########################
# Group Members: Christopher Hammond, Asutosh Savani
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

import petlib
import pytest

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM 
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom

from petlib.bn import Bn
from petlib.cipher import Cipher

def encrypt_message(K, message, key_length=128):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")

    iv = urandom(16)

    if key_length not in [128, 192, 256]:
        raise Exception("Invalid key length")

    aes = Cipher("aes-%s-gcm" % str(key_length))

    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)

    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag, key_length=128):
    """ Decrypt a cipher text under a key K 

        In case the decryption fails, throw an exception.
    """

    if key_length not in [128, 192, 256]:
        raise Exception("Invalid key length")

    aes = Cipher("aes-%s-gcm" % str(key_length))

    plain = aes.quick_gcm_dec(K, iv, ciphertext, tag)

    return plain.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
           or (x is None and y is None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x*x*x + a*x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """
    if (str(x0) == str(x1)) and (str(y0) == str(y1)):
        raise Exception("EC Points must not be equal")

    # Check for inverse

    if (
        (str(x0) == str(x1)) or \
        (not is_point_on_curve(a, b, p, x0, y0) or \
          not is_point_on_curve(a, b, p, x1, y1))):
        return (None, None)

    # if ((x0 == x1) \
    #     or (not is_point_on_curve(a, b, p, x0, y0) or not is_point_on_curve(a, b, p, x1, y1))):
    #     return (None, None)

    # Check whether either point is infinity
    if (x0 is None and y0 is None):
        return (x1, y1)

    if (x1 is None and y1 is None):
        return (x0, y0)

    y1minusy0 = y1.mod_sub(y0, p)
    x1minusx0inv = x1.mod_sub(x0, p).mod_inverse(p)
    lam = y1minusy0.mod_mul(x1minusx0inv, p)

    xr = lam.mod_pow(2, p).mod_sub(x0, p).mod_sub(x1, p)
    
    yr = x0.mod_sub(xr, p).mod_mul(lam, p).mod_sub(y0, p)

    return xr, yr

def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """  

    if x is None and y is None:
        return None, None

    xr, yr = None, None

    lam_part1 = x.mod_pow(2, p).mod_mul(Bn(3), p).mod_add(a, p)
    lam_part2 = Bn(2).mod_mul(y, p).mod_inverse(p)
    lam = lam_part1.mod_mul(lam_part2, p)

    xr = lam.mod_pow(2, p).mod_sub(Bn(2).mod_mul(x, p), p)

    yr = x.mod_sub(xr, p).mod_mul(lam, p).mod_sub(y, p)

    return xr, yr

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    Q = (None, None)
    P = (x, y)

    for i in range(scalar.num_bits()):
        if scalar.is_bit_set(i):
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
        P = point_double(a, b, p, P[0], P[1])

    return Q

def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    R0 = (None, None)
    R1 = (x, y)

    for i in reversed(range(0,scalar.num_bits())):
        if scalar.is_bit_set(i):
            R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R1 = point_double(a, b, p, R1[0], R1[1])
        else:
            R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R0 = point_double(a, b, p, R0[0], R0[1])

    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation 
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification 
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing 
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext =  message.encode("utf8")

    digest = sha256(plaintext).digest()
    sig = do_ecdsa_sign(G, priv_sign, digest)

    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext =  message.encode("utf8")

    digest = sha256(plaintext).digest()
    res = do_ecdsa_verify(G, pub_verify, sig, digest)

    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE: 

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(other_public_key, message, aliceSig = None):
    """ Assume you know the public key of someone else (Bob), 
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """

    G, my_private_key, my_public_key = dh_get_key()

    shared_key = other_public_key.pt_mul(my_private_key)
    shared_key_hash = sha256(shared_key.export()).digest()

    plaintext = message.encode("utf8")

    iv, ciphertext, tag = encrypt_message(shared_key_hash, plaintext, 256)

    signature = None
    if aliceSig:
        signature = ecdsa_sign(G, my_private_key, message)

    message = (iv, ciphertext, tag, signature, my_public_key)

    return message

def dh_decrypt(priv, message, aliceVer = None):
    """ Decrypt a received message encrypted using your public key, 
    of which the private key is provided. Optionally verify 
    the message came from Alice using her verification key."""
    
    G = EcGroup()

    iv, ciphertext, tag, signature, other_public_key = message

    shared_key = other_public_key.pt_mul(priv)
    shared_key_hash = sha256(shared_key.export()).digest()

    plaintext = decrypt_message(shared_key_hash, iv, ciphertext, tag, 256)

    signature_verified = None
    if signature and aliceVer:
        signature_verified = ecdsa_verify(G, other_public_key, plaintext, signature)

    return (plaintext.decode("utf8"), signature_verified)

## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py 

@pytest.mark.task5
def test_encrypt():
    G, priv_dec, pub_enc = dh_get_key()
    plain_text = "test"*100

    # Encrypt without a signature
    iv, ciphertext, tag, signature, my_public_key = dh_encrypt(pub_enc, plain_text, None)
    assert signature == None

    # Encrypt with a signature
    iv, ciphertext, tag, signature, my_public_key = dh_encrypt(pub_enc, plain_text, True)
    assert len(iv) == 16
    assert ciphertext != plain_text

@pytest.mark.task5
def test_decrypt_signed():
    G, priv_dec, pub_enc = dh_get_key()
    plain_text = "T3stTh1sC0de$"*100
    message = dh_encrypt(pub_enc, plain_text, True)

    # Now go and decrypt to ensure the data matches
    dec_message, sig_verified = dh_decrypt(priv_dec, message, True)

    print "dec, plain"
    print dec_message
    print plain_text

    assert dec_message == plain_text
    assert sig_verified == True

@pytest.mark.task5
def test_decrypt_bad_message():
    G, priv_dec, pub_enc = dh_get_key()
    plain_text = "T3stTh1sC0de$"*100

    # Encrypt with a signature
    message = dh_encrypt(pub_enc, plain_text, True)
    
    plain_text_bad = "xxxxxxxx$"*100
    message_2 = dh_encrypt(pub_enc, plain_text_bad, True)

    # Structure of message: (iv, ciphertext, tag, signature, my_pub_key)
    message_new = (message[0], message[1], message[2], message_2[3], message[4])

    # Now go and decrypt to ensure the data matches
    dec_message, sig_verified = dh_decrypt(priv_dec, message_new, True)

    assert dec_message == plain_text
    assert sig_verified == False


#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#           
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different 
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.

# def time_scalar_mul():
#     pass
