# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`asymcrypto` --- SCION asymmetric crypto functions
=======================================================
"""
# External
from nacl.exceptions import BadSignatureError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random

# SCION
from lib.errors import SCIONVerificationError


def sign(msg, signing_key):
    """
    Sign a message with a given signing key and return the signature.

    :param bytes msg: message to be signed.
    :param bytes signing_key: signing key from generate_signature_keypair().
    :returns: ed25519 signature.
    :rtype: bytes
    """
    return SigningKey(signing_key).sign(msg)[:64]


def verify(msg, sig, verifying_key):
    """
    Verify a signature.

    :param bytes msg: message that was signed.
    :param bytes sig: signature to verify.
    :param bytes verifying_key: verifying key from generate_signature_keypair().
    :returns: True or False whether the verification succeeds or fails.
    :rtype: boolean
    """
    try:
        return msg == VerifyKey(verifying_key).verify(msg, sig)
    except BadSignatureError:
        raise SCIONVerificationError("Signature corrupt or forged.") from None


def encrypt(msg, private_key, public_key):
    """
    Encrypt message.

    :param bytes msg: message to be encrypted.
    :param bytes private_key: Private Key of encrypter.
    :param bytes public_key: Public Key of decrypter.
    :returns: The encrypted message.
    :rtype: nacl.utils.EncryptedMessage
    """
    return Box(PrivateKey(private_key), PublicKey(public_key)).encrypt(msg, random(Box.NONCE_SIZE))


def decrypt(msg, private_key, public_key):
    """
    Decrypt ciphertext.

    :param bytes msg: ciphertext to be decrypted.
    :param bytes private_key: Private Key of decrypter.
    :param bytes public_key: Public Key of encrypter.
    :returns: The decrypted message.
    :rtype: bytes
    """
    return Box(PrivateKey(private_key), PublicKey(public_key)).decrypt(msg)
