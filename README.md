
# Security

This library was created to act as a wrapper for more sophisticated cryoptographic and security packages.


# Installation
Installing to use in your own scripts in a virtual environment?

`pip install git+https://github.com/pmp47/Security`

Installing to edit this code and contribute? Clone/download this repo and...

`pip install -r requirements.txt`



# Usage

Secret sharing is useful for splitting sensitive information.
```python
#sensitive info
secret_str = 'test secret'

#minimum shares required to recombine into secret
min_req = 5

#total shares to create
total_shares = 10

#split the secret into a list of shares
shares = Secrets.Sharing.Split(secret_str,min_req=min_req,total_shares=total_shares)

```

Cryptographic hashing is useful for truncating data into a fixed length, or creating unique identifiers.

```python
#data to hash can be of any length
string_to_hash = 'hello world'

#the returned hash is a fixed bit length in this case of SHA256
hashed_str = Hashing.HashStr(string_to_hash)

#can use other hash types such as a constant time bcrypt
bcrypt_str = Hashing.HashStr(string_to_hash,hash_type='bcrypt')

```

The centerpiece of the library is encryption/decryption. Public key (Asymmetric) generation, encryption, and decryption are useful for transmitting data across untrusted networks.


```python
#first we need an asymmtric key (public/private)
asymKeys = Encrypting.Asymmetric.GenerateKey('my new keys',2) #high lvl -> high cpu time

#perhaps we have an object as json on a client
obj_str = 'this is an object as a string' 

#the obj is encrypted using the public key on the client
encrypted_str = Encrypting.Asymmetric.Encrypt(obj_str,asymKeys['public'])

#the encrypted data can be sent to the server where the private key is
decrypted_str = Encrypting.Asymmetric.Decrypt(encrypted_str,asymKeys['private'])

```

Symmetric encryption is useful for storing/sending large data as asymmetric encryption is limited by the level of the public key.


```python
#lets make a passphrase to remember
passphrase = 'the_longer_the_passphrase_the_better_in_terms_of_preventing_cracking'

#and get the data to encrypt as bytes
data_to_encrypt = b'secret string to encrypt symmetrically'

#then encrypt to secure
encrypted_data = Encrypting.Symmetric.Encrypt(data_to_encrypt,passphrase)

#and decrypt later to reveal
decrypted_data = Encrypting.Symmetric.Decrypt(encrypted_data,passphrase)

```

# Notes
Security in any application shouldn't be taken lightly. While this package provides a simple way to use the underlying cryptographic primitives, it still may not meet your requrements.

