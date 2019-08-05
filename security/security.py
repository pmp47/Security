#--start requirements--
#pip installs
from bcrypt import hashpw, gensalt
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from secretsharing import PlaintextToHexSecretSharer
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

#customs

#builtins
import hashlib
import base64
import hmac
import secrets

#--end requirements--

class Secrets:
	"""For handling and managing secrets.
	"""
	class Sharing:
		"""Share secrets using Shamir methodology.
		Ref:
			https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
		"""
		def Split(secret: str,min_req: int,total_shares: int):
			"""Split a secret into shares.
			Args:
				secret(str): Secret data representated as a string
				min_req(int): Minimum shares required to combine to form secret.
				total_shares(int): Total shares to split the secret into.
			Returns:
				list: shares
			"""
			if min_req >= total_shares: raise ValueError('Total shares must be more than minimum required.')
			shares = PlaintextToHexSecretSharer().split_secret(secret,min_req,total_shares)
			return shares
		
		def Combine(shares: list):
			"""Combine a list of shares to form a secret if the minimum number required is supplied.
			Args:
				shares(list): List of shares.
			Returns:
				str: secret
			"""
			secret = PlaintextToHexSecretSharer().recover_secret(shares)
			return secret
		
class Hashing:
	"""For converting variable length inputs to fixed length outputs and also comparing them to each other securely.
	"""
	def HashStr(input: str,hash_type='sha256',bcrypt_rounds=12):
		"""Computes the hash of a string.
		Args:
			input(str): Input string that will be hashed.
			hash_type(str): 'sha256' | 'bcrypt'
			bcrypt_rounds(int): Rounds to compute bcrypt hash, higher takes more time (dependant on hardware).
		Returns:
			str: hash
		Notes:
			The SHA265 hash is a capitalized hexdigest.
			Bcrypt has a maximum password length.
		Ref:
			http://dustwell.com/how-to-handle-passwords-bcrypt.html
			https://www.mscharhag.com/software-development/bcrypt-maximum-password-length
			https://stackoverflow.com/questions/5881169/what-column-type-length-should-i-use-for-storing-a-bcrypt-hashed-password-in-a-d
		TODO:
			Make it so can have sha of varying size like sha512 or sha1024
			Is MD5 necessary?
		"""
		hash_router = {'sha256':lambda i:hashlib.sha256(i.encode('utf-8')).hexdigest().upper(),'bcrypt':lambda i:hashpw(i.encode('utf-8'),gensalt(rounds=bcrypt_rounds)).decode('utf-8')}
		hash = hash_router[hash_type](input)
		return hash
	
	def Compare(compare_this: str,to_that: str,hash_type='sha256'):
		"""Compare hashed strings in a time safe manner.
		Args:
			compare_this(str): Input string to subject to comparison.
			to_that(str): Target previously computed hash.
			hash_type(str): 'sha256' | 'bcrypt'
		Returns:
			bool: are_equal
		Notes:
			The SHA265 hash is a capitalized hexdigest.
		Ref:
			https://thisdata.com/blog/timing-attacks-against-string-comparison/
			https://news.ycombinator.com/item?id=11119154
			https://www.reddit.com/r/Python/comments/49hwq0/constant_time_comparison_in_python/
			https://security.stackexchange.com/questions/83660/simple-string-comparisons-not-secure-against-timing-attacks/83671#83671
			https://docs.python.org/2/library/hmac.html
		"""
		are_equal = hmac.compare_digest(hashpw(compare_this.encode('utf-8'),to_that.encode('utf-8')).decode('utf-8'),to_that) if hash_type == 'bcrypt' else hmac.compare_digest(compare_this,to_that)
		return are_equal
	
class Encrypting:
	"""Class for securing data via encryption.
	Ref:
		https://tools.ietf.org/html/rfc8221
	"""
	def GeneratePassphrase(nbytes=32):
		"""Generate a random url safe text string.
		Args:
			nbytes(int): Number of bytes. Default 32bytes -> 256bit
		Returns:
			str: url_safe_random_str
		Ref:
			https://docs.python.org/3/library/secrets.html
		"""
		url_safe_random_str = secrets.token_urlsafe(nbytes)
		return url_safe_random_str
	
	class Asymmetric:
		"""Library for asymmetric public/private key crytopgraphy.
		Ref:
			https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
		"""
		def GenerateKey(name: str,level: int,public_format='PEM'):
			"""
			Args:
				name(str): 
				level(int): kB level of encryptiong -> higher means longer to compute.
				public_format(str): 'PEM' | 'DER' | 'OpenSSH'
			Returns:
				dict: asymKeys
			"""
			bits = int(level*1024)
			new_key = RSA.generate(bits,e=65527)
			private_key = new_key.exportKey('PEM')
			public_key = new_key.publickey().exportKey(public_format)
			asymKeys = {'ID':name,'private':private_key.decode('utf-8'),'public':public_key.decode('utf-8')}
			return asymKeys
		
		def Fingerprint(asymKeys: dict,usePrivate=False):
			"""Derive the md5 fingerprint of an asymmetric key.
			Args:
				asymKeys(dict): Asymmetric keys created using GenerateKey()
				usePrivate(bool): True to fingerprint the private key, otherwise using the public.
			Returns:
				str: fingerprint
			"""
			key_str = asymKeys['private'] if usePrivate else asymKeys['public']
			key = base64.b64decode(''.join(key_str.splitlines()[1:-1]).encode('ascii'))
			fingerprint = hashlib.md5(key).hexdigest()
			return fingerprint
		
		def Encrypt(obj_as_str: str,public_key: str):
			"""Encrypts a string using an asymmetric public encryption key.
			Args:
				obj_as_str(str): Object represented as a string to be encrypted.
				public_key(str): asymKeys['public']
			Returns:
				str: encrypted_data_str
			"""
			rsa_key = PKCS1_OAEP.new(RSA.importKey(public_key.encode('utf-8'))) #import the publi key and use for encryption using PKCS1_OAEP
			encrypted_data = rsa_key.encrypt(obj_as_str.encode('utf-8'))
			encrypted_data_str = base64.b64encode(encrypted_data).decode('utf-8')
			return encrypted_data_str
		
		def Decrypt(encrypted_data_str: str,private_key: str):
			"""Decrypts a string using an asymmetric private encryption key.
			Args:
				encrypted_data_str(str): Data represented as an encrypted string that is to be decrypted.
				private_key(str): asymKeys['private']
			Returns:
				str: obj_as_str
			"""
			rsa_key = PKCS1_OAEP.new(RSA.importKey(private_key.encode('utf-8')))
			encrypted = base64.b64decode(encrypted_data_str.encode('utf-8'))
			obj_as_str = rsa_key.decrypt(encrypted).decode('utf-8')
			return obj_as_str
		
		def Sign(message: str,private_key: str):
			"""Sign a message using a private key.
			Args:
				message(str): Message to be signed.
				private_key(str): asymKeys['private']
			Returns:
				str: signature
			Ref:
				https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html
			"""
			rsa_key = RSA.importKey(private_key.encode('utf-8'))
			signer = pkcs1_15.new(rsa_key)
			digest = SHA256.new(message.encode('utf-8'))
			signature = base64.b64encode(signer.sign(digest)).decode('utf-8')
			return signature
		
		def IsVerified(message: str,signature: str,public_key: str):
			"""Verifies a message by confirming the signature using a public key.
			Args:
				message(str): Data in the form of a message to be verified
				signature(str): Data signature to be verified.
				public_key(str): Public key string.
			Returns:
				bool: isVerified
			Ref:
				https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html
			"""
			rsa_key = RSA.import_key(public_key.encode('utf-8'))
			signer = pkcs1_15.new(rsa_key)
			digest = SHA256.new(message.encode('utf-8'))
			isVerified = True
			try: signer.verify(digest,base64.b64decode(signature.encode('utf-8')))
			except: isVerified = False
			return isVerified
		
	class Symmetric:
		"""Class for symmetric or public/private key encryption which currently uses AES SHA256 CBC.
		Notes:
			While it is recommended to not use SHA family hashes as keys for securing data, 
			these concerns are in regards to storing passwords and verifying them for authentication purposes, not decryption. 
			The assumption which makes these cases different is that encrypted data is portable and stored passwords are not. 
			Therefore, increasing hashing time will not prevent brute force decryption access because the data is assumed to be decrypted client-side. 
			Instead, we deploy the SHA family of hashing to a passphrase for fast decryption. 
		Ref:
			https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
			https://codahale.com/how-to-safely-store-a-password/
			https://www.pycryptodome.org/en/latest/src/cipher/classic.html
		"""
		def Encrypt(obj_as_bytes: bytes,passphrase: str):
			"""Encrypt a byte object with a given passphrase.
			Args:
				obj_as_bytes(bytes): Data represented as bytes.
				passphrase(str): 
			Returns:
				bytes: encrypted_bytes
			"""
			obj_as_bytes = Encrypting.Utils.pad(obj_as_bytes)
			iv = Random.new().read(AES.block_size)
			cipher = AES.new(hashlib.sha256(passphrase.encode('utf-8')).digest(),AES.MODE_CBC,iv)
			encrypted_bytes = base64.b64encode(iv + cipher.encrypt(obj_as_bytes))
			return encrypted_bytes
		
		def Decrypt(encrypted_bytes: bytes,passphrase: str):
			"""Decrypt an encrypted byte object with a given passphrase.
			Args:
				encrypted_bytes(bytes): Data as bytes already encrypted.
				passphrase(str): 
			Returns:
				bytes: obj_as_bytes
			"""
			encrypted_str = base64.b64decode(encrypted_bytes)
			iv = encrypted_str[:AES.block_size]
			cipher = AES.new(hashlib.sha256(passphrase.encode('utf-8')).digest(),AES.MODE_CBC,iv)
			try: obj_as_bytes = Encrypting.Utils.unpad(cipher.decrypt(encrypted_str[AES.block_size:]))
			except: raise ValueError('Failed to decrypt.')
			return obj_as_bytes
		
	class Utils:
		"""Encrypting support utilities.
		"""
		def UrlSafeB64Decode(input: bytes):
			"""aga
			Args:
				input(bytes): Input bytes to decode.
			Returns:
				str: url_safe_b64
			"""
			url_safe_b64 = input.decode('utf-8').replace('/','_').replace('=','-').replace('+','%')
			return url_safe_b64
		
		def UrlSafeB64Encode(url_safe_b64: str):
			"""ada
			Args:
				url_safe_b64(str): Input string to encode.
			Returns:
				bytes: input
			"""
			input = url_safe_b64.replace('/','_').replace('=','-').replace('+','%').encode('utf-8')
			return input
		
		def pad(data: bytes):
			"""Pads data with null bytes so it is evenly divisible by a minimum blocksize.
			Args:
				data(bytes): Data as bytes to be encrypted.
			Returns:
				bytes: padded_data
			"""
			if not (isinstance(data,bytes)): raise ValueError('data must be bytes')
			block_size = AES.block_size
			padded_data = data + ((block_size - len(data) % block_size) * chr(block_size - len(data) % block_size)).encode('utf-8')
			return padded_data
		
		def unpad(data: bytes):
			"""Removes null byte padding from data.
			Args:
				data(bytes): Data as bytes to be encrypted.
			Returns:
				bytes: unpadded_data
			"""
			unpadded_data = data[0:-data[-1]]
			return unpadded_data
		
class Tests:
	"""Unit tests for this module.
	"""
	def main():
		"""
		"""
		Tests.split_secret_then_combine()
		Tests.sha256_hash_then_compare()
		Tests.bcrypt_hash_then_compare()
		Tests.asymmetric_encryption_and_authentication()
		Tests.symmetric_encryption()
	
	def split_secret_then_combine():
		"""Take an arbitrary string as a secret, split it, then demonstrate recombining.
		"""
		secret_str = 'test secret'
		shares = Secrets.Sharing.Split(secret_str,min_req=5,total_shares=10)
		if Secrets.Sharing.Combine(shares[:4]) == secret_str: raise ValueError('Combined secret shares with less than minimum required')
		if not Secrets.Sharing.Combine(shares[:7]) == secret_str: raise ValueError('Failed to combined shares to reform secret')
	
	def sha256_hash_then_compare():
		"""
		"""
		string_to_hash = 'hello world'
		hashed_str = Hashing.HashStr(string_to_hash)
		if len(hashed_str) != 64: raise ValueError('Incorrect hash length for 256bits')
		if Hashing.HashStr(string_to_hash) != hashed_str: raise ValueError('Hash varied from previous computation')
		if Hashing.HashStr(string_to_hash.upper()) == hashed_str: raise ValueError('Hash was not unique')
		if not Hashing.Compare(Hashing.HashStr(string_to_hash),hashed_str): raise ValueError('Comparison failed')
		print('assert constant time comparison incomplete')
	
	def bcrypt_hash_then_compare():
		"""
		"""
		string_to_hash = 'hello world'
		hashed_str = Hashing.HashStr(string_to_hash,'bcrypt')
		if len(hashed_str) != 60: raise ValueError('bcrypt hash incorrect length')
		if Hashing.HashStr(string_to_hash,'bcrypt') == hashed_str: raise ValueError('bcrypt was inconsistent') 
		if not Hashing.Compare(string_to_hash,hashed_str,'bcrypt'): raise ValueError('bcrypt comparison failed')
	
	def asymmetric_encryption_and_authentication():
		"""
		"""
		obj_str = 'this is an object as a string' 
		asymKeys = Encrypting.Asymmetric.GenerateKey('name',2)
		asymKeys2 = Encrypting.Asymmetric.GenerateKey('other key',2)
		encrypted_str = Encrypting.Asymmetric.Encrypt(obj_str,asymKeys['public'])
		if Encrypting.Asymmetric.Decrypt(encrypted_str,asymKeys['private']) != obj_str: raise ValueError('private key failed to decrypt') 
		try: Encrypting.Asymmetric.Decrypt(encrypted_str,asymKeys2['private'])
		except: pass
		signature = Encrypting.Asymmetric.Sign(obj_str,asymKeys['private'])
		if Encrypting.Asymmetric.Sign(obj_str,asymKeys2['private']) == signature: raise ValueError('signature was not unique')
		if Encrypting.Asymmetric.IsVerified(obj_str,signature,asymKeys['public']) == False: raise ValueError('signature not verified correctly')
		signature2 = Encrypting.Asymmetric.Sign(obj_str,asymKeys2['private'])
		if Encrypting.Asymmetric.IsVerified(obj_str,signature2,asymKeys['public']): raise ValueError('able to impersonate signature')
	
	def symmetric_encryption():
		"""Test symmetric encryption and decryption.
		"""
		data_to_encrypt = b'secret string to encrypt symmetrically'
		passphrase = 'thelongerthepassphrasethebetterintermsofpreventingcracking'
		encrypted_data = Encrypting.Symmetric.Encrypt(data_to_encrypt,passphrase)
		encrypted_data2 = Encrypting.Symmetric.Encrypt(data_to_encrypt,passphrase)
		if encrypted_data == encrypted_data2: raise ValueError('encryption collision')
		decrypted_data = Encrypting.Symmetric.Decrypt(encrypted_data,passphrase)
		if decrypted_data != data_to_encrypt: raise ValueError('decrypted data is incorrect')
		try: Encrypting.Symmetric.Decrypt(encrypted_data,'wrong passphrase')
		except: pass
	
readme = """
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

"""