# Key Management System 

A key management system (KMS), also known as a cryptographic key management system (CKMS) or enterprise key management system (EKMS), is an integrated approach for generating, distributing and managing cryptographic keys for devices and applications. 
They may cover all aspects of security - from the secure generation of keys over the secure exchange of keys up to secure key handling and storage on the client. 
Thus, a KMS includes the backend functionality for key generation, distribution, and replacement as well as the client functionality for injecting keys, storing and managing keys on devices.

Key management refers to management of cryptographic keys in a cryptosystem. 
This includes dealing with the generation, exchange, storage, use, crypto-shredding (destruction) and replacement of keys. 
It includes cryptographic protocol design, key servers, user procedures, and other relevant protocols.

Key management concerns keys at the user level, either between users or systems. 
This is in contrast to key scheduling, which typically refers to the internal handling of keys within the operation of a cipher.
Successful key management is critical to the security of a cryptosystem. 
It is the more challenging side of cryptography in a sense that it involves aspects of social engineering such as system policy, user training, organizational and departmental interactions, 
and coordination between all of these elements, in contrast to pure mathematical practices that can be automated.

Once keys are inventoried, key management typically consists of three steps: exchange, storage and use.

# AES

The Advanced Encryption Standard (AES) is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001.

AES is a variant of the Rijndael block cipher developed by two Belgian cryptographers, Joan Daemen and Vincent Rijmen, who submitted a proposal to NIST during the AES selection process. 
Rijndael is a family of ciphers with different key and block sizes. For AES, NIST selected three members of the Rijndael family, each with a block size of 128 bits, but three different key lengths: 128, 192 and 256 bits.

AES has been adopted by the U.S. government. It supersedes the Data Encryption Standard (DES), which was published in 1977. 
The algorithm described by AES is a symmetric-key algorithm, meaning the same key is used for both encrypting and decrypting the data.

In the United States, AES was announced by the NIST as U.S. FIPS PUB 197 (FIPS 197) on November 26, 2001. 
This announcement followed a five-year standardization process in which fifteen competing designs were presented and evaluated, 
before the Rijndael cipher was selected as the most suitable.

AES is included in the ISO/IEC 18033-3 standard. AES became effective as a U.S. 
federal government standard on May 26, 2002, after approval by the U.S. Secretary of Commerce. 
AES is available in many different encryption packages, and is the first (and only) publicly accessible cipher approved by the U.S. 
National Security Agency (NSA) for top secret information when used in an NSA approved cryptographic module.

# Server / Client / App - Role
Client : cipher key를 암호화, server에 전송

Server : cipher key를 복호화 후, MAC을 통해 무결성 검증

Application : KMS에서 cipher를 가져와 AES 암/복호화 수행, KMS에서 cipher를 가져와 MAC 수행
