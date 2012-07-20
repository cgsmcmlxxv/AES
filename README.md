AES
===

Advanced Encryption Standard (NIST FIPS-197)

Matches bit per bit with the code from http://www.movable-type.co.uk/scripts/aes.html.

The license can be found at the top of the file.

EXPORTS
=======

encrypt/3 :

- encrypts MESSAGE with PASSWORD using NBITS<br/>
---> MESSAGE: plain text which needs to be encrypted<br/>
---> PASSWORD: the password for encryption<br/>
---> NBITS: number of bits in the key length (128, 192 or 256)<br/>
- accepts MESSAGE, PASSWORD and NBITS (in this order)<br/>
- returns cipher text (in base64)

decrypt/3 :

- decrypts CIPHER using PASSWORD in NBITS<br/>
---> CIPHER: cipher text which needs to be decrypted<br/>
---> PASSWORD: required password for decryptioon<br/>
---> NBITS: number of bits in the key length (128, 192 or 256)<br/>
- accepts CIPHER, PASSWORD and NBITS (in this order)<br/>
- returns plain text (in latin1)
