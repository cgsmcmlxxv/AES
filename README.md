AES
===

Advanced Encryption Standard

Matches bit per bit with the code from http://www.movable-type.co.uk/scripts/aes.html.

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

- decrypts CIPHER using PASSWORD in NBITS
---> CIPHER: cipher text which needs to be decrypted
---> PASSWORD: required password for decryptioon
---> NBITS: number of bits in the key length (128, 192 or 256)<br/>
- accepts CIPHER, PASSWORD and NBITS (in this order)<br/>
- returns plain text (in latin1)
