# Meet-in-the-Middle attack against a DoubleDES cipher

This repository holds an implementation of a DoubleDES cipher along with a Meet
In The Middle attack against that cipher. The attack and cipher are 
implemented in Java using the Java Cryptography Extension. 

Read more about meet in the middle attacks here: <https://en.wikipedia.org/wiki/Meet-in-the-middle_attack>

## Description of Repository

Description of this repository files:

* `DoubleDES.java`: this file holds a class `DoubleDES` which allows one to 
 take a pair of secret keys concatenated in a string along with a plaintext
 and returns the corresponding ciphertext encoded by a DoubleDES cipher. 

* `DoubleDESDecrypt.java`: this file holds a class `DoubleDESDecrypt`
  which uses the same cipher in a decryption mode to take a ciphertext and
  along the two keys required and outputs the corresponding plaintext

* `MITM.java`: this file performs an attack against the cipher included in 
  the above files. It does so by performing a meet in the middle attack. 
  To simplify the computations, part of the two keys are provided as an 
  input to the attack method.

## How to run the code

First, here is how to encode a message. Suppose you want to encode `0123456789ABCDEF` 
using keys `00000000000000` and `11111111111111`, you run the following: 

```
java DoubleDES 0000000000000011111111111111 0123456789ABCDEF
```

which should return the ciphertext `3057b90bd52bae5e1dc92a4ef6dd9775`. Now, to decode
you replace `DoubleDES` by `DoubleDESDecrypt` to get back `0123456789ABCDEF`.

To run the meet in the middle attack, simply run `MITM` as the pair of plaintext and
cipher text are hardcoded in the code, along with the partial keys to help with the run time.

### Contact Information 

If you have any questions or suggestions, feel free to submit pull requests or
contact me using:
* Twitter: <http://www.twitter.com/nicolaspapernot>
* My Webpage: <http://www.papernot.fr> 

 
