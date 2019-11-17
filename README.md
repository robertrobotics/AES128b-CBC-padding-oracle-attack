# AES128b-CBC-padding-oracle-attack
## Demo of padding oracle attack algorithm on AES 128b CBC algorithm.

## Table of contents
* [About the idea](#about-the-idea)
* [Required knowledge to understand the algorithm](#required-knowledge)

### About the idea
The attacker's algorithm was made in presentation purposes and should not be used with misintention. The most important information is that every CBC algorithm, not only AES, can be broken in this way. Idea is very simple and it is known as "Padding Oracle Attack" - to get plain text from cipher without knowing the right key to do the decryption. It is possible only when attacker can get somehow information from the server whether padding has been set correctly or not. 

### Required knowledge
* Basics of cryptography.
* How the AES 128b algorithm works.
* Idea of CBC (Cipher Block Chaining) algorithm.
* How PKCS#7 padding works.
