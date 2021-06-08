# Occlude


 ***IMPORTANT***: This is an experimental/work-in-progress implementation and should not be relied upon for high-assurance applications.


Occlude implements the [OPAQUE](https://eprint.iacr.org/2018/163.pdf) protocol, providing an asymmetric password authenticated key exchange (aPAKE) which is secure against precomputation attacks. This library can be used to provide password authentication for a networked service which never exposes the user's plaintext password to the server or to any network attacker. `occlude` utilizes the [Ristretto](https://ristretto.group/) group for protocol operations. Ristretto is preferred since it provides a safe, prime-order elliptic curve group, elements have a defined unique string representation, it provides a correct and simple hash-to-curve operation in Elligator2, and the implementation used in `occlude` is fully constant-time. The OPAQUE design calls for the following paramters: Hash function H (e.g., a SHA2 or SHA3 function), a cyclic group G of prime order q (with a defined unique string representation of its elements), a generator g of G, and hash function H' mapping arbitrary strings into G (where H' is modeled as a random oracle). `

Occlude makes the following implementation choices: 

* `H:` SHA3 (Keccak)
* Group: Ristretto 
* `H'` (hash to curve): Elligator2

All group operations, including hashing to the curve, are constant-time: they run in time dependent only on the length of secret data, not the values of secret data.

 # Why PAKE?

 Password-authenticated key exchanges are, in theory, a straightforward upgrade for any service which performs password authentication. It protects the user from ever exposing their plaintext password to a service, and can be executed safely over a completely insecure channel. Beyond service-level password authentication, PAKEs also have applications in establishing secure channels in the absence of Certificate Authorities (as a replacement, or a backup mechanism). To read more, check out Matthew Green's excellent primer [Let's talk about PAKE](https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/).  
