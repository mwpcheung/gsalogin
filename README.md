# gsalogin
  apple account login srp-6a protocol

The following is a description of SRP-6 and 6a, the latest versions of SRP:

	  N    A large safe prime (N = 2q+1, where q is prime)
	       All arithmetic is done modulo N.
	  g    A generator modulo N
	  k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
	  s    User's salt
	  I    Username
	  p    Cleartext Password
	  H()  One-way hash function
	  ^    (Modular) Exponentiation
	  u    Random scrambling parameter
	  a,b  Secret ephemeral values
	  A,B  Public ephemeral values
	  x    Private key (derived from p and s)
	  v    Password verifier
	The host stores passwords using the following formula:
	  x = H(s, p)               (s is chosen randomly)
	  v = g^x                   (computes password verifier)
	The host then keeps {I, s, v} in its password database. The authentication protocol itself goes as follows:
	User -> Host:  I, A = g^a                  (identifies self, a = random number)
	Host -> User:  s, B = kv + g^b             (sends salt, b = random number)


        Both:  u = H(A, B)

        User:  x = H(s, p)                 (user enters password)
        User:  S = (B - kg^x) ^ (a + ux)   (computes session key)
        User:  K = H(S)

        Host:  S = (Av^u) ^ b              (computes session key)
        Host:  K = H(S)
 # diff between standard and apple
	 1. u = H(A,B)  ==> u = sha256(A+B) 
	 2. k = H(N,g)  ==>  k = sha256(N+g)  N is 256byte big-endian order,  g is256 byte big-endian order bytes
	 3. x = H(s,p)  ==> apple's s => H(":"+P) without username
	 4. P password field P = hmac(pass, salt, iter) where pass = sha256(password_text)
	 5. M1 
			i = H(g) xor H(N)
			M1 = H(i) + H(I) + H(salt) + H(A) + H(B) + H(K) 
			+  ==>  sha256_update
