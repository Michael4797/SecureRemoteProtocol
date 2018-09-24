package me.michael4797.crypto.srp;

import java.math.BigInteger;

/**
 * The server side of the SRP implementation.
 */
public final class SRPServer extends SRP{
	
	private final String username;
	private byte[] A;
	private byte[] B;
	private BigInteger b;
	
	private final byte[] salt;
	private final BigInteger verifier;
	
	/**
	 * Creates a new SRP instance to authenticate a client with the specified username, salt, and verifier.
	 * @param username The username of the client to be authenticated.
	 * @param salt The salt of the client.
	 * @param verifier The verifier of the client.
	 */
	public SRPServer(String username, byte[] salt, byte[] verifier){
	
		this.username = username;
		
		if(salt.length == 32 && salt[0] < 0){
			
			this.salt = new byte[33];
			for(int i = 0; i < 32; i++)
				this.salt[i+1] = salt[i];
		}
		else
			this.salt = salt;
		
		if(verifier.length == 256 && verifier[0] < 0){
			
			byte[] vtmp = new byte[257];
			for(int i = 0; i < 256; i++)
				vtmp[i+1] = verifier[i];
			
			this.verifier = fromByteArray(vtmp);
		}
		else
			this.verifier = fromByteArray(verifier);
	}
	
	/**
	 * Retrieves the client's salt, used in the generation of the client's password verifier.
	 * @return The salt.
	 */
	public byte[] getSalt(){
		
		return salt;
	}
	
	/**
	 * Sets the value of the client's ephemeral.
	 * @param A The client ephemeral.
	 * @throws SRPException If A has already been set.
	 */
	public void setA(byte[] A) throws SRPException{
		
		if(this.A != null)
			throw new SRPException.IncorrectProtocolException();
		
		this.A = A;
	}
	
	/**
	 * Gets the value of the server's ephemeral.
	 * @return The server ephemeral.
	 */
	public byte[] getB() {
		
		if(B != null)
			return B;
		
		b = fromByteArray(SRP.randomBytes(32));		
		B = padToN(k.multiply(verifier).add(g.modPow(b, N)).mod(N));
		
		return B;
	}
	
	/**
	 * Gets the server's proof by hashing the client ephemeral, client proof, and session key.
	 * @param M The client's proof.
	 * @return The server's proof.
	 * @throws SRPException If the authentication failed.
	 */
	public byte[] getHAMK(byte[] M) throws SRPException{
		
		BigInteger u = getU(this.A, B);
		byte[] key = hash(padToN(fromByteArray(A).multiply(verifier.modPow(u, N)).modPow(b, N)));

		byte[] sM = getM(username, salt, A, B, key);
		
		if(sM.length != M.length)
			throw new SRPException.AuthenticationFailedException();
		
		for(int i = 0; i < sM.length; i++)
			if(sM[i] != M[i])
				throw new SRPException.AuthenticationFailedException();
		
		return hash(this.A, M, key);
	}
}
