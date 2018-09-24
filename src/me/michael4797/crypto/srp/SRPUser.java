package me.michael4797.crypto.srp;

import java.math.BigInteger;

/**
 * The client side of the SRP implementation.
 */
public final class SRPUser extends SRP{

	private String username, password;
	private BigInteger a;
	private byte[] s;
	private byte[] A;
	private byte[] B;
	private byte[] K;
	private BigInteger x;
	
	/**
	 * Creates a new SRP instance to authenticate a client with the specified username, and password.
	 * @param username The username of the client.
	 * @param password The password of the client.
	 */
	public SRPUser(String username, String password){
		
		this.username = username;
		this.password = password;
		a = fromByteArray(randomBytes(32));
		A = padToN(g.modPow(a, N));
	}
	
	/**
	 * Encodes the password into a salt and verifier.
	 * @param username The username of the client to be encoded.
	 * @param password The password to be encoded.
	 * @return The password salt and verifier.
	 */
	public static PasswordData encodePassword(String username, String password){
		
		byte[] salt = randomBytes(16);
		BigInteger x = getX(salt, username, password);
		byte[] verifier = padToN(g.modPow(x, N));
		return new PasswordData(salt, verifier);
	}
	
	/**
	 * Retrieves the username of the client being authenticated.
	 * @return The username.
	 */
	public String getUsername(){
		
		return username;
	}
	
	/**
	 * Gets the client ephemeral.
	 * @return The client ephemeral.
	 */
	public byte[] getA(){
		
		return A;
	}
	
	/**
	 * Sets the value of the server ephemeral and generates the session key.
	 * @param B The server ephemeral.
	 * @throws SRPException If the salt has not been set yet.
	 */
	public void setB(byte[] B) throws SRPException{
		
		if(x == null)
			throw new SRPException.IncorrectProtocolException();
		
		this.B = B;
		BigInteger biB = fromByteArray(B);
		K = hash(padToN(biB.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(getU(A, B).multiply(x)), N)));
	}
	
	/**
	 * Sets the salt for the client's password.
	 * @param s The salt used to generate the password verifier.
	 */
	public void setSalt(byte[] s){
		
		this.s = s;
		x = getX(s, username, password);
	}
	
	/**
	 * Calculates the client's proof of session key.
	 * @return The client proof.
	 * @throws SRPException If the server ephemeral has not been set.
	 */
	public byte[] getM() throws SRPException{
		
		if(B == null)
			throw new SRPException.IncorrectProtocolException();
		return getM(username, s, A, B, K);
	}
	
	/**
	 * Verifies the server's proof of session key.
	 * @param HAMK The server proof.
	 * @throws SRPException If the authentication failed.
	 */
	public void verify(byte[] HAMK) throws SRPException{
		
		byte[] cHAMK = hash(A, getM(username, s, A, B, K), K);
		
		if(cHAMK.length != HAMK.length)
			throw new SRPException.AuthenticationFailedException();
		
		for(int i = 0; i < cHAMK.length; i++)
			if(cHAMK[i] != HAMK[i])
				throw new SRPException.AuthenticationFailedException();
	}
	
	
	private static BigInteger getX(byte[] salt, String username, String password){
		
		byte[] I = toByteArray(username + ":" + password);
		byte[] hash = hash(I);

	    return fromByteArray(hash(salt, hash));
	}
	
	/**
	 * Convenience class for storing the salt and verifier of a password.
	 */
	public static class PasswordData{
		
		public final byte[] salt;
		public final byte[] verifier;
		
		public PasswordData(byte[] salt, byte[] verifier) {
			
			this.salt = salt;
			this.verifier = verifier;
		}
	}
}
