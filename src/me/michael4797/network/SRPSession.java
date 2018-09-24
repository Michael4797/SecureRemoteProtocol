package me.michael4797.network;

import me.michael4797.crypto.srp.UserManager;
import me.michael4797.network.packet.PacketClientEphemeral;
import me.michael4797.network.packet.PacketClientNegotiate;
import me.michael4797.network.packet.PacketClientProof;
import me.michael4797.network.packet.PacketServerEphemeral;
import me.michael4797.network.packet.PacketServerNegotiate;
import me.michael4797.network.packet.PacketServerProof;
import me.michael4797.network.protocol.SessionHandle;
import me.michael4797.crypto.srp.SRPException;
import me.michael4797.crypto.srp.SRPServer;
import me.michael4797.crypto.srp.SRPUser;
import me.michael4797.crypto.srp.SRPUser.PasswordData;

/**
 * An extension to the base Session class that adds functionality for authenticating clients
 * using SRP and checking the authentication state of the client.
 */
public class SRPSession extends Session{

	private final Object lock = new Object();
	private boolean authenticated = false;
	private final UserManager manager;
	private SRPServer server;
	private SRPUser user;
	
	/**
	 * Creates a new SRPSession, backed by the specified {@link SessionHandle}, using the specified {@link SessionProtocol}
	 * and using the specified {@link UserManager} to retrieve password data for authentication.
	 * @param handle The SessionHandle created by the underlying protocol.
	 * @param manager The UserManager used to retrieve password data for clients.
	 * @param protocol The SessionProtocol used by this Session.
	 */
	public SRPSession(SessionHandle handle, UserManager manager, SessionProtocol protocol) {
		
		super(handle, protocol);
		this.manager = manager;
	}
	
	
	@Override
	protected synchronized void onDisconnect() {
		
		if(server != null || user != null) {
			
			synchronized(lock) {
				
				server = null;
				user = null;
				authenticated = false;
				lock.notifyAll();
			}
		}
		
		super.onDisconnect();
	}
	
	/**
	 * Begins authenticating as a client with the specified username and password.
	 * @param username The username to authenticate.
	 * @param password The password.
	 * @throws SRPException If an authentication is already in progress.
	 */
	public synchronized void startAuthentication(String username, String password) throws SRPException {
		
		if(server != null || user != null)
			throw new SRPException.IncorrectProtocolException();
		
		if(authenticated)
			authenticated = false;
		
		user = new SRPUser(username, password);
		sendPacketReliably(new PacketClientNegotiate(username));
		launchPacket();
	}
	
	/**
	 * Retrieves the salt for the specified user and sends the appropriate response.
	 * @param username The username of the client to being authenticating.
	 * @throws SRPException If an error is encountered during the authentication.
	 */
	protected synchronized void clientNegotiate(String username) throws SRPException {
		
		if(server != null || user != null)
			throw new SRPException.IncorrectProtocolException();
		
		PasswordData data = manager.getUserData(username);
		server = new SRPServer(username, data.salt, data.verifier);

		sendPacketReliably(new PacketServerNegotiate(data.salt));
		launchPacket();
	}
	
	/**
	 * Sets the salt for this client, generates the client ephemeral, and sends the appropriate response.
	 * @param salt The salt used to generate the password verifier.
	 * @throws SRPException If an error is encountered during the authentication.
	 */
	protected synchronized void serverNegotiate(byte[] salt) throws SRPException {
		
		if(server != null || user == null)
			throw new SRPException.IncorrectProtocolException();
		
		user.setSalt(salt);

		sendPacketReliably(new PacketClientEphemeral(user.getA()));
		launchPacket();
	}
	
	/**
	 * Sets the client ephemeral, generates the server ephemeral, and sends the appropriate response.
	 * @param A The client ephemeral.
	 * @throws SRPException If an error is encountered during the authentication.
	 */
	protected synchronized void clientEphemeral(byte[] A) throws SRPException {
		
		if(server == null || user != null)
			throw new SRPException.IncorrectProtocolException();
		
		server.setA(A);

		sendPacketReliably(new PacketServerEphemeral(server.getB()));
		launchPacket();
	}
	
	/**
	 * Sets the server ephemeral, generates the client proof, and sends the appropriate response.
	 * @param B The server ephemeral.
	 * @throws SRPException If an error is encountered during the authentication.
	 */
	protected synchronized void serverEphemeral(byte[] B) throws SRPException {
		
		if(server != null || user == null)
			throw new SRPException.IncorrectProtocolException();
		
		user.setB(B);

		sendPacketReliably(new PacketClientProof(user.getM()));
		launchPacket();
	}
	
	/**
	 * Verifies the client proof, generates the server proof, and sends the appropriate response.
	 * This finishes the authentication process for the server.
	 * @param M The client proof.
	 * @throws SRPException If an error is encountered during the authentication.
	 */
	protected synchronized void clientProof(byte[] M) throws SRPException {
		
		if(server == null || user != null)
			throw new SRPException.IncorrectProtocolException();
		
		byte[] HAMK = server.getHAMK(M);

		sendPacketReliably(new PacketServerProof(HAMK));
		launchPacket();
		
		authenticated = true;
		server = null;
		user = null;
	}
	
	/**
	 * Verifies the server proof. The authentication process is finished upon successfully returning
	 * from a call to this method.
	 * @param HAMK The server proof.
	 * @throws SRPException If an error is encountered during the authentication.
	 */
	protected synchronized void serverProof(byte[] HAMK) throws SRPException {
		
		if(server != null || user == null)
			throw new SRPException.IncorrectProtocolException();
		
		user.verify(HAMK);
		authenticated = true;
		server = null;
		user = null;
		
		synchronized(lock) {
			lock.notifyAll();
		}
	}
	
	/**
	 * Called if the authentication process fails at any step after being started.
	 */
	protected void failAuthentication() {
		
		user = null;
		server = null;

		synchronized(lock) {
			lock.notifyAll();
		}
	}
	
	/**
	 * Called by a client to wait until authentication is complete. When the client calls this function,
	 * the current thread will block until the authentication is finished. This does not mean that the
	 * authentication succeeded, just that no more responses from the server are expected. If a server
	 * calls this method, it will return immediately.
	 */
	public void waitUntilAuthenticated() {
		
		if(user == null)
			return;
		
		synchronized(lock) {			
			while(!authenticated && user != null) {
				try{
					lock.wait();
				}catch(InterruptedException e) {}
			}
		}
	}

	/**
	 * Returns true if this Session has successfully been authenticated.
	 * @return The authenticated state of this Session.
	 */
	public boolean isAuthenticated() {
		
		return authenticated;
	}
}
