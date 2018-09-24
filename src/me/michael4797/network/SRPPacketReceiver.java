package me.michael4797.network;

import java.net.InetSocketAddress;

import me.michael4797.crypto.srp.UserManager;
import me.michael4797.network.packet.PacketClientEphemeral;
import me.michael4797.network.packet.PacketClientNegotiate;
import me.michael4797.network.packet.PacketClientProof;
import me.michael4797.network.packet.PacketSRPError;
import me.michael4797.network.packet.PacketServerEphemeral;
import me.michael4797.network.packet.PacketServerNegotiate;
import me.michael4797.network.packet.PacketServerProof;
import me.michael4797.network.protocol.SessionHandle;
import me.michael4797.network.protocol.TransportProtocol;

/**
 * An extension of the BasePacketReceiver that adds SRP packets and generates
 * {@link SRPSession SRPSessions}.
 */
public class SRPPacketReceiver extends BasePacketReceiver{
	
	protected final UserManager users;
	
	
	public SRPPacketReceiver(int port, UserManager users) {
		
		this(port, TransportProtocol.UDP_SYNC, users);
	}
	
	
	public SRPPacketReceiver(int port, TransportProtocol protocol, UserManager users) {
		
		super(port, protocol);
		this.users = users;
		
		addPacket(PacketClientNegotiate.class, PacketClientNegotiate::read);
		addPacket(PacketClientEphemeral.class, PacketClientEphemeral::read);
		addPacket(PacketClientProof.class, PacketClientProof::read);
		addPacket(PacketServerNegotiate.class, PacketServerNegotiate::read);
		addPacket(PacketServerEphemeral.class, PacketServerEphemeral::read);
		addPacket(PacketServerProof.class, PacketServerProof::read);
		addPacket(PacketSRPError.class, PacketSRPError::read);
		addListener(new SRPPacketListener());
	}
	

	@Override
	protected SRPSession createSession(SessionHandle handle) {

		return new SRPSession(handle, users, new BaseSessionProtocol());
	}
	

	@Override
	public SRPSession openConnection(InetSocketAddress to) {

		return (SRPSession) super.openConnection(to);
	}


	@Override
	protected Class<? extends SRPSession> getSessionType() {

		return SRPSession.class;
	}
}
