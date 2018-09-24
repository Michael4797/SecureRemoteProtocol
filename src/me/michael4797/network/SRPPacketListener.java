package me.michael4797.network;

import me.michael4797.annotation.PacketHandler;
import me.michael4797.crypto.srp.SRPException;
import me.michael4797.network.packet.PacketClientEphemeral;
import me.michael4797.network.packet.PacketClientNegotiate;
import me.michael4797.network.packet.PacketClientProof;
import me.michael4797.network.packet.PacketSRPError;
import me.michael4797.network.packet.PacketServerEphemeral;
import me.michael4797.network.packet.PacketServerNegotiate;
import me.michael4797.network.packet.PacketServerProof;

/**
 * Implements the Secure Remote Protocol by listening for SRP packets and
 * responding with the next step in the authentication procedure.
 */
public class SRPPacketListener extends PacketListener{

	
	@PacketHandler
	public void onClientNegotiate(SRPSession session, PacketClientNegotiate packet) {
		
		try {
			
			session.clientNegotiate(packet.getUsername());
		} catch (SRPException e) {
			
			session.failAuthentication();
			session.sendPacketReliably(new PacketSRPError(e.getError()));
			session.launchPacket();
		}
	}

	
	@PacketHandler
	public void onServerNegotiate(SRPSession session, PacketServerNegotiate packet) {
		
		try {
			
			session.serverNegotiate(packet.getSalt());
		} catch (SRPException e) {
			
			session.failAuthentication();
			session.sendPacketReliably(new PacketSRPError(e.getError()));
			session.launchPacket();
		}
	}

	
	@PacketHandler
	public void onClientEphemeral(SRPSession session, PacketClientEphemeral packet) {
		
		try {
			
			session.clientEphemeral(packet.getA());
		} catch (SRPException e) {
			
			session.failAuthentication();
			session.sendPacketReliably(new PacketSRPError(e.getError()));
			session.launchPacket();
		}
	}

	
	@PacketHandler
	public void onServerEphemeral(SRPSession session, PacketServerEphemeral packet) {

		try {
			
			session.serverEphemeral(packet.getB());
		} catch (SRPException e) {
			
			session.failAuthentication();
			session.sendPacketReliably(new PacketSRPError(e.getError()));
			session.launchPacket();
		}
	}

	
	@PacketHandler
	public void onClientProof(SRPSession session, PacketClientProof packet) {

		try {
			
			session.clientProof(packet.getM());
		} catch (SRPException e) {
			
			session.failAuthentication();
			session.sendPacketReliably(new PacketSRPError(e.getError()));
			session.launchPacket();
		}
	}

	
	@PacketHandler
	public void onServerProof(SRPSession session, PacketServerProof packet) {

		try {
			
			session.serverProof(packet.getHAMK());
		} catch (SRPException e) {
			
			session.failAuthentication();
			session.sendPacketReliably(new PacketSRPError(e.getError()));
			session.launchPacket();
		}
	}

	
	@PacketHandler
	public void onSRPError(SRPSession session, PacketSRPError packet) {
		
		session.failAuthentication();
	}
}
