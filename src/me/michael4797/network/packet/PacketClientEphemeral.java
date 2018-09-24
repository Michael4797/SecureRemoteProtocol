package me.michael4797.network.packet;

import java.io.IOException;

import me.michael4797.util.BinaryInput;
import me.michael4797.util.BinaryWriter;

public class PacketClientEphemeral extends Packet{

	private byte[] A;
	
	
	public PacketClientEphemeral(byte[] A){
		
		this.A = A;
	}
	
	
	public byte[] getA(){
		
		return A;
	}
	

	public static PacketClientEphemeral read(BinaryInput reader) throws IOException {
		
		return new PacketClientEphemeral(reader.readByteArray(reader.readShort()&65535));
	}

	
	@Override
	public void send(BinaryWriter writer) {

		writer.writeShort((short) A.length);
		writer.writeByteArray(A);
	}
}