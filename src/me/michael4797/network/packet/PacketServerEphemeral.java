package me.michael4797.network.packet;

import java.io.IOException;

import me.michael4797.util.BinaryInput;
import me.michael4797.util.BinaryWriter;

public class PacketServerEphemeral extends Packet{

	private byte[] B;
	
	
	public PacketServerEphemeral(byte[] B){
		
		this.B = B;
	}
	
	
	public byte[] getB(){
		
		return B;
	}
	
	
	public static PacketServerEphemeral read(BinaryInput reader) throws IOException {
		
		return new PacketServerEphemeral(reader.readByteArray(reader.readShort()&65535));
	}

	
	@Override
	public void send(BinaryWriter writer) {

		writer.writeShort((short) B.length);
		writer.writeByteArray(B);
	}
}