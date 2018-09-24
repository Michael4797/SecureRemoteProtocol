package me.michael4797.network.packet;

import java.io.IOException;

import me.michael4797.util.BinaryInput;
import me.michael4797.util.BinaryWriter;

public class PacketServerNegotiate extends Packet{

	private byte[] salt;
	
	
	public PacketServerNegotiate(byte[] salt){
		
		this.salt = salt;
	}
	
	
	public byte[] getSalt(){
		
		return salt;
	}
	
	
	public static PacketServerNegotiate read(BinaryInput reader) throws IOException {
		
		return new PacketServerNegotiate(reader.readByteArray(reader.readByte()&255));
	}

	
	@Override
	public void send(BinaryWriter writer) {

		writer.writeByte((byte) salt.length);
		writer.writeByteArray(salt);
	}
}
