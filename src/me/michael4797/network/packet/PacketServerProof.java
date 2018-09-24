package me.michael4797.network.packet;

import java.io.IOException;

import me.michael4797.util.BinaryInput;
import me.michael4797.util.BinaryWriter;

public class PacketServerProof extends Packet{

	private byte[] HAMK;
	
	
	public PacketServerProof(byte[] HAMK){
		
		this.HAMK = HAMK;
	}
	
	
	public byte[] getHAMK(){
		
		return HAMK;
	}
	
	
	public static PacketServerProof read(BinaryInput reader) throws IOException {
		
		return new PacketServerProof(reader.readByteArray(reader.readByte()&255));
	}

	
	@Override
	public void send(BinaryWriter writer) {

		writer.writeByte((byte) HAMK.length);
		writer.writeByteArray(HAMK);
	}
}