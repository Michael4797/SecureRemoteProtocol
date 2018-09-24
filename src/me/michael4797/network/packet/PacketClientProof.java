package me.michael4797.network.packet;

import java.io.IOException;

import me.michael4797.util.BinaryInput;
import me.michael4797.util.BinaryWriter;

public class PacketClientProof extends Packet{

	private byte[] M;
	
	
	public PacketClientProof(byte[] M){
		
		this.M = M;
	}
	
	
	public byte[] getM(){
		
		return M;
	}


	public static PacketClientProof read(BinaryInput reader) throws IOException {
		
		return new PacketClientProof(reader.readByteArray(reader.readByte()&255));
	}

	
	@Override
	public void send(BinaryWriter writer) {

		writer.writeByte((byte) M.length);
		writer.writeByteArray(M);
	}
}