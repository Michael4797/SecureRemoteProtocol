package me.michael4797.network.packet;

import java.io.IOException;

import me.michael4797.crypto.srp.SRPException;
import me.michael4797.util.BinaryInput;
import me.michael4797.util.BinaryWriter;

public class PacketSRPError extends Packet{
	
	private byte error;
	
	
	public PacketSRPError(byte error){
		
		this.error = error;
	}
	
	
	public byte getError(){
		
		return error;
	}
	
	
	public SRPException getException(){
		
		return SRPException.fromByte(error);
	}
	
	
	public static PacketSRPError read(BinaryInput reader) throws IOException {
		
		return new PacketSRPError(reader.readByte());
	}

	
	@Override
	public void send(BinaryWriter writer) {

		writer.writeByte(error);
	}
}


