package me.michael4797.network.packet;

import java.io.IOException;

import me.michael4797.util.BinaryInput;
import me.michael4797.util.BinaryWriter;

public class PacketClientNegotiate extends Packet{

	private String username;
	
	
	public PacketClientNegotiate(String username){
		
		this.username = username;
	}
	
	
	public String getUsername(){
		
		return username;
	}
	
	
	public static PacketClientNegotiate read(BinaryInput reader) throws IOException {
		
		return new PacketClientNegotiate(reader.readString());
	}

	
	@Override
	public void send(BinaryWriter writer) {

		writer.writeString(username);
	}
}