package me.michael4797.crypto.srp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import me.michael4797.crypto.srp.SRPException.AuthenticationFailedException;
import me.michael4797.crypto.srp.SRPUser.PasswordData;
import me.michael4797.util.BinaryInputStream;
import me.michael4797.util.BinaryOutputStream;

/**
 * A basic implementation of a UserManager that stores user password salt/verifiers
 * as individual files.
 */
public class BaseUserManager implements UserManager{

	private final String directory;
	
	public BaseUserManager(String directory) {
		
		this.directory = directory;
	}
	
	
	@Override
	public PasswordData getUserData(String username) throws SRPException {

		try {
			File file = new File(directory, username + ".key");
			if(file.exists() && file.isFile()) {
				
				BinaryInputStream in = new BinaryInputStream(new FileInputStream(file));
				byte[] salt = in.readByteArray(16);
				byte[] verifier = in.readByteArray(256);				
				in.close();
				
				return new PasswordData(salt, verifier);
			}
		}catch(IOException e) {}
		
		throw new SRPException.AuthenticationFailedException();
	}
	
	
	public void setUserData(String username, PasswordData data) throws AuthenticationFailedException {
		
		try {
			File file = new File(directory, username + ".key");
			if(!file.exists()) {
				
				BinaryOutputStream out = new BinaryOutputStream(new FileOutputStream(file));
				out.writeByteArray(data.salt);
				out.writeByteArray(data.verifier);
				out.close();
			}
		}catch(IOException e) {}
		
		throw new SRPException.AuthenticationFailedException();
	}
}
