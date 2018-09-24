package me.michael4797.crypto.srp;

/**
 * The super class for all SRPExceptions thrown during an authentication attempt.
 */
public abstract class SRPException extends Throwable{

	private static final long serialVersionUID = 1L;
	public SRPException(){}
	public static SRPException fromByte(byte id){
		
		for(Class<?> clazz : SRPException.class.getDeclaredClasses()){
			
			SRPException exception;
			try {
				exception = clazz.asSubclass(SRPException.class).newInstance();
			} catch (Exception e){
				throw new RuntimeException("Error error", e);
			}
			if(exception.getError() == id)
				return exception;
		}
		
		return null;
	}
	public abstract byte getError();
	
	/**
	 * Thrown if the remote client failed to authenticated themselves as the server
	 * or as the client.
	 */
	public static class AuthenticationFailedException extends SRPException{
		private static final long serialVersionUID = 1L;
		public static final byte id = 0;
		@Override
		public byte getError() {
			return id;
		}			
	}
	
	/**
	 * Thrown if the remote client sent unexpected, malicious, malformed, or incorrectly ordered data.
	 */
	public static class IncorrectProtocolException extends SRPException{
		private static final long serialVersionUID = 1L;
		public static final byte id = 1;
		@Override
		public byte getError() {
			return id;
		}			
	}
	
	/**
	 * Thrown if a user is unable to be created due to an existing user sharing the same identifier.
	 */
	public static class UserAlreadyExistsException extends SRPException{
		private static final long serialVersionUID = 1L;
		public static final byte id = 2;
		@Override
		public byte getError() {
			return id;
		}			
	}
}
