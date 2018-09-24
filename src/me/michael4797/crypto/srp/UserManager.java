package me.michael4797.crypto.srp;

import me.michael4797.crypto.srp.SRPUser.PasswordData;

/**
 * Manages persistence of user password information.
 */
public interface UserManager {

	/**
	 * Retrieves stored password data for the specified user.
	 * @param username The user to lookup.
	 * @return The password salt/verifier for the specified user.
	 * @throws SRPException If the user does not exist or an error was encountered
	 * while accessing the user's password data.
	 */
	PasswordData getUserData(String username) throws SRPException;
}
