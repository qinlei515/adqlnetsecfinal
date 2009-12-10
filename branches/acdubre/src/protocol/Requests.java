package protocol;

/**
 * Set of byte arrays common to servers and clients.
 * 
 * Used primarily by servers to determine what type of request they've received,
 * but are used on the client side as well, to distinguish traffic direction when
 * setting up client-client connections and when receiving chat log notifications.
 * 
 * @author Alex Dubreuil
 *
 */
public class Requests 
{
	// Requests common to both servers, though the effects differ.
	public static final byte[] ADD = "ADD".getBytes();
	public static final byte[] UPDATE = "UPDATE".getBytes();
	public static final byte[] CONFIRM = "CONFIRM".getBytes();
	public static final byte[] DENY = "DENY".getBytes();
	public static final byte[] SALT = "SALT".getBytes();
	// Not used
	public static final byte[] SERVER_KEY_RESET = "SKRESET".getBytes();

	// Key server specific requests.
	public static final byte[] PUBLIC = "PUBLIC".getBytes();
	public static final byte[] PRIVATE = "PRIVATE".getBytes();
	
	// Chat server specific requests.
	public static final byte[] LOG_ON = "LOG_ON".getBytes();
	public static final byte[] LOG_OFF = "LOG_OFF".getBytes();
}
