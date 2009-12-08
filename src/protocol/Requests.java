package protocol;

public class Requests 
{
	// Requests common to both servers, though the results differ.
	public static final byte[] ADD = "ADD".getBytes();
	public static final byte[] UPDATE = "UPDATE".getBytes();

	// Key server specific requests.
	public static final byte[] PUBLIC = "PUBLIC".getBytes();
	public static final byte[] PRIVATE = "PRIVATE".getBytes();
	
	// Chat server specific requests.
	public static final byte[] LOG_ON = "LOG_ON".getBytes();
	public static final byte[] LOG_OFF = "LOG_OFF".getBytes();
}
