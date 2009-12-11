package utils.constants;

/**
 * Ports information that for chat server and key server to read.
 * Client program will not use this file, instead it will read server configuration
 * information from a txt file at client side.
 * 
 * @author Alex Dubreuil
 *
 */
public class Ports 
{
	public static final int CHAT_SERVER_PORT = 6417;
	public static final int CHAT_NOTIFY_PORT = 6418;
	
	public static final int KEY_SERVER_PORT = 6473;
	public static final int MESSAGE_PORT = 7418;
}
