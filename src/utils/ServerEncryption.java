package utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import utils.kserver.KSConstants;

public class ServerEncryption 
{
        public static byte[] unsign(byte[] signed)
        {
                try
                {
                        RSAPublicKey key = Constants.getServerPrimaryKey();
                        Cipher rsaCipher = Cipher.getInstance(Constants.SERVER_SIGN_MODE);
                        rsaCipher.init(Cipher.ENCRYPT_MODE, key);
                        return rsaCipher.doFinal(signed);
                }
                // Should be unreachable.
                catch(NoSuchAlgorithmException e) { e.printStackTrace(); }
                catch (NoSuchPaddingException e) { e.printStackTrace(); } 
                //TODO: Handle corrupted etc. key files.
                catch (InvalidKeyException e) { e.printStackTrace(); } 
                catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
                catch (BadPaddingException e) { e.printStackTrace(); }
                return null;
        }
        
        public static byte[] sign(byte[] toSign)
        {
        	try
            {
                    RSAPrivateKey key = KSConstants.serverPrivateKey();
                    Cipher rsaCipher = Cipher.getInstance(Constants.SERVER_SIGN_MODE);
                    rsaCipher.init(Cipher.DECRYPT_MODE, key);
                    return rsaCipher.doFinal(toSign);
            }
            // Should be unreachable.
            catch(NoSuchAlgorithmException e) { e.printStackTrace(); }
            catch (NoSuchPaddingException e) { e.printStackTrace(); } 
            //TODO: Handle corrupted etc. key files.
            catch (InvalidKeyException e) { e.printStackTrace(); } 
            catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
            catch (BadPaddingException e) { e.printStackTrace(); }
            return null;
        }
}
