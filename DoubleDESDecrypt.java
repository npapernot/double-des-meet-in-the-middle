//imports for key formatting 
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;

//import from JCE for crypto-related functionalities
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
		
public class DoubleDESDecrypt {
	/* This class implements a DoubleDES decryption using an existing DES 
	* implementation from JCE. The class contains one method:
	* 'main': takes a string argument of two concatenated keys and a string
	* 		  argument holding the ciphertext message. Returns the 
	* 		  corresponding plaintext encrypted with DoubleDES. 
	*/
	public static void main(String[] args) throws Exception {
		/*
		 * input arguments: a pair of keys along with cyphertext
		 * output printed on screen: hexadecimal value of plaintext
		 */
		
		/*
		 * We first use our function convertKey to transform keys of 
		 * 14 hex digits into DES keys in a format acceptable to JCE
		 */
		
		//creating this instance so we can access the convertKey method
		DoubleDES doubleDES = new DoubleDES();
		SecretKey myKey1 = doubleDES.convertKey(args[0].substring(0, 14));
		SecretKey myKey2 = doubleDES.convertKey(args[0].substring(14, 28));
		
		/*
		 * Now that we have the keys in the right format, we can proceed 
		 * to decrypting using a succession of two DES ciphers
		 */
		
		//the plain text is encoded in HexBinary so we use parseHexBinary() to parse into bytes
		byte[] cypherText = DatatypeConverter.parseHexBinary(args[1]); 
		
		// second DES cipher (we reverse the order because we are now decrypting)
		Cipher myDesCipher2 = Cipher.getInstance("DES/ECB/NoPadding");	
		myDesCipher2.init(Cipher.DECRYPT_MODE, myKey2);
		byte[] secondCipherText = myDesCipher2.doFinal(cypherText);
		
		// first DES cipher (we reverse the order because we are now decrypting)
		Cipher myDesCipher1 = Cipher.getInstance("DES/ECB/PKCS5Padding"); //to allow for any input size, we use padding
		myDesCipher1.init(Cipher.DECRYPT_MODE, myKey1);
		byte[] plainText = myDesCipher1.doFinal(secondCipherText);

		// print of the hexadecimal value of the cipher text
		System.out.println(DatatypeConverter.printHexBinary(plainText));
	}
}
