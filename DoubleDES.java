//imports for key formatting 
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;

//import from JCE for crypto-related functionalities
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

public class DoubleDES {
	/* This class implements a DoubleDES encryption using an existing DES 
	* implementation from JCE. The class contains two method:
	* 'convertKey': converts a key encoded as a string into a SecretKey.
	* 'main': takes a string argument of two concatenated keys and a string
	* 		  argument holding the plaintext message. Returns the 
	* 		  corresponding cipher text encrypted with DoubleDES. 
	*/
	public static SecretKey convertKey(String hexKey) throws Exception{
		/*
		 * This method converts a key in a format acceptable to JCE.
		 * To do so, we consider the hex key, convert into binary keys and 
		 * add the parity bits before converting back to hex
		 */
		
		// I first convert the first cipher's key from hex to binary 
		long longArgKey1 = Long.parseLong(hexKey, 16);
		String binaryArgKey1 = String.format("%56s", Long.toBinaryString(longArgKey1));
		binaryArgKey1 = binaryArgKey1.replace(' ', '0');
		
		// I now add the parity bits (so that every byte in the key has an odd number of "1" bits)
		for (int i = 0; i < 8; i++) {
			// first I count the number of ones
			int numberOnes = 0;
			for (int x = i*7; x < (i*7)+7; x++) {
				if (binaryArgKey1.charAt(x) == '1') 
					numberOnes++;
			}
			// add parity bit 1 if number of ones is even
			if ((numberOnes % 2) == 0)
				binaryArgKey1 = new StringBuilder(binaryArgKey1).insert(((i+1)*8)-1, '1').toString();
			// add parity bit 0 if number of ones is odd (we are good already)
			else
				binaryArgKey1 = new StringBuilder(binaryArgKey1).insert(((i+1)*8)-1, '0').toString();
		} 

		// we now convert back both keys to hex format
		String parityKey1 = new BigInteger(binaryArgKey1, 2).toString(16);

		// we now convert hex to byte array
		if (parityKey1.length() % 2 == 1) 
			parityKey1 = "0" + parityKey1;
		byte[] byteKey1 = DatatypeConverter.parseHexBinary(parityKey1);
		byte[] encodedKey1 = new byte[8]; 
		for (int i = 0; i < byteKey1.length; i++){
			encodedKey1[i] = byteKey1[i];
		}
		
		//generate secret key in JCE acceptable format using DES SecretKeyFactor
		SecretKeyFactory secretKey1 = SecretKeyFactory.getInstance("DES");
		return (SecretKey) secretKey1.generateSecret(new DESKeySpec(encodedKey1));
	}
	
	public static void main(String[] args) throws Exception {
		/*
		 * input arguments: a pair of keys along with plaintext
		 * output printed on screen: hexadecimal value of cyphertext
		 */
		
		/*
		 * We first use our method convertKey to transform keys of 
		 * 14 hex digits into DES keys in a format acceptable to JCE
		 */
		
		SecretKey myKey1 = convertKey(args[0].substring(0, 14));
		SecretKey myKey2 = convertKey(args[0].substring(14, 28));
		
		/*
		 * Now that we have the keys in the right format, we can proceed 
		 * to encrypting using a succession of two DES ciphers
		 */
		
		// the plain text is encoded in HexBinary so we use parseHexBinary()
		// to parse into bytes
		byte[] plainText = DatatypeConverter.parseHexBinary(args[1]); 
		
		// first DES cipher: to allow for any input size, we use padding
		Cipher myDesCipher1 = Cipher.getInstance("DES/ECB/PKCS5Padding"); 
		myDesCipher1.init(Cipher.ENCRYPT_MODE, myKey1);
		byte[] firstCiphertext = myDesCipher1.doFinal(plainText);
		
		// second DES cipher, no padding this time
		Cipher myDesCipher2 = Cipher.getInstance("DES/ECB/NoPadding");	
		myDesCipher2.init(Cipher.ENCRYPT_MODE, myKey2);
		byte[] secondCipherText = myDesCipher2.doFinal(firstCiphertext);

		//print of the hexadecimal value of the cipher text
		System.out.println(DatatypeConverter.printHexBinary(secondCipherText));
	}
}


