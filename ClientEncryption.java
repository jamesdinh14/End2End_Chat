package JavaClientforPHP;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 * @author James (for all encryption/decryption-related methods)
 * @author Kenny (for HMAC and integrity)
 * This class will handle all the encryption and decryption of the messages
 * 
 * Simpleton class to ensure that only one instance of encryption is allowed
 */
public class ClientEncryption {

   // Define encryption variables
   // Use Advanced Encryption Standard, Counter with no padding
   // Use a key size of 256 bits
   private static final String ENCRYPTION_ALGORITHM = "AES";
   private static final String ENCRYPTION_MODE = "CTR";
   private static final String ENCRYPTION_PADDING = "NoPadding"; 
   private static final String provider = "BC"; //Bouncy Castle
   private static final int KEY_SIZE = 256; // bits
   private static final int IV_SIZE = 16; // IV size = 16 bytes or 128 bits
   private static final int PASSWORD_LENGTH = 16; // Used for random password
   
   // Security instance variables
   private Cipher cipher;
   private Key encryptionKey;
   private Key integrityKey;
   
   private static ClientEncryption encryptionInstance = null;
   
   private ClientEncryption() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
      Security.addProvider(new BouncyCastleProvider());
      String cipherTransformation = ENCRYPTION_ALGORITHM + "/" + ENCRYPTION_MODE + "/" + ENCRYPTION_PADDING;
      cipher = Cipher.getInstance(cipherTransformation, provider);
      encryptionKey = generateKey();
      integrityKey = generateKey();
   }
   
   /**
    * Performs initialization on first call
    * Returns already initialized object on later calls
    * 
    * @return the one instance of this class
    */
   public static ClientEncryption getEncryptionInstance() {
      try {
         if (encryptionInstance == null) {
            encryptionInstance = new ClientEncryption();
         }
      } catch (Exception e) {
         // Something went wrong with the initialization
         e.printStackTrace();
      }
      return encryptionInstance;
   }
   
   /**
    * Re-initializes the instance
    * Use to refresh the instance if any of the security variables need to be changed (i.e. keys)
    * @return a re-initialized instance of this class
    */
   public static ClientEncryption resetEncryptionInstance() {
      try {
         encryptionInstance = new ClientEncryption();
      } catch (Exception e) {
         e.printStackTrace();
      }
      return encryptionInstance;
   }
   
   /**
    * Encrypt the given plaintext
    * 
    * @param message - message to be encrypted
    * @return ciphertext - the input message encrypted
    * @throws InvalidAlgorithmParameterException 
    * @throws InvalidKeyException 
    * @throws BadPaddingException 
    * @throws IllegalBlockSizeException 
    */
   public String encrypt(String plaintext) throws InvalidKeyException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
      IvParameterSpec iv = generateIV();
      
      cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
      byte[] encryptedMessage = cipher.doFinal(plaintext.getBytes());
      
      // Prepend iv to encrypted message
      byte[] ciphertext = new byte[IV_SIZE + encryptedMessage.length];
      
      // Prepend IV to the ciphertext 
      System.arraycopy(iv.getIV(), 0, ciphertext, 0, iv.getIV().length); 
      
      // Attach the encrypted message 
      System.arraycopy(encryptedMessage, 0, ciphertext, IV_SIZE, encryptedMessage.length);
      
      return Base64.toBase64String(ciphertext);
   }
   
   /**
    * Decrypt the given ciphertext using the given key
    * 
    * @param ciphertext
    * @param key
    * @return plaintext - the original message decrypted
    * @throws InvalidAlgorithmParameterException 
    * @throws InvalidKeyException 
    * @throws BadPaddingException 
    * @throws IllegalBlockSizeException 
    */
   public String decrypt(String ciphertext, Key key)
         throws InvalidKeyException, InvalidAlgorithmParameterException,
         IllegalBlockSizeException, BadPaddingException {
      byte[] decodedBytes = Base64.decode(ciphertext);
      
      // Extract the IV
      byte[] iv = new byte[IV_SIZE];
      System.arraycopy(decodedBytes, 0, iv, 0, IV_SIZE);
      
      cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
      
      // Extract the message
      int messageLengthInBytes = decodedBytes.length - IV_SIZE;
      byte[] decodedMessage = new byte[messageLengthInBytes];
      System.arraycopy(decodedBytes, IV_SIZE, decodedMessage, 0, messageLengthInBytes);
      
      // Decrypt
      byte[] plaintext = cipher.doFinal(decodedMessage);
      return new String(plaintext);
   }
   
   /**
    * Generate a key for use in encryption/integrity
    * 
    * @return key - An AES key
    * @throws NoSuchProviderException 
    * @throws NoSuchAlgorithmException 
    */
   private Key generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
      KeyGenerator keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
      keyGenerator.init(KEY_SIZE);
      
      return keyGenerator.generateKey();
   }
   
   /**
    * Generate an initialization vector for the encryption process (i.e. AES/CTR)
    * 
    * @return IV - initialization vector
    */
   private IvParameterSpec generateIV() {
      byte[] ivBytes = new byte[16];
      
      // SecureRandom will automatically seed itself on the nextBytes call
      SecureRandom random = new SecureRandom();
      random.nextBytes(ivBytes);
      
      return new IvParameterSpec(ivBytes);
   }

   /**
   * HMAC SHA 256
   */
   public String HmacSHA256(String ciphertext, Key integrityKey) throws Exception{
	  byte[] ik = integrityKey.getEncoded();
      Mac sha256_HMAC= Mac.getInstance("HmacSHA256");
      SecretKeySpec sk = new SecretKeySpec(ik, "HmacSHA256");
      sha256_HMAC.init(sk);
      String tag= Base64.toBase64String(sha256_HMAC.doFinal(ciphertext.getBytes()));
      return tag;
   }
   
   public String CipherTagConcatenate(String ciphertext, String HmacTag){
	   String combined = ciphertext+HmacTag;
	   return combined; 
   }
   
   public void HmacVerify(String tag1, String tag2){
	   if(tag1.equals(tag2)){
		   System.out.println("Hmac test passed!");
	   } else
	      System.out.println("HMAC does not match!");
   }
   
   public Key getEncryptionKey() {
      return encryptionKey;
   }
   public Key getIntegrityKey() {
	  return integrityKey;
   }
}
