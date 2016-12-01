package JavaClientforPHP;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author James
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
    * Use to refresh the instance if any of the security variables need to be
    *  changed (i.e. keys)
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
    * @return ciphertext - the input message encrypted using the input key
    * @throws InvalidAlgorithmParameterException 
    * @throws InvalidKeyException 
    * @throws BadPaddingException 
    * @throws IllegalBlockSizeException 
    */
   public String encrypt(String plaintext) throws InvalidKeyException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
      SecureRandom secureRandom = new SecureRandom();
      IvParameterSpec iv = generateIV(secureRandom);
      
      cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
      byte[] encryptedMessage = cipher.doFinal(plaintext.getBytes());
      
      // Prepend iv to encrypted message
      byte[] ciphertext = new byte[IV_SIZE + encryptedMessage.length];
      
      // Prepend IV to the ciphertext 
      System.arraycopy(iv, 0, ciphertext, 0, IV_SIZE); 
      
      // Attach the encrypted message 
      System.arraycopy(encryptedMessage, 0, ciphertext, IV_SIZE, encryptedMessage.length);
      
      return new String(ciphertext);
   }
   
   /**
    * Decrypt the given ciphertext using the given key
    * 
    * @param ciphertext
    * @param key
    * @param iv
    * @return plaintext
    * @throws InvalidAlgorithmParameterException 
    * @throws InvalidKeyException 
    * @throws BadPaddingException 
    * @throws IllegalBlockSizeException 
    */
   public String decrypt(String ciphertext, Key key, IvParameterSpec iv)
         throws InvalidKeyException, InvalidAlgorithmParameterException,
         IllegalBlockSizeException, BadPaddingException {
      cipher.init(Cipher.DECRYPT_MODE, key, iv);
      byte[] plaintext = cipher.doFinal(ciphertext.getBytes());
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
      KeyGenerator keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM, provider);
      keyGenerator.init(KEY_SIZE);
      return keyGenerator.generateKey();
   }
   
   /**
    * Generate an initialization vector for the encryption process (i.e. AES/CTR)
    * 
    * @param random - A SecureRandom source to produce a pseudorandom IV 
    * @return IV - initialization vector
    */
   private IvParameterSpec generateIV(SecureRandom random) {
      // SecureRandom will automatically seed itself on the nextBytes call
      byte[] ivBytes = new byte[16];
      random.nextBytes(ivBytes);
      
      return new IvParameterSpec(ivBytes);
   }
}
