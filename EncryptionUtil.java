package JavaClientforPHP;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import JavaClientforPHP.EncryptionUtil.ClientEncryption.EncryptionKeys;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

/**
 * Collection of Encryption classes for both AES and RSA.
 * Acts as an overhead that can combine both class functions into one class.
 * @author James
 *
 */
public class EncryptionUtil {
   
   // Encryption class instances
   private static ClientEncryption encryptionInstance = null;
   private static ClientKeyExchange keyExchangeInstance = null;
   private static EncryptionUtil encryptionUtilInstance = null;
   private static EncryptionKeys encryptionKeys = null;
   
   // Define encryption variables
   // Use Advanced Encryption Standard, Counter with no padding
   // Use a key size of 256 bits
   // HMACSHA256 for hashing
   private static final String ENCRYPTION_ALGORITHM = "AES";
   private static final String ENCRYPTION_MODE = "CTR";
   private static final String ENCRYPTION_PADDING = "NoPadding";
   private static final String HASH_ALGORITHM = "HmacSHA256";
   private static final String PROVIDER = "BC"; //Bouncy Castle
   private static final int AES_KEY_SIZE = 256; // bits
   private static final int IV_SIZE = 16; // IV size = 16 bytes or 128 bits
   
   // Define variables for use in RSA key exchange
   // Use RSA with OAEP padding, 2048 bit keys
   private static final String ALGORITHM = "RSA";
   private static final String MODE_OF_OPERATION = "NONE";
   private static final String PADDING = "OAEPWithSHA-256AndMGF1Padding";
   private static final int RSA_KEY_SIZE = 2048; // bits
   
   /**
    * Default constructor that will instantiate the encryption classes.
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws NoSuchPaddingException
    * @throws URISyntaxException
    * @throws IOException
    * @throws InvalidKeySpecException 
    */
   private EncryptionUtil() throws NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, URISyntaxException, IOException, InvalidKeySpecException {
      if (encryptionInstance == null) {
         encryptionInstance = new ClientEncryption();
      }
      if (keyExchangeInstance == null) {
         keyExchangeInstance = new ClientKeyExchange();
      }
   }
   
   /**
    * Only one instance of this class is allowed.
    * Will instantiate the other classes.
    * If an instance already exists, return that instance
    * 
    * @return an EncryptionUtil instance
    */
   public static EncryptionUtil getEncryptionUtilInstance() {
      try {
        if (encryptionUtilInstance == null) {
           encryptionUtilInstance = new EncryptionUtil();
        }
      } catch (Exception e) {
         e.printStackTrace();
      }
        return encryptionUtilInstance;
   }
   
   /**
    * Performs both AES and RSA encryption on the appropriate portions of the message
    * 
    * @param message - Message to be encrypted and sent
    * @param receiver - The person to whom the message will be sent
    * @return the message encrypted, along with decryption tools
    * @throws MessageFailedToSendException 
    */
   public String encryptMessage(String message, String receiver, String receiverPK) throws MessageFailedToSendException {
      try {
         // Encrypt the given message with AES
         // This chunk of data contains the IV, the message, and then tag
         // but is still missing the symmetric keys needed for decryption
         byte[] messageBulk = encryptionInstance.encrypt(message);
         
         // Get the symmetric keys used in the AES encryption
         byte[] encryptionKey = encryptionKeys.getEncryptionKey().getEncoded();
         byte[] integrityKey = encryptionKeys.getIntegrityKey().getEncoded();
         
         // Concatenate the two keys
         // k(e) + k(i)
         byte[] keys = new byte[encryptionKey.length + integrityKey.length];
         System.arraycopy(encryptionKey, 0, keys, 0, encryptionKey.length);
         System.arraycopy(integrityKey, 0, keys, encryptionKey.length, integrityKey.length);
         
         // Get the receiver's public key and use RSA to encrypt the keys
         byte[] decodeKey = Base64.decode(receiverPK);
         X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodeKey);
         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
         PublicKey receiverPublicKey = keyFactory.generatePublic(keySpec);
         //PublicKey receiverPublicKey = keyExchangeInstance.getPublicKey(receiver);
         byte[] encryptedKeys = keyExchangeInstance.encrypt(keys, receiverPublicKey);
         
         // Append result of AES encryption with RSA-encrypted keys
         byte[] encryptedMessage = new byte[messageBulk.length + encryptedKeys.length];
         System.arraycopy(messageBulk, 0, encryptedMessage, 0, messageBulk.length);
         System.arraycopy(encryptedKeys, 0, encryptedMessage, messageBulk.length, encryptedKeys.length);
         
         // Encode the encryptedMessage to String
         return Base64.toBase64String(encryptedMessage);
      } catch (Exception e) {
         e.printStackTrace();
      }
      
      // If the try fails, then the message failed to send
      throw new MessageFailedToSendException();
   }
   
   
   /**
    * Performs AES and RSA decryption to recover the encrypted message
    * 
    * @param message - ciphertext to be decrypted
    * @return the original message
    * @throws MessageFailedToDecryptException
    */
   public String decryptMessage(String message) throws MessageFailedToDecryptException {
      try {
         // Decode the message from Base64
         byte[] ciphertext = Base64.decode(message);
         
         // Extract the symmetric keys
         byte[] keys = new byte[getRSAKeySizeInBytes()];
         System.arraycopy(ciphertext, ciphertext.length - keys.length, keys, 0, keys.length);
         
         // Decrypt the keys with RSA
         byte[] decryptedKeys = keyExchangeInstance.decrypt(keys);
         
         // Separate the keys
         byte[] encodedEncryptionKey = new byte[getAESKeySizeInBytes()];
         byte[] encodedIntegrityKey = new byte[getAESKeySizeInBytes()];
         System.arraycopy(decryptedKeys, 0, encodedEncryptionKey, 0, encodedEncryptionKey.length);
         System.arraycopy(decryptedKeys, encodedIntegrityKey.length, encodedIntegrityKey, 0, encodedIntegrityKey.length);
         SecretKey encryptionKey = new SecretKeySpec(encodedEncryptionKey, ENCRYPTION_ALGORITHM);
         SecretKey integrityKey = new SecretKeySpec(encodedIntegrityKey, ENCRYPTION_ALGORITHM);
         
         // Obtain a message in the form of the AES encrypt
         // IV + message + tag
         byte[] encryptedMessage = new byte[ciphertext.length - keys.length];
         System.arraycopy(ciphertext, 0, encryptedMessage, 0, encryptedMessage.length);
         
         // Decrypt the message with AES
         return encryptionInstance.decrypt(encryptedMessage, encryptionKey, integrityKey);
      } catch (Exception e) {
         e.printStackTrace();
      }
      
      throw new MessageFailedToDecryptException();
   }

   public void addPublicKey(String username, PublicKey pk) {
      keyExchangeInstance.putPublicKey(username, pk);
   }
   
   public PublicKey getMyPublicKey() {
      return keyExchangeInstance.getMyPublicKey();
   }
   
   int getAESKeySizeInBytes() {
      return AES_KEY_SIZE / Byte.SIZE;
   }
   
   int getRSAKeySizeInBytes() {
      return RSA_KEY_SIZE / Byte.SIZE;
   }
   
   /**
    * @author James (for all encryption/decryption-related methods)
    * @author Kenny (for HMAC and integrity)
    * This class will handle all the encryption and decryption of the messages
    * 
    */
   public class ClientEncryption {
      
      // Security instance variables
      private Cipher cipher;
      private SecretKey encryptionKey; // consider removing these keys after key exchange works
      private SecretKey integrityKey;
      private static final String ERROR_MESSAGE = "Tampering detected. Message was discarded";
      
      /**
       * A bundle that will hold the two symmetric keys used in AES.
       * This class will be used to pass the two keys from the AES class
       * to the RSA class for encryption.
       * @author James
       *
       */
      public class EncryptionKeys {
         SecretKey encryptionKey;
         SecretKey integrityKey;
         
         public EncryptionKeys() {}
         
         public EncryptionKeys(SecretKey eKey, SecretKey iKey) {
            encryptionKey = eKey;
            integrityKey = iKey;
         }

         public void setKeys(SecretKey eKey, SecretKey iKey) {
            encryptionKey = eKey;
            integrityKey = iKey;
         }
         
         public SecretKey getEncryptionKey() {
            return encryptionKey;
         }
         
         public SecretKey getIntegrityKey() {
            return integrityKey;
         }
      }
      
      private ClientEncryption() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
         Security.addProvider(new BouncyCastleProvider());
         String cipherTransformation = ENCRYPTION_ALGORITHM + "/" + ENCRYPTION_MODE + "/" + ENCRYPTION_PADDING;
         cipher = Cipher.getInstance(cipherTransformation, PROVIDER);
      }
      
      /**
       * Encrypt the given plaintext.
       * Prepends the IV and appends the HMAC tag.
       * 
       * @param plaintext - message to be encrypted
       * @return ciphertext - the encrypted message
       * @throws InvalidAlgorithmParameterException 
       * @throws InvalidKeyException 
       * @throws BadPaddingException 
       * @throws IllegalBlockSizeException 
       * @throws NoSuchProviderException 
       * @throws NoSuchAlgorithmException 
       */
      public byte[] encrypt(String plaintext) throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
         IvParameterSpec iv = generateIV();
         
         // Generate FRESH keys for every encrypted message
         encryptionKey = generateKey();
         integrityKey = generateKey();
         
         // Encrypt the plaintext
         cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
         byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
         
         // HMAC the ciphertext
         byte[] tag = HmacSHA256(ciphertext, integrityKey);
         
         // Concatenate the two keys
         // k(e) + k(i)
         byte[] keys = new byte[getAESKeySizeInBytes() + getAESKeySizeInBytes()];
         System.arraycopy(encryptionKey.getEncoded(), 0, keys, 0, getAESKeySizeInBytes());
         System.arraycopy(integrityKey.getEncoded(), 0, keys, getAESKeySizeInBytes(), getAESKeySizeInBytes());
         
         // Create the bulk of the message
         // IV + ciphertext + tag
         byte[] message = new byte[IV_SIZE + ciphertext.length + tag.length];
         
         // Prepend IV to the ciphertext 
         System.arraycopy(iv.getIV(), 0, message, 0, iv.getIV().length); 
         
         // Attach the ciphertext
         System.arraycopy(ciphertext, 0, message, IV_SIZE, ciphertext.length);
         
         // Append the tag
         System.arraycopy(tag, 0, message, iv.getIV().length + ciphertext.length, tag.length);
         
//         encryptionKeys.setKeys(encryptionKey, integrityKey);
         encryptionKeys = new EncryptionKeys(encryptionKey, integrityKey);
         
         return message;
      }
      
      /**
       * Decrypt the given ciphertext using the given key
       * 
       * @param ciphertext - Message to be decrypted
       * @param encryptionKey - Symmetric key used for AES decryption
       * @param integrityKey - Symmetric key used for HMAC tag
       * @return plaintext - the original message decrypted
       * @throws InvalidAlgorithmParameterException 
       * @throws InvalidKeyException 
       * @throws BadPaddingException 
       * @throws IllegalBlockSizeException 
       * @throws NoSuchAlgorithmException 
       */
      public String decrypt(byte[] ciphertext, SecretKey encryptionKey, SecretKey integrityKey)
            throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {         
         // Extract the IV
         byte[] iv = new byte[IV_SIZE];
         System.arraycopy(ciphertext, 0, iv, 0, IV_SIZE);
         
         // Extract the tag
         // HMAC tag is the same size of AES key = 256 bits
         byte[] tag = new byte[getAESKeySizeInBytes()];
         System.arraycopy(ciphertext, ciphertext.length - tag.length, tag, 0, tag.length);
         
         // Extract the message
         int messageLengthInBytes = ciphertext.length - IV_SIZE - tag.length;
         byte[] decodedMessage = new byte[messageLengthInBytes];
         System.arraycopy(ciphertext, IV_SIZE, decodedMessage, 0, messageLengthInBytes);
              
         // Check HMAC tags
         byte[] myTag = HmacSHA256(decodedMessage, integrityKey);
         
         // If the tags match, no tampering occurred
         // Decrypt message
         if (HmacVerify(tag, myTag)) {
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
            
            // Decrypt
            byte[] plaintext = cipher.doFinal(decodedMessage);
            return new String(plaintext);
         } else {
            // If the tags don't match, tampering occurred
            // Don't decrypt
            return new String(ERROR_MESSAGE);
         }
      }
      
      /**
       * Generate a key for use in encryption/integrity
       * 
       * @return key - An AES key
       * @throws NoSuchProviderException 
       * @throws NoSuchAlgorithmException 
       */
      private SecretKey generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
         KeyGenerator keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
         keyGenerator.init(AES_KEY_SIZE);
         
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
      * @throws NoSuchAlgorithmException
      * @throws InvalidKeyException 
      */
      public byte[] HmacSHA256(byte[] ciphertext, SecretKey intkey)
            throws NoSuchAlgorithmException, InvalidKeyException {
         byte[] ik = intkey.getEncoded();
         Mac sha256_HMAC= Mac.getInstance(HASH_ALGORITHM);
         SecretKeySpec sk = new SecretKeySpec(ik, HASH_ALGORITHM);
         sha256_HMAC.init(sk);
         return sha256_HMAC.doFinal(ciphertext);
      }
      
      public String CipherTagConcatenate(String ciphertext, String HmacTag){
         String combined = ciphertext+HmacTag;
         return combined; 
      }
      
      public boolean HmacVerify(byte[] tag1, byte[] tag2){
         return Arrays.equals(tag1, tag2);
      }
      
      public Key getEncryptionKey() {
         return encryptionKey;
      }
      public Key getIntegrityKey() {
        return integrityKey;
      }
   }
   public void QRGeneration() {
  	   String publicKey = keyExchangeInstance.myPublicKeyString();
       String myCodeText = publicKey;
       String filePath = "RsaQR.png";
       int size = 250;
       String fileType = "png";
       File myFile = new File(filePath);
       System.out.println(myFile.getAbsolutePath());
       try {
          
          Map<EncodeHintType, Object> hintMap = new EnumMap<EncodeHintType, Object>(EncodeHintType.class);
          hintMap.put(EncodeHintType.CHARACTER_SET, "UTF-8");
          
          
          hintMap.put(EncodeHintType.MARGIN, 1); 
          hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);

          QRCodeWriter qrCodeWriter = new QRCodeWriter();
          BitMatrix byteMatrix = qrCodeWriter.encode(myCodeText, BarcodeFormat.QR_CODE, size,
                size, hintMap);
          int imgWidth = byteMatrix.getWidth();
          BufferedImage image = new BufferedImage(imgWidth, imgWidth,
                BufferedImage.TYPE_INT_RGB);
          image.createGraphics();

          Graphics2D graphics = (Graphics2D) image.getGraphics();
          graphics.setColor(Color.WHITE);
          graphics.fillRect(0, 0, imgWidth, imgWidth);
          graphics.setColor(Color.BLACK);

          for (int i = 0; i < imgWidth; i++) {
             for (int j = 0; j < imgWidth; j++) {
                if (byteMatrix.get(i, j)) {
                   graphics.fillRect(i, j, 1, 1);
                }
             }
          }
          ImageIO.write(image, fileType, myFile);
       } catch (WriterException e) {
          e.printStackTrace();
       } catch (IOException e) {
          e.printStackTrace();
       }
       System.out.println("\n\nYou have successfully created QR Code.");
    }
   public String readFile(String path, Charset encoding) 
		   throws IOException 
		 {
		   byte[] encoded = Files.readAllBytes(Paths.get(path));
		   return new String(encoded, encoding);
		 }
   
   public class ClientKeyExchange {     
      
      private final String KEYS_FILE_NAME = "keys/keys";
      private final String PRIVATE_KEY_FILE_NAME = "keys/private.key";
      private final String PUBLIC_KEY_FILE_NAME = "keys/public.key";
      
      // Define instance variables
      private Cipher cipher;
//      private KeyPair keyPair;
      private PublicKey publicKey;
      private PrivateKey privateKey;
      private File keyFile, privateKeyFile, publicKeyFile;
      private HashMap<String, PublicKey> publicKeys; // store other public keys here
                                               // Write contents of map to file when program closes
                                               // Read contents of map from file when program starts
      
      
      private ClientKeyExchange() throws NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, URISyntaxException, IOException, InvalidKeySpecException {
         String transformation = ALGORITHM + "/" + MODE_OF_OPERATION + "/" + PADDING;
         cipher = Cipher.getInstance(transformation, PROVIDER);
         
         // Create a new File object for the keys
         keyFile = new File(KEYS_FILE_NAME);
         privateKeyFile = new File(PRIVATE_KEY_FILE_NAME);
         publicKeyFile = new File(PUBLIC_KEY_FILE_NAME);
         publicKeys = new HashMap<>();
         
         // Check if the files exist
         // If not, make the parent directory and then create the files in the directory
         if (!(keyFile.exists() && privateKeyFile.exists() && publicKeyFile.exists())) {
            keyFile.getParentFile().mkdirs();
            keyFile.createNewFile();
            privateKeyFile.createNewFile();
            publicKeyFile.createNewFile();
            
            // Generate a key pair if the local machine doesn't have the keys file
            KeyPair keyPair = generateKeyPair(); 
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            
            writeKeysToFiles();

         } else {
            // If directory and file already exists
            // Read the keys from the file
            readKeysFromFiles();
         }     
      }
      
      /**
       * Encrypts the given plaintext with the given public key
       * 
       * @param plaintext - Message to be encrypted
       * @param key - Public key used for RSA encryption
       * @return the encrypted message
       * @throws InvalidKeyException 
       * @throws BadPaddingException 
       * @throws IllegalBlockSizeException 
       */
      public byte[] encrypt(byte[] plaintext, PublicKey key) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {      
         cipher.init(Cipher.ENCRYPT_MODE, key);

         return cipher.doFinal(plaintext);
      }
      
      /**
       * Decrypts the given ciphertext with your private key
       * 
       * @param ciphertext - Message to be decrypted
       * @return the decrypted message
       * @throws InvalidKeyException
       * @throws IllegalBlockSizeException
       * @throws BadPaddingException
       * @throws NoSuchPaddingException 
       * @throws NoSuchAlgorithmException 
       */
      public byte[] decrypt(byte[] ciphertext) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
         cipher.init(Cipher.DECRYPT_MODE, privateKey);
         
         return cipher.doFinal(ciphertext);
      }
      
      /**
       * Generate the RSA public/private key pair
       * 
       * @return KeyPair - RSA public/private keys
       * @throws NoSuchAlgorithmException
       * @throws NoSuchProviderException
       */
      private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
         KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
         generator.initialize(RSA_KEY_SIZE);
         
         return generator.generateKeyPair();
      }
      
      void putPublicKey(String username, PublicKey publicKey) {
         publicKeys.put(username, publicKey);
      }
      
      final PublicKey getPublicKey(String username) {
         return publicKeys.get(username);
      }
      
      // Test methods
      final PublicKey getMyPublicKey() {
         return publicKey;
      }
      
      public String myPublicKeyString() {
    	  PublicKey sKey= getMyPublicKey();
    	  String keyString = Base64.toBase64String(sKey.getEncoded());
    	  return keyString;
      }
      
      // Consider removing later
      final Key getMyPrivateKey() {
         return privateKey;
      }
 
      /**
       * QR code generation, change path "C:/Users/Kenny/workspace/kkkk/RsaQR.png" to your directory to save .png.
       * 
       */
      
      private void writeKeysToFiles() throws IOException {
         FileOutputStream privateKeyOS = null;
         FileOutputStream publicKeyOS = null;
         
         try {

            
            privateKeyOS = new FileOutputStream(privateKeyFile);
            publicKeyOS = new FileOutputStream(publicKeyFile);
            
            privateKeyOS.write(privateKey.getEncoded());
            publicKeyOS.write(publicKey.getEncoded());
         } catch (IOException ioe) {
            throw ioe;
         } finally {
            try {
               if (privateKeyOS != null) {
                  privateKeyOS.close();
               }
               if (publicKeyOS != null) {
                  publicKeyOS.close();
               }
            } catch (IOException ioe) {
               throw ioe;
            }
         }
      }
      
      private void readKeysFromFiles() throws IOException,
         InvalidKeySpecException, NoSuchAlgorithmException {
         FileInputStream privateKeyIS = null;
         FileInputStream publicKeyIS = null;
         InputStream privateKeyBIS = null; // Buffered Input Stream
         InputStream publicKeyBIS = null;
         
         try {            
            privateKeyIS = new FileInputStream(privateKeyFile);
            publicKeyIS = new FileInputStream(publicKeyFile);
            
            privateKeyBIS = new BufferedInputStream(privateKeyIS);
            publicKeyBIS = new BufferedInputStream(publicKeyIS);
            
            byte[] encodedPublicKey = new byte[RSA_KEY_SIZE];
            publicKeyBIS.read(encodedPublicKey); 
            
            X509EncodedKeySpec x509 = new X509EncodedKeySpec(encodedPublicKey);
            publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(x509);
            
            byte[] encodedPrivateKey = new byte[RSA_KEY_SIZE];
            privateKeyBIS.read(encodedPrivateKey);
            
            PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(encodedPrivateKey);
            privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(pkcs8);
            
         } catch (IOException ioe) {
            throw ioe;
         } finally {
            try {
               if (privateKeyIS != null) {
                  privateKeyIS.close();
               }
               if (publicKeyIS != null) {
                  publicKeyIS.close();
               }
            } catch (IOException ioe) {
               throw ioe;
            }
         }
      }
   }
   
   // Custom exception classes
   public class MessageFailedToSendException extends Exception {
      
      static final String message = "Message failed to send";
      
      public MessageFailedToSendException() {
         super(message);
      }
   }
   
   public class MessageFailedToDecryptException extends Exception {
      
      static final String message = "Message failed to decrypt";
      
      public MessageFailedToDecryptException() {
         super(message);
      }      
   }
   

}
