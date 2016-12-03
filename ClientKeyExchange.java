package JavaClientforPHP;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class ClientKeyExchange {

   // Define variables for use in RSA key exchange
   // Use RSA with OAEP padding, 2048 bit keys
   private static final String ALGORITHM = "RSA";
   private static final String MODE_OF_OPERATION = "None";
   private static final String PADDING = "OAEPWithSHA-256AndMGF1Padding";
   private static final String PROVIDER = "BC"; // Bouncy Castle
   private static final int KEY_SIZE = 2048; // bits
   private static final String FILE_PARENT_DIRECTORY = "keys";
   private static final String FILE_NAME = "keys.txt";
   
   
   // Define instance variables
   private Cipher cipher;
//   private KeyPair keyPair;
   private Key publicKey;
   private Key privateKey;
   private HashMap<String, Key> publicKeys; // store other public keys here
                                            // Write contents of map to file when program closes
                                            // Read contents of map from file when program starts
   private File keyFile;
   
   // Single instance of class
   private static ClientKeyExchange keyExchangeInstance = null;
   
   private ClientKeyExchange() throws NoSuchAlgorithmException, NoSuchProviderException,
         NoSuchPaddingException, URISyntaxException, IOException {
      String transformation = ALGORITHM + "/" + MODE_OF_OPERATION + "/" + PADDING;
      cipher = Cipher.getInstance(transformation, PROVIDER);
      KeyPair keyPair = generateKeyPair(); // Consider placing this somewhere else
                                           // Placing it here will result in creating new PK/SKs every time an instance is instantiated
                                           // Which will be whenever program starts
      publicKey = keyPair.getPublic();
      privateKey = keyPair.getPrivate();
      
      // Get the file path of the parent directory
      // Should get C://.../End2End_Client/bin
      URL fileParentDirectory = clientMain.class.getProtectionDomain().getCodeSource().getLocation();
      
      // Get parent of bin, which should be .../End2End_Client/
      File grandparent = (new File(fileParentDirectory.toURI())).getParentFile();
      
      // Form the key directory path, C://.../End2End_Client/keys
      String keyFilePath = grandparent.toString() + File.separator + FILE_PARENT_DIRECTORY + File.separator + FILE_NAME;
            
      // Make a File object to represent the file ".../keys/keys.txt"
      keyFile = new File(keyFilePath);
      
      // Check if the parent directory exists
      // If not, make the parent directory and then create the file in the directory
      if (!(keyFile.exists())) {
         keyFile.getParentFile().mkdirs();
         keyFile.createNewFile();
      } else {
         // If directory and file already exists
         // Read the keys from the file
         
      }
      
   }
   
   /**
    * On first call, instantiates an instance of this class
    * Later calls will return the existing instance
    * Only accessible by this class and the package
    * 
    * @return single instance of this class
    */
   static ClientKeyExchange getKeyExchangeInstance() {
      try {
         if (keyExchangeInstance == null) {
            keyExchangeInstance = new ClientKeyExchange();
         }
      } catch (Exception e) {
         e.printStackTrace();
      }
      return keyExchangeInstance;
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
      generator.initialize(KEY_SIZE);
      
      return generator.generateKeyPair();
   }
   
   // Test methods
   Key getMyPublicKey() {
      return publicKey;
   }
   
   // Consider removing later
   Key getMyPrivateKey() {
      return privateKey;
   }
}
