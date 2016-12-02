package JavaClientforPHP;

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
   
   // Define instance variables
   private Cipher cipher;
   private KeyPair keyPair;
   private HashMap<String, Key> publicKeys; // store other public keys here
                                            // Write contents of map to file when program closes
                                            // Read contents of map from file when program starts
   
   // Single instance of class
   private static ClientKeyExchange keyExchangeInstance = null;
   
   private ClientKeyExchange() throws NoSuchAlgorithmException, NoSuchProviderException,
         NoSuchPaddingException {
      String transformation = ALGORITHM + "/" + MODE_OF_OPERATION + "/" + PADDING;
      cipher = Cipher.getInstance(transformation, PROVIDER);
      keyPair = generateKeyPair(); // Consider placing this somewhere else
                                   // Placing it here will result in creating new PK/SKs every time an instance is instantiated
                                   // Which will be whenever program starts
   }
   
   /**
    * On first call, instantiates an instance of this class
    * Later calls will return the existing instance
    * Only accessible by this class and the package
    * 
    * @return single instance of this class
    */
   ClientKeyExchange getKeyExchangeInstance() {
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
      return keyPair.getPublic();
   }
   
   // Consider Remove later
   Key getMyPrivateKey() {
      return keyPair.getPrivate();
   }
}
