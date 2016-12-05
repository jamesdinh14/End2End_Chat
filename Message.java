package JavaClientforPHP;

import java.util.HashMap;


/**
 * Class that represents the information in one message
 * @author James
 */
public class Message {
   private HashMap<String, String> message;
   private static final String ENCRYPTED_FIELD_KEY = "content";
   
   Message() {
      message = new HashMap<>();
   }
   
   Message(String header, String value) {
      message = new HashMap<>();
      message.put(header, value);
   }
   
   public void addInformation(HashMap<String, String> messageInfo) {
      for(String key : messageInfo.keySet()) {
         message.put(key, messageInfo.get(key));
      }
   }
   
   public void addInformation(String header, String value) {
      message.put(header, value);
   }
   
   public void decryptContents(EncryptionUtil eu) {
      try {
         for (String key : message.keySet()) {
            if (key.equals(ENCRYPTED_FIELD_KEY)) {
               message.replace(key, eu.decryptMessage(message.get(key)));
            }
         }
      } catch (Exception e) {
         e.getMessage();
         e.printStackTrace();
      }
   }
   
   public HashMap<String, String> getMessage() {
      return message;
   }
   
   @Override
   public String toString() {
      String fullMessage = "";
      for (String key : message.keySet()) {
         fullMessage += key + ": " + message.get(key) + "\n";
      }
      return fullMessage + "\n";
   }
}
