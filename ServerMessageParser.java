package JavaClientforPHP;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Collection of parsing classes to fully parse through the messages from the server
 * @author James
 *
 */
public class ServerMessageParser {

   private static final String MESSAGE_DELIMITER = "\n";
   private static final String ROW_DELIMITER = "&&\\*cecs478enddne\\^#%";
   private static final String COLUMN_DELIMITER = "=>";
   private ArrayList<Message> conversation;
    
   public ServerMessageParser() {
      conversation = new ArrayList<>();
      
   }
   
   void parse(String fullMessage) {
      Message message;
      
      // Tokens should be "sender: senderName", "content: encryptedMessage" and "created_at: timestamp"
      // in that order
      // Message structure: sender + delim + encryptedContent + delim + timestamp + delim
      String[] rows = fullMessage.split(MESSAGE_DELIMITER);
      
      for (int i = 0; i < rows.length; i++) {
         message = new Message();
         String[] columns = rows[i].split(ROW_DELIMITER);
         for (int j = 0; j < columns.length; j++) {
            String[] valuePair = columns[j].split(COLUMN_DELIMITER);
            message.addInformation(valuePair[0], valuePair[1]);
         }
         conversation.add(message);
      }     
   }
   
   public ArrayList<Message> getConversation() {
      return conversation;
   }
   
}
