/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JavaClientforPHP;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.swing.JOptionPane;

/**
 *
 * @author Kenny
 */
public class clientMain {
   public static void main(String[] args) throws IOException {
	   
	
      javaClientForPHPService example = new javaClientForPHPService();
//      ClientEncryption test = ClientEncryption.getEncryptionInstance();
      EncryptionUtil eu = EncryptionUtil.getEncryptionUtilInstance();
      eu.QRGeneration();
      String encryptedMessage= null;
      String hmacTag = null;
      Scanner sc = new Scanner(System.in);
      String selection = null;
      boolean ex = true;

      String myUsername = null;
      String JWT = null;
      do{
      selection = JOptionPane.showInputDialog(null, "Type the what you want to do. Register, Login, Send message, Read message.");
      selection.toLowerCase();
      switch (selection) {
      
      case "register":

      String uname = JOptionPane.showInputDialog(null, "Type in your Username.");
      String umail = JOptionPane.showInputDialog(null, "Type in your email.");
      String upass = JOptionPane.showInputDialog(null, "Type in your password.");
      String response = example.registerPost("https://teaminsecurity.club/login_api/register.php", uname, umail, upass);
      JOptionPane.showMessageDialog(null, response);
      break;
      
      
      case "Login":

      case "login":

      String logU = JOptionPane.showInputDialog(null, "Type in your username.");
      String logP = JOptionPane.showInputDialog(null, "Type in your password.");
      response = example.loginPost("https://teaminsecurity.club/login_api/login.php", logU, logP);
      JOptionPane.showMessageDialog(null, response);
      myUsername = logU;
      JWT = response;
      break;
      
      
      case "send": 
    	
      String message = JOptionPane.showInputDialog(null, "Type your message.");
      String receiver = JOptionPane.showInputDialog(null, "Type who you want to send the message to.");
//          try{
//           encryptedMessage = test.encrypt(message);
//          }catch(Exception e){
//        	  e.printStackTrace();
//          }
//          try {
//    		hmacTag = test.HmacSHA256(encryptedMessage, test.getIntegrityKey());
//    	} catch (Exception e) {
//    	
//    		e.printStackTrace();
//    	}
      
      String eMessage = null;
   
      try {
    	 String rePK = eu.readFile("repk.txt", StandardCharsets.UTF_8);
         eu.addPublicKey(myUsername, eu.getMyPublicKey());
         eMessage = eu.encryptMessage(message, receiver, rePK);
      } catch (Exception e) {
         e.getMessage();
         e.printStackTrace();
      }
      
//      String metadata= test.CipherTagConcatenate(hmacTag, encryptedMessage);
      response = example.messagePost("https://teaminsecurity.club/login_api/message.php", JWT, eMessage, receiver);
      JOptionPane.showMessageDialog(null, response);
      break;
      
      case "get":
         String url = "https://teaminsecurity.club/login_api/message.php";
//         System.out.println(example.messageGET(url, JWT));
         String messages = example.messageGET(url, JWT);
         ServerMessageParser smp = new ServerMessageParser();
         smp.parse(messages);
         
         for (Message m : smp.getConversation()) {
            try {
               m.decryptContents(eu);
               System.out.println(m.toString());
            } catch (Exception e) {
               e.getMessage();
               e.printStackTrace();
            }
         }
         
         break;
      
      default:
    	  JOptionPane.showMessageDialog(null, "wrong input");
    	    JOptionPane.showMessageDialog(null, selection);
          break;
      }
      }while(ex==true);  
   }
   
   

}
