/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JavaClientforPHP;

import java.io.IOException;
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
      ClientEncryption test = ClientEncryption.getEncryptionInstance();
      String encryptedMessage= null;
      String hmacTag = null;
      Scanner sc = new Scanner(System.in);
      String selection = null;
      boolean ex = true;
      String JWT = null;
      do{
      selection = JOptionPane.showInputDialog(null, "Type the what you want to do. Register, Login, Send message, Read message.");
      switch (selection) {
      
      case "Register":
      String uname = JOptionPane.showInputDialog(null, "Type in your Username.");
      String umail = JOptionPane.showInputDialog(null, "Type in your email.");
      String upass = JOptionPane.showInputDialog(null, "Type in your password.");
      String response = example.registerPost("https://teaminsecurity.club/login_api/register.php", uname, umail, upass);
      JOptionPane.showMessageDialog(null, response);
      break;
      
      
      
      case "Login":
     
      String logU = JOptionPane.showInputDialog(null, "Type in your username.");
      String logP = JOptionPane.showInputDialog(null, "Type in your password.");
      response = example.loginPost("https://teaminsecurity.club/login_api/login.php", logU, logP);
      JOptionPane.showMessageDialog(null, response);
      JWT = response;
      break;
      
      
      
      case "Send message": 
    	
      String message = JOptionPane.showInputDialog(null, "Type your message.");
      String receiver = JOptionPane.showInputDialog(null, "Type who you want to send the message to.");
          try{
           encryptedMessage = test.encrypt(message);
          }catch(Exception e){
        	  e.printStackTrace();
          }
          try {
    		hmacTag = test.HmacSHA256(encryptedMessage, test.getIntegrityKey());
    	} catch (Exception e) {
    	
    		e.printStackTrace();
    	}
          
      String metadata= test.CipherTagConcatenate(hmacTag, encryptedMessage);
      response = example.messagePost("https://teaminsecurity.club/login_api/message.php", JWT, metadata, receiver);
      JOptionPane.showMessageDialog(null, response);
      break;
      
      
      
      default:
    	  JOptionPane.showMessageDialog(null, "wrong input");
    	    JOptionPane.showMessageDialog(null, selection);
          break;
      }
      }while(ex==true);
      
      
      /**
     System.out.print("Enter JWT(should be automated): ");
      String JWT1 = sc.nextLine();
      response = example.messageGET(url, JWT1);
     
      ClientEncryption ce = ClientEncryption.getEncryptionInstance();
      String plaintext = "0", ciphertext = "0", hmacTag="0";
      try {
         ciphertext = ce.encrypt("Hello, world");
      } catch (Exception e) {
         e.printStackTrace();
      }
      System.out.println("ciphertext is " + ciphertext);
      try {
  		hmacTag = ce.HmacSHA256(ciphertext, ce.getIntegrityKey());
  	} catch (Exception e) {
  	
  		e.printStackTrace();
  	}
      System.out.println("hamc is "+hmacTag);
      try {
         plaintext = ce.decrypt(ciphertext, ce.getEncryptionKey());
      } catch (Exception e) {
         e.printStackTrace();
      }
      System.out.println(plaintext);
      
      System.out.println("Test RSA");
      ClientKeyExchange cke = ClientKeyExchange.getKeyExchangeInstance();
      try {
         String cipherKeys = cke.encrypt("Hello world", cke.getMyPublicKey());
         System.out.println(cipherKeys);
         
         cke.QRGeneration(cipherKeys);
         
         String plainKeys = cke.decrypt(cipherKeys);
         System.out.println(plainKeys);
      } catch (Exception e) {
         e.printStackTrace();
      }
    */  
   }
   
   

}
