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

/**
 *
 * @author Kenny
 */
public class clientMain {
   public static void main(String[] args) throws IOException {
	   /*
      javaClientForPHPService example = new javaClientForPHPService();
      ClientEncryption test = ClientEncryption.getEncryptionInstance();
      String encryptedMessage= null;
      String hmacTag = null;
      Scanner sc = new Scanner(System.in);
      
//      System.out.print("enter username: ");
//      String uname = sc.nextLine();
//      System.out.print("enter email");
//      String umail = sc.nextLine();
//      System.out.print("enter password");
//      String upass = sc.nextLine();
//      String response = example.registerPost("https://teaminsecurity.club/login_api/register.php", uname, umail, upass);
//      System.out.println(response);

      System.out.print("login user: ");
      String logU = sc.nextLine();
      System.out.print("login password: ");
      String logP = sc.nextLine();
      String response = example.loginPost("https://teaminsecurity.club/login_api/login.php", logU, logP);
      System.out.println(response);
      String JWT = response;
     
      System.out.print("enter message: ");
      String message = sc.nextLine();
      System.out.print("enter receiver: ");
      String receiver = sc.nextLine();
//      System.out.print("enter JWT(should be automated): ");
//      String JWT = sc.nextLine();
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
      System.out.println(response);
	
     System.out.print("Enter JWT(should be automated): ");
      String JWT1 = sc.nextLine();
      response = example.messageGET(url, JWT1);
       */
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
      
   }
   
   

}
