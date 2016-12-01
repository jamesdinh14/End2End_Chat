/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JavaClientforPHP;

import java.io.IOException;
import java.util.Scanner;

/**
 *
 * @author Kenny
 */
public class clientMain {
   public static void main(String[] args) throws IOException {
      javaClientForPHPService example = new javaClientForPHPService();
      ClientEncryption test = ClientEncryption.getEncryptionInstance();
      // String json = example.register("clienttest",
      // "clientemail","clientpassword");
      String url = "https://teaminsecurity.club/login_api/login.php";
      Scanner sc = new Scanner(System.in);
      System.out.print("enter username: ");
      String uname = sc.nextLine();
      System.out.print("enter email");
      String umail = sc.nextLine();
      System.out.print("enter password");
      String upass = sc.nextLine();
      String response = example.registerPost(url, uname, umail, upass);
      System.out.println(response);

      System.out.print("login user: ");
      String logU = sc.nextLine();
      System.out.print("login password: ");
      String logP = sc.nextLine();
      response = example.loginPost(url, logU, logP);

      // String response =
      // example.post("https://teaminsecurity.club/login_api/register.php",
      // json);
      System.out.println(response);
      System.out.print("enter message: ");
      String message = sc.nextLine();
      System.out.print("enter receiver: ");
      String receiver = sc.nextLine();
      System.out.print("enter JWT(should be automated): ");
      String JWT = sc.nextLine();
      String encryptedMessage = test.encrypt(message);
      String hmacTag = test.HmacSHA256(encryptedMessage);
      String metadata= test.CipherTagConcatenate(hmacTag, encryptedMessage);
      response = example.messagePost(url, JWT, metadata, receiver);
      System.out.println(response);

      System.out.print("Enter JWT(should be automated): ");
      String JWT1 = sc.nextLine();
      response = example.messageGET(url, JWT1);

      ClientEncryption ce = ClientEncryption.getEncryptionInstance();
      String plaintext = "0", ciphertext = "0";
      try {
         ciphertext = ce.encrypt("Hello, world");
      } catch (Exception e) {
         e.printStackTrace();
      }
      System.out.println(ciphertext);

      try {
         plaintext = ce.decrypt(ciphertext, ce.getEncryptionKey());
      } catch (Exception e) {
         e.printStackTrace();
      }
      System.out.println(plaintext);
   }

}
