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
   // String json = example.register("clienttest", "clientemail","clientpassword");
    Scanner sc = new Scanner(System.in);
    System.out.print("enter username: ");
    String uname= sc.nextLine();
    System.out.print("enter email");
    String umail = sc.nextLine();
    System.out.print("enter password");
    String upass = sc.nextLine();
    String response = example.registerPost("https://teaminsecurity.club/login_api/register.php",uname,umail,upass);
    System.out.println(response);
    
    System.out.print("login user: ");
    String logU = sc.nextLine();
    System.out.print("login password: ");
    String logP = sc.nextLine();
    response = example.loginPost("https://teaminsecurity.club/login_api/login.php", logU, logP);
    
    //String response = example.post("https://teaminsecurity.club/login_api/register.php", json);
    System.out.println(response);
  }
    
}
