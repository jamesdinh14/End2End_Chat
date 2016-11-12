/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JavaClientforPHP;

import java.io.*;
import java.util.Scanner;
import java.io.IOException;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
/**
 *
 * @author Kenny
 */
public class javaClientForPHPService {
  public static final MediaType mediaType = MediaType.parse("multipart/form-data; boundary=---011000010111000001101001");
  /* commented out non working dynamic input with json.
  public static final MediaType JSON
      = MediaType.parse("application/json; charset=utf-8");
*/

  OkHttpClient client = new OkHttpClient();

  String post(String url, String username, String email, String password) throws IOException {
    RequestBody body = RequestBody.create(mediaType, "-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n"+username+"\r\n-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\n"+email+"\r\n-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n"+password+"\r\n-----011000010111000001101001--");
    /*
    RequestBody body = RequestBody.create(JSON, json);
    */
    Request request = new Request.Builder()
        .url(url)
        .post(body)
        .build();
    try (Response response = client.newCall(request).execute()) {
      return response.body().string();
    }
  }
//register() is suppose to fill in json body
  String register(String name, String email, String password) {
        return "{'username':'testclient',"
        + "'email':'testclientemail',"
        + "'password':'testpassword'"
        + "}";
  }

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
    String response = example.post("https://teaminsecurity.club/login_api/register.php",uname,umail,upass);
    //String response = example.post("https://teaminsecurity.club/login_api/register.php", json);
    System.out.println(response);
  }
}