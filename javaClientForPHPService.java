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

   OkHttpClient client = new OkHttpClient();

   String registerPost(String url, String username, String email,
         String password) throws IOException {
      RequestBody body = new FormBody.Builder().add("username", username)
            .add("email", email).add("password", password).build();

      Request request = new Request.Builder().url(url).post(body).build();
      try (Response response = client.newCall(request).execute()) {
         return response.body().string();
      }
   }

   String loginPost(String url, String username, String password)
         throws IOException {
      RequestBody body = new FormBody.Builder().add("username", username)
            .add("password", password).build();
      Request request = new Request.Builder().url(url).post(body).build();
      try (Response response = client.newCall(request).execute()) {
         return response.body().string();
      }
   }

   String messagePost(String url, String JWT, String message, String receiver)
         throws IOException {
      RequestBody body = new FormBody.Builder().add("receiver", receiver)
            .add("message", message).build();
      Request request = new Request.Builder().url(url).post(body)
            .header("Authorization", "Bearer " + JWT).build();
      try (Response response = client.newCall(request).execute()) {
         return response.body().string();
      }
   }

   String messageGET(String url, String key) throws IOException {
      Request request = new Request.Builder().url(url).get()
            .addHeader("authorization", key).build();
      try (Response response = client.newCall(request).execute()) {
         return response.body().string();
      }
   }

}