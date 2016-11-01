package com.example;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

public class chatDAO {
			public List<Chat> getAllClients(){
				List<Chat> clientList = null;
				try{
					File file = new File("client.dat");
					if (!file.exists()){
						Chat client = new Chat(1, "Bob");
						clientList = new ArrayList<Chat>();
						clientList.add(client);
						saveClientList(clientList);
					}
					else{
						FileInputStream fis = new FileInputStream(file);
			            ObjectInputStream ois = new ObjectInputStream(fis);
			            clientList = (List<Chat>) ois.readObject();
			            ois.close();
					}
				}	catch (IOException e) {
			         e.printStackTrace();
			      } catch (ClassNotFoundException e) {
			         e.printStackTrace();
			      }	
				return clientList;
				
			}
			public Chat getClient(long id){
				List<Chat> clients = getAllClients();
				
				for(Chat client: clients){
					if(client.getId()== id){
						return client;
					}
				}
				return null;
			}
			public int addClient(Chat nclient){
				 List<Chat> clientList = getAllClients();
			      boolean clientExists = false;
			      for(Chat client: clientList){
			         if(client.getId() == nclient.getId()){
			            clientExists = true;
			            break;
			         }
			      }	
			      if(!clientExists){
			          clientList.add(nclient);
			          saveClientList(clientList);
			          return 1;
			       }
			       return 0;
			}
			public int updateClient(Chat nclient){
			      List<Chat> clientList = getAllClients();

			      for(Chat client: clientList){
			         if(client.getId() == nclient.getId()){
			            int index = clientList.indexOf(client);			
			            clientList.set(index, nclient);
			            saveClientList(clientList);
			            return 1;
			         }
			      }		
			      return 0;
			   }
			 public int deleteClient(long id){
			      List<Chat> clientList = getAllClients();

			      for(Chat client: clientList){
			         if(client.getId() == id){
			            int index = clientList.indexOf(client);			
			            clientList.remove(index);
			            saveClientList(clientList);
			            return 1;   
			         }
			      }		
			      return 0;
			   }
			 private void saveClientList(List<Chat> clientList){
			      try {
			         File file = new File("clients.dat");
			         FileOutputStream fos;

			         fos = new FileOutputStream(file);

			         ObjectOutputStream oos = new ObjectOutputStream(fos);		
			         oos.writeObject(clientList);
			         oos.close();
			      } catch (FileNotFoundException e) {
			         e.printStackTrace();
			      } catch (IOException e) {
			         e.printStackTrace();
			      }
			   }
}
