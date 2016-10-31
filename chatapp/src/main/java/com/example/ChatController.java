package com.example;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ChatController {
	chatDAO chatDAO = new chatDAO();
    private static final String template = "Hello, %s!";
    private final AtomicLong counter = new AtomicLong();
    private static final String SUCCESS_RESULT = "<result>success</result>";
    private static final String FAILURE_RESULT = "<result>failure</result>";
    
    
    @RequestMapping( method= RequestMethod.POST)
    public String addChat(@RequestParam("ID")long userID, @RequestParam(value="name", defaultValue="nada") String name){
    	Chat chat = new Chat(userID, name);
    	int result = chatDAO.addClient(chat);
    	if(result ==1){return SUCCESS_RESULT;}
    	return FAILURE_RESULT;
}
    @RequestMapping(value="/chat/{ID}", method= RequestMethod.GET)
    public Chat readChat(@PathVariable("ID") long ID) {
        return chatDAO.getClient(ID);
    }
    
    @RequestMapping(value="/chat/class", method = RequestMethod.GET)
    public Chat readChat(@RequestParam(value="name", defaultValue="nada")String name, @RequestParam(value="id", defaultValue ="01")long id){
    	return new Chat(id, name);
    }
}
