package com.example;



public class Chat{
		private final long id;
	    private final String content;

	    public Chat(long id, String content) {
	        this.id = id;
	        this.content = content;
	    }

	    public long getId() {
	        return id;
	    }

	    public String getContent() {
	        return content;
	    }

}
