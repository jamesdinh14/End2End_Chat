CREATE DATABASE IF NOT EXISTS end_to_end; /** Create the Database **/
 
USE end_to_end; /** Select Database **/
 
CREATE TABLE users (
   username varchar(25) PRIMARY KEY UNIQUE,
   name varchar(50),
   email varchar(100) UNIQUE NOT NULL,
   encrypted_password varchar(256) NOT NULL,
   salt varchar(128) UNIQUE NOT NULL
); 

CREATE TABLE messages (
	sender varchar(25) NOT NULL,
	receiver varchar(25) NOT NULL,
	created_at datetime,
	content varchar(140),
	FOREIGN KEY (sender) REFERENCES users(username),
	FOREIGN KEY (receiver) REFERENCES users(username),
	CONSTRAINT pk_message PRIMARY KEY(sender, receiver, created_at)
);