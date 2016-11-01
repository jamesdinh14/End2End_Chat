CREATE DATABASE IF NOT EXISTS end_to_end; /** Create the Database **/
 
USE end_to_end; /** Select Database **/
 
CREATE TABLE users (
   username varchar(25) PRIMARY KEY UNIQUE,
   name varchar(50),
   email varchar(100) UNIQUE NOT NULL,
   encrypted_password varchar(80) NOT NULL,
   salt varchar(256) NOT NULL
); 
