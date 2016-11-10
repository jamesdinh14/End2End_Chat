<?php
 
class db_functions {
 
    private $conn;
 
    // constructor
    function __construct() {
        require_once 'db_connect.php';
        // connecting to database
        $db = new db_connect();
        $this->conn = $db->connect();
    }
 
    // destructor
    function __destruct() {
         
    }
 
    /**
     * Storing new user
     * returns user details
     */
    public function storeUser($username, $email, $password, $name="") {
        $hash = $this->hashSSHA($password);
        $encrypted_password = $hash["encrypted"]; // encrypted password
        $salt = $hash["salt"]; // salt
 
        $sql_statement = "INSERT INTO users(username, name, email, encrypted_password, salt) VALUES(?, ?, ?, ?, ?)";
        $stmt = $this->conn->prepare($sql_statement);
        $stmt->bind_param("sssss", $username, $name, $email, $encrypted_password, $salt);
        $result = $stmt->execute();
        $stmt->close();
 
        // check for successful store
        if ($result) {
            $stmt = $this->conn->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();
 
            return $user;
        } else {
            return false;
        }
    }

    /**
     * Store new message
     */
    public function sendMessage($sender, $receiver, $content) {
        $sql_statement = "INSERT INTO messages(sender, receiver, content, created_at) VALUES (?, ?, ?, NOW())";
        $stmt = $this->conn->prepare($sql_statement); // CODE STOPS HERE
        echo "Statement prepared";
        $stmt->bind_param("sss", $sender, $receiver, $content);
        echo "Params binded";

        $result = $stmt->execute();
        $stmt->close();
        //$response = array("status" => "error", "status_message" => "");

        return $result;
        // if ($result) {
        //     return true;
        // } else {
        //     return false;
        // }

        
    }

    /**
     * Get new messages
     */
    public function getMessages($user, $sender="") {
        $sql_statement = "SELECT sender, content FROM messages WHERE receiver = ? ORDER BY created_at ASC";
        $stmt = $this->conn->prepare($sql_statement);
        $stmt->bind_param("s", $user);
        $stmt->execute();

        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            while ($message = $result->fetch_assoc()) {
                $messages[] = $message; // Append message to the messages array
            }
            return $messages;
        }

        return NULL;
    }
 
    /**
     * Get user by username and password
     */
    public function getUserByUsernameAndPassword($username, $password) {
 
        $stmt = $this->conn->prepare("SELECT * FROM users WHERE username = ?");
 
        $stmt->bind_param("s", $username);
 
        if ($stmt->execute()) {
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();
 
            // verifying user password
            $salt = $user['salt'];
            $encrypted_password = $user['encrypted_password'];
            $hash = $this->checkhashSSHA($salt, $password);
            // check for password equality
            if ($encrypted_password == $hash) {
                // user authentication details are correct
                return $user;
            }
        } else {
            return NULL;
        }
    }
 
    /**
     * Check user is existed or not, using either email or username
     */
    public function isUserExisted($email, $username=NULL) {

    	// If email and username are null, some error happened
        if (is_null($email) && is_null($username)) {
    		return false;
    	}
    	
    	// Prep variable strings for the sql statement
    	$column_name = "email";
    	$seach_param = $email;

    	// If there's a value for username,
    	// search the database using the username rather than email
    	if (!is_null($username)) {
    		$column_name = "username";
    		$search_param = $username;
	   }
	
        $sql_statement = "SELECT {$column_name} FROM users WHERE {$column_name} = ?";

        $stmt = $this->conn->prepare($sql_statement);
    	$stmt->bind_param("s", $search_param);
 
        $stmt->execute();
 
        $stmt->store_result();
 
        if ($stmt->num_rows > 0) {
            // user existed 
            $stmt->close();
            return true;
        } else {
            // user not existed
            $stmt->close();
            return false;
        }
    }
 
    /**
     * Encrypting password
     * @param password
     * returns salt and encrypted password
     */
    public function hashSSHA($password) {

        $salt = hash("sha256", mt_rand());
        $salt = substr($salt, 0, 128);
	
        $encrypted = base64_encode(hash("sha256", $password . $salt) . $salt);
        $hash = array("salt" => $salt, "encrypted" => $encrypted);
        return $hash;
    }
 
    /**
     * Decrypting password
     * @param salt, password
     * returns hash string
     */
    public function checkhashSSHA($salt, $password) {
 
        $hash = base64_encode(hash("sha256", $password . $salt) . $salt);
 
        return $hash;
    }

}
 
?>