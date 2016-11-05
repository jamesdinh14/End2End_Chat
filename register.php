<?php
 
require_once 'db/db_functions.php';
$db = new db_functions();
 
// json response array
$response = array("status" => "error");
 
if (isset($_POST['username']) && isset($_POST['email']) && isset($_POST['password'])) {
 
    // receiving the post params
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = $_POST['password'];
    
    // Name is an optional parameter
    $name = "";
    if (isset($_POST['name'])) {
	   $name = $_POST['name'];
    }
    // check if user is already existed with the same email
    if ($db->isUserExisted($email)) {
        // user already existed
        $response["error_msg"] = "User already existed with email, " . $email;
        echo json_encode($response);
    } else if ($db->isUserExisted(NULL, $username)) {
    	// check for clash in usernames
	$response["error_msg"] = "User already exists with username, " . $username;
	echo json_encode($response);
    } else {
        // create a new user
        $user = $db->storeUser($username, $email, $password, $name);
        if ($user) {
            // user stored successfully
            $response["status"] = "success";
            $response["username"] = $user["username"];
	    $response["user"]["email"] = $user["email"];
	    if ($name) {
            $response["user"]["name"] = $user["name"];
	    }
            echo json_encode($response);
        } else {
            // user failed to store
            $response["error_msg"] = "Unknown error occurred in registration!";
            echo json_encode($response);
        }
    }
} else {
    $response["error_msg"] = "Required parameters (username, email or password) is missing!";
    echo json_encode($response);
}
?>