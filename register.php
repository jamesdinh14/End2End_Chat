<?php
 
require_once 'db/db_functions.php';
$db = new db_functions();
 
// json response array
$response = array("error" => FALSE);
 
if (isset($_POST['username']) && isset($_POST['name']) && isset($_POST['email']) && isset($_POST['password'])) {
 
    // receiving the post params
    $username = $_POST['username'];
    $name = $_POST['name'];
    $email = $_POST['email'];
    $password = $_POST['password'];
 
    // check if user is already existed with the same email
    if ($db->isUserExisted($email)) {
        // user already existed
        $response["error"] = TRUE;
        $response["error_msg"] = "User already existed with email, " . $email;
        echo json_encode($response);
    } else if ($db->isUserExisted($username)) {
    	// check for clash in usernames
	$response["error"] = TRUE;
	$response["error_msg"] = "User already exists with username, " . $username;
	echo json_encode($response);
    } else {
        // create a new user
        $user = $db->storeUser($username, $name, $email, $password);
        if ($user) {
            // user stored successfully
            $response["error"] = FALSE;
            $response["username"] = $user["username"];
            $response["user"]["name"] = $user["name"];
            $response["user"]["email"] = $user["email"];
            echo json_encode($response);
        } else {
            // user failed to store
            $response["error"] = TRUE;
            $response["error_msg"] = "Unknown error occurred in registration!";
            echo json_encode($response);
        }
    }
} else {
    $response["error"] = TRUE;
    $response["error_msg"] = "Required parameters (username, name, email or password) is missing!";
    echo json_encode($response);
}
?>