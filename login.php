<?php
require_once 'db/db_functions.php';
require_once('vendor/autoload.php');

use \Firebase\JWT\JWT;
define('SECRET_KEY', 'team_insecurity')
define('ALGORITHM', 'HS256')

$db = new db_functions();
 
// json response array
$response = array("error" => FALSE);
 
if (isset($_POST['username']) && isset($_POST['password'])) {
 
    // receiving the post params
    $username = $_POST['username'];
    $password = $_POST['password'];
 
    // get the user by email and password
    $user = $db->getUserByUsernameAndPassword($username, $password);
 
    if ($user != NULL) {
        // user is found
        $tokenId = base64_encode(mcrypt_create_iv(32));
	$issuedAt = time();
	$notBefore = $issuedAt + 10; // Add 10 seconds
	$expire = $notBefore + 7200; // Add 60 seconds
	//$serverName = 'https://teaminsecurity.club';
	$serverName = 'https://localhost';

	// Create the token as an array
	$data = [
		'iat' => $issuedAt, // time when the token was generated
		'jti' => $tokenId, // unique identifier for the token
		'iss' => $serverName, //issuer
		'nbf' => $notBefore, // Not before
		'exp' => $expire, // Expiration
		'data' => [
			'username' => $row[0]['username'], // username from the users table
			'name' => $row[0]['name'],
			'email' => $row[0]['email']
		]
	];

	$secretKey = base64_decode(SECRET_KEY);

	// Transform the data array into a JWT
	$jwt = 	JWT::encode(
		   $data, // data to be encoded in the JWT
		   $secretKey, // signing key
		   ALGORITHM
		);
	$unencodedArray = ['jwt' => $jwt];
	
	$response["error"] = FALSE;
	$response["data"] = $data;
	echo json_encode($response);
    } else {
        // user is not found with the credentials
        $response["error"] = TRUE;
        $response["error_msg"] = "Login credentials are wrong. Please try again!";
        echo json_encode($response);
    }
} else {
    // required post params is missing
    $response["error"] = TRUE;
    $response["error_msg"] = "Required parameters username or password is missing!";
    echo json_encode($response);
}
?>