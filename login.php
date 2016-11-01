<?php
require_once 'db/db_functions.php';
require_once 'vendor/autoload.php';

use \Firebase\JWT\JWT;
// SECRET KEY HERE
define('ALGORITHM', 'HS256');

$db = new db_functions();
 
// json response array
$response = array("error" => FALSE);
 
if (isset($_POST['username']) && isset($_POST['password'])) {
 
    // receiving the post params
    $username = $_POST['username'];
    $password = $_POST['password'];
 
    // get the user by username and password
    $user = $db->getUserByUsernameAndPassword($username, $password);
 
    if ($user != NULL) {
        // user is found
        $tokenId = base64_encode(mcrypt_create_iv(32));
	$issuedAt = time();
	$notBefore = $issuedAt + 10; // Add 10 seconds
	$expire = $notBefore + 7200; // Add 60 seconds
	$serverName = 'https://teaminsecurity.club';

	// Create the token as an array
	$data = [
		'iat' => $issuedAt, // time when the token was generated
		'jti' => $tokenId, // unique identifier for the token
		'iss' => $serverName, //issuer
		'nbf' => $notBefore, // Not before
		'exp' => $expire, // Expiration
		'data' => [
			'username' => $user['username'], // username from the users table
			'name' => $user['name'],
			'email' => $user['email']
		]
	];

	$secretKey = base64_encode(SECRET_KEY);

	// Transform the data array into a JWT
	$jwt = 	JWT::encode(
		   $data, // data to be encoded in the JWT
		   $secretKey, // signing key
		   ALGORITHM
		);
	
	echo $jwt;
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