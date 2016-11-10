<?php

require_once 'db/db_functions.php';
require_once 'vendor/autoload.php';
use \Firebase\JWT\JWT;
$db = new db_functions();

/*
if (isset($_POST["message"]) && isset($_POST["receiver"])) {
	
	$message = $_POST["message"];
	$receiver = $_POST["receiver"];
	$http_headers = apache_request_headers();
	$jwt_header = $http_headers['Authorization'];
	$jwt = str_replace('Bearer ', '', $jwt_header);

	try{
		$token = JWT::decode($jwt, SECRET_KEY, array(ALGORITHM));

		$token_data = (array) $token;

		// extract the necessary info
		$sender = $token_data["data"]->username;
		echo "$sender\n";

		if ($db->isUserExisted(NULL, $receiver)) { 
			if ($db->storeMessage($sender, $receiver, $message)) {
				echo "Message sent";
			} else {
				echo "Message failed to send";
			}
		} else {
			echo "Receiver does not exist";
		}
	} catch (Exception $e) {
		// Token was unabled to be decoded
		// Possibility of unverified signature (tampering)
		echo "Token could not be decoded";
	}
}
*/

// Receive POST request from Postman/client
if ($_SERVER["REQUEST_METHOD"] === "POST") {
	$http_headers = apache_request_headers(); // Get all headers from POST
	$jwt_header = $http_headers['Authorization']; // Get the Authorization header (should contain "Bearer <token>")
	$jwt = str_replace('Bearer ', '', $jwt_header); // Get rid of "Bearer" leaving only the JWT
	//$data = file_get_contents('php://input');

	try {
		$token = JWT::decode($jwt, SECRET_KEY, array(ALGORITHM)); // Decode the JWT, key and algorithm found in config.php
		$token_data = (array) $token; // Convert payload into array

		$sender = $token_data["data"]->username; // Access the sender's username from the JWT

		$message = $_POST["message"]; // Receive params from the POST request
		$receiver = $_POST["receiver"];

		$stuff = array("jwt" => $jwt, "post params" => $data, "sender" => $sender, "message" => $message, "receiver" => $receiver);
		print_r($stuff);

		if ($db->isUserExisted(NULL, $receiver)) {
			if ($db->sendMessage($sender, $receiver, $message)) {
				echo "Message sent";
			} else {
				echo "Message failed to send";
			}
		} else {
			echo "Receiver does not exist";
		}
	} catch (Exception $e) {
		echo "Token could not be decoded. " . $e->getMessage();
	}
}


// Receive GET request
if ($_SERVER["REQUEST_METHOD"] === "GET") {

	// Extract JWT from GET request header
	$http_headers = apache_request_headers();
	$jwt_header = $http_headers['Authorization'];
	$jwt = str_replace('Bearer ', '', $jwt_header);

	try {
		$token = JWT::decode($jwt, SECRET_KEY, array(ALGORITHM)); // Decode JWT
		$token_data = (array) $token;

		$user = $token_data["data"]->username;

		if ($db->isUserExisted(NULL, $user)) {
			$messages = $db->getMessages($user);
			if ($messages) {
				printMessages($messages);
			} else {
				echo "No new messages";
			}
		}
	} catch (Exception $e) {
		echo "Token could not be decoded. " . $e->getMessage();
	}
}

function printMessages($messages) {
	foreach ($messages as $message) {
		foreach ($message as $key => $value) {
			echo "{$key}: {$value}\n";
		}
		echo "\n";
	}
} 

?>
