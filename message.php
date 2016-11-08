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


if ($_SERVER["REQUEST_METHOD"] === "POST") {
	$http_headers = apache_request_headers();
	$jwt_header = $http_headers['Authorization'];
	$jwt = str_replace('Bearer ', '', $jwt_header);
	//$data = file_get_contents('php://input');

	try {
		$token = JWT::decode($jwt, SECRET_KEY, array(ALGORITHM));
		$token_data = (array) $token;

		$sender = $token_data["data"]->username;

		$message = $_POST["message"];
		$receiver = $_POST["receiver"];

		//$stuff = array("jwt" => $jwt, "post params" => $data, "sender" => $sender, "message" => $message, "receiver" => $receiver);
		//print_r($stuff);

		if ($db->isUserExisted(NULL, $receiver)) {
			if ($db->sendMessagw($sender, $receiver, $message)) {
				echo "Message sent";
			} else {
				echo "Message failed to send";
			}
		} else {
			echo "Receiver does not exist";
		}
	} catch (Exception $e) {
		echo "Token could not be decoded";
	}
}


?>
