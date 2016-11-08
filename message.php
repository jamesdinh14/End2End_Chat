<?php

require_once 'db/db_functions.php';
require_once 'vendor/autoload.php';
use \Firebase\JWT\JWT;
$db = new db_functions();

if (isset($_POST["message"]) && isset($_POST["receiver"]) && isset($_POST["JWT"])) {
	
	$message = $_POST["message"];
	$receiver = $_POST["receiver"];
	$jwt = $_POST["JWT"];

	try{
		$token = JWT::decode($jwt, SECRET_KEY, array(ALGORITHM));

		$token_data = (array) $token;

		// extract the necessary info
		$sender = $token_data["data"]->username;

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


?>
