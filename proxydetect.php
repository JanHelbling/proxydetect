<?php
/*********************************************************************************************
*	proxydetect.php  Copyright (C) 2013 by Jan Helbling <jan.helbling@gmail.com>
*	This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
*	This is free software, and you are welcome to redistribute it
*	under certain conditions; type `show c' for details.
**********************************************************************************************/
	
	
	// HTTP-Proxy-Headers
	$proxy_headers	=	array(
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_X_REAL_IP',
		'HTTP_X_CLIENT_IP',
		'HTTP_X_FORWARDED_HOST',
		'HTTP_X_FORWARDED_SERVER',
		'HTTP_FORWARDED_FOR',
		'HTTP_CLIENT_IP',
		'HTTP_VIA', 
        	'HTTP_FORWARDED',
        	'HTTP_FORWARDED_FOR_IP',
        	'VIA',
        	'X_FORWARDED_FOR',
        	'FORWARDED_FOR',
        	'X_FORWARDED',
        	'FORWARDED',
        	'CLIENT_IP',
        	'FORWARDED_FOR_IP',
        	'HTTP_PROXY_CONNECTION'
	);
	
	//Ports to scan
	$scan_ports		=	array(
		80,
		443,
		3128,
		8080,
	);
	
	
	//List of ports to compare with the remoteport.
	$ports			=	array(
		78,
		79,
		80,
		81,
		82,
		83,
		443,
		3128,
		8080,
		8081,
		8090,
		8181,
		8282,
		8888,
		9050,
		9999
	);
	
	function check_if_proxy(){
		global $proxy_headers,$scan_ports,$ports;
		
		foreach($proxy_headers as $header){
			if(isset($_SERVER[$header])){
				return true;
			}
		}
		
		foreach($scan_ports as $port){
			if(@fsockopen($_SERVER['REMOTE_ADDR'], $port, $errstr, $errno, 1)){
				return true;
			}
		}
		
		foreach($ports as $port){
			 if($_SERVER["REMOTE_PORT"] == $port){
				return true;
			}
		}
		return false;
	}
?>
