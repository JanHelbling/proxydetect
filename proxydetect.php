<?php
/*********************************************************************************************
*   proxydetect.php  Copyright (C) 2013 by Jan Helbling <jan.helbling@mailbox.org>
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation, either version 3 of the License, or
*   (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
				return "Header: ".$_SERVER[$header];
			}
		}
		
		foreach($scan_ports as $port){
			if(@fsockopen($_SERVER['REMOTE_ADDR'], $port, $errstr, $errno, 1)){
				return "Open scanned Port from ".$_SERVER['REMOTE_ADDR'].": $port";
			}
		}
		
		foreach($ports as $port){
			 if($_SERVER["REMOTE_PORT"] == $port){
				return "RemotePort is $port";
			}
		}
		return false;
	}
?>
