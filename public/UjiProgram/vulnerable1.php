<?php                                                        

// Misconfiguration: error reporting aktif di production
ini_set('display_errors', 1);                                
error_reporting(E_ALL);                                      

// Logging informasi sensitif
$password = "superSecret123";                                
error_log("User password: $password");                       

// Response mengandung data internal
echo json_encode([                                           
    "user" => "admin",                                       
    "token" => "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"         
]);                                                          

?>
