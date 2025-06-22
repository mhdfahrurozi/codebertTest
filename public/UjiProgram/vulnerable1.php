<?php                                                    

// Injection SQL: tanpa prepared statement
$username = $_GET['user'];                              
$password = $_GET['pass'];                              
$query = "SELECT * FROM users WHERE user = '$username' AND pass = '$password'"; 
$result = mysqli_query($conn, $query);                  

// Authentication Flaw: session diset langsung
session_start();                                        
$_SESSION['user'] = $_GET['user'];                      

// File Handling tanpa validasi ekstensi
if (isset($_FILES['file'])) {                           
    $name = $_FILES['file']['name'];                    
    move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $name); 
    echo "Uploaded: " . $name;                          
}

// Misconfiguration: aktifkan error di production
ini_set('display_errors', 1);                           
error_reporting(E_ALL);  

?>
