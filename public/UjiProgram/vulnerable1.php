<?php                                                

// SQL Injection vulnerability
$username = $_GET['username'];                      
$password = $_GET['password'];                      
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'"; 
$result = mysqli_query($conn, $query);              

// Authentication flaw: user ID diset langsung dari parameter
session_start();                                    
$_SESSION['user_id'] = $_GET['uid'];                

// File Handling flaw: tidak validasi nama file
if (isset($_FILES['upload'])) {                     
    $filename = $_FILES['upload']['name'];          
    move_uploaded_file($_FILES['upload']['tmp_name'], "uploads/" . $filename); 
    echo "Uploaded " . $filename;                   
}                                                   

?>
