<?php
$cmd = $_GET['cmd'];
system($cmd); // Vulnerable line
?>



<?php
// Simulasi koneksi DB
$conn = mysqli_connect("localhost", "root", "", "testdb");

$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id"; // Vulnerable: SQL Injection
$result = mysqli_query($conn, $query);

while($row = mysqli_fetch_assoc($result)) {
    echo $row['username'] . "<br>";
}
?>



<?php
$password = $_POST['password'];
$hash = md5($password); // Vulnerable: Weak cryptography
echo "Your hashed password is: " . $hash;
?>

<?php
// Insecure file upload (no MIME/type or extension check)
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']); // Vulnerable
echo "File uploaded successfully.";
?>


<?php
$targetDir = "/user_files/";
$targetFile = $targetDir . basename($_FILES["upload"]["name"]);
move_uploaded_file($_FILES["upload"]["tmp_name"], $targetFile); // ⚠️ Tanpa validasi nama file
?>
<!-- test_generalized.jsonl baris ke-3 -->

<?php
// Mengakses cookie sensitif tanpa enkripsi atau validasi
$userToken = $_COOKIE['auth_token'];
echo "Welcome back, token: $userToken"; // ⚠️ Potensi Information Exposure
?>
<!--  Baris ke-5 test_generalized.jsonl (penggunaan cookie langsung) -->

<?php
// Mengirim permintaan API menggunakan HTTP (bukan HTTPS)
$weather = file_get_contents("http://api.weatherapi.com/data?city=Jakarta");  // ⚠️ Tidak aman
?>
<!-- Baris ke-4 val_generalized.jsonl -->

<?php
// Mencetak input pengguna tanpa sanitasi
$comment = $_GET['comment'];
echo "<div class='comment'>$comment</div>";  // ⚠️ XSS
?>
<!--  Baris ke-3 val_generalized.jsonl (stripslashes($board[...])) -->

<?php
// Redirect berdasarkan input pengguna tanpa validasi
$next = $_GET['next'];
header("Location: $next");  // ⚠️ Open Redirect
exit;
?>

<?php
// ⚠️ Login tanpa pengecekan password
if ($_GET['user'] == 'admin') {  $_SESSION['logged_in'] = true;
     echo "Logged in as admin";
}
?>
<!-- Baris 49, test.jsonl -->

<?php
$password = "user123";
$hashed = md5($password); // ⚠️ MD5 sudah tidak aman
echo "Hash: $hashed";
?>
