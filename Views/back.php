<?php
session_start();

//token
if(!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']){
    die("Error: Token CSRF invalido");
}
unset($_SESSION['csrf_token']);

//Conexión
$conn = new mysqli("localhost", "root", "", "security_app");

if($conn->connect_error){
    die("Error de conexión" . $conn->connect_error);
}


//Sanitización Y validacion
function validateInput($data){
    return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
}

if($_SERVER['REQUEST_METHOD'] ==='POST'){
    $nombre = validateInput($_POST['nombre']);
    $apellidos = validateInput($_POST['apellidos']);
    $email = validateInput($_POST['email']);
    //cifrado
    $password = validateInput(password_hash($_POST['password'],PASSWORD_DEFAULT));
    $user = validateInput($_POST['user']);
}

//consultas parametrizadas
$stmt = $conn->prepare("INSERT INTO security 
(user,nombre,apellidos,email,password)
VALUES (?, ?, ?, ?, ?)");

//sanitización
$stmt->bind_param("sssss", $user, $nombre, $apellidos, $email, $password);

if($stmt->execute()){
    echo "Producto registrado exitosamente.";
}else{
    echo "Error al registrar producto." . $stmt->error;
}

$stmt->close();
$conn->close();


?>