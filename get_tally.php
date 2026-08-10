<?php
$host = 'db-produksi-ajm-do-user-39841023-0.m.db.ondigitalocean.com';
$port = '25060';
$db   = 'defaultdb';
$user = 'doadmin';
$pass = 'AVNS_ecPVYoKXu1mmdvu-0HD';

$conn = new mysqli($host, $user, $pass, $db, $port);

if ($conn->connect_error) {
    die(json_encode(["error" => "Koneksi gagal: " . $conn->connect_error]));
}

// Ganti "nama_tabel_tally" dengan nama tabel asli yang ada di Sequel Ace / DigitalOcean Anda
$sql = "SELECT * FROM nama_tabel_tally"; 
$result = $conn->query($sql);

$data = array();
if ($result) {
    while($row = $result->fetch_assoc()) {
        $data[] = $row;
    }
}

header('Content-Type: application/json');
echo json_encode($data);
$conn->close();
?>