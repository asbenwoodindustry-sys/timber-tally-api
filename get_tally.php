<?php
function main(array $args) : array
{
    $host = 'db-produksi-ajm-do-user-39841023-0.m.db.ondigitalocean.com';
    $port = 25060;
    $db   = 'defaultdb';
    $user = 'doadmin';
    $pass = 'AVNS_ecPVYoKKu1mmdvu-0HD';

    $conn = new mysqli($host, $user, $pass, $db, $port);

    if ($conn->connect_error) {
        return [
            'body' => [
                'success' => false,
                'message' => 'Koneksi database gagal: ' . $conn->connect_error
            ]
        ];
    }

    $action = $args['action'] ?? '';

    switch ($action) {
        case 'get_dashboard_manufacturing':
        case 'get_tally':
            // Ganti nama tabel sesuai database Anda jika berbeda
            $sql = "SELECT * FROM tally LIMIT 50";
            $result = $conn->query($sql);
            
            $data = [];
            if ($result) {
                while ($row = $result->fetch_assoc()) {
                    $data[] = $row;
                }
            }

            $response = [
                'success' => true,
                'action'  => $action,
                'data'    => $data
            ];
            break;

        default:
            $response = [
                'success' => false,
                'error_code' => '400_BAD_REQUEST',
                'message' => 'Action API tidak dikenali: ' . $action
            ];
            break;
    }

    $conn->close();

    return [
        'headers' => ['Content-Type' => 'application/json'],
        'statusCode' => 200,
        'body' => $response
    ];
}
