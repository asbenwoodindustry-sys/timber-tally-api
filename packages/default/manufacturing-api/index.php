<?php

declare(strict_types=1);

// ==============================================================
// 1. FUNGSI HELPER NORMALIZE INPUT
// ==============================================================
function normalizeInput(array $event): array
{
    $data = [];

    if (is_array($event)) {
        $data = array_replace($data, $event);
    }

    $http = is_array($event['http'] ?? null) ? $event['http'] : [];
    
    if (!empty($http['queryString'])) {
        if (is_string($http['queryString'])) {
            parse_str($http['queryString'], $query);
            $data = array_replace($data, $query);
        } elseif (is_array($http['queryString'])) {
            $data = array_replace($data, $http['queryString']);
        }
    }

    if (!empty($_GET)) {
        $data = array_replace($data, $_GET);
    }

    $raw = $http['body'] ?? ($event['body'] ?? ($event['__ow_body'] ?? null));

    if (($http['isBase64Encoded'] ?? ($event['isBase64Encoded'] ?? false)) && is_string($raw)) {
        $raw = base64_decode($raw, true) ?: '';
    }

    if (!empty($raw)) {
        if (is_string($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $data = array_replace($data, $decoded);
            }
        } elseif (is_array($raw)) {
            $data = array_replace($data, $raw);
        }
    }

    if (!empty($_POST)) {
        $data = array_replace($data, $_POST);
    }

    if (empty($data['action'])) {
        foreach (['data', 'payload', 'body', 'params'] as $wrapper) {
            if (isset($data[$wrapper]) && is_array($data[$wrapper]) && !empty($data[$wrapper]['action'])) {
                $data['action'] = $data[$wrapper]['action'];
                break;
            }
        }
    }

    unset($data['http']);
    return $data;
}

// ==============================================================
// 2. FUNGSI SEND RESPONSE (Tanpa CORS Ganda - FIX FLUTTER WEB)
// ==============================================================
function sendResponse(int $statusCode, array $data): array
{
    return [
        'statusCode' => $statusCode,
        'headers' => [
            'Content-Type' => 'application/json'
            // Header CORS dihapus karena DigitalOcean API Gateway sudah menambahkannya otomatis
        ],
        'body' => json_encode($data)
    ];
}

// ==============================================================
// 3. FUNGSI VALIDASI TOKEN
// ==============================================================
function validateBearerToken(PDO $pdo): array 
{
    return ['id_user' => 1, 'id_karyawan' => 1]; 
}

// ==============================================================
// 4. FUNGSI UTAMA (MAIN ROUTER)
// ==============================================================
function main(array $args): array
{
    $method = $_SERVER['REQUEST_METHOD'] ?? ($args['http']['method'] ?? ($args['__ow_method'] ?? 'GET'));
    
    // Blok OPTIONS disederhanakan agar tidak mengirim CORS ganda
    if (strtoupper((string)$method) === 'OPTIONS') {
        return [
            'statusCode' => 200,
            'headers' => [
                'Content-Type' => 'application/json'
            ],
            'body' => json_encode(['status' => 'CORS OK', 'version' => '3.0.5-no-cors-duplicate']),
        ];
    }

    $host   = getenv('DB_HOST')     ?: 'db-produksi-ajm-do-user-39841023-0.m.db.ondigitalocean.com';
    $port   = getenv('DB_PORT')     ?: '25060';
    $dbname = getenv('DB_NAME')     ?: 'db_manufacturing';
    $user   = getenv('DB_USER')     ?: 'doadmin';
    $pass   = getenv('DB_PASS')     ?: (getenv('DB_PASSWORD') ?: 'AVNS_ecPVYoKXu1mmdvu-0HD');

    try {
        $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', $host, $port, $dbname);
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_TIMEOUT => 10,
        ]);

        $data = normalizeInput($args);
        
        $action = '';
        foreach (['action', 'Action', 'ACTION', 'act', 'method'] as $key) {
            if (!empty($data[$key])) {
                $action = trim((string)$data[$key]);
                break;
            }
        }
        if (empty($action) && !empty($_GET['action'])) {
            $action = trim((string)$_GET['action']);
        }
        if (empty($action) && !empty($_POST['action'])) {
            $action = trim((string)$_POST['action']);
        }

        // Fallback otomatis jika login
        if (empty($action)) {
            if (!empty($data['username']) || !empty($data['email']) || !empty($data['password'])) {
                $action = 'login';
            }
        }

        if (empty($action)) {
            return sendResponse(400, [
                'success' => false, 
                'error_code' => '400_BAD_REQUEST', 
                'message' => 'Action API tidak dikenali atau kosong. Pastikan parameter action dikirim dari frontend.'
            ]);
        }

        // ==============================================================
        // AUTHENTICATION GATE
        // ==============================================================
        $authHeader = $args['http']['headers']['authorization'] 
                   ?? ($args['__ow_headers']['authorization'] ?? ($_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '')));

        $publicActions = ['login', 'register'];

        if (!in_array($action, $publicActions, true)) {
            if (!preg_match('/Bearer\s+(\S+)/i', $authHeader, $matches) || empty($matches[1])) {
                return sendResponse(401, [
                    'success'    => false,
                    'error_code' => 'AUTH_REQUIRED',
                    'message'    => 'AUTH_REQUIRED: Token Bearer tidak ditemukan atau tidak valid'
                ]);
            }
        }

        // ==============================================================
        // SWITCH ROUTER UTAMA (SELURUH ENDPOINT)
        // ==============================================================
        switch ($action) {

            // ==========================================
            // MODUL AUTHENTICATION
            // ==========================================
            case 'login':
                $nama_lengkap = trim((string) ($data['nama_lengkap'] ?? ''));
                $password = (string) ($data['password'] ?? '');

                if (empty($nama_lengkap)) {
                    return sendResponse(400, ['success' => false, 'error_code' => '400_BAD_REQUEST', 'message' => 'Nama Lengkap kosong']);
                }

                $stmt = $pdo->prepare("SELECT id_karyawan, nama_lengkap, id_jabatan, password_hash, status_aktif FROM `karyawan` WHERE nama_lengkap = :nama LIMIT 1");
                $stmt->execute([':nama' => $nama_lengkap]);
                $karyawan = $stmt->fetch();

                if (!$karyawan) {
                    return sendResponse(401, ['success' => false, 'error_code' => '401_AUTH_REQUIRED', 'message' => 'Karyawan tidak ditemukan']);
                }

                if ((int)$karyawan['status_aktif'] !== 1 && $karyawan['status_aktif'] !== 'Aktif') {
                    return sendResponse(401, ['success' => false, 'error_code' => '401_AUTH_REQUIRED', 'message' => 'Karyawan Non-Aktif']);
                }

                $db_pass = trim((string) ($karyawan['password_hash'] ?? ''));
                $is_match = empty($db_pass) || password_verify($password, $db_pass) || ($password === $db_pass);

                if (!$is_match) {
                    return sendResponse(401, ['success' => false, 'error_code' => '401_AUTH_REQUIRED', 'message' => 'Password salah']);
                }

                $stmtPerm = $pdo->prepare("SELECT nama_menu FROM `hak_akses_jabatan` WHERE id_role = ? AND is_allow = 'Yes'");
                $stmtPerm->execute([$karyawan['id_jabatan']]);
                $permission_codes = $stmtPerm->fetchAll(PDO::FETCH_COLUMN);

                $authToken = bin2hex(random_bytes(32));

                return sendResponse(200, [
                    'success' => true,
                    'message' => 'Login berhasil',
                    'data' => [
                        'access_token' => $authToken,
                        'id_user' => (int) $karyawan['id_karyawan'],
                        'nama_karyawan' => $karyawan['nama_lengkap'],
                        'permission_codes' => $permission_codes
                    ]
                ]);

            // ==========================================
            // MODUL KARYAWAN & PENGGUNA APP
            // ==========================================
            case 'get_karyawan':
                $stmt = $pdo->query("
                    SELECT id_karyawan, TRIM(nama_lengkap) AS nama_lengkap, id_jabatan, status_aktif 
                    FROM karyawan 
                    WHERE (status_aktif = 1 OR status_aktif = 'Aktif') 
                      AND nama_lengkap IS NOT NULL 
                      AND TRIM(nama_lengkap) <> '' 
                    ORDER BY nama_lengkap ASC
                ");
                return sendResponse(200, [
                    'success' => true,
                    'version' => 'tally-report.v1',
                    'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)
                ]);

            case 'simpan_karyawan':
                $id_karyawan  = (int) ($data['id_karyawan'] ?? 0);
                $nama_lengkap = trim((string) ($data['nama_lengkap'] ?? ''));
                $id_jabatan   = (int) ($data['id_jabatan'] ?? 0);
                $status_aktif = trim((string) ($data['status_aktif'] ?? '1'));
                $password     = trim((string) ($data['password'] ?? ''));

                if ($id_karyawan > 0) { 
                    if (!empty($password)) {
                        $hash = password_hash($password, PASSWORD_DEFAULT);
                        $stmt = $pdo->prepare("UPDATE karyawan SET nama_lengkap=?, id_jabatan=?, status_aktif=?, password_hash=? WHERE id_karyawan=?");
                        $stmt->execute([$nama_lengkap, $id_jabatan, $status_aktif, $hash, $id_karyawan]);
                    } else {
                        $stmt = $pdo->prepare("UPDATE karyawan SET nama_lengkap=?, id_jabatan=?, status_aktif=? WHERE id_karyawan=?");
                        $stmt->execute([$nama_lengkap, $id_jabatan, $status_aktif, $id_karyawan]);
                    }
                    $msg = 'Data karyawan berhasil diupdate';
                } else {
                    $hash = !empty($password) ? password_hash($password, PASSWORD_DEFAULT) : '';
                    $stmt = $pdo->prepare("INSERT INTO karyawan (nama_lengkap, id_jabatan, status_aktif, password_hash) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$nama_lengkap, $id_jabatan, $status_aktif, $hash]);
                    $id_karyawan = (int) $pdo->lastInsertId();
                    $msg = 'Karyawan baru berhasil ditambahkan';
                }
                return sendResponse(200, ['success' => true, 'message' => $msg, 'id_karyawan' => $id_karyawan]);

            case 'hapus_karyawan':
                $id_karyawan = (int) ($data['id_karyawan'] ?? 0);
                if ($id_karyawan <= 0) return sendResponse(400, ['success' => false, 'message' => 'ID Karyawan tidak valid']);
                $stmt = $pdo->prepare("DELETE FROM karyawan WHERE id_karyawan = ?");
                $stmt->execute([$id_karyawan]);
                return sendResponse(200, ['success' => true, 'message' => 'Karyawan berhasil dihapus']);

            case 'get_pengguna_app':
                $stmt = $pdo->query("SELECT * FROM pengguna_app ORDER BY id_user ASC");
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_pengguna_app':
                $id_user = (int) ($data['id_user'] ?? 0);
                $username = trim((string) ($data['username'] ?? ''));
                $nama_lengkap = trim((string) ($data['nama_lengkap'] ?? ''));
                $role = trim((string) ($data['role'] ?? 'User'));
                $is_active = (int) ($data['is_active'] ?? 1);

                if (empty($username)) return sendResponse(400, ['success' => false, 'message' => 'Username wajib diisi']);
                if ($id_user > 0) {
                    $stmt = $pdo->prepare("UPDATE pengguna_app SET username=?, nama_lengkap=?, role=?, is_active=? WHERE id_user=?");
                    $stmt->execute([$username, $nama_lengkap, $role, $is_active, $id_user]);
                    $msg = 'Pengguna berhasil diupdate';
                } else {
                    $stmt = $pdo->prepare("INSERT INTO pengguna_app (username, nama_lengkap, role, is_active) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$username, $nama_lengkap, $role, $is_active]);
                    $id_user = (int) $pdo->lastInsertId();
                    $msg = 'Pengguna berhasil ditambahkan';
                }
                return sendResponse(200, ['success' => true, 'message' => $msg, 'id_user' => $id_user]);

            case 'hapus_pengguna_app':
                $id_user = (int) ($data['id_user'] ?? 0);
                $stmt = $pdo->prepare("DELETE FROM pengguna_app WHERE id_user = ?");
                $stmt->execute([$id_user]);
                return sendResponse(200, ['success' => true, 'message' => 'Pengguna berhasil dihapus']);

            // ==========================================
            // MODUL JABATAN & ROLE
            // ==========================================
            case 'get_jabatan':
                $stmt = $pdo->query("SELECT * FROM jabatan ORDER BY nama_jabatan ASC");
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_jabatan':
                $id_jabatan = (int) ($data['id_jabatan'] ?? 0);
                $nama_jabatan = trim((string) ($data['nama_jabatan'] ?? ''));

                if (empty($nama_jabatan)) return sendResponse(400, ['success' => false, 'message' => 'Nama jabatan wajib diisi']);
                if ($id_jabatan > 0) {
                    $stmt = $pdo->prepare("UPDATE jabatan SET nama_jabatan=? WHERE id_jabatan=?");
                    $stmt->execute([$nama_jabatan, $id_jabatan]);
                    $msg = 'Jabatan diupdate';
                } else {
                    $stmt = $pdo->prepare("INSERT INTO jabatan (nama_jabatan) VALUES (?)");
                    $stmt->execute([$nama_jabatan]);
                    $id_jabatan = (int) $pdo->lastInsertId();
                    $msg = 'Jabatan ditambahkan';
                }
                return sendResponse(200, ['success' => true, 'message' => $msg, 'id_jabatan' => $id_jabatan]);

            case 'hapus_jabatan':
                $id_jabatan = (int) ($data['id_jabatan'] ?? 0);
                $stmt = $pdo->prepare("DELETE FROM jabatan WHERE id_jabatan = ?");
                $stmt->execute([$id_jabatan]);
                return sendResponse(200, ['success' => true, 'message' => 'Jabatan dihapus']);

            case 'get_master_role':
                $stmt = $pdo->query("SELECT * FROM master_role ORDER BY nama_role ASC");
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_master_role':
                $id_role = (int) ($data['id_role'] ?? 0);
                $nama_role = trim((string) ($data['nama_role'] ?? ''));

                if (empty($nama_role)) return sendResponse(400, ['success' => false, 'message' => 'Nama role wajib diisi']);
                if ($id_role > 0) {
                    $stmt = $pdo->prepare("UPDATE master_role SET nama_role=? WHERE id_role=?");
                    $stmt->execute([$nama_role, $id_role]);
                    $msg = 'Role diupdate';
                } else {
                    $stmt = $pdo->prepare("INSERT INTO master_role (nama_role) VALUES (?)");
                    $stmt->execute([$nama_role]);
                    $id_role = (int) $pdo->lastInsertId();
                    $msg = 'Role ditambahkan';
                }
                return sendResponse(200, ['success' => true, 'message' => $msg, 'id_role' => $id_role]);

            case 'hapus_master_role':
                $id_role = (int) ($data['id_role'] ?? 0);
                $stmt = $pdo->prepare("DELETE FROM master_role WHERE id_role = ?");
                $stmt->execute([$id_role]);
                return sendResponse(200, ['success' => true, 'message' => 'Role dihapus']);

            // ==========================================
            // MODUL HAK AKSES & SISTEM
            // ==========================================
            case 'get_hak_akses':
                $stmt = $pdo->query("SELECT * FROM hak_akses ORDER BY nama_menu ASC");
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_hak_akses':
                $id_akses = (int) ($data['id_akses'] ?? 0);
                $nama_menu = trim((string) ($data['nama_menu'] ?? ''));
                $deskripsi = trim((string) ($data['deskripsi'] ?? ''));

                if (empty($nama_menu)) return sendResponse(400, ['success' => false, 'message' => 'Nama menu wajib diisi']);
                if ($id_akses > 0) {
                    $stmt = $pdo->prepare("UPDATE hak_akses SET nama_menu=?, deskripsi=? WHERE id_akses=?");
                    $stmt->execute([$nama_menu, $deskripsi, $id_akses]);
                    $msg = 'Hak akses diupdate';
                } else {
                    $stmt = $pdo->prepare("INSERT INTO hak_akses (nama_menu, deskripsi) VALUES (?, ?)");
                    $stmt->execute([$nama_menu, $deskripsi]);
                    $id_akses = (int) $pdo->lastInsertId();
                    $msg = 'Hak akses ditambahkan';
                }
                return sendResponse(200, ['success' => true, 'message' => $msg, 'id_akses' => $id_akses]);

            case 'hapus_hak_akses':
                $id_akses = (int) ($data['id_akses'] ?? 0);
                $stmt = $pdo->prepare("DELETE FROM hak_akses WHERE id_akses = ?");
                $stmt->execute([$id_akses]);
                return sendResponse(200, ['success' => true, 'message' => 'Hak akses dihapus']);

            case 'get_hak_akses_jabatan':
                $stmt = $pdo->query("SELECT * FROM hak_akses_jabatan");
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_hak_akses_jabatan':
                $id_role = (int) ($data['id_role'] ?? 0);
                $nama_menu = trim((string) ($data['nama_menu'] ?? ''));
                $is_allow = trim((string) ($data['is_allow'] ?? 'Yes'));

                if ($id_role <= 0 || empty($nama_menu)) {
                    return sendResponse(400, ['success' => false, 'message' => 'ID Role dan Nama Menu wajib diisi']);
                }
                $stmt = $pdo->prepare("INSERT INTO hak_akses_jabatan (id_role, nama_menu, is_allow) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE is_allow = ?");
                $stmt->execute([$id_role, $nama_menu, $is_allow, $is_allow]);
                return sendResponse(200, ['success' => true, 'message' => 'Pengaturan hak akses jabatan disimpan']);

            case 'hapus_hak_akses_jabatan':
                $id_role = (int) ($data['id_role'] ?? 0);
                $nama_menu = trim((string) ($data['nama_menu'] ?? ''));
                $stmt = $pdo->prepare("DELETE FROM hak_akses_jabatan WHERE id_role = ? AND nama_menu = ?");
                $stmt->execute([$id_role, $nama_menu]);
                return sendResponse(200, ['success' => true, 'message' => 'Hak akses jabatan dihapus']);

            case 'get_modul_sistem':
                $stmt = $pdo->query("SELECT * FROM modul_sistem ORDER BY nama_modul ASC");
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_modul_sistem':
                $id_modul = (int) ($data['id_modul'] ?? 0);
                $nama_modul = trim((string) ($data['nama_modul'] ?? ''));
                $keterangan = trim((string) ($data['keterangan'] ?? ''));

                if (empty($nama_modul)) return sendResponse(400, ['success' => false, 'message' => 'Nama modul wajib diisi']);
                if ($id_modul > 0) {
                    $stmt = $pdo->prepare("UPDATE modul_sistem SET nama_modul=?, keterangan=? WHERE id_modul=?");
                    $stmt->execute([$nama_modul, $keterangan, $id_modul]);
                    $msg = 'Modul diupdate';
                } else {
                    $stmt = $pdo->prepare("INSERT INTO modul_sistem (nama_modul, keterangan) VALUES (?, ?)");
                    $stmt->execute([$nama_modul, $keterangan]);
                    $id_modul = (int) $pdo->lastInsertId();
                    $msg = 'Modul ditambahkan';
                }
                return sendResponse(200, ['success' => true, 'message' => $msg, 'id_modul' => $id_modul]);

            case 'hapus_modul_sistem':
                $id_modul = (int) ($data['id_modul'] ?? 0);
                $stmt = $pdo->prepare("DELETE FROM modul_sistem WHERE id_modul = ?");
                $stmt->execute([$id_modul]);
                return sendResponse(200, ['success' => true, 'message' => 'Modul dihapus']);

            case 'get_app_help':
                $stmt = $pdo->query("SELECT * FROM app_help ORDER BY id_help ASC");
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_app_help':
                $id_help = (int) ($data['id_help'] ?? 0);
                $judul = trim((string) ($data['judul'] ?? ''));
                $konten = trim((string) ($data['konten'] ?? ''));

                if (empty($judul)) return sendResponse(400, ['success' => false, 'message' => 'Judul help wajib diisi']);
                if ($id_help > 0) {
                    $stmt = $pdo->prepare("UPDATE app_help SET judul=?, konten=? WHERE id_help=?");
                    $stmt->execute([$judul, $konten, $id_help]);
                    $msg = 'Bantuan diupdate';
                } else {
                    $stmt = $pdo->prepare("INSERT INTO app_help (judul, konten) VALUES (?, ?)");
                    $stmt->execute([$judul, $konten]);
                    $id_help = (int) $pdo->lastInsertId();
                    $msg = 'Bantuan ditambahkan';
                }
                return sendResponse(200, ['success' => true, 'message' => $msg, 'id_help' => $id_help]);

            case 'hapus_app_help':
                $id_help = (int) ($data['id_help'] ?? 0);
                $stmt = $pdo->prepare("DELETE FROM app_help WHERE id_help = ?");
                $stmt->execute([$id_help]);
                return sendResponse(200, ['success' => true, 'message' => 'Bantuan dihapus']);

            // ==========================================
            // MODUL AKUNTANSI & BUKU BESAR (COA, JURNAL, SALDO AWAL)
            // ==========================================
            case 'get_akun':
            case 'get_master_akun_coa':
                $stmt = $pdo->query("SELECT id_akun, kode_akun, nama_akun, kategori, posisi_normal FROM akun ORDER BY kode_akun ASC");
                return sendResponse(200, ['success' => true, 'data' => ['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]]);

            case 'get_list_master_akun':
                $page     = max(1, (int)($data['page'] ?? 1));
                $limit    = max(1, min(100, (int)($data['limit'] ?? 50)));
                $offset   = ($page - 1) * $limit;
                $kategori = trim((string)($data['kategori'] ?? ''));
                $search   = trim((string)($data['search'] ?? ''));

                $where = " WHERE 1=1";
                $params = [];

                if (!empty($kategori)) {
                    $where .= " AND kategori = ?";
                    $params[] = $kategori;
                }
                if (!empty($search)) {
                    $where .= " AND (kode_akun LIKE ? OR nama_akun LIKE ?)";
                    $params[] = "%$search%";
                    $params[] = "%$search%";
                }

                $countStmt = $pdo->prepare("SELECT COUNT(*) FROM akun" . $where);
                $countStmt->execute($params);
                $total_items = (int)$countStmt->fetchColumn();
                $total_pages = $total_items > 0 ? (int)ceil($total_items / $limit) : 0;

                $stmt = $pdo->prepare("SELECT id_akun, kode_akun, nama_akun, kategori, posisi_normal, is_active FROM akun $where ORDER BY kode_akun ASC LIMIT ? OFFSET ?");
                $execParams = array_merge($params, [$limit, $offset]);
                foreach ($execParams as $key => $val) {
                    $stmt->bindValue($key + 1, $val, is_int($val) ? PDO::PARAM_INT : PDO::PARAM_STR);
                }
                $stmt->execute();

                return sendResponse(200, [
                    'success' => true,
                    'data' => [
                        'items' => $stmt->fetchAll(PDO::FETCH_ASSOC),
                        'pagination' => [
                            'page'        => $page,
                            'limit'       => $limit,
                            'total_items' => $total_items,
                            'total_pages' => $total_pages
                        ]
                    ]
                ]);

            case 'simpan_akun':
            case 'create_master_akun':
            case 'update_master_akun':
                $id_akun       = (int)($data['id_akun'] ?? 0);
                $kode_akun     = trim((string)($data['kode_akun'] ?? ''));
                $nama_akun     = trim((string)($data['nama_akun'] ?? ''));
                $kategori      = strtoupper(trim((string)($data['kategori'] ?? '')));
                $posisi_normal = strtoupper(trim((string)($data['posisi_normal'] ?? 'DEBIT')));
                $is_active     = isset($data['is_active']) ? (int)$data['is_active'] : 1;

                if (empty($kode_akun) || empty($nama_akun)) {
                    return sendResponse(400, ['success' => false, 'message' => 'Kode Akun dan Nama Akun wajib diisi.']);
                }

                $stmtCheck = $pdo->prepare("SELECT COUNT(*) FROM akun WHERE kode_akun = ? AND id_akun != ?");
                $stmtCheck->execute([$kode_akun, $id_akun]);
                if ((int)$stmtCheck->fetchColumn() > 0) {
                    return sendResponse(409, ['success' => false, 'message' => 'Kode Akun sudah digunakan oleh akun lain.']);
                }

                if ($id_akun > 0) {
                    $stmt = $pdo->prepare("UPDATE akun SET kode_akun = ?, nama_akun = ?, kategori = ?, posisi_normal = ?, is_active = ? WHERE id_akun = ?");
                    $stmt->execute([$kode_akun, $nama_akun, $kategori, $posisi_normal, $is_active, $id_akun]);
                    $msg = 'Akun berhasil diperbarui';
                } else {
                    $stmt = $pdo->prepare("INSERT INTO akun (kode_akun, nama_akun, kategori, posisi_normal, is_active) VALUES (?, ?, ?, ?, ?)");
                    $stmt->execute([$kode_akun, $nama_akun, $kategori, $posisi_normal, $is_active]);
                    $id_akun = (int)$pdo->lastInsertId();
                    $msg = 'Akun berhasil ditambahkan';
                }
                return sendResponse(200, ['success' => true, 'message' => $msg, 'id_akun' => $id_akun]);

            case 'hapus_akun':
            case 'delete_master_akun':
                $id_akun = (int)($data['id_akun'] ?? 0);
                if ($id_akun <= 0) return sendResponse(400, ['success' => false, 'message' => 'ID Akun tidak valid.']);

                $stmtCheckUsage = $pdo->prepare("SELECT COUNT(*) FROM jurnal_detail WHERE id_akun = ?");
                $stmtCheckUsage->execute([$id_akun]);
                if ((int)$stmtCheckUsage->fetchColumn() > 0) {
                    $stmt = $pdo->prepare("UPDATE akun SET is_active = 0 WHERE id_akun = ?");
                    $stmt->execute([$id_akun]);
                    return sendResponse(200, ['success' => true, 'message' => 'Akun memiliki riwayat transaksi dan telah dinonaktifkan.']);
                } else {
                    $stmt = $pdo->prepare("DELETE FROM akun WHERE id_akun = ?");
                    $stmt->execute([$id_akun]);
                    return sendResponse(200, ['success' => true, 'message' => 'Akun berhasil dihapus permanen.']);
                }

            case 'simpan_saldo_awal':
                $tanggal_cutoff = trim((string)($data['tanggal_cutoff'] ?? date('Y-01-01')));
                $keterangan     = trim((string)($data['keterangan'] ?? 'Saldo Awal Pembukuan / Migrasi'));
                $details        = (array)($data['details'] ?? []);

                if (empty($details)) return sendResponse(400, ['success' => false, 'message' => 'Rincian saldo awal akun tidak boleh kosong.']);

                $total_debit_cents  = 0;
                $total_kredit_cents = 0;
                foreach ($details as $row) {
                    $total_debit_cents  += (int)round((float)($row['debit'] ?? 0) * 100);
                    $total_kredit_cents += (int)round((float)($row['kredit'] ?? 0) * 100);
                }

                if ($total_debit_cents !== $total_kredit_cents || $total_debit_cents <= 0) {
                    return sendResponse(400, ['success' => false, 'message' => 'Saldo awal tidak seimbang!']);
                }

                $pdo->beginTransaction();
                try {
                    $stmtCek = $pdo->prepare("SELECT id_jurnal FROM jurnal_header WHERE referensi_tipe = 'SALDO_AWAL'");
                    $stmtCek->execute();
                    $existing_id = $stmtCek->fetchColumn();

                    if ($existing_id) {
                        $pdo->prepare("DELETE FROM jurnal_detail WHERE id_jurnal = ?")->execute([(int)$existing_id]);
                        $pdo->prepare("DELETE FROM jurnal_header WHERE id_jurnal = ?")->execute([(int)$existing_id]);
                    }

                    $no_jurnal = 'OB-' . date('Ymd', strtotime($tanggal_cutoff));
                    $stmtH = $pdo->prepare("INSERT INTO jurnal_header (no_jurnal, tanggal_jurnal, referensi_tipe, id_referensi, keterangan, status_jurnal) VALUES (?, ?, 'SALDO_AWAL', 1, ?, 'POSTED')");
                    $stmtH->execute([$no_jurnal, $tanggal_cutoff, $keterangan]);
                    $id_jurnal = (int)$pdo->lastInsertId();

                    $stmtD = $pdo->prepare("INSERT INTO jurnal_detail (id_jurnal, id_akun, posisi, jumlah, keterangan) VALUES (?, ?, ?, ?, ?)");
                    foreach ($details as $row) {
                        $id_akun = (int)($row['id_akun'] ?? 0);
                        $debit   = (float)($row['debit'] ?? 0);
                        $kredit  = (float)($row['kredit'] ?? 0);

                        if ($id_akun > 0) {
                            if ($debit > 0) $stmtD->execute([$id_jurnal, $id_akun, 'DEBIT', $debit, 'Saldo Awal']);
                            if ($kredit > 0) $stmtD->execute([$id_jurnal, $id_akun, 'KREDIT', $kredit, 'Saldo Awal']);
                        }
                    }

                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Saldo awal berhasil disimpan.', 'data' => ['id_jurnal' => $id_jurnal, 'no_jurnal' => $no_jurnal]]);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal simpan saldo awal: ' . $e->getMessage()]);
                }

           case 'simpan_jurnal_manual':
            case 'create_manual_jurnal':
                $idempotency_key = trim((string)($data['idempotency_key'] ?? ''));
                $tanggal         = trim((string)($data['tanggal'] ?? date('Y-m-d')));
                $referensi_tipe  = trim((string)($data['referensi_tipe'] ?? 'MANUAL'));
                $id_referensi    = (int)($data['id_referensi'] ?? 0);
                $keterangan      = trim((string)($data['keterangan'] ?? ''));
                
                // === INI PENAMBAHAN UNTUK MENANGKAP FILE BUKTI DARI FLUTTER ===
                $bukti_dokumen   = trim((string)($data['bukti_dokumen'] ?? '')); 
                
                $details         = (array)($data['details'] ?? []);

                if (count($details) < 2) {
                    return sendResponse(400, ['success' => false, 'message' => 'Jurnal harus memiliki minimal 2 baris rincian (Debit & Kredit).']);
                }

                $total_debit_cents  = 0;
                $total_kredit_cents = 0;
                foreach ($details as $row) {
                    $cents  = (int)round((float)($row['jumlah'] ?? 0) * 100);
                    $posisi = strtoupper(trim((string)($row['posisi'] ?? '')));
                    if ($posisi === 'DEBIT') $total_debit_cents += $cents;
                    elseif ($posisi === 'KREDIT') $total_kredit_cents += $cents;
                }

                if ($total_debit_cents !== $total_kredit_cents || $total_debit_cents <= 0) {
                    return sendResponse(400, ['success' => false, 'message' => 'Total Debit dan Kredit tidak seimbang.']);
                }

                if (!empty($idempotency_key)) {
                    $stmtIdem = $pdo->prepare("SELECT response_payload FROM api_idempotency WHERE idempotency_key = ?");
                    $stmtIdem->execute([$idempotency_key]);
                    if ($cached = $stmtIdem->fetchColumn()) return sendResponse(200, json_decode($cached, true));
                }

                $pdo->beginTransaction();
                try {
                    $prefix = 'JRN-' . date('Ym', strtotime($tanggal)) . '-';
                    $stmtSeq = $pdo->prepare("SELECT COUNT(*) FROM jurnal_header WHERE no_jurnal LIKE ?");
                    $stmtSeq->execute([$prefix . '%']);
                    $no_jurnal = $prefix . str_pad((string)((int)$stmtSeq->fetchColumn() + 1), 4, '0', STR_PAD_LEFT);

                    $id_referensi_manual = $id_referensi > 0 ? $id_referensi : ((int)(microtime(true) * 1000) % 2147483647);

                    // === INI PENAMBAHAN QUERY AGAR BUKTI DISIMPAN KE DATABASE ===
                    $stmtHeader = $pdo->prepare("
                        INSERT INTO jurnal_header 
                        (no_jurnal, tanggal, referensi_tipe, id_referensi, keterangan, bukti_dokumen, status) 
                        VALUES (?, ?, ?, ?, ?, ?, 'POSTED')
                    ");
                    $stmtHeader->execute([$no_jurnal, $tanggal, $referensi_tipe, $id_referensi_manual, $keterangan, $bukti_dokumen]);
                    $id_jurnal = (int)$pdo->lastInsertId();

                    $stmtDetail = $pdo->prepare("INSERT INTO jurnal_detail (id_jurnal, id_akun, posisi, jumlah, keterangan) VALUES (?, ?, ?, ?, ?)");
                    foreach ($details as $line) {
                        $id_akun  = (int)($line['id_akun'] ?? 0);
                        $posisi   = strtoupper(trim((string)($line['posisi'] ?? 'DEBIT')));
                        $jumlah   = (float)($line['jumlah'] ?? 0);
                        $ket_line = trim((string)($line['keterangan'] ?? $keterangan));
                        if ($id_akun > 0 && $jumlah > 0) {
                            $stmtDetail->execute([$id_jurnal, $id_akun, $posisi, $jumlah, $ket_line]);
                        }
                    }

                    $resData = [
                        'success' => true, 
                        'message' => 'Jurnal manual berhasil diposting beserta bukti.', 
                        'data' => [
                            'id_jurnal' => $id_jurnal, 
                            'no_jurnal' => $no_jurnal,
                            'bukti_dokumen' => $bukti_dokumen // Dikembalikan agar bisa dibaca Flutter
                        ]
                    ];

                    if (!empty($idempotency_key)) {
                        $stmtSaveIdem = $pdo->prepare("INSERT INTO api_idempotency (idempotency_key, action, response_payload) VALUES (?, 'simpan_jurnal_manual', ?)");
                        $stmtSaveIdem->execute([$idempotency_key, json_encode($resData)]);
                    }

                    $pdo->commit();
                    return sendResponse(200, $resData);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal simpan jurnal: ' . $e->getMessage()]);
                }

            case 'get_list_jurnal':
                $page        = max(1, (int) ($data['page'] ?? 1));
                $limit       = max(1, min(100, (int) ($data['limit'] ?? 25)));
                $offset      = ($page - 1) * $limit;
                $keyword     = trim((string) ($data['keyword'] ?? $data['search'] ?? ''));
                $tgl_mulai   = trim((string) ($data['tanggal_dari'] ?? $data['tanggal_mulai'] ?? ''));
                $tgl_selesai = trim((string) ($data['tanggal_sampai'] ?? $data['tanggal_selesai'] ?? ''));

                $where = "WHERE 1=1";
                $params = [];

                if (!empty($keyword)) {
                    $where .= " AND (no_jurnal LIKE ? OR keterangan LIKE ? OR nomor_referensi LIKE ?)";
                    $params[] = "%$keyword%"; $params[] = "%$keyword%"; $params[] = "%$keyword%";
                }
                if (!empty($tgl_mulai) && !empty($tgl_selesai)) {
                    $where .= " AND tanggal_jurnal BETWEEN ? AND ?";
                    $params[] = $tgl_mulai; $params[] = $tgl_selesai;
                }

                $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM jurnal_header $where");
                $stmtCount->execute($params);
                $totalData = (int) $stmtCount->fetchColumn();

                $sql = "SELECT * FROM jurnal_header $where ORDER BY tanggal_jurnal DESC, id_jurnal DESC LIMIT $limit OFFSET $offset";
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);

                return sendResponse(200, [
                    'success'    => true,
                    'page'       => $page,
                    'limit'      => $limit,
                    'total_data' => $totalData,
                    'data'       => $stmt->fetchAll(PDO::FETCH_ASSOC)
                ]);

            case 'get_detail_jurnal':
                $id_jurnal = (int)($data['id_jurnal'] ?? 0);
                $no_jurnal = trim((string)($data['no_jurnal'] ?? ''));

                if ($id_jurnal <= 0 && empty($no_jurnal)) return sendResponse(400, ['success' => false, 'message' => 'id_jurnal atau no_jurnal wajib disertakan.']);

                $stmtH = $pdo->prepare("SELECT * FROM jurnal_header WHERE id_jurnal = ? OR no_jurnal = ? LIMIT 1");
                $stmtH->execute([$id_jurnal, $no_jurnal]);
                if (!$header = $stmtH->fetch(PDO::FETCH_ASSOC)) return sendResponse(404, ['success' => false, 'message' => 'Data jurnal tidak ditemukan.']);

                $stmtD = $pdo->prepare("SELECT jd.*, a.kode_akun, a.nama_akun FROM jurnal_detail jd LEFT JOIN akun a ON jd.id_akun = a.id_akun WHERE jd.id_jurnal = ? ORDER BY jd.id_jurnal_detail ASC");
                $stmtD->execute([(int)$header['id_jurnal']]);
                
                return sendResponse(200, ['success' => true, 'data' => ['header' => $header, 'details' => $stmtD->fetchAll(PDO::FETCH_ASSOC)]]);

            case 'get_master_jurnal_mapping':
                $sql = "SELECT mjm.*, ad.kode_akun AS kode_akun_debit, ad.nama_akun AS nama_akun_debit, ak.kode_akun AS kode_akun_kredit, ak.nama_akun AS nama_akun_kredit
                        FROM master_jurnal_mapping mjm LEFT JOIN akun ad ON mjm.id_akun_debit = ad.id_akun LEFT JOIN akun ak ON mjm.id_akun_kredit = ak.id_akun ORDER BY mjm.id_mapping ASC";
                return sendResponse(200, ['success' => true, 'data' => ['items' => $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC)]]);

            case 'create_master_jurnal_mapping':
                $kode_transaksi = strtoupper(trim((string)($data['kode_transaksi'] ?? '')));
                $nama_transaksi = trim((string)($data['nama_transaksi'] ?? ''));
                $id_akun_debit  = (int)($data['id_akun_debit'] ?? 0);
                $id_akun_kredit = (int)($data['id_akun_kredit'] ?? 0);
                $ket_default    = trim((string)($data['keterangan_default'] ?? ''));

                if (empty($kode_transaksi) || $id_akun_debit <= 0 || $id_akun_kredit <= 0) return sendResponse(400, ['success' => false, 'message' => 'Data mapping tidak lengkap']);
                
                $stmt = $pdo->prepare("INSERT INTO master_jurnal_mapping (kode_transaksi, nama_transaksi, id_akun_debit, id_akun_kredit, keterangan_default) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$kode_transaksi, $nama_transaksi, $id_akun_debit, $id_akun_kredit, $ket_default]);
                return sendResponse(201, ['success' => true, 'message' => 'Mapping ditambahkan', 'data' => ['id_mapping' => $pdo->lastInsertId()]]);

            case 'update_master_jurnal_mapping':
                $id_mapping     = (int)($data['id_mapping'] ?? 0);
                $kode_transaksi = strtoupper(trim((string)($data['kode_transaksi'] ?? '')));
                $nama_transaksi = trim((string)($data['nama_transaksi'] ?? ''));
                $id_akun_debit  = (int)($data['id_akun_debit'] ?? 0);
                $id_akun_kredit = (int)($data['id_akun_kredit'] ?? 0);
                $ket_default    = trim((string)($data['keterangan_default'] ?? ''));

                $stmt = $pdo->prepare("UPDATE master_jurnal_mapping SET kode_transaksi=?, nama_transaksi=?, id_akun_debit=?, id_akun_kredit=?, keterangan_default=? WHERE id_mapping=?");
                $stmt->execute([$kode_transaksi, $nama_transaksi, $id_akun_debit, $id_akun_kredit, $ket_default, $id_mapping]);
                return sendResponse(200, ['success' => true, 'message' => 'Mapping diperbarui']);

            case 'delete_master_jurnal_mapping':
                $id_mapping = (int)($data['id_mapping'] ?? 0);
                $pdo->prepare("DELETE FROM master_jurnal_mapping WHERE id_mapping = ?")->execute([$id_mapping]);
                return sendResponse(200, ['success' => true, 'message' => 'Mapping dihapus']);

            case 'get_laporan_laba_rugi':
                $tgl_mulai   = trim((string)($data['tanggal_mulai'] ?? date('Y-m-01')));
                $tgl_selesai = trim((string)($data['tanggal_selesai'] ?? date('Y-m-d')));

                $sql = "SELECT a.id_akun, a.kode_akun, a.nama_akun, a.kategori, a.posisi_normal,
                            COALESCE(SUM(CASE WHEN jd.posisi = 'DEBIT' THEN jd.jumlah ELSE 0 END), 0) AS total_debit,
                            COALESCE(SUM(CASE WHEN jd.posisi = 'KREDIT' THEN jd.jumlah ELSE 0 END), 0) AS total_kredit
                        FROM akun a LEFT JOIN jurnal_detail jd ON a.id_akun = jd.id_akun AND jd.tanggal BETWEEN ? AND ?
                        WHERE a.kategori IN ('PENDAPATAN', 'HPP', 'BEBAN', 'BEBAN_LAIN', 'PENDAPATAN_LAIN')
                        GROUP BY a.id_akun, a.kode_akun, a.nama_akun, a.kategori, a.posisi_normal ORDER BY a.kode_akun ASC";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$tgl_mulai, $tgl_selesai]);
                
                $pendapatan = []; $hpp = []; $beban = [];
                $tot_pendapatan = 0; $tot_hpp = 0; $tot_beban = 0;

                foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
                    $saldo = ($r['posisi_normal'] === 'KREDIT') ? ($r['total_kredit'] - $r['total_debit']) : ($r['total_debit'] - $r['total_kredit']);
                    $item = ['id_akun' => (int)$r['id_akun'], 'kode_akun' => $r['kode_akun'], 'nama_akun' => $r['nama_akun'], 'saldo' => (float)$saldo];
                    if (str_contains($r['kategori'], 'PENDAPATAN')) { $pendapatan[] = $item; $tot_pendapatan += $saldo; }
                    elseif ($r['kategori'] === 'HPP') { $hpp[] = $item; $tot_hpp += $saldo; }
                    else { $beban[] = $item; $tot_beban += $saldo; }
                }

                return sendResponse(200, ['success' => true, 'data' => [
                    'periode' => ['tanggal_mulai' => $tgl_mulai, 'tanggal_selesai' => $tgl_selesai],
                    'kpi' => ['total_pendapatan' => $tot_pendapatan, 'total_hpp' => $tot_hpp, 'laba_kotor' => $tot_pendapatan - $tot_hpp, 'total_beban' => $tot_beban, 'laba_bersih' => ($tot_pendapatan - $tot_hpp) - $tot_beban],
                    'details' => ['pendapatan' => $pendapatan, 'hpp' => $hpp, 'beban' => $beban]
                ]]);

            case 'get_laporan_neraca':
                $tgl_cutoff = trim((string)($data['tanggal_cutoff'] ?? date('Y-m-d')));

                $sql = "SELECT a.id_akun, a.kode_akun, a.nama_akun, a.kategori, a.posisi_normal,
                            COALESCE(SUM(CASE WHEN jd.posisi = 'DEBIT' THEN jd.jumlah ELSE 0 END), 0) AS total_debit,
                            COALESCE(SUM(CASE WHEN jd.posisi = 'KREDIT' THEN jd.jumlah ELSE 0 END), 0) AS total_kredit
                        FROM akun a LEFT JOIN jurnal_detail jd ON a.id_akun = jd.id_akun AND jd.tanggal <= ?
                        WHERE a.kategori IN ('ASET_LANCAR', 'ASET_TETAP', 'KEWAJIBAN_LANCAR', 'KEWAJIBAN_PANJANG', 'EKUITAS')
                        GROUP BY a.id_akun, a.kode_akun, a.nama_akun, a.kategori, a.posisi_normal ORDER BY a.kode_akun ASC";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$tgl_cutoff]);

                $aset = []; $kewajiban = []; $ekuitas = [];
                $tot_aset = 0; $tot_kewajiban = 0; $tot_ekuitas = 0;

                foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
                    $saldo = ($r['posisi_normal'] === 'DEBIT') ? ($r['total_debit'] - $r['total_kredit']) : ($r['total_kredit'] - $r['total_debit']);
                    $item = ['id_akun' => (int)$r['id_akun'], 'kode_akun' => $r['kode_akun'], 'nama_akun' => $r['nama_akun'], 'saldo' => (float)$saldo];
                    if (str_contains($r['kategori'], 'ASET')) { $aset[] = $item; $tot_aset += $saldo; }
                    elseif (str_contains($r['kategori'], 'KEWAJIBAN')) { $kewajiban[] = $item; $tot_kewajiban += $saldo; }
                    else { $ekuitas[] = $item; $tot_ekuitas += $saldo; }
                }

                return sendResponse(200, ['success' => true, 'data' => [
                    'tanggal_cutoff' => $tgl_cutoff,
                    'kpi' => ['total_aset' => $tot_aset, 'total_kewajiban' => $tot_kewajiban, 'total_ekuitas' => $tot_ekuitas, 'is_balanced' => abs($tot_aset - ($tot_kewajiban + $tot_ekuitas)) <= 0.01],
                    'details' => ['aset' => $aset, 'kewajiban' => $kewajiban, 'ekuitas' => $ekuitas]
                ]]);

            case 'get_status_periode_akuntansi':
                $bulan = (int)($data['bulan'] ?? date('n'));
                $tahun = (int)($data['tahun'] ?? date('Y'));

                $stmtCek = $pdo->prepare("SELECT COUNT(*) FROM jurnal_header WHERE YEAR(tanggal) = ? AND MONTH(tanggal) = ? AND status_jurnal = 'POSTED' AND (tipe_transaksi = 'PENUTUP_BULANAN' OR nomor_jurnal LIKE 'CL-BULAN%')");
                $stmtCek->execute([$tahun, $bulan]);
                $isClosedBulan = ((int)$stmtCek->fetchColumn() > 0);

                $stmtCekThn = $pdo->prepare("SELECT COUNT(*) FROM jurnal_header WHERE YEAR(tanggal) = ? AND status_jurnal = 'POSTED' AND (tipe_transaksi = 'PENUTUP_TAHUNAN' OR nomor_jurnal LIKE 'CL-TAHUN%')");
                $stmtCekThn->execute([$tahun]);
                $isClosedTahun = ((int)$stmtCekThn->fetchColumn() > 0);

                return sendResponse(200, ['success' => true, 'bulan' => $bulan, 'tahun' => $tahun, 'status_bulanan' => $isClosedBulan ? 'CLOSED' : 'OPEN', 'status_tahunan' => $isClosedTahun ? 'CLOSED' : 'OPEN', 'is_locked' => ($isClosedBulan || $isClosedTahun)]);

            case 'preview_tutup_buku':
                $tipe  = trim((string)($data['tipe'] ?? 'BULANAN'));
                $bulan = (int)($data['bulan'] ?? date('n'));
                $tahun = (int)($data['tahun'] ?? date('Y'));

                if ($tipe === 'BULANAN') {
                    $stmtSummary = $pdo->prepare("SELECT COUNT(DISTINCT jh.id_jurnal) AS total_jurnal_posted, COALESCE(SUM(jd.debit), 0) AS total_debit, COALESCE(SUM(jd.kredit), 0) AS total_kredit FROM jurnal_header jh JOIN jurnal_detail jd ON jh.id_jurnal = jd.id_jurnal WHERE YEAR(jh.tanggal) = ? AND MONTH(jh.tanggal) = ? AND jh.status_jurnal = 'POSTED'");
                    $stmtSummary->execute([$tahun, $bulan]);
                    $summary = $stmtSummary->fetch(PDO::FETCH_ASSOC);
                    return sendResponse(200, ['success' => true, 'tipe' => 'BULANAN', 'bulan' => $bulan, 'tahun' => $tahun, 'total_jurnal_posted' => (int)$summary['total_jurnal_posted'], 'total_debit' => (float)$summary['total_debit'], 'total_kredit' => (float)$summary['total_kredit']]);
                } else {
                    $stmtRev = $pdo->prepare("SELECT COALESCE(SUM(jd.kredit - jd.debit), 0) FROM jurnal_detail jd JOIN jurnal_header jh ON jd.id_jurnal = jh.id_jurnal JOIN akun a ON jd.id_akun = a.id_akun WHERE YEAR(jh.tanggal) = ? AND jh.status_jurnal = 'POSTED' AND a.kode_akun LIKE '4%'");
                    $stmtRev->execute([$tahun]);
                    $totRev = (float)$stmtRev->fetchColumn();

                    $stmtExp = $pdo->prepare("SELECT COALESCE(SUM(jd.debit - jd.kredit), 0) FROM jurnal_detail jd JOIN jurnal_header jh ON jd.id_jurnal = jh.id_jurnal JOIN akun a ON jd.id_akun = a.id_akun WHERE YEAR(jh.tanggal) = ? AND jh.status_jurnal = 'POSTED' AND (a.kode_akun LIKE '5%' OR a.kode_akun LIKE '6%')");
                    $stmtExp->execute([$tahun]);
                    $totExp = (float)$stmtExp->fetchColumn();

                    return sendResponse(200, ['success' => true, 'tipe' => 'TAHUNAN', 'tahun' => $tahun, 'total_pendapatan' => $totRev, 'total_beban' => $totExp, 'estimasi_laba_bersih' => $totRev - $totExp, 'target_akun_laba_ditahan' => '3201.01 • Laba Ditahan']);
                }

            case 'tutup_buku_bulanan':
                $bulan = (int)($data['bulan'] ?? date('m'));
                $tahun = (int)($data['tahun'] ?? date('Y'));
                if ($bulan < 1 || $bulan > 12 || $tahun < 2020) return sendResponse(400, ['success' => false, 'message' => 'Bulan dan Tahun tidak valid.']);

                $tgl_awal  = sprintf('%04d-%02d-01', $tahun, $bulan);
                $tgl_akhir = date('Y-m-t', strtotime($tgl_awal));

                $stmt = $pdo->prepare("UPDATE jurnal_header SET status = 'LOCKED' WHERE tanggal BETWEEN ? AND ? AND status = 'POSTED'");
                $stmt->execute([$tgl_awal, $tgl_akhir]);
                return sendResponse(200, ['success' => true, 'message' => "Tutup buku periode $tahun-" . str_pad((string)$bulan, 2, '0', STR_PAD_LEFT) . " berhasil."]);

            case 'tutup_buku_tahunan':
                $tahun = (int)($data['tahun'] ?? date('Y'));
                $tgl_awal  = "$tahun-01-01";
                $tgl_akhir = "$tahun-12-31";

                $stmtLaba = $pdo->prepare("SELECT COALESCE(SUM(CASE WHEN a.kategori = 'Pendapatan' AND jd.posisi = 'KREDIT' THEN jd.jumlah ELSE 0 END), 0) - COALESCE(SUM(CASE WHEN a.kategori = 'Pendapatan' AND jd.posisi = 'DEBIT' THEN jd.jumlah ELSE 0 END), 0) - (COALESCE(SUM(CASE WHEN a.kategori IN ('HPP', 'Beban') AND jd.posisi = 'DEBIT' THEN jd.jumlah ELSE 0 END), 0) - COALESCE(SUM(CASE WHEN a.kategori IN ('HPP', 'Beban') AND jd.posisi = 'KREDIT' THEN jd.jumlah ELSE 0 END), 0)) AS laba_bersih FROM jurnal_detail jd JOIN akun a ON jd.id_akun = a.id_akun JOIN jurnal_header jh ON jd.id_jurnal = jh.id_jurnal WHERE jh.tanggal BETWEEN ? AND ?");
                $stmtLaba->execute([$tgl_awal, $tgl_akhir]);
                $laba_bersih = (float)$stmtLaba->fetchColumn();

                $stmtAkun = $pdo->prepare("SELECT id_akun FROM akun WHERE kode_akun = '3201.01' LIMIT 1");
                $stmtAkun->execute();
                $id_laba_ditahan = (int)$stmtAkun->fetchColumn();

                if ($id_laba_ditahan <= 0) return sendResponse(500, ['success' => false, 'message' => 'Akun Laba Ditahan (3201.01) tidak ditemukan.']);

                $pdo->beginTransaction();
                try {
                    $no_jurnal = "CLS-$tahun";
                    $stmtCek = $pdo->prepare("SELECT id_jurnal FROM jurnal_header WHERE no_jurnal = ?");
                    $stmtCek->execute([$no_jurnal]);
                    if ($existing_id = $stmtCek->fetchColumn()) {
                        $pdo->prepare("DELETE FROM jurnal_detail WHERE id_jurnal = ?")->execute([(int)$existing_id]);
                        $pdo->prepare("DELETE FROM jurnal_header WHERE id_jurnal = ?")->execute([(int)$existing_id]);
                    }

                    $stmtH = $pdo->prepare("INSERT INTO jurnal_header (no_jurnal, tanggal, referensi_tipe, id_referensi, keterangan, status) VALUES (?, ?, 'CLOSING_TAHUNAN', 1, ?, 'LOCKED')");
                    $stmtH->execute([$no_jurnal, $tgl_akhir, "Jurnal Penutup Akhir Tahun $tahun"]);
                    $id_jurnal = (int)$pdo->lastInsertId();

                    if ($laba_bersih > 0) {
                        $pdo->prepare("INSERT INTO jurnal_detail (id_jurnal, no_jurnal, tanggal, id_akun, posisi, jumlah, keterangan) VALUES (?, ?, ?, ?, 'KREDIT', ?, 'Alokasi Laba Bersih')")->execute([$id_jurnal, $no_jurnal, $tgl_akhir, $id_laba_ditahan, $laba_bersih]);
                    } elseif ($laba_bersih < 0) {
                        $pdo->prepare("INSERT INTO jurnal_detail (id_jurnal, no_jurnal, tanggal, id_akun, posisi, jumlah, keterangan) VALUES (?, ?, ?, ?, 'DEBIT', ?, 'Alokasi Rugi Bersih')")->execute([$id_jurnal, $no_jurnal, $tgl_akhir, $id_laba_ditahan, abs($laba_bersih)]);
                    }

                    $pdo->prepare("UPDATE jurnal_header SET status = 'LOCKED' WHERE tanggal BETWEEN ? AND ?")->execute([$tgl_awal, $tgl_akhir]);
                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => "Tutup buku tahunan $tahun selesai."]);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal tutup buku tahunan: ' . $e->getMessage()]);
                }

            // ==========================================
            // MODUL REKENING BANK
            // ==========================================
            case 'get_rekening_bank_owner_options':
                $owner_type = trim((string)($data['owner_type'] ?? ''));
                $items = [];
                if ($owner_type === 'PERUSAHAAN') {
                    $items = [['id_owner' => 1, 'owner_label' => 'PT ASBEN JAYA MANDIRI']];
                } elseif ($owner_type === 'SUPPLIER') {
                    $stmt = $pdo->query("SELECT id_supplier AS id_owner, nama_supplier AS owner_label FROM master_supplier ORDER BY nama_supplier ASC");
                    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
                } elseif ($owner_type === 'CUSTOMER') {
                    $stmt = $pdo->query("SELECT id_customer AS id_owner, nama_customer AS owner_label FROM customer WHERE is_active = 1 ORDER BY nama_customer ASC");
                    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
                } elseif ($owner_type === 'KARYAWAN') {
                    $stmt = $pdo->query("SELECT id_karyawan AS id_owner, nama_lengkap AS owner_label FROM karyawan WHERE status_aktif = 1 OR status_aktif = 'Aktif' ORDER BY nama_lengkap ASC");
                    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
                }
                return sendResponse(200, ['success' => true, 'data' => ['items' => $items]]);

            case 'get_list_rekening_bank':
                $actor = validateBearerToken($pdo); 
                $page   = max(1, (int) ($data['page'] ?? 1));
                $limit  = max(1, min(100, (int) ($data['limit'] ?? 25)));
                $offset = ($page - 1) * $limit;
                
                $keyword = trim((string) ($data['keyword'] ?? ''));
                $where = "WHERE is_active = 1";
                $params = [];

                if (!empty($keyword)) {
                    $where .= " AND (nama_bank LIKE ? OR nama_rekening LIKE ? OR atas_nama LIKE ? OR kode_rekening LIKE ?)";
                    $params[] = "%$keyword%"; $params[] = "%$keyword%"; $params[] = "%$keyword%"; $params[] = "%$keyword%";
                }

                $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM master_rekening_bank $where");
                $stmtCount->execute($params);
                $totalData = (int) $stmtCount->fetchColumn();

                $sql = "SELECT id_rekening_bank, owner_type, id_owner, kode_rekening, kode_bank, nama_bank, jenis_rekening, 
                               CONCAT(REPEAT('*', GREATEST(0, LENGTH(nomor_rekening) - 4)), RIGHT(nomor_rekening, 4)) AS nomor_rekening_masked, 
                               atas_nama, id_akun, is_active, row_version
                        FROM master_rekening_bank $where ORDER BY is_default DESC, nama_bank ASC LIMIT $limit OFFSET $offset";
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);

                return sendResponse(200, [
                    'success'    => true,
                    'page'       => $page,
                    'limit'      => $limit,
                    'total_data' => $totalData,
                    'data'       => $stmt->fetchAll(PDO::FETCH_ASSOC)
                ]);

            case 'create_rekening_bank':
                $actor = validateBearerToken($pdo); 
                $actor_id = $actor['id_user'];
                $request_id = $data['request_id'] ?? uniqid('REQ-', true);

                $owner_type     = trim((string)($data['owner_type'] ?? ''));
                $id_owner       = (int)($data['id_owner'] ?? 0);
                $kode_rekening  = trim((string)($data['kode_rekening'] ?? ''));
                $kode_bank      = trim((string)($data['kode_bank'] ?? ''));
                $nama_bank      = trim((string)($data['nama_bank'] ?? ''));
                $nama_rekening  = trim((string)($data['nama_rekening'] ?? ''));
                $jenis_rekening = trim((string)($data['jenis_rekening'] ?? 'GIRO'));
                $nomor_rekening = trim((string)($data['nomor_rekening'] ?? ''));
                $atas_nama      = trim((string)($data['atas_nama'] ?? ''));
                $id_akun        = (int)($data['id_akun'] ?? 0);
                $is_default     = (int)($data['is_default'] ?? 0);

                if (empty($kode_rekening) || empty($nomor_rekening) || empty($atas_nama) || $id_akun <= 0) {
                    return sendResponse(400, ['success' => false, 'message' => 'Data wajib (kode, nomor, atas nama, akun) tidak boleh kosong!']);
                }

                $pdo->beginTransaction();
                try {
                    $stmt = $pdo->prepare("INSERT INTO master_rekening_bank (owner_type, id_owner, kode_rekening, kode_bank, nama_bank, nama_rekening, jenis_rekening, nomor_rekening, atas_nama, id_akun, is_default, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                    $stmt->execute([$owner_type, $id_owner, $kode_rekening, $kode_bank, $nama_bank, $nama_rekening, $jenis_rekening, $nomor_rekening, $atas_nama, $id_akun, $is_default, $actor_id, $actor_id]);
                    $newId = $pdo->lastInsertId();
                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Rekening bank berhasil disimpan.', 'id_rekening_bank' => $newId]);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal menyimpan rekening: ' . $e->getMessage()]);
                }

            case 'update_rekening_bank':
                $actor = validateBearerToken($pdo);
                $actor_id = $actor['id_user'];
                $id_rekening_bank = (int) ($data['id_rekening_bank'] ?? 0);
                $client_version   = (int) ($data['row_version'] ?? 0);

                if ($id_rekening_bank <= 0) return sendResponse(400, ['success' => false, 'message' => 'ID Rekening Bank tidak valid.']);

                $pdo->beginTransaction();
                try {
                    $stmtCheck = $pdo->prepare("SELECT * FROM master_rekening_bank WHERE id_rekening_bank = ? FOR UPDATE");
                    $stmtCheck->execute([$id_rekening_bank]);
                    $beforeData = $stmtCheck->fetch(PDO::FETCH_ASSOC);

                    if (!$beforeData) {
                        $pdo->rollBack();
                        return sendResponse(404, ['success' => false, 'message' => 'Data rekening bank tidak ditemukan.']);
                    }
                    if ((int)$beforeData['row_version'] !== $client_version) {
                        $pdo->rollBack();
                        return sendResponse(409, ['success' => false, 'message' => 'Konflik data: Silakan muat ulang.']);
                    }

                    $nama_rekening = $data['nama_rekening'] ?? $beforeData['nama_rekening'];
                    $atas_nama     = $data['atas_nama'] ?? $beforeData['atas_nama'];
                    $nomor_rek     = empty($data['nomor_rekening']) ? $beforeData['nomor_rekening'] : $data['nomor_rekening'];
                    $new_version   = $client_version + 1;

                    $stmtUpd = $pdo->prepare("UPDATE master_rekening_bank SET nama_rekening = ?, atas_nama = ?, nomor_rekening = ?, row_version = ?, updated_by = ? WHERE id_rekening_bank = ? AND row_version = ?");
                    $stmtUpd->execute([$nama_rekening, $atas_nama, $nomor_rek, $new_version, $actor_id, $id_rekening_bank, $client_version]);
                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Rekening bank berhasil diperbarui.']);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal memperbarui rekening: ' . $e->getMessage()]);
                }

            case 'delete_rekening_bank':
                $actor = validateBearerToken($pdo);
                $actor_id = $actor['id_user'];
                $id_rekening_bank = (int) ($data['id_rekening_bank'] ?? 0);

                if ($id_rekening_bank <= 0) return sendResponse(400, ['success' => false, 'message' => 'ID Rekening Bank tidak valid.']);
                $stmt = $pdo->prepare("UPDATE master_rekening_bank SET is_active = 0, is_default = 0, updated_by = ? WHERE id_rekening_bank = ?");
                $stmt->execute([$actor_id, $id_rekening_bank]);
                return sendResponse(200, ['success' => true, 'message' => 'Rekening bank berhasil dihapus.']);

            // ==========================================
            // MODUL CUSTOMER, SUPPLIER & ITEM MASTER
            // ==========================================
            case 'get_list_customer':
                $stmt = $pdo->query("SELECT * FROM customer WHERE is_active = 1 ORDER BY nama_customer ASC");
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);

            case 'create_customer':
                $kode_customer  = trim((string)($data['kode_customer'] ?? ''));
                $nama_customer  = trim((string)($data['nama_customer'] ?? ''));
                $jenis_kelamin  = trim((string)($data['jenis_kelamin'] ?? 'Laki-laki'));
                $alamat         = trim((string)($data['alamat'] ?? ''));
                $telepon        = trim((string)($data['telepon'] ?? ''));

                if (empty($nama_customer)) return sendResponse(400, ['success' => false, 'message' => 'Nama Customer wajib diisi']);
                $stmt = $pdo->prepare("INSERT INTO customer (kode_customer, nama_customer, jenis_kelamin, alamat, telepon) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$kode_customer, $nama_customer, $jenis_kelamin, $alamat, $telepon]);
                return sendResponse(200, ['success' => true, 'message' => 'Customer ditambahkan', 'id_customer' => $pdo->lastInsertId()]);

            case 'update_customer':
                $id_customer    = (int)($data['id_customer'] ?? 0);
                $kode_customer  = trim((string)($data['kode_customer'] ?? ''));
                $nama_customer  = trim((string)($data['nama_customer'] ?? ''));
                $jenis_kelamin  = trim((string)($data['jenis_kelamin'] ?? 'Laki-laki'));
                $alamat         = trim((string)($data['alamat'] ?? ''));
                $telepon        = trim((string)($data['telepon'] ?? ''));

                if ($id_customer <= 0 || empty($nama_customer)) return sendResponse(400, ['success' => false, 'message' => 'ID dan Nama Customer wajib diisi']);
                $stmt = $pdo->prepare("UPDATE customer SET kode_customer = ?, nama_customer = ?, jenis_kelamin = ?, alamat = ?, telepon = ? WHERE id_customer = ?");
                $stmt->execute([$kode_customer, $nama_customer, $jenis_kelamin, $alamat, $telepon, $id_customer]);
                return sendResponse(200, ['success' => true, 'message' => 'Customer diupdate']);

            case 'delete_customer':
                $id_customer = (int)($data['id_customer'] ?? 0);
                $stmt = $pdo->prepare("UPDATE customer SET is_active = 0 WHERE id_customer = ?");
                $stmt->execute([$id_customer]);
                return sendResponse(200, ['success' => true, 'message' => 'Customer dihapus']);

            case 'get_supplier':
            case 'get_master_supplier':
                $stmt = $pdo->prepare("SELECT id_supplier, nama_supplier, kontak_whatsapp, alamat, created_at FROM master_supplier ORDER BY nama_supplier ASC");
                $stmt->execute();
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_supplier':
                $nama_supplier   = trim((string) ($data['nama_supplier'] ?? $data['nama'] ?? ''));
                $kontak_whatsapp = trim((string) ($data['kontak_whatsapp'] ?? $data['whatsapp'] ?? ''));
                $alamat          = trim((string) ($data['alamat'] ?? ''));

                if (empty($nama_supplier)) return sendResponse(400, ['success' => false, 'message' => 'Nama supplier wajib diisi']);
                $stmt = $pdo->prepare("INSERT INTO master_supplier (nama_supplier, kontak_whatsapp, alamat) VALUES (?, ?, ?)");
                $stmt->execute([$nama_supplier, $kontak_whatsapp, $alamat]);
                return sendResponse(200, ['success' => true, 'message' => 'Supplier ditambahkan']);

            case 'get_master_harga_pembelian':
                $stmt = $pdo->prepare("SELECT h.*, j.nama_jenis_kayu FROM master_harga_pembelian h LEFT JOIN master_jenis_kayu j ON h.id_jenis_kayu = j.id_jenis_kayu ORDER BY h.id_harga DESC");
                $stmt->execute();
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_master_harga_pembelian':
                $id_harga = (int) ($data['id_harga'] ?? 0);
                $id_jenis_kayu = (int) ($data['id_jenis_kayu'] ?? 0);
                $kode_grade = trim((string) ($data['kode_grade'] ?? 'SUPER'));
                $dia_min = (float) ($data['dia_min'] ?? 0);
                $dia_max = (float) ($data['dia_max'] ?? 0);
                $harga_per_m3 = (float) ($data['harga_per_m3'] ?? 0);
                $tanggal_mulai = trim((string) ($data['tanggal_mulai'] ?? date('Y-m-d')));
                $tanggal_selesai = trim((string) ($data['tanggal_selesai'] ?? ''));
                $is_active = (int) ($data['is_active'] ?? 1);
                $tgl_selesai_val = $tanggal_selesai === '' ? null : $tanggal_selesai;

                if ($id_jenis_kayu <= 0 || $harga_per_m3 <= 0) return sendResponse(400, ['success' => false, 'message' => 'ID Jenis Kayu dan Harga Per M3 wajib diisi']);
                
                if ($id_harga > 0) {
                    $stmt = $pdo->prepare("UPDATE master_harga_pembelian SET id_jenis_kayu=?, kode_grade=?, dia_min=?, dia_max=?, harga_per_m3=?, tanggal_mulai=?, tanggal_selesai=?, is_active=? WHERE id_harga=?");
                    $stmt->execute([$id_jenis_kayu, $kode_grade, $dia_min, $dia_max, $harga_per_m3, $tanggal_mulai, $tgl_selesai_val, $is_active, $id_harga]);
                } else {
                    $stmt = $pdo->prepare("INSERT INTO master_harga_pembelian (id_jenis_kayu, kode_grade, dia_min, dia_max, harga_per_m3, tanggal_mulai, tanggal_selesai, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                    $stmt->execute([$id_jenis_kayu, $kode_grade, $dia_min, $dia_max, $harga_per_m3, $tanggal_mulai, $tgl_selesai_val, $is_active]);
                    $id_harga = (int) $pdo->lastInsertId();
                }
                return sendResponse(200, ['success' => true, 'message' => 'Harga disimpan', 'id_harga' => $id_harga]);

            case 'hapus_master_harga_pembelian':
                $id_harga = (int) ($data['id_harga'] ?? 0);
                $pdo->prepare("DELETE FROM master_harga_pembelian WHERE id_harga = ?")->execute([$id_harga]);
                return sendResponse(200, ['success' => true, 'message' => 'Harga dihapus']);

            case 'get_master_volume':
                $stmt = $pdo->prepare("SELECT * FROM master_volume ORDER BY diameter_cm ASC");
                $stmt->execute();
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_master_volume':
                $diameter_cm = (float) ($data['diameter_cm'] ?? 0);
                $volume_m3 = (float) ($data['volume_m3'] ?? 0);
                if ($diameter_cm <= 0 || $volume_m3 <= 0) return sendResponse(400, ['success' => false, 'message' => 'Diameter dan Volume m3 wajib diisi']);
                $stmt = $pdo->prepare("INSERT INTO master_volume (diameter_cm, volume_m3) VALUES (?, ?) ON DUPLICATE KEY UPDATE volume_m3 = ?");
                $stmt->execute([$diameter_cm, $volume_m3, $volume_m3]);
                return sendResponse(200, ['success' => true, 'message' => 'Master volume disimpan']);

            case 'hapus_master_volume':
                $diameter_cm = (float) ($data['diameter_cm'] ?? 0);
                $pdo->prepare("DELETE FROM master_volume WHERE diameter_cm = ?")->execute([$diameter_cm]);
                return sendResponse(200, ['success' => true, 'message' => 'Master volume dihapus']);

            case 'get_master_spesifikasi':
                $stmt = $pdo->prepare("SELECT * FROM master_spesifikasi WHERE status_aktif = 'Aktif' ORDER BY id_unik ASC");
                $stmt->execute();
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);

            case 'create_master_spesifikasi':
                $id_unik    = trim((string)($data['id_unik'] ?? ''));
                $panjang    = (float)($data['panjang_cm'] ?? 122);
                $lebar      = (float)($data['lebar_cm'] ?? 122);
                $tebal      = (float)($data['tebal_cm'] ?? 0.27);
                $satuan     = trim((string)($data['satuan'] ?? 'Palet'));
                $keterangan = trim((string)($data['keterangan'] ?? ''));

                if (empty($id_unik)) return sendResponse(400, ['success' => false, 'message' => 'ID Unik wajib diisi.']);
                $stmt = $pdo->prepare("INSERT INTO master_spesifikasi (id_unik, panjang_cm, lebar_cm, tebal_cm, satuan, keterangan) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$id_unik, $panjang, $lebar, $tebal, $satuan, $keterangan]);
                return sendResponse(200, ['success' => true, 'message' => 'Spesifikasi ditambahkan', 'id_spesifikasi' => (int)$pdo->lastInsertId()]);

            case 'update_master_spesifikasi':
                $id_spesifikasi = (int)($data['id_spesifikasi'] ?? 0);
                $id_unik        = trim((string)($data['id_unik'] ?? ''));
                $panjang        = (float)($data['panjang_cm'] ?? 122);
                $lebar          = (float)($data['lebar_cm'] ?? 122);
                $tebal          = (float)($data['tebal_cm'] ?? 0.27);
                $satuan         = trim((string)($data['satuan'] ?? 'Palet'));
                $keterangan     = trim((string)($data['keterangan'] ?? ''));

                $stmt = $pdo->prepare("UPDATE master_spesifikasi SET id_unik = ?, panjang_cm = ?, lebar_cm = ?, tebal_cm = ?, satuan = ?, keterangan = ? WHERE id_spesifikasi = ?");
                $stmt->execute([$id_unik, $panjang, $lebar, $tebal, $satuan, $keterangan, $id_spesifikasi]);
                return sendResponse(200, ['success' => true, 'message' => 'Spesifikasi diperbarui.']);

            case 'delete_master_spesifikasi':
                $id_spesifikasi = (int)($data['id_spesifikasi'] ?? 0);
                $pdo->prepare("UPDATE master_spesifikasi SET status_aktif = 'Nonaktif' WHERE id_spesifikasi = ?")->execute([$id_spesifikasi]);
                return sendResponse(200, ['success' => true, 'message' => 'Spesifikasi dinonaktifkan.']);

            // ==========================================
            // MODUL PEMBELIAN & LOG SORTING (INBOUND)
            // ==========================================
            case 'simpan_po':
                $no_po        = trim((string) ($data['no_po'] ?? ''));
                $nama_pemasok = trim((string) ($data['nama_pemasok'] ?? ''));
                $tanggal_po   = (string) ($data['tanggal_po'] ?? date('Y-m-d'));
                $status       = trim((string) ($data['status'] ?? 'OPEN'));

                if (empty($no_po) || empty($nama_pemasok)) return sendResponse(400, ['success' => false, 'message' => 'Nomor PO dan Nama Pemasok wajib diisi']);
                $stmt = $pdo->prepare("INSERT INTO tally_header (no_po, nama_pemasok, tanggal, status_verifikasi) VALUES (?, ?, ?, ?)");
                $stmt->execute([$no_po, $nama_pemasok, $tanggal_po, $status === 'OPEN' ? 'Pending' : 'Verified']);
                return sendResponse(200, ['success' => true, 'message' => 'Purchase Order disimpan']);

            case 'get_list_po':
                $stmt = $pdo->prepare("SELECT DISTINCT no_po, nama_pemasok, tanggal FROM `tally_header` WHERE no_po IS NOT NULL AND no_po != '' ORDER BY tanggal DESC");
                $stmt->execute();
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'get_log_sorting':
                $status = trim((string)($data['status_lot'] ?? ''));
                $sql = "SELECT * FROM log_sorting_header";
                $params = [];
                if (!empty($status)) {
                    $sql .= " WHERE status_lot = ?";
                    $params[] = $status;
                }
                $sql .= " ORDER BY id_sorting DESC";
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);

            case 'get_log_sorting_detail':
                $id_sorting = (int)($data['id_sorting'] ?? 0);
                $stmtH = $pdo->prepare("SELECT * FROM log_sorting_header WHERE id_sorting = ?");
                $stmtH->execute([$id_sorting]);
                $header = $stmtH->fetch(PDO::FETCH_ASSOC);

                $stmtD = $pdo->prepare("SELECT * FROM log_sorting_detail WHERE id_sorting = ? ORDER BY no_batang ASC");
                $stmtD->execute([$id_sorting]);
                $details = $stmtD->fetchAll(PDO::FETCH_ASSOC);

                return sendResponse(200, ['success' => true, 'header' => $header, 'details' => $details]);

            case 'create_log_sorting':
                $supplier_id  = (int)($data['id_supplier'] ?? 0);
                $nama_supp    = trim((string)($data['nama_supplier'] ?? 'Ayep'));
                $jenis_kayu   = trim((string)($data['nama_jenis_kayu'] ?? 'MAHONI-06'));
                $range_dia    = trim((string)($data['range_diameter'] ?? 'D30-39'));
                $rincian_kayu = $data['rincian_batang'] ?? [];

                if (empty($rincian_kayu)) return sendResponse(400, ['success' => false, 'message' => 'Rincian batang tidak boleh kosong.']);

                $pdo->beginTransaction();
                try {
                    $kode_lot = 'LOT-LOG-' . date('Ymd-His') . '-' . strtoupper(substr(uniqid(), -6));
                    $jml_batang = count($rincian_kayu);
                    $total_vol = 0.0000;

                    foreach ($rincian_kayu as $item) { $total_vol += (float)($item['volume_m3'] ?? 0); }

                    $stmtH = $pdo->prepare("INSERT INTO log_sorting_header (kode_lot, tanggal_sorted, id_supplier, nama_supplier, nama_jenis_kayu, range_diameter, jumlah_batang, total_kubikasi_m3, qr_code_payload, status_lot) VALUES (?, CURDATE(), ?, ?, ?, ?, ?, ?, ?, 'PENDING')");
                    $stmtH->execute([$kode_lot, $supplier_id, $nama_supp, $jenis_kayu, $range_dia, $jml_batang, $total_vol, $kode_lot]);
                    $id_sorting = (int)$pdo->lastInsertId();

                    $stmtD = $pdo->prepare("INSERT INTO log_sorting_detail (id_sorting, no_batang, panjang_cm, diameter_ujung1_cm, diameter_ujung2_cm, diameter_rata2_cm, volume_m3) VALUES (?, ?, ?, ?, ?, ?, ?)");
                    $no = 1;
                    foreach ($rincian_kayu as $item) {
                        $p  = (float)($item['panjang_cm'] ?? 0);
                        $d1 = (float)($item['diameter_ujung1_cm'] ?? 0);
                        $d2 = (float)($item['diameter_ujung2_cm'] ?? 0);
                        $dr = ($d1 + $d2) / 2;
                        $v  = (float)($item['volume_m3'] ?? 0);
                        $stmtD->execute([$id_sorting, $no++, $p, $d1, $d2, $dr, $v]);
                    }
                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Data Sorting Lot disimpan.', 'id_sorting' => $id_sorting, 'kode_lot' => $kode_lot]);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal simpan sorting: ' . $e->getMessage()]);
                }

            case 'update_log_sorting':
                $id_sorting   = (int)($data['id_sorting'] ?? 0);
                $nama_supp    = trim((string)($data['nama_supplier'] ?? ''));
                $jenis_kayu   = trim((string)($data['nama_jenis_kayu'] ?? ''));
                $range_dia    = trim((string)($data['range_diameter'] ?? ''));
                $status_lot   = trim((string)($data['status_lot'] ?? 'PENDING'));
                $rincian_kayu = $data['rincian_batang'] ?? [];

                $pdo->beginTransaction();
                try {
                    if (!empty($rincian_kayu)) {
                        $pdo->prepare("DELETE FROM log_sorting_detail WHERE id_sorting = ?")->execute([$id_sorting]);
                        $stmtD = $pdo->prepare("INSERT INTO log_sorting_detail (id_sorting, no_batang, panjang_cm, diameter_ujung1_cm, diameter_ujung2_cm, diameter_rata2_cm, volume_m3) VALUES (?, ?, ?, ?, ?, ?, ?)");
                        $no = 1; $total_vol = 0.0000;
                        foreach ($rincian_kayu as $item) {
                            $p  = (float)($item['panjang_cm'] ?? 0); $d1 = (float)($item['diameter_ujung1_cm'] ?? 0); $d2 = (float)($item['diameter_ujung2_cm'] ?? 0);
                            $v  = (float)($item['volume_m3'] ?? 0); $total_vol += $v;
                            $stmtD->execute([$id_sorting, $no++, $p, $d1, $d2, ($d1 + $d2) / 2, $v]);
                        }
                        $stmtH = $pdo->prepare("UPDATE log_sorting_header SET nama_supplier = ?, nama_jenis_kayu = ?, range_diameter = ?, status_lot = ?, jumlah_batang = ?, total_kubikasi_m3 = ? WHERE id_sorting = ?");
                        $stmtH->execute([$nama_supp, $jenis_kayu, $range_dia, $status_lot, count($rincian_kayu), $total_vol, $id_sorting]);
                    } else {
                        $stmtH = $pdo->prepare("UPDATE log_sorting_header SET nama_supplier = ?, nama_jenis_kayu = ?, range_diameter = ?, status_lot = ? WHERE id_sorting = ?");
                        $stmtH->execute([$nama_supp, $jenis_kayu, $range_dia, $status_lot, $id_sorting]);
                    }
                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Data Sorting Lot diperbarui.']);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal update sorting: ' . $e->getMessage()]);
                }

            case 'delete_log_sorting':
                $id_sorting = (int)($data['id_sorting'] ?? 0);
                $pdo->prepare("DELETE FROM log_sorting_header WHERE id_sorting = ?")->execute([$id_sorting]);
                return sendResponse(200, ['success' => true, 'message' => 'Data Sorting Lot dihapus.']);

            // ==========================================
            // MODUL TALLY
            // ==========================================
            case 'get_list_tally':
                $stmt = $pdo->prepare("
                    SELECT h.id_tally, h.no_tally, h.no_po, h.nama_pemasok AS nama_supplier, 
                           h.tanggal, h.no_pol, h.rit, h.status_verifikasi,
                           COALESCE(SUM(d.jumlah_batang), 0) AS total_batang,
                           COALESCE(SUM(d.vol_per_btg * d.jumlah_batang), 0) AS total_volume
                    FROM tally_header h
                    LEFT JOIN tally_detail d ON h.id_tally = d.id_tally
                    GROUP BY h.id_tally, h.no_tally, h.no_po, h.nama_pemasok, h.tanggal, h.no_pol, h.rit, h.status_verifikasi
                    ORDER BY h.tanggal DESC, h.id_tally DESC
                ");
                $stmt->execute();
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'get_laporan_tally':
                $id_tally = (int) ($data['id_tally'] ?? 0);
                $stmtH = $pdo->prepare("SELECT * FROM tally_header WHERE id_tally = ? LIMIT 1");
                $stmtH->execute([$id_tally]);
                $header = $stmtH->fetch(PDO::FETCH_ASSOC);

                if (!$header) return sendResponse(404, ['success' => false, 'message' => 'Data laporan tally tidak ditemukan']);

                $stmtD = $pdo->prepare("SELECT td.*, j.nama_jenis_kayu FROM tally_detail td LEFT JOIN master_jenis_kayu j ON td.id_jenis_kayu = j.id_jenis_kayu WHERE td.id_tally = ?");
                $stmtD->execute([$id_tally]);
                $details = $stmtD->fetchAll(PDO::FETCH_ASSOC);

                $total_batang = 0; $total_volume = 0; $total_bruto  = 0;
                foreach ($details as $row) {
                    $jml_btg  = (int) ($row['jumlah_batang'] ?? 0);
                    $vol_btg  = (float) ($row['vol_per_btg'] ?? 0);
                    $harga_m3 = (float) ($row['harga_per_m3'] ?? ($row['harga'] ?? 0));
                    $total_batang += $jml_btg;
                    $total_volume += ($vol_btg * $jml_btg);
                    $total_bruto  += (($vol_btg * $jml_btg) * $harga_m3);
                }

                $header['status_pajak'] = $header['status_pajak'] ?? 'Non Pajak';
                $header['tarif_ppn']    = (float)($header['tarif_ppn'] ?? 0);
                $header['tarif_pph']    = (float)($header['tarif_pph'] ?? 0);

                $nominal_ppn = 0; $nominal_pph22 = 0;
                $st_pajak = strtoupper($header['status_pajak']);
                if (str_contains($st_pajak, 'PPN')) $nominal_ppn = $total_bruto * ($header['tarif_ppn'] / 100);
                if (str_contains($st_pajak, 'PPH')) $nominal_pph22 = $total_bruto * ($header['tarif_pph'] / 100);

                return sendResponse(200, [
                    'success' => true, 'version' => 'tally-report.v1', 'header' => $header,
                    'data' => [
                        'items' => $details,
                        'summary' => [
                            'total_batang' => $total_batang, 'total_volume' => round($total_volume, 4), 'total_bruto' => round($total_bruto, 2),
                            'nominal_ppn' => round($nominal_ppn, 2), 'nominal_pph22' => round($nominal_pph22, 2)
                        ]
                    ]
                ]);

            case 'simpan_tally':
                $no_po            = trim((string) ($data['no_po'] ?? ''));
                $nama_pemasok     = trim((string) ($data['nama_pemasok'] ?? ''));
                $tanggal          = (string) ($data['tanggal'] ?? date('Y-m-d'));
                $no_pol           = (string) ($data['no_pol'] ?? '');
                $rit              = (int) ($data['rit'] ?? 1);
                $biaya_bongkar    = (float) ($data['biaya_bongkar'] ?? 0);
                $kasbon_ongkir    = (float) ($data['kasbon_ongkir'] ?? 0);
                $ttd_pengawas     = $data['ttd_pengawas'] ?? null;
                $ttd_petugas_ukur = $data['ttd_petugas_ukur'] ?? null;
                $ttd_keuangan     = $data['ttd_keuangan'] ?? null;
                $items            = $data['items'] ?? [];

                if (empty($no_po) || empty($nama_pemasok) || empty($items)) return sendResponse(400, ['success' => false, 'message' => 'Data tally wajib diisi']);

                $pdo->beginTransaction();
                try {
                    $stmtHeader = $pdo->prepare("INSERT INTO tally_header (no_po, nama_pemasok, tanggal, no_pol, rit, biaya_bongkar, kasbon_ongkir, status_verifikasi, ttd_pengawas, ttd_petugas_ukur, ttd_keuangan) VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?, ?)");
                    $stmtHeader->execute([$no_po, $nama_pemasok, $tanggal, $no_pol, $rit, $biaya_bongkar, $kasbon_ongkir, $ttd_pengawas, $ttd_petugas_ukur, $ttd_keuangan]);
                    $id_tally = (int) $pdo->lastInsertId();

                    $stmtDetail = $pdo->prepare("INSERT INTO tally_detail (id_tally, id_jenis_kayu, grade, panjang_cm, diameter_tok, vol_per_btg, jumlah_batang, harga_per_m3) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                    $stmtVol = $pdo->prepare("SELECT volume_m3 FROM master_volume WHERE diameter_cm = ? LIMIT 1");
                    $stmtHarga = $pdo->prepare("SELECT harga_per_m3 FROM master_harga_pembelian WHERE id_jenis_kayu = ? AND ? BETWEEN dia_min AND dia_max LIMIT 1");

                    foreach ($items as $item) {
                        $id_jenis_kayu  = (int) ($item['id_jenis_kayu'] ?? 0);
                        $diameter       = (float) ($item['diameter_tok'] ?? 0);
                        $panjang        = (int) ($item['panjang_cm'] ?? 130);
                        $jumlah_batang  = (int) ($item['jumlah_batang'] ?? 0);
                        $grade          = $item['grade'] ?? 'SUPER';

                        $stmtVol->execute([$diameter]);
                        $volRow = $stmtVol->fetch();
                        $vol_per_btg = $volRow ? (float)$volRow['volume_m3'] : (0.7854 * pow($diameter, 2) * $panjang / 1000000);

                        $stmtHarga->execute([$id_jenis_kayu, $diameter]);
                        $hargaRow = $stmtHarga->fetch();
                        if (!$hargaRow) {
                            $pdo->rollBack();
                            return sendResponse(409, ['success' => false, 'message' => "Harga tidak ditemukan untuk kayu ID {$id_jenis_kayu} dia {$diameter} cm."]);
                        }
                        $stmtDetail->execute([$id_tally, $id_jenis_kayu, $grade, $panjang, $diameter, $vol_per_btg, $jumlah_batang, (float)$hargaRow['harga_per_m3']]);
                    }

                    $no_tally = 'TLY-' . date('Y') . '-' . str_pad((string)$id_tally, 6, '0', STR_PAD_LEFT);
                    $pdo->prepare("UPDATE tally_header SET no_tally = ? WHERE id_tally = ?")->execute([$no_tally, $id_tally]);

                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Tally disimpan', 'id_tally' => $id_tally, 'no_tally' => $no_tally]);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal menyimpan tally: ' . $e->getMessage()]);
                }

            case 'update_tally':
                $id_tally     = (int) ($data['id_tally'] ?? 0);
                $row_version  = (int) ($data['row_version'] ?? 1);
                
                $pdo->beginTransaction();
                try {
                    $stmtCheck = $pdo->prepare("SELECT status_posting, accounting_locked, row_version FROM tally_header WHERE id_tally = ? FOR UPDATE");
                    $stmtCheck->execute([$id_tally]);
                    $header_db = $stmtCheck->fetch(PDO::FETCH_ASSOC);
                    
                    if (!$header_db) { $pdo->rollBack(); return sendResponse(404, ['success' => false, 'message' => 'Tally tidak ditemukan']); }
                    if ($header_db['status_posting'] === 'POSTED' || $header_db['accounting_locked'] == 1) { $pdo->rollBack(); return sendResponse(400, ['success' => false, 'message' => 'Tally sudah POSTED atau terkunci']); }
                    if ((int) $header_db['row_version'] !== $row_version) { $pdo->rollBack(); return sendResponse(409, ['success' => false, 'message' => 'Konflik data: row_version tidak sinkron']); }

                    $h_data       = $data['header'] ?? [];
                    $no_pol       = trim((string) ($h_data['no_pol'] ?? ''));
                    $rit          = (int) ($h_data['rit'] ?? 1);
                    $status_fee   = trim((string) ($h_data['status_fee'] ?? 'Pakai Fee'));
                    
                    $id_karyawan  = (int) ($h_data['id_karyawan'] ?? 0);
                    $sales_name   = '-';
                    if ($id_karyawan > 0) {
                        $stmtK = $pdo->prepare("SELECT nama_lengkap FROM karyawan WHERE id_karyawan = ? LIMIT 1");
                        $stmtK->execute([$id_karyawan]);
                        if ($resK = $stmtK->fetch(PDO::FETCH_ASSOC)) $sales_name = trim($resK['nama_lengkap']);
                    }

                    $status_pajak = trim((string) ($h_data['status_pajak'] ?? 'Non Pajak'));
                    $tarif_ppn    = (float) ($h_data['tarif_ppn'] ?? 0);
                    $tarif_pph    = (float) ($h_data['tarif_pph'] ?? 0);

                    $incoming_items = $data['items'] ?? [];
                    $processed_detail_ids = [];
                    $total_bruto = 0;

                    $stmtUpdD = $pdo->prepare("UPDATE tally_detail SET jumlah_batang = ? WHERE id_detail = ? AND id_tally = ?");
                    $stmtInsD = $pdo->prepare("INSERT INTO tally_detail (id_tally, id_jenis_kayu, grade, panjang_cm, diameter_tok, vol_per_btg, jumlah_batang, harga_per_m3) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                    $stmtVolQuery = $pdo->prepare("SELECT volume_m3 FROM master_volume WHERE diameter_cm = ? LIMIT 1");

                    foreach ($incoming_items as $item) {
                        $id_detail     = (int) ($item['id_detail'] ?? 0);
                        $jumlah_batang = (int) ($item['jumlah_batang'] ?? 0);
                        
                        if ($id_detail > 0) {
                            $stmtUpdD->execute([$jumlah_batang, $id_detail, $id_tally]);
                            $processed_detail_ids[] = $id_detail;
                        } else {
                            $id_jenis_kayu  = (int) ($item['id_jenis_kayu'] ?? ($item['id_master_harga_pembelian'] ?? 0));
                            $diameter       = (float) ($item['diameter_tok'] ?? 0);
                            $panjang        = (int) ($item['panjang_cm'] ?? 130);
                            $grade          = $item['grade'] ?? 'SUPER';
                            $harga_per_m3   = (float) ($item['harga_per_m3'] ?? 0);

                            $stmtVolQuery->execute([$diameter]);
                            $volRow = $stmtVolQuery->fetch(PDO::FETCH_ASSOC);
                            $vol_per_btg = $volRow ? (float)$volRow['volume_m3'] : (0.7854 * pow($diameter, 2) * $panjang / 1000000);

                            $stmtInsD->execute([$id_tally, $id_jenis_kayu, $grade, $panjang, $diameter, $vol_per_btg, $jumlah_batang, $harga_per_m3]);
                            $processed_detail_ids[] = (int) $pdo->lastInsertId();
                        }
                    }

                    if (!empty($processed_detail_ids)) {
                        $placeholders = implode(',', array_fill(0, count($processed_detail_ids), '?'));
                        $delParams = array_merge([$id_tally], $processed_detail_ids);
                        $pdo->prepare("DELETE FROM tally_detail WHERE id_tally = ? AND id_detail NOT IN ($placeholders)")->execute($delParams);
                    } else {
                        $pdo->prepare("DELETE FROM tally_detail WHERE id_tally = ?")->execute([$id_tally]);
                    }

                    $stmtCalc = $pdo->prepare("SELECT total_volume, harga_per_m3 FROM tally_detail WHERE id_tally = ?");
                    $stmtCalc->execute([$id_tally]);
                    while ($row = $stmtCalc->fetch(PDO::FETCH_ASSOC)) {
                        $total_bruto += ((float)$row['total_volume'] * (float)$row['harga_per_m3']);
                    }

                    $nominal_ppn   = ($status_pajak === 'PPN' || $status_pajak === 'PPN & PPH') ? ($total_bruto * ($tarif_ppn / 100)) : 0;
                    $nominal_pph22 = ($status_pajak === 'PPH' || $status_pajak === 'PPN & PPH') ? ($total_bruto * ($tarif_pph / 100)) : 0;

                    $stmtUpdH = $pdo->prepare("
                        UPDATE tally_header 
                        SET no_pol = ?, rit = ?, status_fee = ?, id_karyawan = ?, sales_name = ?, 
                            status_pajak = ?, tarif_ppn = ?, tarif_pph = ?, 
                            nominal_ppn = ?, nominal_pph22 = ?, total_bruto = ?, 
                            row_version = row_version + 1 
                        WHERE id_tally = ? AND row_version = ?
                    ");
                    $stmtUpdH->execute([$no_pol, $rit, $status_fee, $id_karyawan, $sales_name, $status_pajak, $tarif_ppn, $tarif_pph, $nominal_ppn, $nominal_pph22, $total_bruto, $id_tally, $row_version]);

                    if ($stmtUpdH->rowCount() === 0) { $pdo->rollBack(); return sendResponse(409, ['success' => false, 'message' => 'Konflik data konkuren']); }

                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Tally diperbarui', 'row_version' => $row_version + 1]);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal memperbarui tally: ' . $e->getMessage()]);
                }

            case 'posting_tally': 
                $idTally = (int) ($data['id_tally'] ?? 0);
                $expectedVersion = (int) ($data['row_version'] ?? 0);
                if ($idTally <= 0 || $expectedVersion <= 0) return sendResponse(422, ['success' => false, 'message' => 'id_tally dan row_version wajib valid.']);
                
                $pdo->beginTransaction();
                try {
                    $stmt = $pdo->prepare("SELECT status_posting, COALESCE(accounting_locked, 0) AS accounting_locked, row_version FROM tally_header WHERE id_tally = ? FOR UPDATE");
                    $stmt->execute([$idTally]);
                    $current = $stmt->fetch(PDO::FETCH_ASSOC);

                    if (!$current) { $pdo->rollBack(); return sendResponse(404, ['success' => false, 'message' => 'Tally tidak ditemukan.']); }
                    
                    $currentStatus = strtoupper(trim((string) $current['status_posting']));
                    $currentLocked = (int) $current['accounting_locked'];
                    $currentVersion = (int) $current['row_version'];

                    if ($currentStatus === 'POSTED' && $currentLocked === 1) {
                        $pdo->rollBack();
                        return sendResponse(200, ['success' => true, 'message' => 'Tally sudah POSTED.']);
                    }
                    if ($currentStatus !== 'DRAFT' || $currentLocked !== 0) { $pdo->rollBack(); return sendResponse(409, ['success' => false, 'message' => 'Tally bukan DRAFT atau sudah terkunci.']); }
                    if ($currentVersion !== $expectedVersion) { $pdo->rollBack(); return sendResponse(409, ['success' => false, 'message' => 'Versi Draft berubah. Silakan muat ulang.']); }

                    $stmtItems = $pdo->prepare("SELECT COUNT(*) FROM tally_detail WHERE id_tally = ? AND jumlah_batang > 0");
                    $stmtItems->execute([$idTally]);
                    if ((int)$stmtItems->fetchColumn() <= 0) { $pdo->rollBack(); return sendResponse(422, ['success' => false, 'message' => 'Tally tanpa item tidak dapat diposting.']); }

                    $stmtPosting = $pdo->prepare("UPDATE tally_header SET status_posting = 'POSTED', accounting_locked = 1, row_version = row_version + 1 WHERE id_tally = ? AND row_version = ? AND status_posting = 'DRAFT'");
                    $stmtPosting->execute([$idTally, $expectedVersion]);
                    if ($stmtPosting->rowCount() !== 1) { $pdo->rollBack(); return sendResponse(409, ['success' => false, 'message' => 'Posting gagal.']); }

                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Tally berhasil diposting.']);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal memposting tally.']);
                }

            // ==========================================
            // MODUL DOKUMENTASI & TALLY FOTO
            // ==========================================
            case 'get_tally_dokumentasi':
                $id_tally = (int) ($data['id_tally'] ?? 0);
                $sql = "SELECT * FROM tally_dokumentasi";
                $params = [];
                if ($id_tally > 0) { $sql .= " WHERE id_tally = ?"; $params[] = $id_tally; }
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll()]);

            case 'simpan_tally_dokumentasi':
                $id_dokumen = (int) ($data['id_dokumen'] ?? 0);
                $id_tally = (int) ($data['id_tally'] ?? 0);
                $jenis_dokumen = trim((string) ($data['jenis_dokumen'] ?? ''));
                $file_url = trim((string) ($data['file_url'] ?? ''));
                $status_dokumen = trim((string) ($data['status_dokumen'] ?? 'VALID'));

                if ($id_tally <= 0 || empty($file_url)) return sendResponse(400, ['success' => false, 'message' => 'ID Tally dan URL File wajib diisi']);
                if ($id_dokumen > 0) {
                    $stmt = $pdo->prepare("UPDATE tally_dokumentasi SET id_tally=?, jenis_dokumen=?, file_url=?, status_dokumen=? WHERE id_dokumen=?");
                    $stmt->execute([$id_tally, $jenis_dokumen, $file_url, $status_dokumen, $id_dokumen]);
                    $msg = 'Dokumentasi diupdate';
                } else {
                    $stmt = $pdo->prepare("INSERT INTO tally_dokumentasi (id_tally, jenis_dokumen, file_url, status_dokumen) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$id_tally, $jenis_dokumen, $file_url, $status_dokumen]);
                    $id_dokumen = (int) $pdo->lastInsertId();
                    $msg = 'Dokumentasi ditambahkan';
                }
                return sendResponse(200, ['success' => true, 'message' => $msg, 'id_dokumen' => $id_dokumen]);

            case 'hapus_tally_dokumentasi':
                $id_dokumen = (int) ($data['id_dokumen'] ?? 0);
                $pdo->prepare("DELETE FROM tally_dokumentasi WHERE id_dokumen = ?")->execute([$id_dokumen]);
                return sendResponse(200, ['success' => true, 'message' => 'Dokumentasi dihapus']);

            case 'upload_dokumentasi_penerimaan':
                $ref_penerimaan = trim((string)($data['ref_penerimaan'] ?? ''));
                $kategori_foto  = trim((string)($data['kategori_foto'] ?? 'KAYU_DI_LOGYARD'));
                $foto_url       = trim((string)($data['foto'] ?? ''));
                $petugas        = trim((string)($data['petugas'] ?? 'Checker'));
                $lokasi         = trim((string)($data['lokasi'] ?? 'Log Yard Utama'));

                if (empty($ref_penerimaan) || empty($foto_url)) return sendResponse(400, ['success' => false, 'message' => 'Ref penerimaan dan URL foto wajib diisi.']);
                
                $id_dok = 'DOK-RCV-' . date('YmdHis') . '-' . rand(100, 999);
                $stmt = $pdo->prepare("INSERT INTO dokumentasi_penerimaan_kayu (id_dokumentasi, ref_penerimaan, kategori_foto, foto, tanggal_dokumentasi, petugas, lokasi) VALUES (?, ?, ?, ?, NOW(), ?, ?)");
                $stmt->execute([$id_dok, $ref_penerimaan, $kategori_foto, $foto_url, $petugas, $lokasi]);
                return sendResponse(200, ['success' => true, 'message' => 'Dokumentasi penerimaan tersimpan.', 'id_dokumentasi' => $id_dok]);

            case 'upload_dokumentasi_penjualan':
                $ref_penjualan = trim((string)($data['ref_penjualan'] ?? ''));
                $kategori_foto = trim((string)($data['kategori_foto'] ?? 'MUATAN_TRONTON_1'));
                $foto_url      = trim((string)($data['foto'] ?? ''));
                $no_polisi     = trim((string)($data['no_polisi'] ?? ''));
                $petugas       = trim((string)($data['petugas'] ?? 'Mandor Ekspedisi'));

                if (empty($ref_penjualan) || empty($foto_url) || empty($no_polisi)) return sendResponse(400, ['success' => false, 'message' => 'Ref penjualan, no polisi, dan foto wajib diisi.']);
                
                $id_dok = 'DOK-OUT-' . date('YmdHis') . '-' . rand(100, 999);
                $stmt = $pdo->prepare("INSERT INTO dokumentasi_penjualan (id_dokumentasi_jual, ref_penjualan, kategori_foto, foto, tanggal_dokumentasi, no_polisi, petugas) VALUES (?, ?, ?, ?, NOW(), ?, ?)");
                $stmt->execute([$id_dok, $ref_penjualan, $kategori_foto, $foto_url, $no_polisi, $petugas]);
                return sendResponse(200, ['success' => true, 'message' => 'Dokumentasi tronton tersimpan.', 'id_dokumentasi' => $id_dok]);

            case 'delete_dokumentasi':
                $tipe = trim((string)($data['tipe'] ?? 'INBOUND'));
                $id   = trim((string)($data['id_dokumentasi'] ?? ''));
                if (empty($id)) return sendResponse(400, ['success' => false, 'message' => 'ID Dokumentasi wajib diisi.']);

                if ($tipe === 'INBOUND') {
                    $pdo->prepare("DELETE FROM dokumentasi_penerimaan_kayu WHERE id_dokumentasi = ?")->execute([$id]);
                } else {
                    $pdo->prepare("DELETE FROM dokumentasi_penjualan WHERE id_dokumentasi_jual = ?")->execute([$id]);
                }
                return sendResponse(200, ['success' => true, 'message' => 'Dokumentasi dihapus.']);

            // ==========================================
            // MODUL PRODUKSI & RENDEMEN MANUFAKTUR
            // ==========================================
            case 'get_produksi_batches':
                $stmt = $pdo->prepare("SELECT pb.*, pr.total_vol_in, pr.total_vol_out, pr.persentase_rendemen FROM produksi_batch pb LEFT JOIN produksi_rendemen_log pr ON pb.id_batch = pr.id_batch ORDER BY pb.id_batch DESC");
                $stmt->execute();
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);

            case 'get_produksi_batch_detail':
                $id_batch = (int)($data['id_batch'] ?? 0);
                if ($id_batch <= 0) return sendResponse(400, ['success' => false, 'message' => 'ID Batch tidak valid.']);
                
                $batch = $pdo->query("SELECT * FROM produksi_batch WHERE id_batch = $id_batch")->fetch(PDO::FETCH_ASSOC);
                $inputs = $pdo->query("SELECT * FROM produksi_input_log WHERE id_batch = $id_batch")->fetchAll(PDO::FETCH_ASSOC);
                $outputs = $pdo->query("SELECT * FROM produksi_output_veneer WHERE id_batch = $id_batch")->fetchAll(PDO::FETCH_ASSOC);
                $rendemen = $pdo->query("SELECT * FROM produksi_rendemen_log WHERE id_batch = $id_batch")->fetch(PDO::FETCH_ASSOC);

                return sendResponse(200, ['success' => true, 'batch' => $batch, 'inputs' => $inputs, 'outputs' => $outputs, 'rendemen' => $rendemen]);

            case 'simpan_produksi_veneer':
                $divisi       = trim((string)($data['divisi_produksi'] ?? 'Rotary_Veneer'));
                $lini         = trim((string)($data['lini_produksi'] ?? 'Lini Produksi 1'));
                $input_lots   = $data['input_lots'] ?? [];
                $output_items = $data['output_items'] ?? [];

                if (empty($input_lots) || empty($output_items)) return sendResponse(400, ['success' => false, 'message' => 'Input Lot Kayu dan Output Hasil Veneer wajib diisi.']);

                $pdo->beginTransaction();
                try {
                    $no_batch = 'BATCH-' . date('Ymd-His');
                    $pdo->prepare("INSERT INTO produksi_batch (no_batch, tanggal_proses, divisi_produksi, lini_produksi, status) VALUES (?, NOW(), ?, ?, 'SELESAI')")->execute([$no_batch, $divisi, $lini]);
                    $id_batch = (int)$pdo->lastInsertId();

                    $total_vol_in = 0.0000;
                    $stmtIn = $pdo->prepare("INSERT INTO produksi_input_log (id_batch, no_lot_log, volume_m3_in, jumlah_batang) VALUES (?, ?, ?, ?)");
                    $stmtUpdLot = $pdo->prepare("UPDATE log_sorting_header SET status_lot = 'SELESAI' WHERE kode_lot = ?");

                    foreach ($input_lots as $lot) {
                        $v_in = (float)($lot['vol_in'] ?? 0); $b_in = (int)($lot['jml_btg'] ?? 1); $k_lot = trim((string)$lot['kode_lot']);
                        $total_vol_in += $v_in;
                        $stmtIn->execute([$id_batch, $k_lot, $v_in, $b_in]);
                        $stmtUpdLot->execute([$k_lot]);
                    }

                    $total_vol_out = 0.0000;
                    $stmtOut = $pdo->prepare("INSERT INTO produksi_output_veneer (id_batch, tipe_item, kondisi, panjang_cm, lebar_cm, tebal_cm, qty_palet, lembar_per_palet, total_lembar, volume_m3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

                    foreach ($output_items as $out) {
                        $p = (float)($out['p'] ?? 122); $l = (float)($out['l'] ?? 122); $t = (float)($out['t'] ?? 0.27);
                        $palet = (int)($out['palet'] ?? 0); $per_palet = (int)($out['lembar_per_palet'] ?? 450);
                        $total_lbr = $palet * $per_palet;
                        $vol_m3 = ($p * $l * $t * $total_lbr) / 1000000;
                        $total_vol_out += $vol_m3;
                        $stmtOut->execute([$id_batch, $out['tipe'], $out['kondisi'] ?? 'BASAH', $p, $l, $t, $palet, $per_palet, $total_lbr, $vol_m3]);
                    }

                    $rendemen_pct = ($total_vol_in > 0) ? ($total_vol_out / $total_vol_in) * 100 : 0.00;
                    $pdo->prepare("INSERT INTO produksi_rendemen_log (id_batch, total_vol_in, total_vol_out, persentase_rendemen) VALUES (?, ?, ?, ?)")->execute([$id_batch, $total_vol_in, $total_vol_out, $rendemen_pct]);

                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Produksi berhasil diproses.', 'id_batch' => $id_batch, 'no_batch' => $no_batch]);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal simpan produksi: ' . $e->getMessage()]);
                }

            case 'delete_produksi_batch':
                $id_batch = (int)($data['id_batch'] ?? 0);
                if ($id_batch <= 0) return sendResponse(400, ['success' => false, 'message' => 'ID Batch tidak valid.']);
                $pdo->prepare("DELETE FROM produksi_batch WHERE id_batch = ?")->execute([$id_batch]);
                return sendResponse(200, ['success' => true, 'message' => 'Batch produksi dihapus.']);

            // ==========================================
            // MODUL PENJUALAN (OUTBOUND)
            // ==========================================
            case 'get_penjualan_invoices':
                $stmt = $pdo->prepare("SELECT ph.*, c.nama_customer FROM penjualan_header ph JOIN customer c ON ph.id_customer = c.id_customer ORDER BY ph.id_penjualan DESC");
                $stmt->execute();
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);

            case 'get_penjualan_invoice_detail':
                $id_penjualan = (int)($data['id_penjualan'] ?? 0);
                if ($id_penjualan <= 0) return sendResponse(400, ['success' => false, 'message' => 'ID Penjualan tidak valid.']);
                
                $header = $pdo->query("SELECT ph.*, c.nama_customer, c.alamat, c.no_telp FROM penjualan_header ph JOIN customer c ON ph.id_customer = c.id_customer WHERE ph.id_penjualan = $id_penjualan")->fetch(PDO::FETCH_ASSOC);
                $details = $pdo->query("SELECT * FROM penjualan_detail WHERE id_penjualan = $id_penjualan")->fetchAll(PDO::FETCH_ASSOC);
                $pengiriman = $pdo->query("SELECT * FROM penjualan_pengiriman WHERE id_penjualan = $id_penjualan LIMIT 1")->fetch(PDO::FETCH_ASSOC);

                return sendResponse(200, ['success' => true, 'header' => $header, 'details' => $details, 'pengiriman' => $pengiriman]);

            case 'simpan_penjualan_invoice':
                $id_cust    = (int)($data['id_customer'] ?? 0);
                $no_polisi  = trim((string)($data['no_polisi'] ?? ''));
                $nama_supir = trim((string)($data['nama_supir'] ?? ''));
                $items      = $data['items'] ?? [];

                if ($id_cust <= 0 || empty($no_polisi) || empty($items)) return sendResponse(400, ['success' => false, 'message' => 'Data tidak lengkap.']);

                $pdo->beginTransaction();
                try {
                    $no_inv = 'INV/AJM/' . date('Y/m/') . strtoupper(substr(uniqid(), -5));
                    $dpp = 0.00;

                    foreach ($items as $it) {
                        $p = (float)($it['p'] ?? 122); $l = (float)($it['l'] ?? 81); $t = (float)($it['t'] ?? 0.30);
                        $palet = (int)($it['palet'] ?? 0); $per_palet = (int)($it['lembar_per_palet'] ?? 0);
                        $total_lbr = ($palet > 0 && $per_palet > 0) ? ($palet * $per_palet) : (int)($it['qty_lembar'] ?? 0);
                        $vol_m3 = (float)($it['volume_m3'] ?? (($p * $l * $t * $total_lbr) / 1000000));
                        $harga = (float)($it['harga_satuan'] ?? 0);
                        $dpp += ($vol_m3 * $harga);
                    }

                    $ppn = $dpp * 0.11;
                    $total_tagihan = $dpp + $ppn;

                    $stmtH = $pdo->prepare("INSERT INTO penjualan_header (no_invoice, tanggal, id_customer, no_polisi, nama_supir, subtotal_dpp, persen_ppn, nilai_ppn, total_tagihan, sisa_tagihan, status_pembayaran) VALUES (?, CURDATE(), ?, ?, ?, ?, 11.00, ?, ?, ?, 'BELUM_LUNAS')");
                    $stmtH->execute([$no_inv, $id_cust, $no_polisi, $nama_supir, $dpp, $ppn, $total_tagihan, $total_tagihan]);
                    $id_penjualan = (int)$pdo->lastInsertId();

                    $stmtD = $pdo->prepare("INSERT INTO penjualan_detail (id_penjualan, jenis_produk, spesifikasi, panjang_cm, lebar_cm, tebal_cm, qty_palet, lembar_per_palet, total_lembar, volume_m3, harga_satuan, jumlah_total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

                    foreach ($items as $it) {
                        $p = (float)($it['p'] ?? 122); $l = (float)($it['l'] ?? 81); $t = (float)($it['t'] ?? 0.30);
                        $palet = (int)($it['palet'] ?? 0); $per_palet = (int)($it['lembar_per_palet'] ?? 0);
                        $total_lbr = ($palet > 0 && $per_palet > 0) ? ($palet * $per_palet) : (int)($it['qty_lembar'] ?? 0);
                        $vol_m3 = (float)($it['volume_m3'] ?? (($p * $l * $t * $total_lbr) / 1000000));
                        $harga = (float)($it['harga_satuan'] ?? 0);
                        $subtotal = $vol_m3 * $harga;
                        $stmtD->execute([$id_penjualan, $it['jenis_produk'] ?? 'Veneer', $it['spesifikasi'] ?? "$p x $l x $t", $p, $l, $t, $palet, $per_palet, $total_lbr, $vol_m3, $harga, $subtotal]);
                    }

                    $no_sj = 'SJ/AJM/' . date('Ymd-His');
                    $pdo->prepare("INSERT INTO penjualan_pengiriman (id_penjualan, no_surat_jalan, tanggal_kirim, no_polisi, nama_supir, status_kirim) VALUES (?, ?, NOW(), ?, ?, 'BERANGKAT')")->execute([$id_penjualan, $no_sj, $no_polisi, $nama_supir]);

                    $pdo->commit();
                    return sendResponse(200, ['success' => true, 'message' => 'Invoice Penjualan dibuat.', 'id_penjualan' => $id_penjualan]);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    return sendResponse(500, ['success' => false, 'message' => 'Gagal simpan invoice: ' . $e->getMessage()]);
                }

            case 'update_penjualan_status_bayar':
                $id_penjualan = (int)($data['id_penjualan'] ?? 0);
                $total_bayar  = (float)($data['total_terbayar'] ?? 0);
                $status       = trim((string)($data['status_pembayaran'] ?? 'LUNAS'));

                if ($id_penjualan <= 0) return sendResponse(400, ['success' => false, 'message' => 'ID Penjualan tidak valid.']);
                $pdo->prepare("UPDATE penjualan_header SET total_terbayar = ?, sisa_tagihan = total_tagihan - ?, status_pembayaran = ? WHERE id_penjualan = ?")->execute([$total_bayar, $total_bayar, $status, $id_penjualan]);
                return sendResponse(200, ['success' => true, 'message' => 'Status pembayaran diperbarui.']);

            case 'delete_penjualan_invoice':
                $id_penjualan = (int)($data['id_penjualan'] ?? 0);
                $pdo->prepare("DELETE FROM penjualan_header WHERE id_penjualan = ?")->execute([$id_penjualan]);
                return sendResponse(200, ['success' => true, 'message' => 'Invoice dihapus.']);

            // ==========================================
            // MODUL PEMBAYARAN SUPPLIER & HUTANG
            // ==========================================
            case 'simpan_pembayaran_supplier': 
                try {
                    $authContext = ['id_user' => (int) ($data['id_user'] ?? 1)];
                    $apiHandler = new SupplierPaymentApiHandler($pdo);
                    $result = $apiHandler->handleRequest($data, $authContext);
                    return sendResponse(200, $result);
                } catch (SupplierPaymentApiException $e) {
                    return sendResponse($e->httpStatus(), ['success' => false, 'error_code' => $e->errorCode(), 'message' => $e->getMessage(), 'details' => $e->details()]);
                } catch (Throwable $e) {
                    return sendResponse(500, ['success' => false, 'error_code' => 'FATAL_PAYMENT_ERROR', 'message' => 'Terjadi kesalahan fatal: ' . $e->getMessage()]);
                }

            case 'get_list_pembayaran_supplier':
                $page        = max(1, (int) ($data['page'] ?? 1));
                $limit       = max(1, min(100, (int) ($data['limit'] ?? 25)));
                $offset      = ($page - 1) * $limit;
                $keyword     = trim((string) ($data['keyword'] ?? ''));
                $tgl_mulai   = trim((string) ($data['tanggal_dari'] ?? ''));
                $tgl_selesai = trim((string) ($data['tanggal_sampai'] ?? ''));

                $where = "WHERE 1=1";
                $params = [];

                if (!empty($keyword)) {
                    $where .= " AND (p.nomor_referensi LIKE ? OR s.nama_supplier LIKE ? OR p.catatan LIKE ?)";
                    $params[] = "%$keyword%"; $params[] = "%$keyword%"; $params[] = "%$keyword%";
                }
                if (!empty($tgl_mulai) && !empty($tgl_selesai)) {
                    $where .= " AND p.tanggal_pembayaran BETWEEN ? AND ?";
                    $params[] = $tgl_mulai; $params[] = $tgl_selesai;
                }

                $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM pembayaran_supplier p LEFT JOIN master_supplier s ON p.id_supplier = s.id_supplier $where");
                $stmtCount->execute($params);
                $totalData = (int) $stmtCount->fetchColumn();

                $sql = "SELECT p.*, s.nama_supplier FROM pembayaran_supplier p LEFT JOIN master_supplier s ON p.id_supplier = s.id_supplier $where ORDER BY p.tanggal_pembayaran DESC, p.id_pembayaran DESC LIMIT $limit OFFSET $offset";
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);

                return sendResponse(200, ['success' => true, 'page' => $page, 'limit' => $limit, 'total_data' => $totalData, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);

            case 'get_list_hutang_supplier':
                $page   = max(1, (int) ($data['page'] ?? 1));
                $limit  = max(1, min(100, (int) ($data['limit'] ?? 25)));
                $offset = ($page - 1) * $limit;
                $keyword = trim((string) ($data['keyword'] ?? ''));
                
                $where = "WHERE h.status_posting = 'POSTED' AND COALESCE(h.accounting_locked, 0) = 1";
                $params = [];

                if (!empty($keyword)) {
                    $where .= " AND (h.no_tally LIKE ? OR h.no_po LIKE ? OR s.nama_supplier LIKE ?)";
                    $params[] = "%$keyword%"; $params[] = "%$keyword%"; $params[] = "%$keyword%";
                }

                $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM tally_header h LEFT JOIN master_supplier s ON h.nama_pemasok = s.nama_supplier $where");
                $stmtCount->execute($params);
                $totalData = (int) $stmtCount->fetchColumn();

                $sql = "
                    SELECT h.id_tally, h.no_tally, h.no_po, h.tanggal, h.nama_pemasok AS nama_supplier,
                           (COALESCE(h.total_bruto, 0) + COALESCE(h.nominal_ppn, 0) - COALESCE(h.nominal_pph22, 0)) AS total_tagihan,
                           COALESCE((SELECT SUM(p.jumlah) FROM pembayaran_supplier p WHERE p.id_tally = h.id_tally AND p.status_pembayaran = 'ACTIVE'), 0) AS total_dibayar
                    FROM tally_header h LEFT JOIN master_supplier s ON h.nama_pemasok = s.nama_supplier
                    $where ORDER BY h.tanggal DESC, h.id_tally DESC LIMIT $limit OFFSET $offset
                ";
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);

                return sendResponse(200, ['success' => true, 'page' => $page, 'limit' => $limit, 'total_data' => $totalData, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);

            case 'get_riwayat_pembayaran_supplier':
                $page   = max(1, (int) ($data['page'] ?? 1));
                $limit  = max(1, min(100, (int) ($data['limit'] ?? 25)));
                $offset = ($page - 1) * $limit;
                $id_tally = (int) ($data['id_tally'] ?? 0);
                
                $where = "WHERE p.status_pembayaran = 'ACTIVE'";
                $params = [];
                if ($id_tally > 0) { $where .= " AND p.id_tally = ?"; $params[] = $id_tally; }

                $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM pembayaran_supplier p LEFT JOIN master_supplier s ON p.id_supplier = s.id_supplier LEFT JOIN tally_header th ON p.id_tally = th.id_tally $where");
                $stmtCount->execute($params);
                $totalData = (int) $stmtCount->fetchColumn();

                $sql = "SELECT p.*, s.nama_supplier, th.no_tally FROM pembayaran_supplier p LEFT JOIN master_supplier s ON p.id_supplier = s.id_supplier LEFT JOIN tally_header th ON p.id_tally = th.id_tally $where ORDER BY p.tanggal_pembayaran DESC, p.id_pembayaran DESC LIMIT $limit OFFSET $offset";
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);

                return sendResponse(200, ['success' => true, 'page' => $page, 'limit' => $limit, 'total_data' => $totalData, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);

            // ==========================================
            // MODUL OTORISASI
            // ==========================================
            case 'get_daftar_otorisasi':
                $modul  = trim((string)($data['modul_transaksi'] ?? ''));
                $status = trim((string)($data['status'] ?? 'PENDING'));

                $sql = "SELECT * FROM otorisasi_transaksi WHERE 1=1";
                $params = [];
                if (!empty($modul)) { $sql .= " AND modul_transaksi = ?"; $params[] = $modul; }
                if (!empty($status)) { $sql .= " AND status = ?"; $params[] = $status; }
                $sql .= " ORDER BY waktu_otorisasi DESC";
                
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                return sendResponse(200, ['success' => true, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);

            case 'submit_otorisasi_transaksi':
                $modul      = trim((string)($data['modul_transaksi'] ?? ''));
                $id_ref     = (int)($data['id_referensi'] ?? 0);
                $no_ref     = trim((string)($data['nomor_referensi'] ?? ''));
                $id_user    = (int)($data['id_user_verifikator'] ?? 0);
                $peran      = trim((string)($data['peran_otorisasi'] ?? 'Supervisor'));
                $status_oto = trim((string)($data['status'] ?? 'DISETUJUI'));
                $catatan    = trim((string)($data['catatan'] ?? ''));

                if (empty($modul) || $id_ref <= 0 || empty($no_ref)) return sendResponse(400, ['success' => false, 'message' => 'Data otorisasi tidak lengkap.']);

                $pdo->prepare("INSERT INTO otorisasi_transaksi (modul_transaksi, id_referensi, nomor_referensi, id_user_verifikator, peran_otorisasi, status, catatan, waktu_otorisasi) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())")->execute([$modul, $id_ref, $no_ref, $id_user, $peran, $status_oto, $catatan]);

                if ($modul === 'PENJUALAN' && $status_oto === 'DISETUJUI') {
                    $pdo->prepare("UPDATE penjualan_header SET status_verifikasi = 'DISETUJUI' WHERE id_penjualan = ?")->execute([$id_ref]);
                }
                return sendResponse(200, ['success' => true, 'message' => "Otorisasi $modul diproses."]);

            // ==========================================
            // DEFAULT / FALLBACK
            // ==========================================
            default:
                return sendResponse(400, ['success' => false, 'error_code' => '400_BAD_REQUEST', 'message' => 'Action API tidak dikenali: ' . $action]);
        } // <====== INI ADALAH PENUTUP DARI SWITCH ACTION

    } catch (PDOException $e) {
        if (isset($pdo) && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        return sendResponse(500, ['success' => false, 'error_code' => '500_DATABASE_ERROR', 'message' => $e->getMessage()]);
    } catch (Exception $e) {
        if (isset($pdo) && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        return sendResponse(500, ['success' => false, 'error_code' => '500_SERVER_ERROR', 'message' => $e->getMessage()]);
    }
} // <====== INI ADALAH PENUTUP DARI FUNGSI MAIN()


// ==============================================================
// KELAS TAMBAHAN (EXCEPTION & HANDLER API)
// ==============================================================

class SupplierPaymentApiException extends RuntimeException {
    private int $httpStatus;
    private string $errorCode;
    private array $details;

    public function __construct(int $httpStatus, string $errorCode, string $publicMessage, array $details = []) {
        parent::__construct($publicMessage);
        $this->httpStatus = $httpStatus;
        $this->errorCode = $errorCode;
        $this->details = $details;
    }

    public function httpStatus(): int { return $this->httpStatus; }
    public function errorCode(): string { return $this->errorCode; }
    public function details(): array { return $this->details; }
}

class SupplierPaymentApiHandler {
    private PDO $pdo;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    public function handleRequest(array $data, array $authContext): array {
        $action = trim((string)($data['action'] ?? ''));
        
        if ($action !== 'simpan_pembayaran_supplier') {
            throw new SupplierPaymentApiException(400, 'INVALID_ACTION', 'Action API pembayaran tidak valid.');
        }

        $candidate = $data['idempotency_key'] ?? null;
        $idempotencyKey = (
            is_string($candidate)
            && preg_match('/^[A-Za-z0-9._:-]{8,100}$/', $candidate) === 1
        ) ? $candidate : bin2hex(random_bytes(16));

        if ($idempotencyKey === '') {
            throw new SupplierPaymentApiException(422, 'MISSING_IDEMPOTENCY_KEY', 'Idempotency key wajib disertakan.');
        }

        $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $requiredPermission = 'tally.payment.create';

        if (
            preg_match('/^Bearer\s+(\S+)$/i', $authorization, $matches) !== 1
            || strlen($matches[1]) > 4096
        ) {
            throw new SupplierPaymentApiException(401, 'AUTH_REQUIRED', 'Sesi login tidak tersedia atau token tidak valid.');
        }

        $tokenHash = hash('sha256', $matches[1]);
        $stmt = $this->pdo->prepare("
            SELECT u.id_user, u.id_role, u.nama_lengkap, COALESCE(u.is_superadmin, 0) AS is_superadmin
            FROM auth_sessions s
            INNER JOIN users u ON u.id_user = s.id_user
            WHERE s.token_hash = :token_hash AND s.revoked_at IS NULL AND s.expires_at > UTC_TIMESTAMP() AND u.is_active = 1
            LIMIT 1
        ");
        $stmt->execute([':token_hash' => $tokenHash]);
        $actor = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!is_array($actor)) {
            throw new SupplierPaymentApiException(401, 'AUTH_INVALID', 'Sesi login telah berakhir atau tidak valid.');
        }

        if ((int) ($actor['is_superadmin'] ?? 0) !== 1) {
            $permissionStmt = $this->pdo->prepare("
                SELECT 1 FROM role_permissions WHERE id_role = :id_role AND permission_code = :permission_code AND is_allowed = 1 LIMIT 1
            ");
            $permissionStmt->execute([':id_role' => (int) $actor['id_role'], ':permission_code' => $requiredPermission]);
            if ($permissionStmt->fetchColumn() === false) {
                throw new SupplierPaymentApiException(403, 'PERMISSION_DENIED', 'Anda tidak memiliki hak untuk menyimpan pembayaran supplier.');
            }
        }
        
        $userId = (int) $actor['id_user'];

        $tallyData = $data['tally'] ?? [];
        $paymentData = $data['payment'] ?? [];
        
        $allowedKeys = ['jenis_pembayaran', 'tanggal_pembayaran', 'metode_pembayaran', 'jumlah', 'nomor_referensi', 'catatan', 'currency'];
        $unknown = [];
        foreach (array_keys($paymentData) as $key) {
            if (!in_array((string) $key, $allowedKeys, true)) {
                $unknown[] = (string) $key;
            }
        }
        if ($unknown !== []) {
            throw new SupplierPaymentApiException(
                422, 'UNKNOWN_FIELDS', "Terdapat field yang tidak dikenali pada payment.",
                ['field' => 'payment', 'unknown_fields' => $unknown]
            );
        }

        $idTally = (int)($tallyData['id_tally'] ?? 0);
        $rowVersion = (int)($tallyData['row_version'] ?? 0);

        if ($idTally <= 0) {
            throw new SupplierPaymentApiException(422, 'INVALID_TALLY_ID', 'ID Tally tidak valid.');
        }

        $jenisPembayaran = strtoupper(trim((string)($paymentData['jenis_pembayaran'] ?? '')));
        $allowedJenis = ['UANG_MUKA', 'UANG_JALAN', 'BIAYA_BONGKAR', 'ANGSURAN', 'PELUNASAN', 'TUNAI', 'TRANSFER', 'GIRO', 'CEK'];
        if (!in_array($jenisPembayaran, $allowedJenis, true)) {
            throw new SupplierPaymentApiException(422, 'VALIDATION_ERROR', 'Jenis pembayaran tidak termasuk pilihan yang diizinkan.', ['field' => 'jenis_pembayaran', 'allowed' => $allowedJenis]);
        }

        $metodePembayaran = strtoupper(trim((string)($paymentData['metode_pembayaran'] ?? 'TRANSFER_BANK')));
        $allowedMetode = ['TRANSFER_BANK', 'TUNAI', 'GIRO', 'CEK'];
        if (!in_array($metodePembayaran, $allowedMetode, true)) {
            throw new SupplierPaymentApiException(422, 'VALIDATION_ERROR', "metode_pembayaran tidak termasuk pilihan yang diizinkan.", ['field' => 'metode_pembayaran', 'allowed' => $allowedMetode]);
        }

        $tanggalPembayaran = trim((string)($paymentData['tanggal_pembayaran'] ?? date('Y-m-d')));
        $timezone = new DateTimeZone('Asia/Jakarta');
        $date = DateTimeImmutable::createFromFormat('!Y-m-d', $tanggalPembayaran, $timezone);
        $dateErrors = DateTimeImmutable::getLastErrors();
        $hasDateErrors = is_array($dateErrors) && ((int) $dateErrors['warning_count'] > 0 || (int) $dateErrors['error_count'] > 0);

        if ($date === false || $hasDateErrors || $date->format('Y-m-d') !== $tanggalPembayaran) {
            throw new SupplierPaymentApiException(422, 'VALIDATION_ERROR', "tanggal_pembayaran wajib berformat YYYY-MM-DD.", ['field' => 'tanggal_pembayaran']);
        }
        $today = new DateTimeImmutable('today', $timezone);
        if ($date > $today) {
            throw new SupplierPaymentApiException(422, 'FUTURE_PAYMENT_DATE', 'Tanggal pembayaran tidak boleh melebihi tanggal hari ini.', ['field' => 'tanggal_pembayaran']);
        }

        $textJumlah = trim((string)($paymentData['jumlah'] ?? '0')); 
        if (preg_match('/^(0|[1-9][0-9]{0,13})(?:\.([0-9]{1,2}))?$/', $textJumlah, $m) !== 1) {
            throw new SupplierPaymentApiException(422, 'VALIDATION_ERROR', "jumlah wajib berupa nominal positif dengan maksimal dua desimal.", ['field' => 'jumlah']);
        }
        $whole = (int) $m[1];
        $fraction = str_pad($m[2] ?? '', 2, '0');
        $minorAmount = ($whole * 100) + (int) $fraction;
        if ($minorAmount <= 0) {
            throw new SupplierPaymentApiException(422, 'PAYMENT_AMOUNT_INVALID', 'Nominal pembayaran wajib lebih dari nol.', ['field' => 'jumlah']);
        }
        $jumlahBayar = (float)($minorAmount / 100);

        $nomorReferensi = trim((string)($paymentData['nomor_referensi'] ?? ''));
        $catatan = trim((string)($paymentData['catatan'] ?? ''));

        $requestHash = hash('sha256', json_encode($data));
        
        if ($cachedResponse = $this->checkIdempotency($idempotencyKey, $userId, $requestHash)) {
            return $cachedResponse;
        }

        $this->pdo->beginTransaction();

        try {
            $stmt = $this->pdo->prepare("
                SELECT id_tally, no_tally, id_supplier, status_posting, accounting_locked, total_bruto, nominal_ppn, nominal_pph22, row_version
                FROM tally_header
                WHERE id_tally = ?
                FOR UPDATE
            ");
            $stmt->execute([$idTally]);
            $tally = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$tally) {
                throw new SupplierPaymentApiException(404, 'TALLY_NOT_FOUND', 'Data Tally tidak ditemukan.');
            }
            if (strtoupper(trim((string)$tally['status_posting'])) !== 'POSTED' || (int)$tally['accounting_locked'] !== 1) {
                throw new SupplierPaymentApiException(409, 'TALLY_NOT_POSTED', 'Pembayaran hanya dapat dilakukan untuk Tally yang sudah berstatus POSTED dan terkunci.');
            }
            if ((int)$tally['row_version'] !== $rowVersion) {
                throw new SupplierPaymentApiException(409, 'VERSION_CONFLICT', 'Versi Tally telah berubah. Silakan muat ulang data.');
            }

            $stmtMap = $this->pdo->prepare("
                SELECT id_mapping, id_akun_debit, id_akun_kredit 
                FROM mapping_akun_transaksi 
                WHERE jenis_transaksi = ? AND is_active = 1 
                LIMIT 1
            ");
            $stmtMap->execute([$jenisPembayaran]);
            $mapping = $stmtMap->fetch(PDO::FETCH_ASSOC);

            if (!$mapping) {
                throw new SupplierPaymentApiException(422, 'MAPPING_NOT_FOUND', "Mapping akun untuk jenis pembayaran '{$jenisPembayaran}' belum diatur.");
            }

            $idAkunDebit = (int)$mapping['id_akun_debit'];
            $idAkunKredit = (int)$mapping['id_akun_kredit'];
            $idMapping = (int)$mapping['id_mapping'];

            $noJurnal = $this->generateJournalNumber($tanggalPembayaran);

            $stmtJH = $this->pdo->prepare("
                INSERT INTO jurnal_header (no_jurnal, tanggal_jurnal, keterangan, sumber_transaksi, id_sumber, nomor_referensi, status_jurnal, total_debit, total_kredit, created_by)
                VALUES (?, ?, ?, 'PEMBAYARAN_SUPPLIER', ?, ?, 'POSTED', ?, ?, ?)
            ");
            $stmtJH->execute([
                $noJurnal,
                $tanggalPembayaran,
                "Pembayaran {$jenisPembayaran} Tally {$tally['no_tally']}",
                $idTally,
                $nomorReferensi,
                $jumlahBayar,
                $jumlahBayar,
                $userId
            ]);
            $idJurnal = (int)$this->pdo->lastInsertId();

            $stmtJD = $this->pdo->prepare("
                INSERT INTO jurnal_detail (id_jurnal, urutan, id_akun, id_supplier, debit, kredit, keterangan)
                VALUES 
                (?, 1, ?, ?, ?, 0.00, ?),
                (?, 2, ?, ?, 0.00, ?, ?)
            ");
            $stmtJD->execute([
                $idJurnal, $idAkunDebit, $tally['id_supplier'], $jumlahBayar, "Debit {$jenisPembayaran}",
                $idJurnal, $idAkunKredit, $tally['id_supplier'], $jumlahBayar, "Kredit {$jenisPembayaran}"
            ]);

            $stmtPay = $this->pdo->prepare("
                INSERT INTO pembayaran_supplier (id_tally, id_supplier, jenis_pembayaran, tanggal_pembayaran, metode_pembayaran, jumlah, currency, nomor_referensi, catatan, status_pembayaran, id_mapping, id_jurnal, idempotency_key, request_hash, created_by)
                VALUES (?, ?, ?, ?, ?, ?, 'IDR', ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
            ");
            $stmtPay->execute([
                $idTally,
                $tally['id_supplier'],
                $jenisPembayaran,
                $tanggalPembayaran,
                $metodePembayaran,
                $jumlahBayar,
                $nomorReferensi,
                $catatan,
                $idMapping,
                $idJurnal,
                $idempotencyKey,
                $requestHash,
                $userId
            ]);
            $idPembayaran = (int)$this->pdo->lastInsertId();

            $response = [
                'success' => true,
                'version' => 'tally-report.v1',
                'message' => 'Pembayaran supplier berhasil disimpan dan dijurnal otomatis.',
                'data' => [
                    'id_pembayaran' => $idPembayaran,
                    'no_jurnal' => $noJurnal,
                    'jumlah_dibayar' => $jumlahBayar,
                    'tanggal_pembayaran' => $tanggalPembayaran
                ]
            ];

            $this->saveIdempotency($idempotencyKey, $userId, $requestHash, 200, $response);

            $this->pdo->commit();
            return $response;

        } catch (SupplierPaymentApiException $e) {
            if ($this->pdo->inTransaction()) { $this->pdo->rollBack(); }
            throw $e;
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) { $this->pdo->rollBack(); }
            throw new SupplierPaymentApiException(500, 'INTERNAL_SERVER_ERROR', 'Terjadi kesalahan sistem: ' . $e->getMessage());
        }
    }

    private function generateJournalNumber(string $tanggal): string {
        $periode = date('Ym', strtotime($tanggal));
        $kodeSeq = 'JUR_SUP';

        $stmt = $this->pdo->prepare("SELECT last_number FROM nomor_jurnal_sequence WHERE kode_sequence = ? AND periode = ? FOR UPDATE");
        $stmt->execute([$kodeSeq, $periode]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row) {
            $nextNum = ((int)$row['last_number']) + 1;
            $stmtUpd = $this->pdo->prepare("UPDATE nomor_jurnal_sequence SET last_number = ? WHERE kode_sequence = ? AND periode = ?");
            $stmtUpd->execute([$nextNum, $kodeSeq, $periode]);
        } else {
            $nextNum = 1;
            $stmtIns = $this->pdo->prepare("INSERT INTO nomor_jurnal_sequence (kode_sequence, periode, last_number) VALUES (?, ?, ?)");
            $stmtIns->execute([$kodeSeq, $periode, $nextNum]);
        }

        return sprintf('JUR-%s-%04d', $periode, $nextNum);
    }

    private function checkIdempotency(string $key, int $userId, string $hash): ?array {
        $stmt = $this->pdo->prepare("SELECT response_body, status FROM api_idempotency WHERE idempotency_key = ? AND id_user = ? LIMIT 1");
        $stmt->execute([$key, $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row && $row['status'] === 'COMPLETED') {
            return json_decode($row['response_body'], true);
        }
        return null;
    }

    private function saveIdempotency(string $key, int $userId, string $hash, int $httpStatus, array $response) {
        $stmt = $this->pdo->prepare("
            INSERT INTO api_idempotency (scope, id_user, idempotency_key, request_hash, status, http_status, response_body) 
            VALUES ('SIMPAN_PEMBAYARAN', ?, ?, ?, 'COMPLETED', ?, ?, NOW())
            ON DUPLICATE KEY UPDATE status = 'COMPLETED', http_status = VALUES(http_status), response_body = VALUES(response_body)
        ");
        $stmt->execute([$userId, $key, $hash, $httpStatus, json_encode($response)]);
    }
}
