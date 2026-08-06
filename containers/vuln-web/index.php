<?php
// Script intencionalmente vulnerável para fins de laboratório (Air-gapped)

// 1. Inicializa o banco SQLite em memória/disco temporário
$db_path = '/tmp/vuln_app.sqlite';
$db = new PDO('sqlite:' . $db_path);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// 2. Cria a tabela e popula com a flag do CTF (Seeded credential)
$db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
$db->exec("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'CTF{sqli_admin_bypass_9921}')");

$search = $_GET['search'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Portal Soluciones Formativas VAL</title>
    <style>
        body { font-family: monospace; background: #0B0E14; color: #E6E9EF; padding: 2rem; }
        input { padding: 0.5rem; background: #10141D; color: #5FD4E8; border: 1px solid #1E2430; }
        button { padding: 0.5rem 1rem; background: #1E2430; color: #E6E9EF; border: 1px solid #5A6478; cursor: pointer;}
        .error { color: #E5484D; }
    </style>
</head>
<body>
    <h2>Diretório de Colaboradores</h2>
    
    <!-- VULNERABILIDADE 1: Reflected XSS (Nenhuma sanitização na saída HTML) -->
    <p>Resultados da busca para: <strong><?php echo $search; ?></strong></p>
    
    <form method="GET">
        <input type="text" name="search" placeholder="Buscar usuário..." autocomplete="off">
        <button type="submit">Consultar</button>
    </form>

    <ul>
    <?php
    if ($search) {
        // VULNERABILIDADE 2: SQL Injection (Concatenação direta na string da query)
        $query = "SELECT username FROM users WHERE username = '$search'";
        
        try {
            $stmt = $db->query($query);
            if ($stmt) {
                while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                    echo "<li>" . htmlspecialchars($row['username']) . "</li>";
                }
            }
        } catch (Exception $e) {
            // VULNERABILIDADE 3: Information Disclosure (Vazamento de stack trace/erros SQL)
            echo "<li class='error'>Erro SQL: " . $e->getMessage() . "</li>";
        }
    }
    ?>
    </ul>
</body>
</html>