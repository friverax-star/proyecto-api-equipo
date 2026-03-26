## Proyecto API REST en PHP para gestión de usuarios 
## Stack PHP 8.2, sin frameworks, PDO + MySQL 
## Reglas de código - PSR-12 para estilo - hash_equals() para comparar tokens (seguridad) - Siempre validar inputs antes de consultar BD - Respuestas en JSON con estructura: {status, data, error} 
## Lo que ya existe - Tabla `users` (id, email, password_hash, token) - Conexión PDO en /src/Database.php 
## Lo que hay que construir - AuthMiddleware.php (validar token en cada request) - UserController.php (CRUD básico)