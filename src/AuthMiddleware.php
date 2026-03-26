<?php

declare(strict_types=1);

/**
 * AuthMiddleware
 *
 * Intercepta cada request HTTP y valida el Bearer token
 * contra la tabla `users` de la base de datos.
 *
 * Respuestas JSON con estructura: {status, data, error}
 */
class AuthMiddleware
{
    private PDO $pdo;

    /**
     * Constructor.
     *
     * @param PDO $pdo Instancia de conexión PDO inyectada desde Database.php
     */
    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * Punto de entrada del middleware.
     *
     * Extrae el Bearer token del header Authorization, lo valida
     * contra la BD y detiene el request con 401 si no es válido.
     *
     * @return array{id: int, email: string} Datos del usuario autenticado
     *                                        si el token es válido.
     */
    public function handle(): array
    {
        $token = $this->extractBearerToken();

        if ($token === null) {
            $this->sendUnauthorized('Token no proporcionado');
        }

        $user = $this->findUserByToken($token);

        if ($user === null) {
            $this->sendUnauthorized('Token inválido o expirado');
        }

        return $user;
    }

    /**
     * Extrae el Bearer token del header Authorization.
     *
     * Soporta tanto la variable de servidor estándar HTTP_AUTHORIZATION
     * como REDIRECT_HTTP_AUTHORIZATION (CGI/FastCGI).
     *
     * @return string|null El token crudo, o null si no se encontró.
     */
    private function extractBearerToken(): ?string
    {
        $header = $_SERVER['HTTP_AUTHORIZATION']
            ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
            ?? '';

        if (!str_starts_with($header, 'Bearer ')) {
            return null;
        }

        $token = substr($header, 7);

        return $token !== '' ? $token : null;
    }

    /**
     * Busca un usuario en la BD y verifica el token de forma segura.
     *
     * Usa hash_equals() para la comparación, evitando ataques de
     * temporización (timing attacks).
     *
     * @param string $rawToken Token extraído del request.
     * @return array{id: int, email: string}|null Datos del usuario o null
     *                                             si no se encontró coincidencia.
     */
    private function findUserByToken(string $rawToken): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, email, token FROM users WHERE token IS NOT NULL LIMIT 1000'
        );
        $stmt->execute();

        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if (hash_equals((string) $row['token'], $rawToken)) {
                return [
                    'id'    => (int) $row['id'],
                    'email' => (string) $row['email'],
                ];
            }
        }

        return null;
    }

    /**
     * Envía una respuesta 401 en formato JSON y detiene la ejecución.
     *
     * @param string $message Mensaje de error descriptivo.
     * @return never
     */
    private function sendUnauthorized(string $message): never
    {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');

        echo json_encode([
            'status' => 'error',
            'data'   => null,
            'error'  => $message,
        ], JSON_UNESCAPED_UNICODE);

        exit;
    }
}
