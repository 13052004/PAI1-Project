# PAI-1 Project – Secure Client/Server Implementation (Python)

## Descripción
Este proyecto implementa un sistema **cliente-servidor seguro** en Python para la asignatura de SSII.  
El servidor gestiona usuarios, sesiones y transacciones; el cliente permite registrarse, iniciar sesión y enviar operaciones firmadas.  
Se han aplicado medidas de seguridad como almacenamiento seguro de contraseñas, integridad de mensajes, nonces para evitar replays, bloqueo por fuerza bruta, expiración de sesiones y soporte de **TCP** y **TLS**.

---

## Estructura del proyecto
- **`security_utils.py`**  
  Funciones auxiliares de seguridad y base de datos:
  - Hash de contraseñas con PBKDF2-HMAC-SHA256 (200.000 iteraciones, salt único por usuario).  
  - Generación/verificación de HMAC-SHA256 con claves de sesión de 256 bits.  
  - Gestión de usuarios (registro, login, bloqueo por fuerza bruta).  
  - Gestión de sesiones (creación, expiración, logout).  
  - Control de nonces para prevenir ataques de repetición (replay).  

- **`server.py`**  
  Servidor concurrente que escucha en `127.0.0.1:9000` y procesa mensajes JSON delimitados por `\n`.  
  - Soporta **TCP plano** o **TLS** según configuración.  
  - Operaciones soportadas: `register`, `login`, `tx`, `logout`.  
  - Incluye logs detallados de seguridad (intentos fallidos, replays, etc.).

- **`client.py`**  
  Cliente sencillo con funciones de alto nivel:
  - `register(username, password)`  
  - `login(username, password)`  
  - `send_tx(session_id, session_key, from_acc, to_acc, amount)`  
  - `logout(session_id)`  

  El cliente selecciona automáticamente entre **TCP o TLS** usando la variable global:
  ```python
  USE_INSECURE_TESTING = True   # TCP plano
  USE_INSECURE_TESTING = False  # TLS

## Ejecución
1. **Servidor**  
   - TCP: Ejecutar la orden `python server.py`  
   - TLS: generar `server.crt` y `server.key` para ello ejecutar la orden `python gen_cert.py`, luego `python server.py`  

2. **Cliente/Tests**  
   - Cambiar en `client.py` → `USE_INSECURE_TESTING = True` (TCP) / `False` (TLS).  
   - Ejecutar tests:  
     ```bash
     python tests/test_valid.py
     python tests/test_tamper.py
     python tests/test_replay.py
     python tests/test_bruteforce.py
     python tests/test_expiry.py
     python tests/test_logout.py
     ```

---

## Tests
- **test_valid.py** → flujo básico (registro, login, tx válida).  
- **test_tamper.py** → mensaje manipulado → rechazo.  
- **test_replay.py** → replay de transacción → rechazo.  
- **test_bruteforce.py** → bloqueo tras 5 fallos de login.  
- **test_expiry.py** → sesión expirada → rechazo.  
- **test_logout.py** → logout invalida la sesión.  



## Seguridad
- Contraseñas: PBKDF2-HMAC-SHA256 (200k iteraciones, salt único).  
- Integridad: HMAC-SHA256 con claves de sesión de 256 bits.  
- Nonces: previenen replay.  
- Bloqueo: 5 intentos fallidos → usuario bloqueado 5 min.  
- Sesiones: expiración automática y logout.  
- TLS: disponible (con certificado autofirmado para pruebas).
