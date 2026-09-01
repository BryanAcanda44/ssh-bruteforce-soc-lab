# Mapeo MITRE ATT&CK — Incidente Fuerza Bruta SSH
**Fecha del incidente:** 2026-09-01  
**Host objetivo:** ubuntu-server (192.168.56.103)  
**IP atacante:** 192.168.56.102 (Kali Linux)

---

## Táctica 1: Credential Access

### T1110 — Brute Force
- **Descripción:** El atacante realizó múltiples intentos de autenticación SSH contra el sistema objetivo con el objetivo de obtener credenciales válidas.
- **Evidencia en el lab:** 22 intentos fallidos de SSH contra el usuario `soclab` desde `192.168.56.102` registrados en `/var/log/auth.log`.
- **Reglas Wazuh que lo detectaron:**
  - `5760` (nivel 5) — Fallo individual de autenticación SSH
  - `5551` (nivel 10) — PAM: múltiples fallos en poco tiempo
  - `5763` (nivel 10) — Fuerza bruta detectada por SSH

---

### T1110.001 — Password Guessing
- **Descripción:** Subtécnica de fuerza bruta donde el atacante prueba contraseñas predecibles o de diccionario contra cuentas conocidas del sistema.
- **Evidencia en el lab:** Los intentos se realizaron contra el usuario `soclab`, una cuenta válida del sistema. Las contraseñas probadas seguían patrones predecibles (`wrongpass1`, `badpass11`, etc.).
- **Por qué aplica:** A diferencia de un ataque de credential stuffing (T1110.004), aquí se conocía el nombre de usuario y se variaba la contraseña — patrón clásico de password guessing.
- **Reglas Wazuh:** 5760, 5763

---

## Táctica 2: Initial Access (post-éxito)

### T1078 — Valid Accounts
- **Descripción:** Tras el ataque de fuerza bruta, el atacante obtuvo acceso al sistema utilizando credenciales válidas de la cuenta `soclab`.
- **Evidencia en el lab:**
  - Timestamp: `2026-09-01T09:30:41 UTC`
  - Log: `Accepted password for soclab from 192.168.56.102 port 34804 ssh2`
  - Regla Wazuh: `5715` (nivel 3) — autenticación exitosa
  - Correlación: `40112` (nivel 12) — múltiples fallos seguidos de éxito
  - Regla personalizada: `100010` (nivel 12) — confirma el patrón
- **Impacto:** El atacante obtuvo una sesión interactiva en el sistema con los privilegios del usuario `soclab`.

---

## Resumen del mapeo

| Táctica | Técnica | Subtécnica | Evidencia | Regla Wazuh |
|---|---|---|---|---|
| Credential Access | T1110 Brute Force | T1110.001 Password Guessing | 22 fallos SSH en auth.log | 5760, 5763, 5551 |
| Initial Access | T1078 Valid Accounts | — | Login exitoso soclab 09:30:41 | 5715, 40112, 100010 |

---

## Cadena de ataque (Kill Chain)

```
[Reconocimiento implícito]
        ↓
[T1110.001] Password Guessing × 22 intentos
        ↓
[Detección] rule:5763 nivel 10 — fuerza bruta detectada
        ↓
[T1078] Login exitoso con soclab/soclab123
        ↓
[Correlación] rule:40112 / rule:100010 nivel 12 — ALERTA CRÍTICA
```

---

## Controles de detección aplicados

| Control | Tipo | Descripción |
|---|---|---|
| Wazuh + auth.log | Detective | Monitorización de logs SSH en tiempo real |
| Regla 5763 | Detective | Umbral de fallos por IP y ventana de tiempo |
| Regla 100010 (custom) | Detective | Correlación fallos → éxito desde misma IP |
| MITRE ATT&CK mapping | Analítico | Clasificación automática por Wazuh |

## Controles preventivos recomendados

| Control | Tipo | Técnica mitigada |
|---|---|---|
| Autenticación por clave SSH | Preventivo | T1110, T1110.001 |
| Fail2ban / rate limiting | Preventivo | T1110 |
| MFA o VPN para acceso SSH | Preventivo | T1110, T1078 |
| Deshabilitar login por contraseña | Preventivo | T1110.001 |
| Principio de mínimo privilegio en soclab | Preventivo | T1078 |
