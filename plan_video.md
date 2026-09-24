# Plan del vídeo — Laboratorio SOC: Fuerza Bruta SSH con Wazuh
**Autor:** Bryan Acanda Gonzalez — Bootcamp Ciberseguridad, Neoland

---

## Arquitectura del laboratorio
| VM | IP | Rol |
|---|---|---|
| Kali Linux | 192.168.56.102 | Atacante |
| Ubuntu Server 26.04 | 192.168.56.103 | Objetivo SSH + Wazuh Manager all-in-one |

**Credenciales:**
- Ubuntu sistema: kali / kali
- Usuario lab: soclab / soclab123
- Wazuh dashboard: admin / 7CuttX52*s.sBMI*pJZuOi2mCJTfDgG0

---

## Estado del servidor (al salir)
- Wazuh: DESINSTALADO completamente
- /var/ossec: ELIMINADO
- auth.log: LIMPIO
- Usuario soclab: EXISTE (no hace falta recrearlo)
- Disco: 15% usado, 20 GB libres
- SSH: Activo y funcionando
- sshd_config: Valores por defecto (todo comentado, sin cambios)
- Fail2ban: No instalado

---

## Progreso actual
- [x] Paso 1 — Leer el guion de introducción
- [x] Paso 2 — Mostrar las dos VMs y la arquitectura de red
- [x] Paso 3 — Verificar conectividad entre Kali y Ubuntu (ping)
- [x] Paso 4 — Verificar que SSH funciona en Ubuntu
- [x] Paso 5 — Descargar el script de instalación oficial
- [x] Paso 6 — Ejecutar la instalación all-in-one
- [x] Paso 7 — Acceder al dashboard de Wazuh por primera vez
- [x] Paso 8 — Registrar el agente Wazuh en Ubuntu (manager actúa como agente local)

---

## Plan completo

### BLOQUE 1 — Presentación
- [x] Paso 1 — Leer el guion de introducción

### BLOQUE 2 — Preparar el entorno
- [x] Paso 2 — Mostrar las dos VMs y la arquitectura de red
- [ ] Paso 3 — Verificar conectividad entre Kali y Ubuntu (ping)
- [ ] Paso 4 — Verificar que SSH funciona en Ubuntu

### BLOQUE 3 — Instalar Wazuh
- [x] Paso 5 — Descargar el script de instalación oficial
- [x] Paso 6 — Ejecutar la instalación all-in-one
- [x] Paso 7 — Acceder al dashboard de Wazuh por primera vez
- [x] Paso 8 — Registrar el agente Wazuh en Ubuntu (manager actúa como agente local)
- [x] Paso 9 — Verificar que el agente aparece como "Active"
- [x] Paso 10 — Verificar que Wazuh monitoriza logs SSH (vía journald)

### BLOQUE 4 — Ataque 1 (servidor sin hardening)
- [x] Paso 11 — Mostrar que el servidor no tiene protección
- [x] Paso 12 — Lanzar el ataque de fuerza bruta con Hydra desde Kali
- [x] Paso 13 — Ver las alertas en el dashboard de Wazuh en tiempo real
- [x] Paso 14 — Hacer login exitoso con las credenciales obtenidas
- [x] Paso 15 — Ver la alerta de correlación nivel 12 en Wazuh
- [x] Paso 16 — Construir el timeline del incidente en el dashboard ← AQUÍ NOS QUEDAMOS

### BLOQUE 5 — Hardening del servidor
- [x] Paso 17 — Modificar /etc/ssh/sshd_config (deshabilitar contraseña, limitar intentos)
- [x] Paso 18 — Reiniciar SSH y verificar los cambios
- [x] Paso 19 — Instalar y configurar Fail2ban
- [x] Paso 20 — Verificar que Fail2ban está activo

### BLOQUE 6 — Ataque 2 (servidor hardenizado)
- [x] Paso 21 — Lanzar el mismo ataque con Hydra
- [x] Paso 22 — Explicar Fail2ban como segunda capa (defensa en profundidad)
- [x] Paso 23 — Ver las alertas en Wazuh (sin login exitoso)

### BLOQUE 7 — Regla personalizada en Wazuh
- [x] Paso 24 — Escribir la regla 100010 en local_rules.xml
- [x] Paso 25 — Verificado directamente (regla correcta)
- [x] Paso 26 — Reiniciar Wazuh y confirmar en el dashboard ← AQUÍ NOS QUEDAMOS

### BLOQUE 8 — Informe comparativo
- [ ] Paso 27 — Mostrar la tabla comparativa Ataque 1 vs Ataque 2
- [ ] Paso 28 — Explicar el mapeo MITRE ATT&CK
- [ ] Paso 29 — Conclusiones
