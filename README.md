# Laboratorio SOC — Investigación de Fuerza Bruta SSH con Wazuh

**Autor:** Bryan Acanda Gonzalez  
**Bootcamp:** Ciberseguridad — Neoland  
**Enfoque:** Blue Team / SOC Analyst L1  
**SIEM:** Wazuh 4.14.7

---

## Descripción

Laboratorio práctico de análisis de un incidente de fuerza bruta SSH. Se simula un ataque real, se detecta con Wazuh y se investiga como lo haría un analista SOC L1.

## Arquitectura

| VM | IP | Rol |
|---|---|---|
| Kali Linux | 192.168.56.102 | Atacante |
| Ubuntu Server 22.04 | 192.168.56.103 | Objetivo SSH + Wazuh Manager (all-in-one) |

## Resumen del incidente

- **22 intentos fallidos** de SSH contra el usuario `soclab` desde `192.168.56.102`
- **1 login exitoso** posterior desde la misma IP
- Detección automática por Wazuh con alerta de nivel 12 (correlación fuerza bruta + éxito)
- Mapeo MITRE ATT&CK: **T1110.001** (Password Guessing) + **T1078** (Valid Accounts)

## Reglas Wazuh

| Rule ID | Nivel | Descripción |
|---|---|---|
| 5760 | 5 | Fallo individual de autenticación SSH |
| 5763 | 10 | Fuerza bruta SSH detectada |
| 5551 | 10 | PAM: múltiples fallos en poco tiempo |
| 5715 | 3 | Login exitoso |
| 40112 | 12 | Múltiples fallos seguidos de éxito (nativa) |
| **100010** | **12** | **Múltiples fallos seguidos de éxito (custom)** |

## Estructura del repositorio

```
├── README.md
├── detecciones/
│   ├── local_rules.xml          ← Regla personalizada 100010
│   └── mitre_attack_mapping.md  ← Mapeo MITRE ATT&CK completo
├── evidencias/
│   ├── 01-failed-attempts.png   ← 20 fallos SSH detectados
│   ├── 02-source-ip.png         ← Detalle del evento con srcip
│   ├── 03-dashboard-overview.png← Overview de alertas Wazuh
│   ├── 04-mitre-attack.png      ← Dashboard MITRE ATT&CK
│   └── 05-brute-force-detection.png ← Alertas nivel 10/12
└── informes/
    └── informe_incidente_final.pdf  ← Informe completo del incidente
```

## Habilidades demostradas

- Configuración de Wazuh SIEM (all-in-one) en entorno de laboratorio
- Monitorización de `/var/log/auth.log` para detección de ataques SSH
- Análisis de alertas y construcción de timeline de incidente
- Escritura de reglas de correlación personalizadas en Wazuh (`local_rules.xml`)
- Validación de reglas con `wazuh-logtest`
- Mapeo de técnicas a MITRE ATT&CK
- Redacción de informe de incidente

## Entorno

- Kali Linux (atacante)
- Ubuntu Server 22.04 (objetivo)
- Wazuh 4.14.7 (Manager + Indexer + Dashboard)
- Red Host-Only aislada (sin conectividad externa)
