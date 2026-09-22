# REAPER

**Red team Enumeration And Pentesting Enhanced Resource**

Framework de pentest todo-en-uno para GNU/Linux con CLI interactivo y Web UI.

<img width="1168" height="784" alt="REAPER - Red team Enumeration And Pentesting Enhanced Resource" src="https://github.com/user-attachments/assets/fba552d2-0422-439f-a25e-d91de68faa7b" />

---

## Instalacion rapida

```bash
git clone https://github.com/rayoieltxu/reaper
cd reaper
bash install.sh
```

### Requisitos
- Python 3.11+
- GNU/Linux (Kali, Parrot, Ubuntu recomendado)
- Las herramientas externas se instalan via `install.sh`

---

## Uso rapido

```bash
# Crear sesion y lanzar escaneo automatico
reaper session new corp-ext 192.168.1.0/24 --profile internal
reaper run auto

# Pentest web
reaper session new webapp https://target.com --profile web
reaper run auto

# Active Directory
reaper session new ad-audit 10.10.10.1 --profile ad
reaper run auto

# Ver resultados
reaper findings
reaper findings --severity critical
reaper report --format html

# Web UI
reaper web  # abre http://127.0.0.1:8080
```

---

## Modulos disponibles

### Reconocimiento
| Modulo | Herramienta | Descripcion |
|--------|-------------|-------------|
| `nmap` | Nmap | Port scan con deteccion de servicios y OS |
| `masscan` | Masscan | Scan ultrarapido para rangos CIDR grandes |
| `subfinder` | Subfinder | Enumeracion pasiva de subdominios |
| `httpx` | httpx | Probing HTTP masivo con deteccion de tecnologias |
| `theharvester` | theHarvester | OSINT: emails, subdominios, IPs |
| `trufflehog` | TruffleHog | Busqueda de secrets en repos git |
| `katana` | Katana | Crawler web de ultima generacion |
| `wayback` | CDX API | URLs historicas de Wayback Machine (sin tool externa) |

### Aplicaciones Web
| Modulo | Herramienta | Descripcion |
|--------|-------------|-------------|
| `nuclei` | Nuclei | Scanner de vulnerabilidades basado en templates |
| `ffuf` | FFuf | Fuzzing de directorios, endpoints, VHosts |
| `sqlmap` | SQLMap | Deteccion y explotacion de SQL injection |
| `nikto` | Nikto | Scanner de configuracion erronea en servidores web |
| `dalfox` | Dalfox | Analisis y escaneo de XSS |
| `whatweb` | WhatWeb | Fingerprinting de tecnologias web |
| `cors` | *Python puro* | Detector de misconfiguracion CORS |

### Active Directory
| Modulo | Herramienta | Descripcion |
|--------|-------------|-------------|
| `netexec` | NetExec/CME | Enumeracion SMB/LDAP/WinRM y password spraying |
| `kerbrute` | Kerbrute | Enumeracion de usuarios Kerberos |
| `bloodhound` | BloodHound.py | Recoleccion de attack paths en AD |
| `certipy` | Certipy | Ataques a AD CS (ESC1-ESC13) |
| `responder` | Responder | Captura de hashes LLMNR/NBT-NS/mDNS |
| `linwinpwn` | linWinPwn | Enumeracion AD automatizada completa |

### Post-Explotacion
| Modulo | Herramienta | Descripcion |
|--------|-------------|-------------|
| `hashcat` | Hashcat | Cracking de passwords (NTLM, NTLMv2, Kerberoast...) |
| `hydra` | Hydra | Brute force de servicios de red |
| `linpeas` | LinPEAS | Escalada de privilegios en Linux |
| `pacu` | Pacu | Framework de explotacion AWS |
| `prowler` | Prowler | Auditoria de seguridad AWS/GCP/Azure |
| `ligolo` | *Config gen* | Generador de comandos para tunneling con ligolo-ng |

---

## Perfiles de sesion

Cada sesion tiene un perfil que determina que modulos lanza `reaper run auto`:

| Perfil | Caso de uso | Modulos auto |
|--------|-------------|--------------|
| `recon` | Reconocimiento inicial | subfinder, httpx, whatweb, wayback |
| `web` | Pentest de aplicacion web | nuclei, nikto, dalfox, ffuf, cors |
| `ad` | Auditoria Active Directory | netexec, kerbrute, bloodhound, certipy |
| `internal` | Red interna | masscan, nmap, netexec, nuclei |
| `external` | Perimetro externo | subfinder, theharvester, nuclei |
| `cloud` | AWS/GCP/Azure | nuclei, prowler, pacu |

```bash
reaper session profile mi-sesion web
reaper run auto --profile ad   # override puntual
```

---

## Estructura del proyecto

```
reaper/
  cli.py          # CLI (Click + Rich)
  db.py           # Persistencia SQLite (~/.reaper/reaper.db)
  report.py       # Generador HTML / Markdown / JSON
  modules/
    __init__.py   # BaseModule: streaming, SIGINT, timeout
    recon.py      # Modulos de reconocimiento
    web.py        # Modulos web
    ad.py         # Modulos Active Directory
    post.py       # Modulos post-explotacion
  web/
    app.py        # FastAPI + dashboard embebido + SSE streaming
```

---

## Gestion de sesiones

```bash
reaper session new <nombre> <target> [--profile PERFIL]
reaper session list
reaper session use <id>
reaper session profile <nombre> <perfil>
reaper session delete <id>
reaper status
```

## Opciones de modulos

Cada modulo acepta opciones JSON via `--opts`:

```bash
reaper run nmap --opts '{"ports":"80,443,8080-8090","flags":"-sV --open"}'
reaper run ffuf --opts '{"wordlist":"/path/wordlist.txt"}'
reaper run hashcat --opts '{"mode":"ntlmv2","wordlist":"/usr/share/wordlists/rockyou.txt"}'
reaper run kerbrute --opts '{"domain":"corp.local","dc":"10.10.10.1","action":"userenum"}'
reaper run bloodhound --opts '{"username":"user","password":"pass","domain":"corp.local"}'
reaper run ligolo --opts '{"operator_ip":"10.10.10.5","pivot_network":"172.16.0.0/24"}'
```

---

## Web UI

```bash
reaper web                        # http://127.0.0.1:8080
reaper web --host 0.0.0.0 --port 4444
```

La Web UI permite:
- Gestionar sesiones
- Lanzar modulos con output en tiempo real (SSE streaming)
- Ver y filtrar findings
- Generar reportes HTML/Markdown/JSON

---

## Base de datos

Los datos se guardan en `~/.reaper/reaper.db` (SQLite).
Los reportes se generan en `~/.reaper/reports/`.

---

## Advertencia legal

Esta herramienta es para uso en sistemas propios o con autorizacion expresa por escrito.
El uso no autorizado es ilegal. El autor no se responsabiliza del mal uso.
