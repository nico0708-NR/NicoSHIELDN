"""
NicoShield — tools.py
Motor de herramientas de ciberseguridad (defensivas/educativas).
Desarrollado por Nicolás Rodríguez.
"""

import re
import math
import json
import socket
import hashlib
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════
#  1. ANALIZADOR DE CONTRASEÑAS
# ═══════════════════════════════════════════════════════════════

# Contraseñas más comunes (lista reducida)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "football", "monkey", "letmein", "shadow",
    "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "superman", "1qaz2wsx", "7777777", "fuckyou",
    "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
    "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger", "sunshine",
    "iloveyou", "2000", "charlie", "robert", "thomas", "hockey",
    "ranger", "daniel", "george", "access", "123abc", "notrelevant",
    "admin", "1234", "test", "pass", "nicoshield", "password1",
}


def analyze_password(password: str) -> dict:
    """
    Evalúa la fortaleza de una contraseña.
    Retorna un dict con score, nivel, sugerencias y detalles.
    """
    result = {
        "length": len(password),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password)),
        "has_spaces": bool(re.search(r"\s", password)),
        "is_common": password.lower() in COMMON_PASSWORDS,
        "has_repetition": bool(re.search(r"(.)\1{2,}", password)),
        "has_sequential": _has_sequential(password),
    }

    # ── Cálculo de entropía ──────────────────────────────────────
    charset = 0
    if result["has_lower"]:   charset += 26
    if result["has_upper"]:   charset += 26
    if result["has_digit"]:   charset += 10
    if result["has_special"]: charset += 32
    if result["has_spaces"]:  charset += 1
    if charset == 0:          charset = 1

    entropy = len(password) * math.log2(charset)
    result["entropy"] = round(entropy, 1)

    # ── Score (0–100) ────────────────────────────────────────────
    score = 0
    if len(password) >= 8:  score += 10
    if len(password) >= 12: score += 15
    if len(password) >= 16: score += 10
    if result["has_lower"]:   score += 10
    if result["has_upper"]:   score += 10
    if result["has_digit"]:   score += 10
    if result["has_special"]: score += 20
    if result["has_spaces"]:  score += 5
    if entropy >= 40: score += 10
    if entropy >= 60: score += 10
    if result["is_common"]:      score -= 40
    if result["has_repetition"]: score -= 10
    if result["has_sequential"]: score -= 10
    if len(password) < 6:        score -= 20

    score = max(0, min(100, score))
    result["score"] = score

    # ── Nivel ────────────────────────────────────────────────────
    if score >= 80:
        result["level"] = "Muy fuerte"
        result["level_en"] = "very_strong"
        result["color"] = "#22c55e"
    elif score >= 60:
        result["level"] = "Fuerte"
        result["level_en"] = "strong"
        result["color"] = "#84cc16"
    elif score >= 40:
        result["level"] = "Media"
        result["level_en"] = "medium"
        result["color"] = "#eab308"
    elif score >= 20:
        result["level"] = "Débil"
        result["level_en"] = "weak"
        result["color"] = "#f97316"
    else:
        result["level"] = "Muy débil"
        result["level_en"] = "very_weak"
        result["color"] = "#ef4444"

    # ── Sugerencias ──────────────────────────────────────────────
    tips = []
    if len(password) < 12:
        tips.append("Usa al menos 12 caracteres.")
    if not result["has_upper"]:
        tips.append("Agrega letras mayúsculas (A-Z).")
    if not result["has_lower"]:
        tips.append("Agrega letras minúsculas (a-z).")
    if not result["has_digit"]:
        tips.append("Incluye números (0-9).")
    if not result["has_special"]:
        tips.append("Añade caracteres especiales (!@#$...).")
    if result["is_common"]:
        tips.append("⚠️ Esta contraseña es muy conocida. Cámbiala inmediatamente.")
    if result["has_repetition"]:
        tips.append("Evita caracteres repetidos consecutivos.")
    if result["has_sequential"]:
        tips.append("Evita secuencias como '123' o 'abc'.")
    if not tips:
        tips.append("✅ Excelente contraseña. Considera guardarla en un gestor de contraseñas.")

    result["tips"] = tips

    # ── Tiempo estimado de crackeo (simplificado) ────────────────
    combinations = charset ** len(password)
    speed = 1e10  # 10 mil millones intentos/seg (GPU moderna)
    seconds = combinations / speed / 2  # promedio

    if seconds < 1:
        crack_time = "instantáneo"
    elif seconds < 60:
        crack_time = f"{int(seconds)} segundos"
    elif seconds < 3600:
        crack_time = f"{int(seconds/60)} minutos"
    elif seconds < 86400:
        crack_time = f"{int(seconds/3600)} horas"
    elif seconds < 2592000:
        crack_time = f"{int(seconds/86400)} días"
    elif seconds < 31536000:
        crack_time = f"{int(seconds/2592000)} meses"
    elif seconds < 3153600000:
        crack_time = f"{int(seconds/31536000)} años"
    else:
        crack_time = "siglos"

    result["crack_time"] = crack_time
    return result


def _has_sequential(password: str) -> bool:
    p = password.lower()
    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop",
                 "asdfghjkl", "zxcvbnm"]
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in p:
                return True
    return False


# ═══════════════════════════════════════════════════════════════
#  2. DETECTOR DE PHISHING / URLs SOSPECHOSAS
# ═══════════════════════════════════════════════════════════════

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "update",
    "account", "secure", "security", "password", "passwd", "credential",
    "banking", "paypal", "amazon", "google", "microsoft", "apple",
    "facebook", "instagram", "netflix", "support", "helpdesk", "alert",
    "urgent", "suspended", "confirm", "validate", "access", "recover",
    "unlock", "limited", "expire", "renewal",
]

TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "github.com", "linkedin.com", "paypal.com", "netflix.com", "spotify.com",
    "wikipedia.org", "reddit.com", "stackoverflow.com",
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                   ".club", ".work", ".click", ".link", ".win"}


def analyze_url(url: str) -> dict:
    """
    Analiza una URL en busca de indicadores de phishing.
    Completamente estático / sin hacer requests reales.
    """
    # Normalizar
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return {"error": "URL inválida"}

    domain = parsed.netloc.lower().replace("www.", "")
    full_url = url.lower()

    indicators = []
    score = 0  # 0 = seguro, mayor = más sospechoso

    # ── Indicadores negativos (suman riesgo) ────────────────────

    # 1. HTTP sin HTTPS
    if parsed.scheme == "http":
        indicators.append({"type": "warning", "msg": "Usa HTTP sin cifrado (no HTTPS)"})
        score += 10

    # 2. IP en lugar de dominio
    try:
        ipaddress.ip_address(domain.split(":")[0])
        indicators.append({"type": "danger", "msg": "URL usa dirección IP directa (muy sospechoso)"})
        score += 40
    except ValueError:
        pass

    # 3. Dominio muy largo
    if len(domain) > 50:
        indicators.append({"type": "warning", "msg": f"Dominio inusualmente largo ({len(domain)} chars)"})
        score += 15

    # 4. Muchos subdominios
    subdomains = domain.split(".")
    if len(subdomains) > 4:
        indicators.append({"type": "warning", "msg": f"Exceso de subdominios ({len(subdomains)-2})"})
        score += 20

    # 5. Marca conocida en subdominio (spoofing)
    for brand in ["paypal", "amazon", "google", "microsoft", "apple", "facebook",
                  "netflix", "instagram", "bank", "secure"]:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            indicators.append({"type": "danger", "msg": f"Posible suplantación de '{brand}' en el dominio"})
            score += 35

    # 6. Palabras clave de phishing en la URL
    kw_found = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    if kw_found:
        indicators.append({"type": "warning",
                           "msg": f"Palabras sospechosas en URL: {', '.join(kw_found[:5])}"})
        score += min(len(kw_found) * 8, 30)

    # 7. TLD sospechoso
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            indicators.append({"type": "warning", "msg": f"TLD de alto riesgo: {tld}"})
            score += 20
            break

    # 8. Guiones excesivos
    if domain.count("-") >= 3:
        indicators.append({"type": "warning",
                           "msg": f"Guiones excesivos en dominio ({domain.count('-')})"})
        score += 15

    # 9. Caracteres @ (redirección engañosa)
    if "@" in parsed.netloc:
        indicators.append({"type": "danger", "msg": "Carácter '@' en la URL (técnica de engaño)"})
        score += 40

    # 10. URL muy larga
    if len(url) > 200:
        indicators.append({"type": "info", "msg": f"URL muy larga ({len(url)} chars)"})
        score += 10

    # 11. Dominio con números mezclados (homoglyph)
    if re.search(r"\d{4,}", domain):
        indicators.append({"type": "warning", "msg": "Cadena numérica larga en el dominio"})
        score += 10

    # ── Indicadores positivos (reducen riesgo) ──────────────────
    root_domain = ".".join(subdomains[-2:]) if len(subdomains) >= 2 else domain
    if root_domain in TRUSTED_DOMAINS:
        indicators.append({"type": "safe", "msg": f"Dominio raíz reconocido: {root_domain}"})
        score = max(0, score - 30)

    if parsed.scheme == "https":
        indicators.append({"type": "safe", "msg": "Usa HTTPS (conexión cifrada)"})
        score = max(0, score - 5)

    score = min(100, score)

    # ── Nivel de riesgo ──────────────────────────────────────────
    if score == 0:
        risk = "Segura"
        risk_level = "none"
        risk_color = "#22c55e"
    elif score <= 20:
        risk = "Baja sospecha"
        risk_level = "low"
        risk_color = "#84cc16"
    elif score <= 45:
        risk = "Sospechosa"
        risk_level = "medium"
        risk_color = "#eab308"
    elif score <= 70:
        risk = "Alto riesgo"
        risk_level = "high"
        risk_color = "#f97316"
    else:
        risk = "Phishing probable"
        risk_level = "critical"
        risk_color = "#ef4444"

    return {
        "url": url,
        "domain": domain,
        "scheme": parsed.scheme,
        "path": parsed.path,
        "score": score,
        "risk": risk,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "indicators": indicators,
        "indicators_count": len(indicators),
    }


# ═══════════════════════════════════════════════════════════════
#  3. ESCÁNER DE PUERTOS
# ═══════════════════════════════════════════════════════════════

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 194: "IRC", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP-TLS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2082: "cPanel", 2083: "cPanel-SSL",
    2222: "SSH-alt", 3000: "Dev-Server", 3306: "MySQL", 3389: "RDP",
    4000: "Dev-Server", 5000: "Flask/UPnP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6443: "K8s-API", 8000: "HTTP-alt",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB",
}

PORT_RISK = {
    21: "medium", 23: "high", 110: "medium", 111: "medium",
    135: "high", 139: "high", 143: "medium", 445: "critical",
    1433: "high", 1521: "high", 3306: "high", 3389: "high",
    5900: "high", 6379: "high", 27017: "high",
}


def _scan_single_port(host: str, port: int, timeout: float) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            risk = PORT_RISK.get(port, "low")
            return {"port": port, "status": "open", "service": service, "risk": risk}
    except (socket.error, OSError):
        pass
    return None


def scan_ports(target: str, port_range: str = "common", timeout: float = 1.0) -> dict:
    """
    Escanea puertos de un host (solo para auditorías autorizadas).
    Limitado a IPs privadas o localhost para uso ético.
    """
    # ── Resolver host ────────────────────────────────────────────
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"error": f"No se pudo resolver el host: {target}"}

    # ── Validación ética: solo IPs privadas / loopback ───────────
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not (ip_obj.is_private or ip_obj.is_loopback):
            return {
                "error": "Por razones éticas y legales, el escáner solo opera en redes privadas "
                         "(192.168.x.x, 10.x.x.x, 172.16-31.x.x) o localhost. "
                         "Para escanear sistemas externos, se requiere autorización explícita del propietario."
            }
    except ValueError:
        return {"error": "IP inválida"}

    # ── Definir puertos ──────────────────────────────────────────
    if port_range == "common":
        ports = list(COMMON_SERVICES.keys())
    elif port_range == "top100":
        ports = list(COMMON_SERVICES.keys())[:30] + list(range(1, 71))
        ports = sorted(set(ports))[:100]
    else:
        # Rango personalizado "80-443"
        try:
            start, end = map(int, port_range.split("-"))
            end = min(end, start + 999)   # máximo 1000 puertos
            ports = list(range(start, end + 1))
        except Exception:
            return {"error": "Formato de rango inválido. Usa 'common', 'top100' o 'inicio-fin'"}

    # ── Escaneo concurrente ──────────────────────────────────────
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(_scan_single_port, ip, p, timeout): p for p in ports
        }
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])

    # ── Estadísticas ─────────────────────────────────────────────
    risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for p in open_ports:
        risk_counts[p["risk"]] = risk_counts.get(p["risk"], 0) + 1

    overall_risk = "none"
    if risk_counts["critical"] > 0:
        overall_risk = "critical"
    elif risk_counts["high"] > 0:
        overall_risk = "high"
    elif risk_counts["medium"] > 0:
        overall_risk = "medium"
    elif risk_counts["low"] > 0:
        overall_risk = "low"

    return {
        "target": target,
        "ip": ip,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "risk_counts": risk_counts,
        "overall_risk": overall_risk,
    }


# ═══════════════════════════════════════════════════════════════
#  4. ANALIZADOR DE ARCHIVOS (HASHES)
# ═══════════════════════════════════════════════════════════════

# Hashes de archivos conocidos como maliciosos (muestra educativa)
KNOWN_MALICIOUS_MD5 = {
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR test file (MD5)
    "cf8bd9dfddff007f75adf4c2be48005a",
    "69630e4574ec6798239b091cda43dca0",
}
KNOWN_MALICIOUS_SHA256 = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR SHA256
}

# Extensiones de alto riesgo
HIGH_RISK_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi",
    ".scr", ".pif", ".com", ".hta", ".wsf", ".reg",
}
MEDIUM_RISK_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".xls", ".doc", ".pdf", ".zip",
    ".rar", ".7z", ".tar", ".gz", ".iso", ".img",
}


def analyze_file(file_data: bytes, filename: str) -> dict:
    """
    Calcula hashes y evalúa riesgo de un archivo.
    No ejecuta el archivo, solo análisis estático.
    """
    size = len(file_data)
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # ── Hashes ───────────────────────────────────────────────────
    md5    = hashlib.md5(file_data).hexdigest()
    sha1   = hashlib.sha1(file_data).hexdigest()
    sha256 = hashlib.sha256(file_data).hexdigest()
    sha512 = hashlib.sha512(file_data).hexdigest()

    # ── Chequeo contra lista negra ───────────────────────────────
    is_known_malicious = (
        md5 in KNOWN_MALICIOUS_MD5 or
        sha256 in KNOWN_MALICIOUS_SHA256
    )

    # ── Análisis de firma mágica (magic bytes) ───────────────────
    magic = _detect_magic(file_data)

    # ── Entropía (detecta archivos cifrados/comprimidos) ─────────
    entropy = _calculate_entropy(file_data[:4096])

    # ── Riesgo ───────────────────────────────────────────────────
    indicators = []
    risk_score = 0

    if is_known_malicious:
        indicators.append({"type": "danger", "msg": "⚠️ Hash coincide con archivo CONOCIDO COMO MALICIOSO"})
        risk_score += 100

    if ext in HIGH_RISK_EXTENSIONS:
        indicators.append({"type": "danger", "msg": f"Extensión de alto riesgo: {ext}"})
        risk_score += 40

    elif ext in MEDIUM_RISK_EXTENSIONS:
        indicators.append({"type": "warning", "msg": f"Extensión de riesgo moderado: {ext}"})
        risk_score += 15

    if entropy > 7.5:
        indicators.append({"type": "warning",
                           "msg": f"Entropía muy alta ({entropy:.2f}/8.0) — posible archivo cifrado/comprimido"})
        risk_score += 20
    elif entropy > 6.5:
        indicators.append({"type": "info",
                           "msg": f"Entropía elevada ({entropy:.2f}/8.0)"})
        risk_score += 5

    # Extensión vs tipo real
    if magic and ext:
        if _extension_mismatch(ext, magic):
            indicators.append({"type": "danger",
                               "msg": f"Tipo real ({magic}) no coincide con extensión ({ext}) — posible engaño"})
            risk_score += 30

    if size == 0:
        indicators.append({"type": "warning", "msg": "Archivo vacío"})

    risk_score = min(100, risk_score)

    if risk_score == 0:
        indicators.append({"type": "safe", "msg": "No se encontraron indicadores de riesgo"})

    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 45:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    elif risk_score > 0:
        risk_level = "low"
    else:
        risk_level = "none"

    return {
        "filename": filename,
        "size": size,
        "size_human": _human_size(size),
        "extension": ext,
        "magic_type": magic or "Desconocido",
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "sha512": sha512,
        "entropy": round(entropy, 4),
        "is_known_malicious": is_known_malicious,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
    }


def _detect_magic(data: bytes) -> str | None:
    sigs = [
        (b"\x4d\x5a", "PE/EXE (Windows Executable)"),
        (b"\x7fELF", "ELF (Linux Executable)"),
        (b"\xff\xd8\xff", "JPEG Image"),
        (b"\x89PNG\r\n\x1a\n", "PNG Image"),
        (b"GIF8", "GIF Image"),
        (b"PK\x03\x04", "ZIP Archive"),
        (b"\x1f\x8b", "GZIP Archive"),
        (b"BZh", "BZIP2 Archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive"),
        (b"%PDF", "PDF Document"),
        (b"\xd0\xcf\x11\xe0", "OLE2 (Office doc/xls)"),
        (b"PK\x03\x04\x14\x00\x06\x00", "DOCX/XLSX/PPTX (Office Open XML)"),
        (b"<!DOCTYPE html", "HTML Document"),
        (b"<html", "HTML Document"),
        (b"#!/", "Shell Script"),
        (b"\xca\xfe\xba\xbe", "Java Class"),
        (b"ITSF", "CHM Help File"),
    ]
    for sig, name in sigs:
        if data[:len(sig)] == sig:
            return name
    return None


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    n = len(data)
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


def _extension_mismatch(ext: str, magic: str) -> bool:
    safe_combos = {
        ".jpg": ["JPEG"], ".jpeg": ["JPEG"],
        ".png": ["PNG"], ".gif": ["GIF"],
        ".pdf": ["PDF"], ".zip": ["ZIP"],
        ".gz": ["GZIP"], ".7z": ["7-Zip"],
        ".exe": ["PE/EXE"], ".elf": ["ELF"],
        ".docx": ["DOCX/XLSX/PPTX"], ".xlsx": ["DOCX/XLSX/PPTX"],
        ".pptx": ["DOCX/XLSX/PPTX"],
        ".doc": ["OLE2"], ".xls": ["OLE2"],
        ".html": ["HTML"], ".htm": ["HTML"],
        ".jar": ["ZIP"], ".war": ["ZIP"], ".apk": ["ZIP"],
    }
    allowed = safe_combos.get(ext, [])
    if not allowed:
        return False
    return not any(m in magic for m in allowed)


def _human_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"