"""
url_features.py
----------------
Módulo dedicado a la extracción de características (features) de URLs.

Se mantiene separado del resto de la lógica para que en el futuro puedas:
  1. Reutilizar estas features para entrenar un modelo de Machine Learning
     (ej. Random Forest, XGBoost) que sustituya o complemente al motor heurístico.
  2. Agregar nuevas features sin tocar app.py.
  3. Exponer este módulo como microservicio independiente si el proyecto crece.

Cada feature está documentada para facilitar la incorporación de nuevas reglas.
"""

import concurrent.futures
import ipaddress
import logging
import os
import re
import socket
import ssl
import unicodedata
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests

from cache_ttl import TTLCache

logger = logging.getLogger(__name__)

# ------------------------- Configuración (vía .env) -------------------------
def _env_bool(nombre: str, defecto: bool) -> bool:
    return os.getenv(nombre, str(defecto)).strip().lower() in ("1", "true", "yes", "si", "sí")

CHEQUEOS_RED_ACTIVOS = _env_bool("ENABLE_NETWORK_CHECKS", True)   # WHOIS / SSL / HEAD
DESACORTAR_TODAS = _env_bool("UNSHORTEN_ALL", False)              # False: solo acortadores conocidos
TIMEOUT_RED = float(os.getenv("NETWORK_TIMEOUT", "5"))            # segundos por operación de red
MAX_REDIRECCIONES = int(os.getenv("MAX_REDIRECTS", "8"))
MAX_URLS_ANALISIS = int(os.getenv("MAX_URLS_ANALISIS", "3"))
USER_AGENT = "PhishGuard/1.0 (analisis-de-seguridad)"

_cache_whois = TTLCache(max_entries=1000, ttl_seconds=24 * 3600)
_cache_ssl = TTLCache(max_entries=1000, ttl_seconds=3600)
# Dos pools separados: uno para analizar URLs y otro para las consultas de red que estas
# lanzan (así una URL nunca espera a un hilo que ella misma está ocupando -> sin deadlock).
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="pg-red")
_EXECUTOR_URLS = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="pg-url")

# Palabras que suelen aparecer en URLs de phishing para simular legitimidad
PALABRAS_CLAVE_URL = [
    "login", "secure", "account", "verify", "update", "confirm",
    "signin", "banking", "wallet", "password", "wp-admin", "reset",
    "unlock", "invoice", "support"
]

# TLDs frecuentemente asociados a campañas de phishing (bajo costo / poco control)
TLDS_SOSPECHOSOS = ['.xyz', '.top', '.club', '.work', '.info', '.cc', '.tk', '.gq']

# Puertos considerados "estándar" para tráfico web
PUERTOS_ESTANDAR = (80, 443)


def _normalizar_url(url: str) -> str:
    """Agrega esquema si el usuario pegó la URL sin http(s):// para poder parsearla."""
    if "://" not in url:
        return "http://" + url
    return url


def extraer_caracteristicas_url(url_original: str) -> dict:
    """
    Extrae un conjunto de características estructurales y léxicas de una URL.
    Devuelve un diccionario con las features individuales y un score de riesgo
    parcial (0-100) basado únicamente en la URL.
    """
    url = url_original.strip()
    url_normalizada = _normalizar_url(url)
    parsed = urlparse(url_normalizada)
    hostname = parsed.hostname or ""

    # --- Features estructurales básicas ---
    longitud_url = len(url)
    num_puntos = url.count(".")
    num_guiones = url.count("-")
    num_caracteres_especiales = sum(url.count(c) for c in ["@", "_", "%", "=", "&", "?", "#", "~"])
    tiene_arroba = "@" in url

    # --- Dirección IP en lugar de dominio ---
    es_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

    # --- Protocolo ---
    protocolo = parsed.scheme or "desconocido"
    es_https = protocolo == "https"

    # --- Puerto no estándar ---
    try:
        puerto = parsed.port
    except ValueError:            # puerto fuera de rango / mal formado
        puerto = -1
    puerto_no_estandar = puerto is not None and puerto not in PUERTOS_ESTANDAR

    # --- Subdominios ---
    partes_host = [p for p in hostname.split(".") if p] if hostname else []
    # Aproximación: dominio + TLD ocupan las últimas 2 posiciones; el resto son subdominios
    num_subdominios = max(len(partes_host) - 2, 0)

    # --- TLD sospechoso ---
    tld_sospechoso = next((tld for tld in TLDS_SOSPECHOSOS if hostname.endswith(tld)), None)

    # --- Palabras clave sospechosas dentro de la URL ---
    url_lower = url.lower()
    palabras_encontradas = [p for p in PALABRAS_CLAVE_URL if p in url_lower]

    # --- Codificación / ofuscación (porcentajes, unicode, punycode) ---
    tiene_porcentaje = "%" in url
    tiene_unicode = bool(re.search(r"[^\x00-\x7F]", url))
    tiene_punycode = "xn--" in hostname
    tiene_codificacion = tiene_porcentaje or tiene_unicode or tiene_punycode

    features = {
        "url_normalizada": url_normalizada,
        "longitud_url": longitud_url,
        "num_puntos": num_puntos,
        "num_guiones": num_guiones,
        "num_caracteres_especiales": num_caracteres_especiales,
        "tiene_arroba": tiene_arroba,
        "es_ip": es_ip,
        "protocolo": protocolo,
        "es_https": es_https,
        "puerto": puerto,
        "puerto_no_estandar": puerto_no_estandar,
        "num_subdominios": num_subdominios,
        "tld_sospechoso": tld_sospechoso,
        "palabras_sospechosas_url": palabras_encontradas,
        "tiene_codificacion": tiene_codificacion,
    }

    features["score_url"] = _calcular_score(features)
    features["hallazgos_url"] = _generar_hallazgos(features, url_original)

    return features


def _calcular_score(f: dict) -> int:
    """
    Calcula un score heurístico 0-100 en base a las features extraídas.
    Los pesos son ajustables: este es el punto ideal para calibrar el
    sistema con datos reales o para reemplazar por un modelo entrenado.
    """
    puntos = 0
    if f["longitud_url"] > 75:
        puntos += 10
    if f["num_puntos"] > 3:
        puntos += 10
    if f["num_guiones"] > 2:
        puntos += 10
    if f["num_caracteres_especiales"] > 5:
        puntos += 10
    if f["tiene_arroba"]:
        puntos += 15
    if f["es_ip"]:
        puntos += 20
    if not f["es_https"]:
        puntos += 10
    if f["puerto_no_estandar"]:
        puntos += 15
    if f["num_subdominios"] > 3:
        puntos += 10
    if f["tld_sospechoso"]:
        puntos += 15
    if f["palabras_sospechosas_url"]:
        puntos += 15
    if f["tiene_codificacion"]:
        puntos += 10
    return min(puntos, 100)


def _generar_hallazgos(f: dict, url_original: str) -> list:
    """Traduce las features técnicas a mensajes legibles para el usuario final."""
    hallazgos = []
    if f["longitud_url"] > 75:
        hallazgos.append(f"URL inusualmente larga ({f['longitud_url']} caracteres).")
    if f["num_puntos"] > 3:
        hallazgos.append(f"Número elevado de puntos en la URL ({f['num_puntos']}).")
    if f["num_guiones"] > 2:
        hallazgos.append(f"Número elevado de guiones ({f['num_guiones']}), común en dominios falsificados.")
    if f["tiene_arroba"]:
        hallazgos.append("Uso del símbolo '@' en la URL: puede ocultar el dominio real.")
    if f["es_ip"]:
        hallazgos.append("La URL usa una dirección IP directa en lugar de un nombre de dominio.")
    if not f["es_https"]:
        hallazgos.append("La conexión no usa HTTPS (protocolo inseguro).")
    if f["puerto_no_estandar"]:
        hallazgos.append(f"Uso de puerto no estándar ({f['puerto']}).")
    if f["num_subdominios"] > 3:
        hallazgos.append(f"Cantidad elevada de subdominios ({f['num_subdominios']}), técnica común para simular dominios legítimos.")
    if f["tld_sospechoso"]:
        hallazgos.append(f"Dominio de nivel superior (TLD) de alto riesgo: {f['tld_sospechoso']}")
    if f["palabras_sospechosas_url"]:
        hallazgos.append(f"Palabras clave sospechosas dentro de la URL: {', '.join(f['palabras_sospechosas_url'])}")
    if f["tiene_codificacion"]:
        hallazgos.append("Se detectó codificación/ofuscación (porcentajes, Unicode o punycode) en la URL.")
    return hallazgos


def analizar_multiples_urls(urls: list) -> dict:
    """
    Aplica extraer_caracteristicas_url a una lista de URLs (útil cuando se
    analiza el cuerpo de un correo que contiene varios enlaces) y devuelve
    un resumen agregado con el score más alto encontrado.
    """
    resultados = [extraer_caracteristicas_url(u) for u in urls]
    score_maximo = max((r["score_url"] for r in resultados), default=0)
    return {
        "detalle_por_url": resultados,
        "score_maximo": score_maximo,
    }


# ============================================================================
# NUEVO — UTILIDADES DE DOMINIO Y PROTECCIÓN SSRF
# ============================================================================

# Sufijos de segundo nivel frecuentes (aproximación sin depender de tldextract)
SLD_COMPUESTOS = {
    "com.pe", "org.pe", "gob.pe", "edu.pe", "net.pe", "nom.pe", "com.ar", "com.br",
    "com.mx", "com.co", "com.ec", "com.bo", "com.cl", "com.uy", "com.py", "com.ve",
    "com.pa", "com.gt", "com.do", "com.es", "co.uk", "org.uk", "com.au", "co.jp",
    "co.in", "gob.mx", "gob.ar", "gob.cl", "gov.co",
}


def _hostname_ascii(hostname: str) -> str:
    """Convierte un hostname Unicode a su forma ASCII (punycode). Si falla, devuelve el original."""
    try:
        return hostname.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return hostname


def _hostname_unicode(hostname: str) -> str:
    """Decodifica punycode (xn--...) a Unicode para poder analizar homóglifos."""
    try:
        return hostname.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return hostname


def dominio_registrable(hostname: str) -> str:
    """'login.g00gle.com.pe' -> 'g00gle.com.pe' (aproximación con lista de SLD compuestos)."""
    partes = [p for p in hostname.lower().strip(".").split(".") if p]
    if len(partes) <= 2:
        return ".".join(partes)
    if ".".join(partes[-2:]) in SLD_COMPUESTOS:
        return ".".join(partes[-3:])
    return ".".join(partes[-2:])


def _es_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _resolver_publico(hostname: str):
    """
    Protección SSRF. Devuelve (ips_publicas, motivo_error).
    Solo devuelve IPs si TODAS las direcciones resueltas son globales; así evitamos que
    un atacante use PhishGuard para consultar localhost, 169.254.169.254 (metadatos cloud)
    o la red interna. Limitación conocida: DNS rebinding entre esta comprobación y la
    conexión real de `requests` (el chequeo SSL sí fija la IP validada).
    """
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return [], "no_resuelve"
    except UnicodeError:
        return [], "hostname_invalido"

    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            return [], "ip_no_publica"
        ips.append(str(ip))
    return (ips, None) if ips else ([], "no_resuelve")


# ============================================================================
# NUEVO — DESACORTADOR DE URLs (HEAD + redirecciones controladas)
# ============================================================================

ACORTADORES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "lnkd.in", "s.id", "bit.do",
    "v.gd", "shorte.st", "adf.ly", "bl.ink", "qrco.de", "ln.run",
}


def es_acortador(hostname: str) -> bool:
    return dominio_registrable(hostname or "") in ACORTADORES


def desacortar_url(url: str, max_saltos: int = None) -> dict:
    """
    Sigue manualmente las redirecciones con HEAD (sin descargar cuerpos) y devuelve la
    URL final. Cada salto se valida contra SSRF ANTES de contactarlo. Si el servidor no
    acepta HEAD (403/405/501) reintenta ese salto con GET en streaming y cierra sin leer.
    """
    max_saltos = max_saltos or MAX_REDIRECCIONES
    actual = _normalizar_url(url.strip())
    resultado = {"url_original": url, "url_final": actual, "cadena": [actual],
                 "saltos": 0, "error": None}

    sesion = requests.Session()
    sesion.headers["User-Agent"] = USER_AGENT
    try:
        for _ in range(max_saltos):
            host = urlparse(actual).hostname or ""
            _, motivo = _resolver_publico(host)
            if motivo:
                resultado["error"] = {
                    "no_resuelve": "El dominio no resuelve (posiblemente inexistente o dado de baja).",
                    "ip_no_publica": "El destino apunta a una red privada/local; no se consulta.",
                }.get(motivo, "Destino no válido.")
                break

            resp = sesion.head(actual, allow_redirects=False, timeout=TIMEOUT_RED)
            if resp.status_code in (403, 405, 501):
                resp.close()
                resp = sesion.get(actual, allow_redirects=False, stream=True, timeout=TIMEOUT_RED)
            resp.close()

            destino = resp.headers.get("Location")
            if resp.status_code in (301, 302, 303, 307, 308) and destino:
                siguiente = urljoin(actual, destino)
                if urlparse(siguiente).scheme not in ("http", "https"):
                    resultado["error"] = "Redirección a un esquema no HTTP(S)."
                    break
                resultado["cadena"].append(siguiente)
                actual = siguiente
                continue
            break                                   # respuesta final (no redirige)
        else:
            resultado["error"] = f"Se superó el máximo de {max_saltos} redirecciones."
    except requests.RequestException as e:
        logger.warning("Desacortador: fallo consultando %s: %s", actual, e)
        resultado["error"] = f"No se pudo seguir la redirección: {type(e).__name__}"
    except Exception:
        logger.exception("Desacortador: error inesperado con %s", url)
        resultado["error"] = "Error inesperado al desacortar la URL."
    finally:
        sesion.close()

    resultado["url_final"] = resultado["cadena"][-1]
    resultado["saltos"] = len(resultado["cadena"]) - 1
    return resultado


# ============================================================================
# NUEVO — WHOIS: ANTIGÜEDAD DEL DOMINIO
# ============================================================================

def _a_datetime_utc(valor):
    """Normaliza los formatos heterogéneos de python-whois (datetime, str, lista) a datetime UTC."""
    if isinstance(valor, (list, tuple)):
        candidatos = [d for d in (_a_datetime_utc(v) for v in valor) if d]
        return min(candidatos) if candidatos else None
    if isinstance(valor, datetime):
        return valor if valor.tzinfo else valor.replace(tzinfo=timezone.utc)
    if isinstance(valor, str):
        try:
            d = datetime.fromisoformat(valor.replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _whois_python(dominio: str):
    import whois                                    # pip install python-whois
    w = whois.whois(dominio)
    registrador = w.registrar
    if isinstance(registrador, (list, tuple)):
        registrador = registrador[0] if registrador else None
    return _a_datetime_utc(w.creation_date), registrador


def _whois_rdap(dominio: str):
    """Respaldo sin dependencias extra: RDAP (sucesor JSON de WHOIS) vía rdap.org."""
    r = requests.get(f"https://rdap.org/domain/{dominio}", timeout=TIMEOUT_RED,
                     headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    for ev in r.json().get("events", []):
        if ev.get("eventAction") == "registration":
            return _a_datetime_utc(ev.get("eventDate")), None
    return None, None


def consultar_whois(hostname: str) -> dict:
    """Devuelve edad del dominio en días. Nunca lanza excepciones."""
    dominio = _hostname_ascii(dominio_registrable(hostname))
    res = {"dominio": dominio, "disponible": False, "fecha_creacion": None,
           "edad_dias": None, "registrador": None, "fuente": None, "error": None}

    en_cache = _cache_whois.get(dominio)
    if en_cache:
        return en_cache

    creacion, registrador = None, None
    for nombre, fn in (("whois", _whois_python), ("rdap", _whois_rdap)):
        try:
            creacion, registrador = fn(dominio)
            res["fuente"] = nombre
            if creacion:
                break
        except ImportError:
            logger.warning("python-whois no instalado; se usa RDAP como respaldo.")
            res["error"] = "python-whois no instalado"
        except Exception as e:                      # timeouts, dominio sin registro, TLD sin WHOIS
            logger.info("%s falló para %s: %s", nombre, dominio, e)
            res["error"] = f"{nombre}: {type(e).__name__}"

    if creacion:
        res.update(disponible=True, error=None, registrador=registrador,
                   fecha_creacion=creacion.date().isoformat(),
                   edad_dias=max((datetime.now(timezone.utc) - creacion).days, 0))
        _cache_whois.set(dominio, res)              # solo cacheamos éxitos
    return res


# ============================================================================
# NUEVO — CERTIFICADO SSL/TLS
# ============================================================================

def verificar_ssl(hostname: str, puerto: int = 443) -> dict:
    """Valida el certificado (cadena + hostname), y extrae emisor y vencimiento."""
    host = _hostname_ascii(hostname)
    res = {"host": host, "disponible": False, "valido": None, "emisor": None,
           "sujeto": None, "vence": None, "dias_restantes": None, "error": None}

    en_cache = _cache_ssl.get(host)
    if en_cache:
        return en_cache

    if _es_ip(host):
        res["error"] = "El destino es una IP; no se valida el certificado por nombre."
        return res

    ips, motivo = _resolver_publico(host)
    if motivo:
        res["error"] = "El dominio no resuelve." if motivo == "no_resuelve" else "Destino no público."
        return res

    ctx = ssl.create_default_context()              # verifica cadena y hostname
    try:
        # Conectamos a la IP ya validada (evita rebinding) pero verificando contra el hostname
        with socket.create_connection((ips[0], puerto), timeout=TIMEOUT_RED) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        emisor = dict(x[0] for x in cert.get("issuer", ()))
        sujeto = dict(x[0] for x in cert.get("subject", ()))
        expira = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        res.update(disponible=True, valido=True,
                   emisor=emisor.get("organizationName") or emisor.get("commonName"),
                   sujeto=sujeto.get("commonName"),
                   vence=expira.date().isoformat(),
                   dias_restantes=(expira - datetime.now(timezone.utc)).days)
    except ssl.SSLCertVerificationError as e:       # caducado, autofirmado, hostname distinto...
        res.update(disponible=True, valido=False, error=e.verify_message or str(e))
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError) as e:
        res["error"] = f"Sin HTTPS/TLS accesible ({type(e).__name__})"
    except Exception:
        logger.exception("Error inesperado verificando SSL de %s", host)
        res["error"] = "Error inesperado verificando el certificado."

    if res["disponible"] or res["error"]:
        _cache_ssl.set(host, res)
    return res


# ============================================================================
# NUEVO — TYPOSQUATTING Y HOMÓGLIFOS
# ============================================================================

# marca -> dominios registrables legítimos (ampliar según tu público objetivo)
MARCAS = {
    "google": {"google.com", "google.com.pe", "googleusercontent.com", "gstatic.com", "goo.gl",
               "youtube.com", "gmail.com", "googleapis.com", "g.co"},
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "office365.com",
                  "microsoftonline.com", "windows.com", "azure.com", "bing.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.es", "amazon.com.mx", "amazon.co.uk", "amazon.de", "amazonaws.com"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "messenger.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "dropbox": {"dropbox.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "mercadolibre": {"mercadolibre.com", "mercadolibre.com.pe", "mercadolibre.com.ar",
                     "mercadolibre.com.mx", "mercadopago.com"},
    "bbva": {"bbva.com", "bbva.pe", "bbva.es", "bbva.mx", "bbva.com.ar", "bbva.com.co"},
    "santander": {"santander.com", "santander.es", "santander.com.mx"},
    "interbank": {"interbank.pe"},
    "scotiabank": {"scotiabank.com", "scotiabank.com.pe"},
    "bcp": {"viabcp.com", "bcp.com.pe", "credicorpbank.com"},
    "yape": {"yape.com.pe"},
    "sunat": {"sunat.gob.pe"},
    "reniec": {"reniec.gob.pe"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
}
_DOMINIOS_LEGITIMOS = set().union(*MARCAS.values())

# Palabras "señuelo" que los atacantes concatenan a una marca (paypalsecure.com, googlelogin.net)
PALABRAS_ENGANO = ("login", "secure", "verify", "verif", "support", "account", "update", "help",
                   "seguro", "seguridad", "soporte", "ayuda", "bono", "premio", "promo", "cuenta",
                   "banco", "online", "pago", "cliente", "actualiza", "acceso", "billing", "wallet")

# Caracteres Unicode visualmente idénticos a letras latinas (Cirílico, Griego, Latin extendido)
HOMOGLIFOS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "υ": "u", "ϲ": "c",
    "ɡ": "g", "ı": "i", "ɑ": "a", "ⅼ": "l", "ǀ": "l",
}
# Sustituciones "leet" típicas (0->o, 3->e, ...). El '1' es ambiguo (i o l): se prueban ambas.
LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a", "!": "i", "|": "l"})


def _esqueleto(etiqueta: str) -> set:
    """
    Reduce una etiqueta de dominio a sus formas 'canónicas' comparables con una marca:
    NFKC -> homóglifos -> sin diacríticos -> leet -> 'rn'->'m', 'vv'->'w'.
    Devuelve un conjunto porque '1' puede ser 'l' o 'i'.
    """
    s = unicodedata.normalize("NFKC", etiqueta.lower())
    s = "".join(HOMOGLIFOS.get(c, c) for c in s)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    s = s.translate(LEET)
    variantes = {s.replace("1", "l"), s.replace("1", "i")}
    return {v.replace("rn", "m").replace("vv", "w") for v in variantes} | variantes


def _distancia_osa(a: str, b: str) -> int:
    """Distancia de edición con transposiciones (Damerau-Levenshtein restringida)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            costo = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + costo)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _scripts_de(etiqueta: str) -> set:
    scripts = set()
    for c in etiqueta:
        if c.isalpha():
            try:
                scripts.add(unicodedata.name(c).split()[0])   # LATIN, CYRILLIC, GREEK...
            except ValueError:
                scripts.add("DESCONOCIDO")
    return scripts


def detectar_typosquatting(hostname: str) -> dict:
    """
    Detecta suplantación de marcas por: sustitución de caracteres (g00gle), homóglifos
    Unicode/IDN (gооgle con 'о' cirílica), errores de tipeo a 1 edición (paypall, googel),
    marca incrustada en un dominio no oficial (paypal-secure-login.com) o marca usada como
    subdominio (paypal.com.evil.xyz).
    """
    res = {"sospechoso": False, "es_idn": False, "mezcla_scripts": False,
           "hallazgos": [], "puntos": 0}
    if not hostname or _es_ip(hostname):
        return res
    try:
        host = _hostname_unicode(hostname.lower().strip("."))
        host_ascii = _hostname_ascii(host)
        registrable = dominio_registrable(host)
        etiqueta = registrable.split(".")[0]
        subdominios = host[: -len(registrable)].strip(".")

        res["es_idn"] = host_ascii.startswith("xn--") or ".xn--" in host_ascii or host != host_ascii
        res["mezcla_scripts"] = any(len(_scripts_de(p)) > 1 for p in host.split("."))
        puntos, hallazgos = 0, []

        if res["mezcla_scripts"]:
            puntos = max(puntos, 30)
            hallazgos.append("El dominio mezcla alfabetos distintos (p. ej. latino + cirílico): técnica típica de homóglifos.")
        elif res["es_idn"]:
            puntos = max(puntos, 15)
            hallazgos.append("Dominio internacionalizado (IDN/punycode): verifica que no imite a otro.")

        if registrable in _DOMINIOS_LEGITIMOS or _hostname_ascii(registrable) in _DOMINIOS_LEGITIMOS:
            res.update(sospechoso=bool(hallazgos), hallazgos=hallazgos, puntos=puntos)
            return res

        esq = _esqueleto(etiqueta)
        # Tokens del dominio (separados por guiones/dígitos) en su forma cruda y "normalizada"
        tokens = {t for v in esq | {etiqueta} for t in re.split(r"[-_.\d]+", v) if t}
        mejor = None                                     # (puntos, mensaje)

        def candidato(p, msg):
            nonlocal mejor
            if mejor is None or p > mejor[0]:
                mejor = (p, msg)

        for marca in MARCAS:
            if etiqueta == marca:
                candidato(25, f"Usa el nombre de la marca «{marca}» en un dominio que no es el oficial ({registrable}).")
            elif marca in esq:
                candidato(40, f"Sustitución de caracteres/homóglifos: «{etiqueta}» imita a «{marca}».")
            elif len(marca) >= 5 and any(_distancia_osa(v, marca) == 1 for v in esq if abs(len(v) - len(marca)) <= 1):
                candidato(30, f"Posible typosquatting: «{etiqueta}» difiere en un solo carácter de «{marca}».")
            elif marca in tokens or any(
                    marca in v and any(k in v.replace(marca, "") for k in PALABRAS_ENGANO) for v in esq):
                # 'bcp-seguro', 'paypalsecure', 'micr0soft-support': marca + señuelo (o con leet)
                con_leet = marca not in etiqueta
                candidato(35 if con_leet else 25,
                          f"El dominio incluye la marca «{marca}»{' (con sustitución de caracteres)' if con_leet else ''}"
                          f" pero no es el sitio oficial ({registrable}).")
            elif subdominios and any(marca == s or (len(marca) >= 5 and marca in s) for s in subdominios.split(".")):
                candidato(30, f"La marca «{marca}» aparece como subdominio de un dominio ajeno ({registrable}).")

        if mejor:
            puntos = max(puntos, mejor[0]) + (10 if res["es_idn"] else 0)
            hallazgos.append(mejor[1])

        res.update(sospechoso=bool(hallazgos), hallazgos=hallazgos, puntos=min(puntos, 50))
    except Exception:
        logger.exception("Error en detectar_typosquatting(%s)", hostname)
    return res


# ============================================================================
# NUEVO — ORQUESTADOR: ANÁLISIS COMPLETO DE UNA URL
# ============================================================================

def _puntos_whois(w: dict):
    edad = w.get("edad_dias")
    if edad is None:
        return 0, None
    if edad < 30:
        return 30, f"Dominio registrado hace solo {edad} días: los sitios de phishing suelen ser muy recientes."
    if edad < 90:
        return 20, f"Dominio joven: registrado hace {edad} días."
    if edad < 365:
        return 8, f"Dominio con menos de un año de antigüedad ({edad} días)."
    return 0, None


def _puntos_ssl(s: dict):
    if s.get("valido") is False:
        return 25, f"Certificado SSL/TLS NO válido: {s.get('error') or 'error de verificación'}."
    if s.get("valido") and s.get("dias_restantes") is not None and s["dias_restantes"] < 7:
        return 5, f"El certificado vence en {s['dias_restantes']} días."
    if not s.get("disponible") and s.get("error") and "IP" not in s["error"] and "no resuelve" not in s["error"]:
        return 5, "El sitio no ofrece HTTPS/TLS accesible."
    return 0, None


def analizar_url_completa(url: str, chequeos_red: bool = None) -> dict:
    """
    Combina las features estructurales existentes con: desacortador, typosquatting,
    WHOIS y SSL. Devuelve score 0-100 e 'indicadores' [{tipo, texto, puntos}].
    Cada módulo falla de forma aislada: un error de red nunca rompe el análisis.
    """
    chequeos_red = CHEQUEOS_RED_ACTIVOS if chequeos_red is None else chequeos_red
    base = extraer_caracteristicas_url(url)
    host_orig = urlparse(base["url_normalizada"]).hostname or ""

    salida = {"url": url, "url_final": base["url_normalizada"], "caracteristicas": base,
              "acortador": None, "typosquatting": None, "whois": None, "ssl": None,
              "chequeos_red": chequeos_red, "indicadores": [], "score": 0}
    indicadores = [{"tipo": "estructura", "texto": h, "puntos": 0} for h in base["hallazgos_url"]]
    extra = 0
    host_destino, score_estructural = host_orig, base["score_url"]

    try:
        # 1) Desacortar (solo acortadores conocidos, salvo UNSHORTEN_ALL=true)
        if chequeos_red and (DESACORTAR_TODAS or es_acortador(host_orig)):
            d = desacortar_url(base["url_normalizada"])
            salida["acortador"] = d
            if es_acortador(host_orig):
                extra += 5
                indicadores.append({"tipo": "acortador", "puntos": 5,
                                    "texto": "La URL usa un acortador que oculta el destino real."})
            if d["url_final"] != base["url_normalizada"]:
                final = extraer_caracteristicas_url(d["url_final"])
                salida["url_final"] = d["url_final"]
                salida["caracteristicas_final"] = final
                host_destino = urlparse(final["url_normalizada"]).hostname or host_orig
                score_estructural = max(score_estructural, final["score_url"])
                indicadores.append({"tipo": "acortador", "puntos": 0,
                                    "texto": f"Destino final tras {d['saltos']} redirección(es): {d['url_final']}"})
                indicadores += [{"tipo": "estructura", "texto": f"[Destino] {h}", "puntos": 0}
                                for h in final["hallazgos_url"]]
            if d.get("error"):
                indicadores.append({"tipo": "acortador", "puntos": 0, "texto": d["error"]})

        # 2) Typosquatting sobre el host inicial y el final
        typo = detectar_typosquatting(host_destino)
        if host_destino != host_orig:
            otro = detectar_typosquatting(host_orig)
            typo = typo if typo["puntos"] >= otro["puntos"] else otro
        salida["typosquatting"] = typo
        extra += typo["puntos"]
        indicadores += [{"tipo": "typosquatting", "texto": h, "puntos": typo["puntos"]} for h in typo["hallazgos"]]

        # 3) WHOIS + SSL en paralelo (con timeout global)
        if chequeos_red and host_destino and not _es_ip(host_destino):
            f_w = _EXECUTOR.submit(consultar_whois, host_destino)
            f_s = _EXECUTOR.submit(verificar_ssl, host_destino)
            for clave, fut, fn_puntos in (("whois", f_w, _puntos_whois), ("ssl", f_s, _puntos_ssl)):
                try:
                    salida[clave] = fut.result(timeout=TIMEOUT_RED * 3)
                    p, texto = fn_puntos(salida[clave])
                    if texto:
                        extra += p
                        indicadores.append({"tipo": clave, "texto": texto, "puntos": p})
                except concurrent.futures.TimeoutError:
                    logger.warning("Timeout en %s para %s", clave, host_destino)
                    salida[clave] = {"disponible": False, "error": "Tiempo de espera agotado"}
                except Exception:
                    logger.exception("Fallo en %s para %s", clave, host_destino)
                    salida[clave] = {"disponible": False, "error": "Error interno"}
    except Exception:
        logger.exception("Error analizando la URL %s", url)

    salida["indicadores"] = indicadores
    salida["score"] = min(score_estructural + extra, 100)
    return salida


def analizar_urls(urls: list, chequeos_red: bool = None) -> list:
    """Analiza hasta MAX_URLS_ANALISIS URLs en paralelo. Devuelve una lista de resultados."""
    urls = list(dict.fromkeys(urls))[:MAX_URLS_ANALISIS]      # sin duplicados, con tope
    futuros = [_EXECUTOR_URLS.submit(analizar_url_completa, u, chequeos_red) for u in urls]
    resultados = []
    for u, f in zip(urls, futuros):
        try:
            resultados.append(f.result(timeout=TIMEOUT_RED * 6))
        except Exception:
            logger.exception("No se pudo analizar la URL %s", u)
    return resultados
