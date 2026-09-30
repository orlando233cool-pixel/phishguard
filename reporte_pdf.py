"""
reporte_pdf.py
--------------
Genera el reporte PDF de un análisis de PhishGuard con reportlab (pip install reportlab).

generar_reporte_pdf(datos: dict) -> bytes
`datos` es el resultado guardado por app.py (puntuación, análisis local, URLs, IA, tokens).
"""

import io
import logging
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

logger = logging.getLogger(__name__)

COLORES_NIVEL = {"BAJO": "#16a34a", "MEDIO": "#d97706", "ALTO": "#dc2626"}
ETIQUETAS_CATEGORIA = {
    "urgencia": "Urgencia", "amenaza": "Amenaza", "credenciales": "Credenciales",
    "verificacion": "Verificación", "accion": "Llamado a la acción", "premio": "Premios/ofertas",
    "financiero": "Contexto financiero", "adjunto": "Adjuntos peligrosos",
    "ofuscacion": "Ofuscación", "dominio": "Dominio/URL", "ia": "Detectado por la IA",
}


def _t(valor) -> str:
    """
    Texto seguro para un Paragraph: escapa el marcado XML (evita inyección en el PDF) y
    muestra los caracteres fuera de Latin-1 como \\uXXXX. Así los homóglifos de una URL
    (p. ej. la 'о' cirílica) se ven explícitamente en el reporte en lugar de aparecer
    como un cuadro vacío o pasar desapercibidos.
    """
    s = "" if valor is None else str(valor)
    s = s.encode("latin-1", "backslashreplace").decode("latin-1")
    return escape(s)


def _pie_de_pagina(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(2 * cm, 1.2 * cm, "PhishGuard - Reporte automático. No sustituye el criterio de un especialista.")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Página {doc.page}")
    canvas.restoreState()


def _tabla(filas, anchos, cabecera=True, extra=None):
    t = Table(filas, colWidths=anchos, repeatRows=1 if cabecera else 0)
    estilo = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if cabecera:
        estilo += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                   ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(estilo + (extra or [])))
    return t


def generar_reporte_pdf(datos: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=1.8 * cm, bottomMargin=2 * cm,
                            title="Reporte PhishGuard", author="PhishGuard")

    base = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=base["Title"], fontSize=20, textColor=colors.HexColor("#0f172a"), spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=base["Heading2"], fontSize=12.5, textColor=colors.HexColor("#1d4ed8"),
                        spaceBefore=14, spaceAfter=6)
    normal = ParagraphStyle("n", parent=base["BodyText"], fontSize=9.5, leading=13)
    chico = ParagraphStyle("c", parent=normal, fontSize=8.5, leading=11)
    mono = ParagraphStyle("m", parent=normal, fontName="Courier", fontSize=8.5, leading=11,
                          backColor=colors.HexColor("#f1f5f9"), borderPadding=6)
    hd = ParagraphStyle("hd", parent=chico, textColor=colors.white, fontName="Helvetica-Bold")
    centro = ParagraphStyle("ce", parent=normal, alignment=TA_CENTER, textColor=colors.white,
                            fontSize=13, leading=17, fontName="Helvetica-Bold")

    P = lambda txt, st=normal: Paragraph(txt, st)          # noqa: E731  (txt ya escapado)

    punt = datos.get("puntuacion", {})
    nivel = punt.get("nivel", "MEDIO")
    color = colors.HexColor(COLORES_NIVEL.get(nivel, "#d97706"))
    ia = datos.get("analisis_ia", {})
    local = datos.get("analisis_local", {})
    urls = datos.get("analisis_urls", [])
    tokens = datos.get("tokens_detectados", [])

    try:
        fecha = datetime.fromisoformat(datos.get("fecha", "")).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        fecha = "N/D"

    H = []   # historia (flowables)
    H += [P("PhishGuard", h1), P("Reporte detallado de análisis de amenazas", chico), Spacer(1, 8)]

    # ---- 1. Resumen ----
    badge = Table([[P(f"RIESGO {_t(nivel)} — {int(punt.get('valor', 0))}/100", centro)]], colWidths=[17 * cm])
    badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color),
                               ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
    H += [badge, Spacer(1, 8)]

    comp = punt.get("componentes", {})
    filas = [
        [P("<b>Fecha</b>", chico), P(_t(fecha), chico), P("<b>Tipo de análisis</b>", chico), P(_t(datos.get("tipo")), chico)],
        [P("<b>Fuente del puntaje</b>", chico), P(_t(punt.get("fuente")), chico),
         P("<b>ID</b>", chico), P(_t(datos.get("id_analisis")), chico)],
        [P("<b>Heurística</b>", chico), P(f"{comp.get('heuristica', 0)}/100 (léxico {comp.get('lexico', 0)} + URLs {comp.get('urls', 0)})", chico),
         P("<b>Puntaje IA</b>", chico), P("N/D" if comp.get("ia") is None else f"{comp['ia']}/100", chico)],
    ]
    H.append(_tabla(filas, [3.2 * cm, 6 * cm, 3.2 * cm, 4.6 * cm], cabecera=False))

    # ---- 2. Contenido ----
    H.append(P("1. Contenido analizado (versión anonimizada)", h2))
    H.append(P(_t(datos.get("contenido_muestra", "")).replace("\n", "<br/>") or "(vacío)", mono))
    dlp = datos.get("privacidad", {}).get("datos_enmascarados", {})
    if dlp:
        H.append(Spacer(1, 4))
        H.append(P("Datos personales enmascarados antes de consultar a la IA: "
                   + _t(", ".join(f"{k}: {v}" for k, v in dlp.items())), chico))

    # ---- 3. Indicadores de URL ----
    H.append(P("2. Indicadores de URL e infraestructura", h2))
    if not urls:
        H.append(P("No se encontraron URLs en el contenido.", normal))
    for i, u in enumerate(urls, 1):
        who, ssl_ = u.get("whois") or {}, u.get("ssl") or {}
        typo = u.get("typosquatting") or {}
        cab = [
            [P(f"<b>URL {i}</b>", chico), P(_t(u.get("url")), chico)],
            [P("<b>Destino final</b>", chico), P(_t(u.get("url_final")), chico)],
            [P("<b>Puntaje de la URL</b>", chico), P(f"{u.get('score', 0)}/100", chico)],
            [P("<b>Antigüedad (WHOIS)</b>", chico),
             P(_t(f"{who['edad_dias']} días (creado {who['fecha_creacion']})") if who.get("edad_dias") is not None
               else "No disponible" + (f" — {_t(who.get('error'))}" if who.get("error") else ""), chico)],
            [P("<b>Certificado SSL/TLS</b>", chico),
             P(_t(f"Válido — emisor: {ssl_.get('emisor')} — vence: {ssl_.get('vence')} ({ssl_.get('dias_restantes')} días)")
               if ssl_.get("valido") else "NO válido: " + _t(ssl_.get("error")) if ssl_.get("valido") is False
               else "No disponible" + (f" — {_t(ssl_.get('error'))}" if ssl_.get("error") else ""), chico)],
            [P("<b>Typosquatting / homóglifos</b>", chico),
             P(_t(" ".join(typo.get("hallazgos", []))) or "Sin señales", chico)],
        ]
        bloque = [_tabla(cab, [4.2 * cm, 12.8 * cm], cabecera=False)]
        inds = u.get("indicadores", [])
        if inds:
            filas_i = [[P("Tipo", hd), P("Hallazgo", hd), P("Pts", hd)]]
            for ind in inds:
                filas_i.append([P(_t(ind.get("tipo")), chico), P(_t(ind.get("texto")), chico),
                                P(str(ind.get("puntos", 0)), chico)])
            t_i = _tabla(filas_i, [2.6 * cm, 13 * cm, 1.4 * cm])
            bloque += [Spacer(1, 3), t_i]
        H.append(KeepTogether(bloque + [Spacer(1, 8)]))

    # ---- 4. Análisis léxico ----
    H.append(P("3. Análisis léxico (palabras y patrones detectados)", h2))
    if tokens:
        agrupados = {}
        for t in tokens:
            agrupados.setdefault(t.get("categoria", "otro"), []).append(t.get("texto", ""))
        filas_t = [[P("Categoría", hd), P("Cant.", hd), P("Fragmentos", hd)]]
        for cat, lista in sorted(agrupados.items(), key=lambda kv: -len(kv[1])):
            filas_t.append([P(_t(ETIQUETAS_CATEGORIA.get(cat, cat)), chico), P(str(len(lista)), chico),
                            P(_t(", ".join(dict.fromkeys(x.lower() for x in lista))[:300]), chico)])
        t_t = _tabla(filas_t, [4.2 * cm, 1.4 * cm, 11.4 * cm])
        H.append(t_t)
    else:
        H.append(P("No se detectaron palabras o patrones sospechosos.", normal))
    if local.get("hallazgos"):
        H.append(Spacer(1, 6))
        for h in local["hallazgos"]:
            H.append(P("• " + _t(h), chico))

    # ---- 5. IA ----
    H.append(P("4. Explicación de la IA", h2))
    veredicto = "Posible phishing" if ia.get("es_phishing") else "Sin señales concluyentes de phishing"
    H.append(P(f"<b>Veredicto:</b> {_t(veredicto)} — <b>Nivel:</b> {_t(ia.get('nivel_riesgo'))}"
               + (f" — <b>Modelo:</b> {_t(ia.get('modelo_usado'))}" if ia.get("modelo_usado") else ""), normal))
    H.append(Spacer(1, 3))
    H.append(P(_t(ia.get("motivo", "Sin explicación disponible.")), normal))
    if ia.get("frases_sospechosas"):
        H.append(Spacer(1, 4))
        H.append(P("<b>Frases señaladas:</b> " + _t(" | ".join(ia["frases_sospechosas"])), chico))

    # ---- 6. Recomendaciones ----
    H.append(P("5. Recomendaciones", h2))
    recs = {
        "ALTO": ["No hagas clic en enlaces ni abras adjuntos.", "No entregues contraseñas, códigos ni datos bancarios.",
                 "Reporta el mensaje a tu equipo de seguridad o al proveedor suplantado y elimínalo."],
        "MEDIO": ["Verifica al remitente por un canal oficial distinto al del mensaje.",
                  "Escribe tú mismo la dirección del sitio en el navegador en lugar de usar el enlace."],
        "BAJO": ["No se detectaron señales relevantes, pero mantén la precaución habitual."],
    }
    for r in recs.get(nivel, recs["MEDIO"]):
        H.append(P("• " + _t(r), normal))

    doc.build(H, onFirstPage=_pie_de_pagina, onLaterPages=_pie_de_pagina)
    return buf.getvalue()
