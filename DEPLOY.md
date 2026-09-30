# Desplegar PhishGuard en Vercel

1. Sube esta carpeta a un repositorio de GitHub (el `.gitignore` ya excluye `.env`).
2. En https://vercel.com/new importa el repositorio (Framework: Flask u Other).
3. En Environment Variables agrega:
   - GEMINI_API_KEY = tu clave de Gemini
   - SECRET_KEY     = python -c "import secrets; print(secrets.token_hex(32))"
4. Pulsa Deploy y abre la URL que te da Vercel.

Prueba local:
    python -m venv .venv && source .venv/bin/activate   (Windows: .venv\Scripts\activate)
    pip install -r requirements.txt
    copia .env.example a .env y complétalo
    python app.py   ->  http://127.0.0.1:5000
