from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from datetime import datetime
import os
import httpx

app = FastAPI()

LOG_FILE = "ip_logs.txt"

# Asegura que el archivo exista desde el arranque
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("Fecha y hora | IP | País | Ciudad | ISP\n")

@app.get("/")
def root():
    return RedirectResponse("/track")

@app.get("/track")
async def track(request: Request):
    # Intenta obtener la IP real del visitante (encabezado o conexión directa)
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.client.host

    # Consulta información geográfica (opcional)
    info = {"country": "Desconocido", "city": "Desconocido", "isp": "Desconocido"}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"http://ip-api.com/json/{ip}")
            data = r.json()
            if data["status"] == "success":
                info["country"] = data["country"]
                info["city"] = data["city"]
                info["isp"] = data["isp"]
    except Exception:
        pass  # En caso de error, deja info como "Desconocido"

    # Guarda la información en el archivo
    timestamp = datetime.now().isoformat()
    log_line = f"{timestamp} | IP: {ip} | Country: {info['country']} | City: {info['city']} | ISP: {info['isp']}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

    # Redirige al usuario a otro sitio
    return RedirectResponse("https://www.google.com")
