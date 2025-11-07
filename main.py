# ═══════════════════════════════════════════════════════════════════
# GEOTRACKER PRO V3 - SISTEMA COMPLETO DE RASTREO GEOGRÁFICO
# Con autenticación, geofencing, historial y actualización periódica
# ═══════════════════════════════════════════════════════════════════

from fastapi import FastAPI, Request, HTTPException, Query, Path, Depends, status, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from datetime import datetime, timedelta
import httpx
import json
import os
from typing import Optional, List, Dict, Any
import asyncio
from pydantic import BaseModel, Field, validator
import sqlite3
from contextlib import asynccontextmanager
import secrets
import hashlib
from math import radians, cos, sin, asin, sqrt

# ═══════════════════════════════════════════════════════════════════
# MODELOS PYDANTIC
# ═══════════════════════════════════════════════════════════════════

class UserRegister(BaseModel):
    """Registro de nuevo usuario"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    email: Optional[str] = None
    phone: Optional[str] = None

class DeviceRegister(BaseModel):
    """Registro de dispositivo por teléfono"""
    phone: str = Field(..., description="Número telefónico (+573001234567)")
    name: str = Field(..., description="Nombre del propietario")
    update_interval: int = Field(600, description="Intervalo de actualización en segundos (default: 10 min)")
    auto_tracking: bool = Field(True, description="Activar rastreo automático")
    custom_url: Optional[str] = Field(None, description="URL personalizada para mostrar (YouTube, web, etc)")
    
    @validator('phone')
    def validate_phone(cls, v):
        phone = ''.join(filter(str.isdigit, v))
        if len(phone) < 10:
            raise ValueError('Número telefónico inválido')
        return f"+{phone}" if not v.startswith('+') else v
    
    @validator('custom_url')
    def validate_url(cls, v):
        if v and not v.startswith(('http://', 'https://')):
            raise ValueError('URL debe empezar con http:// o https://')
        return v

class LocationUpdate(BaseModel):
    """Actualización de ubicación"""
    phone: str
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    accuracy: Optional[float] = None
    altitude: Optional[float] = None
    speed: Optional[float] = None
    heading: Optional[float] = None
    battery_level: Optional[float] = None

class GeofenceZone(BaseModel):
    """Zona de geofencing"""
    name: str
    phone: str
    latitude: float
    longitude: float
    radius_meters: float = Field(..., gt=0, description="Radio en metros")
    alert_on_enter: bool = True
    alert_on_exit: bool = True
    active: bool = True

class LocationHistoryQuery(BaseModel):
    """Consulta de historial"""
    phone: str
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    limit: int = Field(100, le=1000)

# ═══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════

DATABASE = "tracker.db"
BASE_URL = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:10000")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# Seguridad HTTP Basic
security = HTTPBasic()

# ═══════════════════════════════════════════════════════════════════
# BASE DE DATOS MEJORADA
# ═══════════════════════════════════════════════════════════════════
def upgrade_db_for_custom_urls():
    """Agregar columna custom_url a la tabla devices"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    try:
        c.execute('ALTER TABLE devices ADD COLUMN custom_url TEXT')
        conn.commit()
        print("✅ Base de datos actualizada con custom_url")
    except sqlite3.OperationalError:
        print("ℹ️ Columna custom_url ya existe")
    finally:
        conn.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Tabla de usuarios (para autenticación)
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    ''')
    
    # Tabla de dispositivos registrados
    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            user_id INTEGER,
            update_interval INTEGER DEFAULT 600,
            auto_tracking BOOLEAN DEFAULT 1,
            last_update TEXT,
            battery_level REAL,
            is_active BOOLEAN DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Tabla de ubicaciones (historial completo)
    c.execute('''
        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            accuracy REAL,
            altitude REAL,
            speed REAL,
            heading REAL,
            battery_level REAL,
            ip_address TEXT,
            country TEXT,
            city TEXT,
            address TEXT,
            method TEXT,
            FOREIGN KEY (device_id) REFERENCES devices (id)
        )
    ''')
    
    # Tabla de zonas de geofencing
    c.execute('''
        CREATE TABLE IF NOT EXISTS geofence_zones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            device_id INTEGER NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            radius_meters REAL NOT NULL,
            alert_on_enter BOOLEAN DEFAULT 1,
            alert_on_exit BOOLEAN DEFAULT 1,
            active BOOLEAN DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices (id)
        )
    ''')
    
    # Tabla de alertas generadas
    c.execute('''
        CREATE TABLE IF NOT EXISTS geofence_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            read BOOLEAN DEFAULT 0,
            FOREIGN KEY (zone_id) REFERENCES geofence_zones (id),
            FOREIGN KEY (device_id) REFERENCES devices (id)
        )
    ''')
    
    # Tabla de tokens de acceso para dispositivos
    c.execute('''
        CREATE TABLE IF NOT EXISTS device_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices (id)
        )
    ''')
    
    # Índices para optimizar consultas
    c.execute('CREATE INDEX IF NOT EXISTS idx_locations_device ON locations(device_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_locations_timestamp ON locations(timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_devices_phone ON devices(phone)')
    
    # Usuario admin por defecto
    c.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
    if c.fetchone()[0] == 0:
        password_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute('''
            INSERT INTO users (username, password_hash, created_at)
            VALUES (?, ?, ?)
        ''', ('admin', password_hash, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()

# ═══════════════════════════════════════════════════════════════════
# FUNCIONES DE AUTENTICACIÓN
# ═══════════════════════════════════════════════════════════════════

def verify_password(username: str, password: str) -> bool:
    """Verificar credenciales de usuario"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    c.execute('SELECT id FROM users WHERE username = ? AND password_hash = ?', 
              (username, password_hash))
    result = c.fetchone()
    
    if result:
        c.execute('UPDATE users SET last_login = ? WHERE username = ?',
                  (datetime.now().isoformat(), username))
        conn.commit()
    
    conn.close()
    return result is not None

def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    """Dependency para verificar autenticación"""
    if not verify_password(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# ═══════════════════════════════════════════════════════════════════
# FUNCIONES DE GEOLOCALIZACIÓN
# ═══════════════════════════════════════════════════════════════════

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calcular distancia en metros entre dos coordenadas"""
    R = 6371000  # Radio de la Tierra en metros
    
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    
    return R * c

async def get_address_from_coords(lat: float, lon: float) -> Dict[str, str]:
    """Obtener dirección desde coordenadas usando Nominatim"""
    try:
        async with httpx.AsyncClient() as client:
            url = f"https://nominatim.openstreetmap.org/reverse"
            params = {
                'lat': lat,
                'lon': lon,
                'format': 'json',
                'zoom': 18
            }
            headers = {'User-Agent': 'GeoTracker/1.0'}
            r = await client.get(url, params=params, headers=headers, timeout=5)
            data = r.json()
            return {
                'address': data.get('display_name', ''),
                'city': data.get('address', {}).get('city', ''),
                'country': data.get('address', {}).get('country', '')
            }
    except:
        return {'address': '', 'city': '', 'country': ''}

async def check_geofencing(device_id: int, lat: float, lon: float):
    """Verificar si la ubicación entra/sale de zonas de geofencing"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Obtener zonas activas para este dispositivo
    c.execute('''
        SELECT id, name, latitude, longitude, radius_meters, alert_on_enter, alert_on_exit
        FROM geofence_zones
        WHERE device_id = ? AND active = 1
    ''', (device_id,))
    
    zones = c.fetchall()
    
    # Obtener última ubicación para comparar
    c.execute('''
        SELECT latitude, longitude FROM locations
        WHERE device_id = ? 
        ORDER BY timestamp DESC LIMIT 1 OFFSET 1
    ''', (device_id,))
    
    prev_location = c.fetchone()
    
    for zone in zones:
        zone_id, name, z_lat, z_lon, radius, alert_enter, alert_exit = zone
        
        # Calcular distancia actual
        current_distance = haversine_distance(lat, lon, z_lat, z_lon)
        is_inside = current_distance <= radius
        
        # Verificar estado anterior si existe
        if prev_location:
            prev_lat, prev_lon = prev_location
            prev_distance = haversine_distance(prev_lat, prev_lon, z_lat, z_lon)
            was_inside = prev_distance <= radius
            
            # Detectar entrada
            if not was_inside and is_inside and alert_enter:
                c.execute('''
                    INSERT INTO geofence_alerts (zone_id, device_id, alert_type, timestamp, latitude, longitude)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (zone_id, device_id, 'ENTER', datetime.now().isoformat(), lat, lon))
                print(f"🚨 ALERTA: Dispositivo {device_id} ENTRÓ a zona '{name}'")
            
            # Detectar salida
            elif was_inside and not is_inside and alert_exit:
                c.execute('''
                    INSERT INTO geofence_alerts (zone_id, device_id, alert_type, timestamp, latitude, longitude)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (zone_id, device_id, 'EXIT', datetime.now().isoformat(), lat, lon))
                print(f"🚨 ALERTA: Dispositivo {device_id} SALIÓ de zona '{name}'")
    
    conn.commit()
    conn.close()

# ═══════════════════════════════════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    upgrade_db_for_custom_urls()
    # Iniciar tarea de actualización periódica
    asyncio.create_task(periodic_location_updater())
    yield

app = FastAPI(
    title="🎯 GeoTracker Pro V3",
    description="""
## Sistema Profesional de Rastreo Geográfico con Autenticación

### 🚀 Nuevas Características V3:
- 🔐 **Autenticación segura** (usuario: admin, contraseña: admin123)
- 📱 **Registro por número telefónico**
- 🔄 **Actualización automática periódica**
- 🗺️ **Visualización en mapa interactivo**
- 🚨 **Alertas de geofencing**
- 📊 **Historial completo de ubicaciones**
- 🔋 **Monitoreo de batería**
- 📍 **Geocodificación inversa** (dirección desde coordenadas)

### 🔒 Seguridad:
Todos los endpoints requieren autenticación HTTP Basic.
    """,
    version="3.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════════════════
# ENDPOINTS - GESTIÓN DE DISPOSITIVOS
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/devices/register")
async def register_device(
    device: DeviceRegister,
    username: str = Depends(get_current_user)
):
    """Registrar un nuevo dispositivo por número telefónico"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user_id = c.fetchone()[0]
    
    try:
        c.execute('''
            INSERT INTO devices (phone, name, user_id, update_interval, auto_tracking, custom_url, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (device.phone, device.name, user_id, device.update_interval, 
              device.auto_tracking, device.custom_url, datetime.now().isoformat()))
        
        device_id = c.lastrowid
        
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(days=365)).isoformat()
        
        c.execute('''
            INSERT INTO device_tokens (device_id, token, expires_at, created_at)
            VALUES (?, ?, ?, ?)
        ''', (device_id, token, expires_at, datetime.now().isoformat()))
        
        conn.commit()
        
        tracking_url = f"{BASE_URL}/track/{token}"
        
        return {
            "success": True,
            "device_id": device_id,
            "phone": device.phone,
            "name": device.name,
            "token": token,
            "tracking_url": tracking_url,
            "custom_url": device.custom_url,
            "update_interval": device.update_interval,
            "instructions": f"Envía este link a {device.name} para activar rastreo automático"
        }
        
    except sqlite3.IntegrityError:
        raise HTTPException(400, f"El teléfono {device.phone} ya está registrado")
    finally:
        conn.close()


@app.get("/api/devices/list")
async def list_devices(username: str = Depends(get_current_user)):
    """Listar todos los dispositivos registrados"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user_id = c.fetchone()[0]
    
    c.execute('''
        SELECT 
            d.id, d.phone, d.name, d.update_interval, d.auto_tracking,
            d.last_update, d.battery_level, d.is_active,
            l.latitude, l.longitude, l.accuracy
        FROM devices d
        LEFT JOIN (
            SELECT device_id, latitude, longitude, accuracy
            FROM locations
            WHERE id IN (
                SELECT MAX(id) FROM locations GROUP BY device_id
            )
        ) l ON d.id = l.device_id
        WHERE d.user_id = ?
        ORDER BY d.created_at DESC
    ''', (user_id,))
    
    devices = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return {"total": len(devices), "devices": devices}

@app.post("/api/devices/{phone}/update-settings")
async def update_device_settings(
    phone: str,
    update_interval: Optional[int] = None,
    auto_tracking: Optional[bool] = None,
    is_active: Optional[bool] = None,
    username: str = Depends(get_current_user)
):
    """Actualizar configuración de un dispositivo"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    updates = []
    params = []
    
    if update_interval is not None:
        updates.append("update_interval = ?")
        params.append(update_interval)
    if auto_tracking is not None:
        updates.append("auto_tracking = ?")
        params.append(auto_tracking)
    if is_active is not None:
        updates.append("is_active = ?")
        params.append(is_active)
    
    if not updates:
        raise HTTPException(400, "No se proporcionaron actualizaciones")
    
    params.append(phone)
    
    c.execute(f'''
        UPDATE devices 
        SET {", ".join(updates)}
        WHERE phone = ?
    ''', params)
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Configuración actualizada"}

# ═══════════════════════════════════════════════════════════════════
# ENDPOINTS - UBICACIONES
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/locations/update")
async def update_location(
    location: LocationUpdate,
    request: Request,
    background_tasks: BackgroundTasks
):
    """Actualizar ubicación de un dispositivo"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Buscar dispositivo
    c.execute('SELECT id FROM devices WHERE phone = ? AND is_active = 1', (location.phone,))
    device = c.fetchone()
    
    if not device:
        conn.close()
        raise HTTPException(404, "Dispositivo no encontrado o inactivo")
    
    device_id = device[0]
    
    # Obtener IP
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.client.host
    
    # Obtener información de dirección (en background)
    address_info = await get_address_from_coords(location.latitude, location.longitude)
    
    # Guardar ubicación
    c.execute('''
        INSERT INTO locations (
            device_id, timestamp, latitude, longitude, accuracy,
            altitude, speed, heading, battery_level, ip_address,
            country, city, address, method
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        device_id, datetime.now().isoformat(),
        location.latitude, location.longitude, location.accuracy,
        location.altitude, location.speed, location.heading,
        location.battery_level, ip,
        address_info.get('country'), address_info.get('city'),
        address_info.get('address'), 'GPS'
    ))
    
    # Actualizar estado del dispositivo
    c.execute('''
        UPDATE devices
        SET last_update = ?, battery_level = ?
        WHERE id = ?
    ''', (datetime.now().isoformat(), location.battery_level, device_id))
    
    conn.commit()
    conn.close()
    
    # Verificar geofencing en background
    background_tasks.add_task(check_geofencing, device_id, location.latitude, location.longitude)
    
    print(f"📍 Ubicación actualizada: {location.phone} -> {location.latitude}, {location.longitude}")
    
    return {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "address": address_info.get('address', 'N/A')
    }

@app.get("/api/locations/current/{phone}")
async def get_current_location(
    phone: str,
    username: str = Depends(get_current_user)
):
    """Obtener ubicación actual de un dispositivo"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('''
        SELECT l.*, d.name, d.battery_level
        FROM locations l
        JOIN devices d ON l.device_id = d.id
        WHERE d.phone = ?
        ORDER BY l.timestamp DESC
        LIMIT 1
    ''', (phone,))
    
    location = c.fetchone()
    conn.close()
    
    if not location:
        raise HTTPException(404, "No se encontró ubicación para este dispositivo")
    
    return dict(location)

@app.post("/api/locations/history")
async def get_location_history(
    query: LocationHistoryQuery,
    username: str = Depends(get_current_user)
):
    """Obtener historial de ubicaciones de un dispositivo"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Buscar device_id
    c.execute('SELECT id FROM devices WHERE phone = ?', (query.phone,))
    device = c.fetchone()
    
    if not device:
        conn.close()
        raise HTTPException(404, "Dispositivo no encontrado")
    
    device_id = device[0]
    
    # Construir query con filtros opcionales
    sql = '''
        SELECT * FROM locations
        WHERE device_id = ?
    '''
    params = [device_id]
    
    if query.start_date:
        sql += ' AND timestamp >= ?'
        params.append(query.start_date)
    
    if query.end_date:
        sql += ' AND timestamp <= ?'
        params.append(query.end_date)
    
    sql += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(query.limit)
    
    c.execute(sql, params)
    locations = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    return {
        "phone": query.phone,
        "total": len(locations),
        "locations": locations
    }

# ═══════════════════════════════════════════════════════════════════
# ENDPOINTS - GEOFENCING
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/geofence/create")
async def create_geofence_zone(
    zone: GeofenceZone,
    username: str = Depends(get_current_user)
):
    """Crear una zona de geofencing"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Buscar dispositivo
    c.execute('SELECT id FROM devices WHERE phone = ?', (zone.phone,))
    device = c.fetchone()
    
    if not device:
        conn.close()
        raise HTTPException(404, "Dispositivo no encontrado")
    
    device_id = device[0]
    
    c.execute('''
        INSERT INTO geofence_zones (
            name, device_id, latitude, longitude, radius_meters,
            alert_on_enter, alert_on_exit, active, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        zone.name, device_id, zone.latitude, zone.longitude, zone.radius_meters,
        zone.alert_on_enter, zone.alert_on_exit, zone.active, datetime.now().isoformat()
    ))
    
    zone_id = c.lastrowid
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "zone_id": zone_id,
        "name": zone.name,
        "message": f"Zona de geofencing '{zone.name}' creada"
    }

@app.get("/api/geofence/list/{phone}")
async def list_geofence_zones(
    phone: str,
    username: str = Depends(get_current_user)
):
    """Listar zonas de geofencing de un dispositivo"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('''
        SELECT gz.* FROM geofence_zones gz
        JOIN devices d ON gz.device_id = d.id
        WHERE d.phone = ?
        ORDER BY gz.created_at DESC
    ''', (phone,))
    
    zones = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return {"total": len(zones), "zones": zones}

@app.get("/api/geofence/alerts")
async def get_geofence_alerts(
    phone: Optional[str] = None,
    unread_only: bool = False,
    limit: int = 50,
    username: str = Depends(get_current_user)
):
    """Obtener alertas de geofencing"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    sql = '''
        SELECT 
            ga.*, gz.name as zone_name, d.phone, d.name as device_name
        FROM geofence_alerts ga
        JOIN geofence_zones gz ON ga.zone_id = gz.id
        JOIN devices d ON ga.device_id = d.id
        WHERE 1=1
    '''
    params = []
    
    if phone:
        sql += ' AND d.phone = ?'
        params.append(phone)
    
    if unread_only:
        sql += ' AND ga.read = 0'
    
    sql += ' ORDER BY ga.timestamp DESC LIMIT ?'
    params.append(limit)
    
    c.execute(sql, params)
    alerts = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    return {"total": len(alerts), "alerts": alerts}

@app.post("/api/geofence/alerts/{alert_id}/mark-read")
async def mark_alert_read(
    alert_id: int,
    username: str = Depends(get_current_user)
):
    """Marcar alerta como leída"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('UPDATE geofence_alerts SET read = 1 WHERE id = ?', (alert_id,))
    conn.commit()
    conn.close()
    
    return {"success": True}

# ═══════════════════════════════════════════════════════════════════
# ACTUALIZACIÓN PERIÓDICA AUTOMÁTICA
# ═══════════════════════════════════════════════════════════════════

async def periodic_location_updater():
    """Tarea en background para recordar actualizaciones periódicas"""
    while True:
        try:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            
            # Buscar dispositivos con rastreo automático activo
            c.execute('''
                SELECT id, phone, name, update_interval, last_update
                FROM devices
                WHERE auto_tracking = 1 AND is_active = 1
            ''')
            
            devices = c.fetchall()
            
            for device in devices:
                device_id, phone, name, interval, last_update = device
                
                if last_update:
                    last_dt = datetime.fromisoformat(last_update)
                    elapsed = (datetime.now() - last_dt).total_seconds()
                    
                    if elapsed > interval:
                        print(f"⏰ Dispositivo {phone} ({name}) debería actualizar ubicación")
            
            conn.close()
            
        except Exception as e:
            print(f"Error en periodic_location_updater: {e}")
        
        await asyncio.sleep(60)  # Revisar cada minuto

# ═══════════════════════════════════════════════════════════════════
# PÁGINA DE RASTREO PARA DISPOSITIVO
# ═══════════════════════════════════════════════════════════════════

@app.get("/manifest/{token}")
async def get_manifest(token: str):
    """Generar manifest.json para PWA"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('''
        SELECT d.name FROM device_tokens dt
        JOIN devices d ON dt.device_id = d.id
        WHERE dt.token = ?
    ''', (token,))
    
    device = c.fetchone()
    conn.close()
    
    if not device:
        raise HTTPException(404, "Token inválido")
    
    name = device[0]
    
    return JSONResponse({
        "name": f"GeoTracker - {name}",
        "short_name": "GeoTracker",
        "description": "Sistema de rastreo GPS en tiempo real",
        "start_url": f"/track/{token}",
        "display": "standalone",
        "background_color": "#667eea",
        "theme_color": "#667eea",
        "orientation": "portrait",
        "icons": [
            {
                "src": "/static/icon-192.png",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any maskable"
            },
            {
                "src": "/static/icon-512.png",
                "sizes": "512x512",
                "type": "image/png"
            }
        ]
    })

@app.get("/service-worker.js", response_class=HTMLResponse)
async def service_worker():
    """Service Worker para funcionalidad offline y background sync"""
    return HTMLResponse(content="""
// Service Worker para GeoTracker
const CACHE_NAME = 'geotracker-v1';
const urlsToCache = ['/'];

// Instalación
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(urlsToCache))
    );
    self.skipWaiting();
});

// Activación
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
    self.clients.claim();
});

// Background Sync
self.addEventListener('sync', event => {
    if (event.tag === 'location-sync') {
        event.waitUntil(syncLocation());
    }
});

async function syncLocation() {
    try {
        const position = await new Promise((resolve, reject) => {
            navigator.geolocation.getCurrentPosition(resolve, reject, {
                enableHighAccuracy: true,
                timeout: 10000,
                maximumAge: 0
            });
        });
        
        // Aquí iría la lógica de envío al servidor
        console.log('📍 Ubicación sincronizada en background:', position);
        
        // Mostrar notificación
        self.registration.showNotification('GeoTracker', {
            body: '📍 Ubicación actualizada en segundo plano',
            icon: '/static/icon-192.png',
            badge: '/static/badge-72.png',
            tag: 'location-sync'
        });
        
    } catch (error) {
        console.error('Error en sync:', error);
    }
}

// Periodic Sync (experimental - solo Chrome Android)
self.addEventListener('periodicsync', event => {
    if (event.tag === 'location-sync') {
        event.waitUntil(syncLocation());
    }
});

// Fetch
self.addEventListener('fetch', event => {
    event.respondWith(
        fetch(event.request).catch(() => {
            return caches.match(event.request);
        })
    );
});
    """, media_type="application/javascript")

@app.get("/track/{token}", response_class=HTMLResponse)
async def tracking_page(token: str):
    """Página que activa el rastreo automático con Service Worker"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('''
        SELECT d.id, d.phone, d.name, d.update_interval, d.custom_url
        FROM device_tokens dt
        JOIN devices d ON dt.device_id = d.id
        WHERE dt.token = ? AND dt.expires_at > ?
    ''', (token, datetime.now().isoformat()))
    
    device = c.fetchone()
    conn.close()
    
    if not device:
        raise HTTPException(404, "Token inválido o expirado")
    
    device_id, phone, name, update_interval, custom_url = device
    
    # Si hay URL personalizada, mostrar iframe
    content_html = ""
    if custom_url:
        content_html = f"""
        <div style="margin-top: 20px; border-radius: 10px; overflow: hidden; box-shadow: 0 5px 15px rgba(0,0,0,0.2);">
            <iframe 
                src="{custom_url}" 
                style="width: 100%; height: 500px; border: none;"
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                allowfullscreen>
            </iframe>
        </div>
        """
    
    return HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GeoTracker - {name}</title>
        <link rel="manifest" href="/manifest/{token}">
        <meta name="theme-color" content="#667eea">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                background: white;
                border-radius: 20px;
                padding: 30px;
                max-width: 600px;
                margin: 0 auto;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }}
            h1 {{ color: #667eea; margin-bottom: 10px; text-align: center; }}
            .status {{
                padding: 15px;
                margin: 15px 0;
                border-radius: 10px;
                font-size: 14px;
                font-weight: 600;
                text-align: center;
            }}
            .status.active {{ background: #d4edda; color: #155724; border: 2px solid #28a745; }}
            .status.waiting {{ background: #fff3cd; color: #856404; border: 2px solid #ffc107; }}
            .status.error {{ background: #f8d7da; color: #721c24; border: 2px solid #dc3545; }}
            .info {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 10px;
                margin: 15px 0;
            }}
            .info-item {{
                display: flex;
                justify-content: space-between;
                padding: 8px 0;
                border-bottom: 1px solid #dee2e6;
                font-size: 14px;
            }}
            .info-item:last-child {{ border-bottom: none; }}
            .label {{ color: #666; }}
            .value {{ font-weight: 600; color: #333; }}
            .btn {{
                background: #667eea;
                color: white;
                border: none;
                padding: 12px 20px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                width: 100%;
                margin-top: 10px;
                transition: all 0.3s;
            }}
            .btn:hover {{ background: #5568d3; transform: translateY(-2px); }}
            .btn:disabled {{ background: #ccc; cursor: not-allowed; transform: none; }}
            .spinner {{
                border: 3px solid rgba(102, 126, 234, 0.3);
                border-top: 3px solid #667eea;
                border-radius: 50%;
                width: 30px;
                height: 30px;
                animation: spin 1s linear infinite;
                margin: 10px auto;
            }}
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
            .updates-list {{
                max-height: 150px;
                overflow-y: auto;
                background: #f8f9fa;
                border-radius: 8px;
                padding: 10px;
                margin-top: 15px;
                font-size: 13px;
            }}
            .update-item {{
                padding: 8px;
                background: white;
                margin-bottom: 8px;
                border-radius: 5px;
                border-left: 3px solid #667eea;
            }}
            .install-prompt {{
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                padding: 15px;
                border-radius: 10px;
                margin: 15px 0;
                text-align: center;
                display: none;
            }}
            .install-prompt.show {{ display: block; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📍 Rastreo Activo</h1>
            <p style="text-align: center; color: #666; margin-bottom: 15px;">Hola {name}</p>
            
            <!-- Prompt para instalar PWA -->
            <div class="install-prompt" id="install-prompt">
                <div style="font-size: 2em; margin-bottom: 10px;">📱</div>
                <strong>¡Instala la App!</strong>
                <p style="font-size: 0.9em; margin: 10px 0;">
                    Para rastreo continuo en segundo plano, instala esta aplicación en tu dispositivo
                </p>
                <button class="btn" style="background: white; color: #667eea;" onclick="installPWA()">
                    📥 Instalar Aplicación
                </button>
            </div>
            
            <div class="status waiting" id="status">
                <div class="spinner"></div>
                Inicializando rastreo GPS...
            </div>
            
            <div class="info">
                <div class="info-item">
                    <span class="label">📱 Teléfono:</span>
                    <span class="value">{phone}</span>
                </div>
                <div class="info-item">
                    <span class="label">⏱️ Intervalo:</span>
                    <span class="value">{update_interval // 60} minutos</span>
                </div>
                <div class="info-item">
                    <span class="label">🔋 Batería:</span>
                    <span class="value" id="battery">Detectando...</span>
                </div>
                <div class="info-item">
                    <span class="label">📍 Última actualización:</span>
                    <span class="value" id="last-update">Nunca</span>
                </div>
                <div class="info-item">
                    <span class="label">📊 Total enviadas:</span>
                    <span class="value" id="total-updates">0</span>
                </div>
                <div class="info-item">
                    <span class="label">⚙️ Service Worker:</span>
                    <span class="value" id="sw-status">Desactivado</span>
                </div>
            </div>
            
            <button class="btn" id="manual-btn" onclick="sendLocationNow()">
                📍 Enviar Ubicación Ahora
            </button>
            
            <button class="btn" style="background: #28a745;" onclick="requestNotificationPermission()">
                🔔 Activar Notificaciones
            </button>
            
            <div class="updates-list" id="updates-list" style="display: none;">
                <strong>Últimas actualizaciones:</strong>
                <div id="updates-content"></div>
            </div>
            
            {content_html}
        </div>
        
        <script>
            const PHONE = "{phone}";
            const UPDATE_INTERVAL = {update_interval} * 1000;
            const TOKEN = "{token}";
            let updateCount = 0;
            let trackingInterval = null;
            let batteryLevel = null;
            let deferredPrompt = null;
            
            // ========== SERVICE WORKER ==========
            async function registerServiceWorker() {{
                if (!('serviceWorker' in navigator)) {{
                    console.warn('Service Worker no soportado');
                    return;
                }}
                
                try {{
                    const registration = await navigator.serviceWorker.register('/service-worker.js');
                    console.log('✅ Service Worker registrado:', registration);
                    document.getElementById('sw-status').textContent = '✅ Activo';
                    document.getElementById('sw-status').style.color = '#28a745';
                    
                    // Configurar sincronización periódica (experimental)
                    if ('periodicSync' in registration) {{
                        try {{
                            await registration.periodicSync.register('location-sync', {{
                                minInterval: UPDATE_INTERVAL
                            }});
                            console.log('✅ Sincronización periódica configurada');
                            addUpdate('✅ Sincronización en segundo plano activada');
                        }} catch (err) {{
                            console.log('Periodic Sync no disponible:', err);
                        }}
                    }}
                    
                    return registration;
                }} catch (error) {{
                    console.error('Error al registrar Service Worker:', error);
                    document.getElementById('sw-status').textContent = '❌ Error';
                }}
            }}
            
            // ========== INSTALACIÓN PWA ==========
            window.addEventListener('beforeinstallprompt', (e) => {{
                e.preventDefault();
                deferredPrompt = e;
                document.getElementById('install-prompt').classList.add('show');
            }});
            
            async function installPWA() {{
                if (!deferredPrompt) {{
                    alert('La instalación no está disponible en este navegador');
                    return;
                }}
                
                deferredPrompt.prompt();
                const {{ outcome }} = await deferredPrompt.userChoice;
                
                if (outcome === 'accepted') {{
                    console.log('✅ PWA instalada');
                    document.getElementById('install-prompt').classList.remove('show');
                    addUpdate('✅ Aplicación instalada correctamente');
                }} else {{
                    console.log('❌ Instalación cancelada');
                }}
                
                deferredPrompt = null;
            }}
            
            // ========== NOTIFICACIONES ==========
            async function requestNotificationPermission() {{
                if (!('Notification' in window)) {{
                    alert('Notificaciones no soportadas en este navegador');
                    return;
                }}
                
                const permission = await Notification.requestPermission();
                
                if (permission === 'granted') {{
                    new Notification('🎯 GeoTracker Activo', {{
                        body: 'Rastreo en segundo plano activado',
                        icon: '/static/icon-192.png',
                        badge: '/static/badge-72.png'
                    }});
                    addUpdate('✅ Notificaciones activadas');
                }} else {{
                    alert('❌ Permisos de notificación denegados');
                }}
            }}
            
            // ========== FUNCIONES DE UBICACIÓN ==========
            function setStatus(message, type = 'waiting') {{
                const statusEl = document.getElementById('status');
                statusEl.className = `status ${{type}}`;
                statusEl.innerHTML = message;
            }}
            
            function addUpdate(message) {{
                const list = document.getElementById('updates-list');
                const content = document.getElementById('updates-content');
                list.style.display = 'block';
                
                const item = document.createElement('div');
                item.className = 'update-item';
                item.textContent = `${{new Date().toLocaleTimeString()}} - ${{message}}`;
                content.insertBefore(item, content.firstChild);
                
                while (content.children.length > 5) {{
                    content.removeChild(content.lastChild);
                }}
            }}
            
            async function getBattery() {{
                try {{
                    const battery = await navigator.getBattery();
                    batteryLevel = Math.round(battery.level * 100);
                    document.getElementById('battery').textContent = `${{batteryLevel}}%`;
                    
                    battery.addEventListener('levelchange', () => {{
                        batteryLevel = Math.round(battery.level * 100);
                        document.getElementById('battery').textContent = `${{batteryLevel}}%`;
                    }});
                }} catch (e) {{
                    document.getElementById('battery').textContent = 'No disponible';
                }}
            }}
            
            async function sendLocation(latitude, longitude, accuracy) {{
                try {{
                    const response = await fetch('/api/locations/update', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            phone: PHONE,
                            latitude: latitude,
                            longitude: longitude,
                            accuracy: accuracy,
                            battery_level: batteryLevel
                        }})
                    }});
                    
                    const data = await response.json();
                    
                    if (data.success) {{
                        updateCount++;
                        document.getElementById('total-updates').textContent = updateCount;
                        document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
                        
                        const address = data.address || 'Ubicación capturada';
                        setStatus(`✅ Ubicación enviada<br><small>${{address}}</small>`, 'active');
                        addUpdate(`✅ Enviado: ${{latitude.toFixed(6)}}, ${{longitude.toFixed(6)}}`);
                        
                        // Enviar notificación si está permitido
                        if (Notification.permission === 'granted') {{
                            new Notification('📍 Ubicación Actualizada', {{
                                body: `${{address}}`,
                                icon: '/static/icon-192.png',
                                tag: 'location-update',
                                requireInteraction: false
                            }});
                        }}
                        
                        return true;
                    }}
                }} catch (error) {{
                    console.error('Error al enviar ubicación:', error);
                    setStatus('❌ Error al enviar ubicación', 'error');
                    addUpdate('❌ Error de conexión');
                    return false;
                }}
            }}
            
            async function captureLocation() {{
                return new Promise((resolve) => {{
                    if (!navigator.geolocation) {{
                        setStatus('❌ Geolocalización no soportada', 'error');
                        resolve(null);
                        return;
                    }}
                    
                    setStatus('🔍 Obteniendo ubicación GPS...', 'waiting');
                    
                    navigator.geolocation.getCurrentPosition(
                        async (position) => {{
                            const {{ latitude, longitude, accuracy }} = position.coords;
                            const success = await sendLocation(latitude, longitude, accuracy);
                            resolve(success);
                        }},
                        (error) => {{
                            console.error('Error GPS:', error);
                            setStatus(`❌ Error GPS: ${{error.message}}`, 'error');
                            addUpdate(`❌ Error: ${{error.message}}`);
                            resolve(false);
                        }},
                        {{
                            enableHighAccuracy: true,
                            timeout: 15000,
                            maximumAge: 0
                        }}
                    );
                }});
            }}
            
            async function sendLocationNow() {{
                const btn = document.getElementById('manual-btn');
                btn.disabled = true;
                btn.textContent = '📍 Enviando...';
                await captureLocation();
                btn.disabled = false;
                btn.textContent = '📍 Enviar Ubicación Ahora';
            }}
            
            async function startTracking() {{
                setStatus('🚀 Iniciando rastreo automático...', 'waiting');
                
                const success = await captureLocation();
                
                if (success) {{
                    trackingInterval = setInterval(async () => {{
                        await captureLocation();
                    }}, UPDATE_INTERVAL);
                    
                    const minutes = Math.round(UPDATE_INTERVAL / 60000);
                    addUpdate(`🚀 Rastreo automático activado (cada ${{minutes}} min)`);
                }}
            }}
            
            // ========== MANTENER ACTIVO ==========
            function keepAlive() {{
                // Wake Lock API
                if ('wakeLock' in navigator) {{
                    navigator.wakeLock.request('screen')
                        .then(wakeLock => {{
                            console.log('✅ Wake Lock activado');
                            addUpdate('✅ Pantalla permanecerá activa');
                        }})
                        .catch(err => {{
                            console.log('Wake Lock no disponible:', err);
                        }});
                }}
                
                // Background Sync
                if ('serviceWorker' in navigator && 'sync' in ServiceWorkerRegistration.prototype) {{
                    navigator.serviceWorker.ready.then(registration => {{
                        return registration.sync.register('location-sync');
                    }}).then(() => {{
                        console.log('✅ Background Sync registrado');
                    }}).catch(err => {{
                        console.log('Background Sync no disponible:', err);
                    }});
                }}
            }}
            
            // ========== INICIALIZACIÓN ==========
            window.addEventListener('load', async () => {{
                await registerServiceWorker();
                await getBattery();
                await startTracking();
                keepAlive();
                
                if (Notification.permission === 'default') {{
                    setTimeout(() => {{
                        requestNotificationPermission();
                    }}, 3000);
                }}
            }});
            
            // Manejar visibilidad
            document.addEventListener('visibilitychange', () => {{
                if (document.hidden) {{
                    console.log('📱 Página oculta - rastreo en segundo plano activo');
                    addUpdate('📱 App en segundo plano');
                }} else {{
                    console.log('👁️ Página visible - rastreo activo');
                    addUpdate('👁️ App visible');
                }}
            }});
            
            // Prevenir cierre
            window.addEventListener('beforeunload', (e) => {{
                e.preventDefault();
                e.returnValue = 'El rastreo GPS está activo. ¿Cerrar?';
                return e.returnValue;
            }});
        </script>
    </body>
    </html>
    """)



# ═══════════════════════════════════════════════════════════════════
# DASHBOARD MEJORADO CON MAPA INTERACTIVO
# ═══════════════════════════════════════════════════════════════════

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(username: str = Depends(get_current_user)):
    """Dashboard interactivo con gestión completa de funciones"""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>GeoTracker Dashboard V3</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #f5f7fa;
                overflow-x: hidden;
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .header h1 { margin: 0; font-size: 2em; }
            .header .subtitle { opacity: 0.9; margin-top: 5px; }
            .header-actions {
                display: flex;
                gap: 10px;
            }
            .container {
                display: grid;
                grid-template-columns: 320px 1fr;
                gap: 20px;
                padding: 20px;
                max-width: 1900px;
                margin: 0 auto;
                height: calc(100vh - 100px);
            }
            .sidebar {
                background: white;
                border-radius: 15px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                overflow-y: auto;
                max-height: calc(100vh - 140px);
            }
            .sidebar h3 {
                color: #667eea;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 2px solid #667eea;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .device-card {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 10px;
                margin-bottom: 15px;
                cursor: pointer;
                transition: all 0.3s;
                border-left: 4px solid #667eea;
                position: relative;
            }
            .device-card:hover {
                background: #e9ecef;
                transform: translateX(5px);
            }
            .device-card.active {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }
            .device-name {
                font-weight: 600;
                font-size: 1.1em;
                margin-bottom: 5px;
            }
            .device-info {
                font-size: 0.9em;
                opacity: 0.8;
                margin: 3px 0;
            }
            .device-status {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 12px;
                font-size: 0.8em;
                font-weight: 600;
                margin-top: 5px;
            }
            .status-active { background: #28a745; color: white; }
            .status-inactive { background: #dc3545; color: white; }
            .device-actions {
                display: flex;
                gap: 5px;
                margin-top: 10px;
            }
            .device-actions button {
                flex: 1;
                padding: 5px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 0.8em;
                font-weight: 600;
                transition: all 0.2s;
            }
            .btn-edit { background: #ffc107; color: #000; }
            .btn-delete { background: #dc3545; color: white; }
            .btn-zones { background: #17a2b8; color: white; }
            .device-actions button:hover { opacity: 0.8; transform: scale(1.05); }
            .main-content {
                display: grid;
                grid-template-rows: auto 1fr;
                gap: 20px;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
            }
            .stat-card {
                background: white;
                padding: 20px;
                border-radius: 15px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
            }
            .stat-icon { font-size: 2.5em; margin-bottom: 10px; }
            .stat-value {
                font-size: 2em;
                font-weight: bold;
                color: #667eea;
                margin-bottom: 5px;
            }
            .stat-label { color: #666; font-size: 0.9em; }
            #map {
                height: 100%;
                border-radius: 15px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            
            /* MODALES */
            .modal {
                display: none;
                position: fixed;
                z-index: 2000;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0,0,0,0.5);
                animation: fadeIn 0.3s;
            }
            .modal.show { display: flex; align-items: center; justify-content: center; }
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            .modal-content {
                background: white;
                border-radius: 20px;
                padding: 30px;
                max-width: 500px;
                width: 90%;
                max-height: 90vh;
                overflow-y: auto;
                box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                animation: slideUp 0.3s;
            }
            @keyframes slideUp {
                from { transform: translateY(50px); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
            .modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 2px solid #667eea;
            }
            .modal-header h2 {
                color: #667eea;
                margin: 0;
            }
            .close-modal {
                background: none;
                border: none;
                font-size: 2em;
                cursor: pointer;
                color: #999;
                line-height: 1;
            }
            .close-modal:hover { color: #333; }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 600;
            }
            .form-group input, .form-group select, .form-group textarea {
                width: 100%;
                padding: 12px;
                border: 2px solid #e9ecef;
                border-radius: 8px;
                font-size: 1em;
                transition: all 0.3s;
            }
            .form-group input:focus, .form-group select:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .form-group small {
                display: block;
                margin-top: 5px;
                color: #666;
                font-size: 0.85em;
            }
            .form-row {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 15px;
            }
            .checkbox-group {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .checkbox-group input[type="checkbox"] {
                width: auto;
                cursor: pointer;
            }
            .btn {
                padding: 12px 25px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                font-size: 1em;
                transition: all 0.3s;
            }
            .btn-primary {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                width: 100%;
            }
            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            }
            .btn-secondary {
                background: #6c757d;
                color: white;
            }
            .btn-success {
                background: #28a745;
                color: white;
            }
            .btn-danger {
                background: #dc3545;
                color: white;
            }
            .btn-warning {
                background: #ffc107;
                color: #000;
            }
            .btn-info {
                background: #17a2b8;
                color: white;
            }
            .btn-group {
                display: flex;
                gap: 10px;
                margin-top: 20px;
            }
            .btn-group button {
                flex: 1;
            }
            
            /* ALERTAS/NOTIFICACIONES */
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                background: white;
                padding: 20px 25px;
                border-radius: 10px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.2);
                z-index: 3000;
                min-width: 300px;
                animation: slideInRight 0.3s;
                display: none;
            }
            .notification.show { display: block; }
            @keyframes slideInRight {
                from { transform: translateX(400px); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            .notification.success { border-left: 5px solid #28a745; }
            .notification.error { border-left: 5px solid #dc3545; }
            .notification.warning { border-left: 5px solid #ffc107; }
            .notification.info { border-left: 5px solid #17a2b8; }
            .notification-title {
                font-weight: 600;
                margin-bottom: 5px;
                font-size: 1.1em;
            }
            .notification-message {
                color: #666;
                font-size: 0.9em;
            }
            
            /* LISTA DE ZONAS */
            .zone-list {
                max-height: 300px;
                overflow-y: auto;
            }
            .zone-item {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 10px;
                border-left: 4px solid #667eea;
            }
            .zone-item.inactive {
                opacity: 0.6;
                border-left-color: #999;
            }
            .zone-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 10px;
            }
            .zone-name {
                font-weight: 600;
                color: #333;
            }
            .zone-badge {
                padding: 3px 8px;
                border-radius: 12px;
                font-size: 0.8em;
                font-weight: 600;
            }
            .badge-active { background: #28a745; color: white; }
            .badge-inactive { background: #6c757d; color: white; }
            .zone-info {
                font-size: 0.85em;
                color: #666;
                margin: 3px 0;
            }
            
            /* TABLA DE ALERTAS */
            .alerts-table {
                max-height: 400px;
                overflow-y: auto;
            }
            .alert-row {
                display: flex;
                align-items: center;
                padding: 12px;
                background: #f8f9fa;
                border-radius: 8px;
                margin-bottom: 8px;
                gap: 15px;
            }
            .alert-row.unread {
                background: #fff3cd;
                border-left: 4px solid #ffc107;
            }
            .alert-row.enter {
                border-left: 4px solid #28a745;
            }
            .alert-row.exit {
                border-left: 4px solid #dc3545;
            }
            .alert-icon {
                font-size: 1.5em;
            }
            .alert-content {
                flex: 1;
            }
            .alert-title {
                font-weight: 600;
                margin-bottom: 3px;
            }
            .alert-details {
                font-size: 0.85em;
                color: #666;
            }
            .alert-actions button {
                padding: 5px 10px;
                font-size: 0.8em;
            }
            
            /* LOADING SPINNER */
            .spinner {
                border: 3px solid rgba(102, 126, 234, 0.3);
                border-top: 3px solid #667eea;
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
            
            /* RESPONSIVE */
            @media (max-width: 968px) {
                .container {
                    grid-template-columns: 1fr;
                    grid-template-rows: auto 1fr;
                }
                .sidebar { max-height: 300px; }
                .form-row { grid-template-columns: 1fr; }
                .btn-group { flex-direction: column; }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>🎯 GeoTracker Pro Dashboard V3</h1>
                <p class="subtitle">Sistema de Rastreo en Tiempo Real con Geofencing</p>
            </div>
            <div class="header-actions">
                <button class="btn btn-success" onclick="showRegisterDeviceModal()">➕ Nuevo Dispositivo</button>
                <button class="btn btn-info" onclick="showAlertsModal()">🚨 Ver Alertas</button>
            </div>
        </div>
        
        <div class="container">
            <div class="sidebar">
                <h3>
                    📱 Dispositivos
                    <button class="btn btn-sm btn-primary" style="padding: 5px 10px; font-size: 0.8em;" onclick="loadDevices()">🔄</button>
                </h3>
                <div id="devices-list">
                    <div class="spinner"></div>
                </div>
            </div>
            
            <div class="main-content">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-icon">📱</div>
                        <div class="stat-value" id="total-devices">0</div>
                        <div class="stat-label">Dispositivos</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">📍</div>
                        <div class="stat-value" id="total-locations">0</div>
                        <div class="stat-label">Ubicaciones</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">✅</div>
                        <div class="stat-value" id="active-devices">0</div>
                        <div class="stat-label">Activos Hoy</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">🚨</div>
                        <div class="stat-value" id="total-alerts">0</div>
                        <div class="stat-label">Alertas</div>
                    </div>
                </div>
                
                <div id="map"></div>
            </div>
        </div>
        
        <!-- MODAL: REGISTRAR DISPOSITIVO -->
        <div id="registerDeviceModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>➕ Registrar Nuevo Dispositivo</h2>
                    <button class="close-modal" onclick="closeModal('registerDeviceModal')">&times;</button>
                </div>
                <form id="registerDeviceForm" onsubmit="registerDevice(event)">
                    <div class="form-group">
                        <label>📞 Número Telefónico *</label>
                        <input type="text" name="phone" required placeholder="+573001234567">
                        <small>Incluye código de país (ej: +57 para Colombia)</small>
                    </div>
                    <div class="form-group">
                        <label>👤 Nombre del Propietario *</label>
                        <input type="text" name="name" required placeholder="Juan Pérez">
                    </div>
                    <div class="form-group">
                        <label>⏱️ Intervalo de Actualización (minutos)</label>
                        <input type="number" name="update_interval" value="10" min="1" required>
                        <small>Frecuencia con la que se enviará la ubicación</small>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" name="auto_tracking" id="auto_tracking" checked>
                        <label for="auto_tracking">🔄 Activar rastreo automático</label>
                    </div>
                        <div class="form-group">
                        <label>🔗 URL Personalizada (Opcional)</label>
                        <input type="url" name="custom_url" placeholder="https://www.youtube.com/watch?v=...">
                        <small>Puedes mostrar un video de YouTube o cualquier página web mientras se rastrea</small>
                    </div>
                    <button type="submit" class="btn btn-primary">✅ Registrar Dispositivo</button>
                </form>
            </div>
        </div>
        
        <!-- MODAL: EDITAR DISPOSITIVO -->
        <div id="editDeviceModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>✏️ Editar Configuración</h2>
                    <button class="close-modal" onclick="closeModal('editDeviceModal')">&times;</button>
                </div>
                <form id="editDeviceForm" onsubmit="updateDevice(event)">
                    <input type="hidden" name="phone" id="edit_phone">
                    <div class="form-group">
                        <label>👤 Dispositivo</label>
                        <input type="text" id="edit_name" readonly style="background: #f8f9fa;">
                    </div>
                    <div class="form-group">
                        <label>⏱️ Intervalo de Actualización (minutos)</label>
                        <input type="number" name="update_interval" id="edit_interval" min="1" required>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" name="auto_tracking" id="edit_auto_tracking">
                        <label for="edit_auto_tracking">🔄 Rastreo automático activo</label>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" name="is_active" id="edit_is_active">
                        <label for="edit_is_active">✅ Dispositivo activo</label>
                    </div>
                    <div class="btn-group">
                        <button type="submit" class="btn btn-success">💾 Guardar Cambios</button>
                        <button type="button" class="btn btn-secondary" onclick="closeModal('editDeviceModal')">Cancelar</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- MODAL: GESTIONAR ZONAS -->
        <div id="zonesModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>🗺️ Zonas de Geofencing</h2>
                    <button class="close-modal" onclick="closeModal('zonesModal')">&times;</button>
                </div>
                <div style="margin-bottom: 20px;">
                    <strong id="zones_device_name"></strong>
                    <button class="btn btn-success" style="margin-top: 10px; width: 100%;" onclick="showCreateZoneModal()">➕ Crear Nueva Zona</button>
                </div>
                <div class="zone-list" id="zones-list">
                    <div class="spinner"></div>
                </div>
            </div>
        </div>
        
        <!-- MODAL: CREAR ZONA -->
        <div id="createZoneModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>➕ Crear Zona de Geofencing</h2>
                    <button class="close-modal" onclick="closeModal('createZoneModal')">&times;</button>
                </div>
                <form id="createZoneForm" onsubmit="createZone(event)">
                    <input type="hidden" name="phone" id="zone_phone">
                    <div class="form-group">
                        <label>🏷️ Nombre de la Zona *</label>
                        <input type="text" name="name" required placeholder="Casa, Oficina, Colegio...">
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>📍 Latitud *</label>
                            <input type="number" name="latitude" step="any" required placeholder="4.6097">
                            <small>Click en el mapa para obtener</small>
                        </div>
                        <div class="form-group">
                            <label>📍 Longitud *</label>
                            <input type="number" name="longitude" step="any" required placeholder="-74.0817">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>📏 Radio (metros) *</label>
                        <input type="number" name="radius_meters" value="100" min="10" required>
                        <small>Área de cobertura de la zona</small>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" name="alert_on_enter" id="alert_enter" checked>
                        <label for="alert_enter">🔔 Alertar al ENTRAR</label>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" name="alert_on_exit" id="alert_exit" checked>
                        <label for="alert_exit">🔔 Alertar al SALIR</label>
                    </div>
                    <div class="btn-group">
                        <button type="submit" class="btn btn-success">✅ Crear Zona</button>
                        <button type="button" class="btn btn-secondary" onclick="closeModal('createZoneModal')">Cancelar</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- MODAL: VER TODAS LAS ALERTAS -->
        <div id="alertsModal" class="modal">
            <div class="modal-content" style="max-width: 700px;">
                <div class="modal-header">
                    <h2>🚨 Alertas de Geofencing</h2>
                    <button class="close-modal" onclick="closeModal('alertsModal')">&times;</button>
                </div>
                <div style="margin-bottom: 15px; display: flex; gap: 10px;">
                    <button class="btn btn-info" onclick="loadAllAlerts(false)">Todas</button>
                    <button class="btn btn-warning" onclick="loadAllAlerts(true)">Solo No Leídas</button>
                    <button class="btn btn-success" onclick="markAllAlertsRead()" style="margin-left: auto;">✅ Marcar Todas Leídas</button>
                </div>
                <div class="alerts-table" id="alerts-table">
                    <div class="spinner"></div>
                </div>
            </div>
        </div>
        
        <!-- MODAL: RESULTADO REGISTRO -->
        <div id="resultModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>✅ Dispositivo Registrado</h2>
                    <button class="close-modal" onclick="closeModal('resultModal')">&times;</button>
                </div>
                <div id="result-content"></div>
            </div>
        </div>
        
        <!-- NOTIFICACIÓN -->
        <div id="notification" class="notification">
            <div class="notification-title" id="notif-title"></div>
            <div class="notification-message" id="notif-message"></div>
        </div>
        
        <script>
            let map;
            let markers = {};
            let selectedDevice = null;
            let currentZoneDevice = null;
            
            // ========== INICIALIZACIÓN ==========
            function initMap() {
                map = L.map('map').setView([4.6097, -74.0817], 12);
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap contributors',
                    maxZoom: 19
                }).addTo(map);
                
                // Click en mapa para obtener coordenadas
                map.on('click', function(e) {
                    const lat = e.latlng.lat.toFixed(6);
                    const lon = e.latlng.lng.toFixed(6);
                    
                    // Si el modal de crear zona está abierto, llenar coordenadas
                    const zoneModal = document.getElementById('createZoneModal');
                    if (zoneModal.classList.contains('show')) {
                        document.querySelector('[name="latitude"]').value = lat;
                        document.querySelector('[name="longitude"]').value = lon;
                        showNotification('info', 'Coordenadas Capturadas', `Lat: ${lat}, Lon: ${lon}`);
                    }
                });
            }
            
            // ========== FUNCIONES AUXILIARES ==========
            function showNotification(type, title, message) {
                const notif = document.getElementById('notification');
                notif.className = `notification ${type} show`;
                document.getElementById('notif-title').textContent = title;
                document.getElementById('notif-message').textContent = message;
                
                setTimeout(() => {
                    notif.classList.remove('show');
                }, 4000);
            }
            
            function showModal(modalId) {
                document.getElementById(modalId).classList.add('show');
            }
            
            function closeModal(modalId) {
                document.getElementById(modalId).classList.remove('show');
            }
            
            function showRegisterDeviceModal() {
                document.getElementById('registerDeviceForm').reset();
                showModal('registerDeviceModal');
            }
            
            // ========== DISPOSITIVOS ==========
            async function loadDevices() {
                try {
                    const response = await fetch('/api/devices/list');
                    if (!response.ok) throw new Error('Error al cargar dispositivos');
                    
                    const data = await response.json();
                    const devicesList = document.getElementById('devices-list');
                    devicesList.innerHTML = '';
                    
                    document.getElementById('total-devices').textContent = data.total;
                    let activeCount = 0;
                    
                    // Limpiar marcadores existentes
                    Object.values(markers).forEach(marker => map.removeLayer(marker));
                    markers = {};
                    
                    data.devices.forEach(device => {
                        const isActiveToday = device.last_update && 
                            new Date(device.last_update).toDateString() === new Date().toDateString();
                        
                        if (isActiveToday) activeCount++;
                        
                        const card = document.createElement('div');
                        card.className = 'device-card';
                        card.onclick = (e) => {
                            if (!e.target.closest('.device-actions')) {
                                selectDevice(device);
                            }
                        };
                        
                        card.innerHTML = `
                            <div class="device-name">📱 ${device.name}</div>
                            <div class="device-info">📞 ${device.phone}</div>
                            <div class="device-info">🔋 ${device.battery_level ? device.battery_level + '%' : 'N/A'}</div>
                            <div class="device-info">⏱️ ${device.update_interval ? (device.update_interval / 60) + ' min' : 'N/A'}</div>
                            <span class="device-status ${isActiveToday ? 'status-active' : 'status-inactive'}">
                                ${isActiveToday ? '● ACTIVO' : '○ Inactivo'}
                            </span>
                            <div class="device-actions">
                                <button class="btn-edit" onclick="editDevice('${device.phone}', event)" title="Editar">✏️</button>
                                <button class="btn-zones" onclick="showZones('${device.phone}', event)" title="Zonas">🗺️</button>
                                <button class="btn-delete" onclick="confirmdeleteDevice('${device.phone}', '${device.name}', event)" title="Eliminar">🗑️</button>
                            </div>
                        `;
                        
                        devicesList.appendChild(card);
                        
                        // Agregar marcador al mapa si tiene ubicación
                        if (device.latitude && device.longitude) {
                            addMarkerToMap(device);
                        }
                    });
                    
                    document.getElementById('active-devices').textContent = activeCount;
                    
                } catch (error) {
                    console.error('Error al cargar dispositivos:', error);
                    showNotification('error', 'Error', 'No se pudieron cargar los dispositivos');
                }
            }
            
            function addMarkerToMap(device) {
                if (markers[device.phone]) {
                    map.removeLayer(markers[device.phone]);
                }
                
                const marker = L.marker([device.latitude, device.longitude])
                    .bindPopup(`
                        <div style="min-width: 200px;">
                            <div style="font-weight: 600; font-size: 1.1em; color: #667eea; margin-bottom: 10px;">
                                ${device.name}
                            </div>
                            <div style="margin: 5px 0;">📱 ${device.phone}</div>
                            <div style="margin: 5px 0;">📍 ${device.latitude.toFixed(6)}, ${device.longitude.toFixed(6)}</div>
                            <div style="margin: 5px 0;">🎯 Precisión: ±${device.accuracy ? device.accuracy.toFixed(1) : 'N/A'}m</div>
                            <div style="margin: 5px 0;">🔋 Batería: ${device.battery_level || 'N/A'}%</div>
                            <div style="margin: 5px 0;">⏱️ ${device.last_update ? new Date(device.last_update).toLocaleString() : 'N/A'}</div>
                            <button onclick="viewHistory('${device.phone}')" style="
                                margin-top: 10px;
                                padding: 8px 15px;
                                background: #667eea;
                                color: white;
                                border: none;
                                border-radius: 5px;
                                cursor: pointer;
                                width: 100%;
                            ">📊 Ver Historial</button>
                        </div>
                    `)
                    .addTo(map);
                
                markers[device.phone] = marker;
            }
            
            function selectDevice(device) {
                selectedDevice = device;
                
                // Actualizar UI
                document.querySelectorAll('.device-card').forEach(card => {
                    card.classList.remove('active');
                });
                event.currentTarget.classList.add('active');
                
                // Centrar mapa
                if (device.latitude && device.longitude) {
                    map.setView([device.latitude, device.longitude], 15);
                    markers[device.phone].openPopup();
                }
            }
            
            async function registerDevice(event) {
                event.preventDefault();
                const form = event.target;
                const formData = new FormData(form);
                
                const data = {
                    phone: formData.get('phone'),
                    name: formData.get('name'),
                    update_interval: parseInt(formData.get('update_interval')) * 60, // Convertir a segundos
                    auto_tracking: formData.get('auto_tracking') === 'on'
                    custom_url: formData.get('custom_url') || null 
                };
                
                try {
                    const response = await fetch('/api/devices/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    
                    if (!response.ok) throw new Error('Error al registrar dispositivo');
                    
                    const result = await response.json();
                    
                    closeModal('registerDeviceModal');
                    
                    // Mostrar resultado con link
                    const resultContent = document.getElementById('result-content');
                    resultContent.innerHTML = `
                        <div style="text-align: center;">
                            <div style="font-size: 3em; margin-bottom: 20px;">✅</div>
                            <h3 style="color: #28a745; margin-bottom: 20px;">¡Dispositivo Registrado!</h3>
                            <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
                                <p style="margin: 10px 0;"><strong>Nombre:</strong> ${result.name}</p>
                                <p style="margin: 10px 0;"><strong>Teléfono:</strong> ${result.phone}</p>
                                <p style="margin: 10px 0;"><strong>Intervalo:</strong> ${result.update_interval / 60} minutos</p>
                            </div>
                            <div style="background: #fff3cd; padding: 15px; border-radius: 10px; margin-bottom: 20px; border-left: 4px solid #ffc107;">
                                <strong>📱 Link de Rastreo:</strong>
                                <div style="margin-top: 10px; padding: 10px; background: white; border-radius: 5px; word-break: break-all; font-family: monospace; font-size: 0.9em;">
                                    ${result.tracking_url}
                                </div>
                                <button onclick="copyToClipboard('${result.tracking_url}')" style="
                                    margin-top: 10px;
                                    padding: 10px 20px;
                                    background: #667eea;
                                    color: white;
                                    border: none;
                                    border-radius: 5px;
                                    cursor: pointer;
                                    width: 100%;
                                    font-weight: 600;
                                ">📋 Copiar Link</button>
                            </div>
                            <p style="color: #666; font-size: 0.9em;">
                                ${result.instructions}
                            </p>
                        </div>
                    `;
                    
                    showModal('resultModal');
                    loadDevices();
                    showNotification('success', 'Éxito', 'Dispositivo registrado correctamente');
                    
                } catch (error) {
                    console.error('Error:', error);
                    showNotification('error', 'Error', 'No se pudo registrar el dispositivo');
                }
            }
            
            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(() => {
                    showNotification('success', 'Copiado', 'Link copiado al portapapeles');
                });
            }
            
            function editDevice(phone, event) {
                event.stopPropagation();
                
                // Buscar datos del dispositivo
                fetch('/api/devices/list')
                    .then(r => r.json())
                    .then(data => {
                        const device = data.devices.find(d => d.phone === phone);
                        if (!device) return;
                        
                        document.getElementById('edit_phone').value = device.phone;
                        document.getElementById('edit_name').value = device.name;
                        document.getElementById('edit_interval').value = device.update_interval / 60;
                        document.getElementById('edit_auto_tracking').checked = device.auto_tracking;
                        document.getElementById('edit_is_active').checked = device.is_active;
                        
                        showModal('editDeviceModal');
                    });
            }
            
            async function updateDevice(event) {
                event.preventDefault();
                const form = event.target;
                const formData = new FormData(form);
                
                const phone = formData.get('phone');
                const params = new URLSearchParams({
                    update_interval: parseInt(formData.get('update_interval')) * 60,
                    auto_tracking: formData.get('auto_tracking') === 'on',
                    is_active: formData.get('is_active') === 'on'
                });
                
                try {
                    const response = await fetch(`/api/devices/${encodeURIComponent(phone)}/update-settings?${params}`, {
                        method: 'POST'
                    });
                    
                    if (!response.ok) throw new Error('Error al actualizar');
                    
                    closeModal('editDeviceModal');
                    loadDevices();
                    showNotification('success', 'Actualizado', 'Configuración guardada correctamente');
                    
                } catch (error) {
                    console.error('Error:', error);
                    showNotification('error', 'Error', 'No se pudo actualizar la configuración');
                }
            }
            
            function confirmDeleteDevice(phone, name, event) {
                event.stopPropagation();
                
                if (confirm(`¿Estás seguro de eliminar el dispositivo "${name}"?\n\n⚠️ Se borrarán TODOS los datos: ubicaciones, zonas y alertas.\n\nEsta acción NO se puede deshacer.`)) {
                    deleteDevice(phone);
                }
            }
            
            async function deleteDevice(phone) {
                try {
                    const response = await fetch(`/api/devices/${encodeURIComponent(phone)}`, {
                        method: 'DELETE'
                    });
                    
                    if (!response.ok) throw new Error('Error al eliminar');
                    
                    loadDevices();
                    showNotification('success', 'Eliminado', 'Dispositivo eliminado correctamente');
                    
                } catch (error) {
                    console.error('Error:', error);
                    showNotification('error', 'Error', 'No se pudo eliminar el dispositivo');
                }
            }
            
            function viewHistory(phone) {
                window.open(`/history/${encodeURIComponent(phone)}`, '_blank');
            }
            
            // ========== ZONAS DE GEOFENCING ==========
            function showZones(phone, event) {
                event.stopPropagation();
                currentZoneDevice = phone;
                
                // Buscar nombre del dispositivo
                fetch('/api/devices/list')
                    .then(r => r.json())
                    .then(data => {
                        const device = data.devices.find(d => d.phone === phone);
                        document.getElementById('zones_device_name').textContent = 
                            `Zonas de: ${device ? device.name : phone}`;
                    });
                
                loadZones(phone);
                showModal('zonesModal');
            }
            
            async function loadZones(phone) {
                const zonesList = document.getElementById('zones-list');
                zonesList.innerHTML = '<div class="spinner"></div>';
                
                try {
                    const response = await fetch(`/api/geofence/list/${encodeURIComponent(phone)}`);
                    if (!response.ok) throw new Error('Error al cargar zonas');
                    
                    const data = await response.json();
                    zonesList.innerHTML = '';
                    
                    if (data.total === 0) {
                        zonesList.innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">No hay zonas configuradas</p>';
                        return;
                    }
                    
                    data.zones.forEach(zone => {
                        const zoneItem = document.createElement('div');
                        zoneItem.className = `zone-item ${zone.active ? '' : 'inactive'}`;
                        zoneItem.innerHTML = `
                            <div class="zone-header">
                                <div class="zone-name">🗺️ ${zone.name}</div>
                                <span class="zone-badge ${zone.active ? 'badge-active' : 'badge-inactive'}">
                                    ${zone.active ? '✅ ACTIVA' : '⏸️ PAUSADA'}
                                </span>
                            </div>
                            <div class="zone-info">📍 Centro: ${zone.latitude.toFixed(6)}, ${zone.longitude.toFixed(6)}</div>
                            <div class="zone-info">📏 Radio: ${zone.radius_meters}m</div>
                            <div class="zone-info">
                                🔔 Alertas: 
                                ${zone.alert_on_enter ? '➡️ Entrada' : ''} 
                                ${zone.alert_on_enter && zone.alert_on_exit ? 'y' : ''}
                                ${zone.alert_on_exit ? '⬅️ Salida' : ''}
                            </div>
                            <button onclick="showZoneOnMap(${zone.latitude}, ${zone.longitude}, ${zone.radius_meters})" style="
                                margin-top: 10px;
                                padding: 8px;
                                background: #667eea;
                                color: white;
                                border: none;
                                border-radius: 5px;
                                cursor: pointer;
                                width: 100%;
                                font-size: 0.9em;
                            ">📍 Ver en Mapa</button>
                        `;
                        zonesList.appendChild(zoneItem);
                    });
                    
                } catch (error) {
                    console.error('Error:', error);
                    zonesList.innerHTML = '<p style="text-align: center; color: red;">Error al cargar zonas</p>';
                }
            }
            
            function showZoneOnMap(lat, lon, radius) {
                map.setView([lat, lon], 15);
                
                // Dibujar círculo temporal
                const circle = L.circle([lat, lon], {
                    radius: radius,
                    color: '#667eea',
                    fillColor: '#667eea',
                    fillOpacity: 0.2
                }).addTo(map);
                
                // Remover después de 5 segundos
                setTimeout(() => {
                    map.removeLayer(circle);
                }, 5000);
                
                closeModal('zonesModal');
            }
            
            function showCreateZoneModal() {
                document.getElementById('zone_phone').value = currentZoneDevice;
                document.getElementById('createZoneForm').reset();
                document.getElementById('zone_phone').value = currentZoneDevice;
                
                // Si hay un dispositivo seleccionado, usar su ubicación
                if (selectedDevice && selectedDevice.latitude && selectedDevice.longitude) {
                    document.querySelector('[name="latitude"]').value = selectedDevice.latitude;
                    document.querySelector('[name="longitude"]').value = selectedDevice.longitude;
                }
                
                closeModal('zonesModal');
                showModal('createZoneModal');
            }
            
            async function createZone(event) {
                event.preventDefault();
                const form = event.target;
                const formData = new FormData(form);
                
                const data = {
                    name: formData.get('name'),
                    phone: formData.get('phone'),
                    latitude: parseFloat(formData.get('latitude')),
                    longitude: parseFloat(formData.get('longitude')),
                    radius_meters: parseFloat(formData.get('radius_meters')),
                    alert_on_enter: formData.get('alert_on_enter') === 'on',
                    alert_on_exit: formData.get('alert_on_exit') === 'on',
                    active: true
                };
                
                try {
                    const response = await fetch('/api/geofence/create', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    
                    if (!response.ok) throw new Error('Error al crear zona');
                    
                    closeModal('createZoneModal');
                    showNotification('success', 'Zona Creada', 'La zona de geofencing se creó correctamente');
                    
                    // Volver a mostrar modal de zonas
                    setTimeout(() => {
                        showZones(data.phone, { stopPropagation: () => {} });
                    }, 500);
                    
                } catch (error) {
                    console.error('Error:', error);
                    showNotification('error', 'Error', 'No se pudo crear la zona');
                }
            }
            
            // ========== ALERTAS ==========
            function showAlertsModal() {
                loadAllAlerts(false);
                showModal('alertsModal');
            }
            
            async function loadAllAlerts(unreadOnly = false) {
                const alertsTable = document.getElementById('alerts-table');
                alertsTable.innerHTML = '<div class="spinner"></div>';
                
                try {
                    const params = new URLSearchParams({
                        limit: 50,
                        unread_only: unreadOnly
                    });
                    
                    const response = await fetch(`/api/geofence/alerts?${params}`);
                    if (!response.ok) throw new Error('Error al cargar alertas');
                    
                    const data = await response.json();
                    alertsTable.innerHTML = '';
                    
                    if (data.total === 0) {
                        alertsTable.innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">No hay alertas</p>';
                        return;
                    }
                    
                    data.alerts.forEach(alert => {
                        const alertRow = document.createElement('div');
                        const typeClass = alert.alert_type.toLowerCase();
                        const unreadClass = alert.read ? '' : 'unread';
                        
                        alertRow.className = `alert-row ${typeClass} ${unreadClass}`;
                        alertRow.innerHTML = `
                            <div class="alert-icon">
                                ${alert.alert_type === 'ENTER' ? '➡️' : '⬅️'}
                            </div>
                            <div class="alert-content">
                                <div class="alert-title">
                                    ${alert.alert_type === 'ENTER' ? 'ENTRADA' : 'SALIDA'} - ${alert.zone_name}
                                </div>
                                <div class="alert-details">
                                    📱 ${alert.device_name} (${alert.phone})<br>
                                    ⏱️ ${new Date(alert.timestamp).toLocaleString()}<br>
                                    ${alert.read ? '✅ Leída' : '🔔 No leída'}
                                </div>
                            </div>
                            <div class="alert-actions">
                                ${!alert.read ? `<button class="btn btn-warning" onclick="markAlertRead(${alert.id})">✅ Marcar Leída</button>` : ''}
                            </div>
                        `;
                        alertsTable.appendChild(alertRow);
                    });
                    
                    document.getElementById('total-alerts').textContent = data.total;
                    
                } catch (error) {
                    console.error('Error:', error);
                    alertsTable.innerHTML = '<p style="text-align: center; color: red;">Error al cargar alertas</p>';
                }
            }
            
            async function markAlertRead(alertId) {
                try {
                    const response = await fetch(`/api/geofence/alerts/${alertId}/mark-read`, {
                        method: 'POST'
                    });
                    
                    if (!response.ok) throw new Error('Error al marcar alerta');
                    
                    loadAllAlerts(false);
                    showNotification('success', 'Actualizado', 'Alerta marcada como leída');
                    
                } catch (error) {
                    console.error('Error:', error);
                    showNotification('error', 'Error', 'No se pudo actualizar la alerta');
                }
            }
            
            async function markAllAlertsRead() {
                if (!confirm('¿Marcar TODAS las alertas como leídas?')) return;
                
                try {
                    // Obtener todas las alertas no leídas
                    const response = await fetch('/api/geofence/alerts?unread_only=true&limit=1000');
                    const data = await response.json();
                    
                    // Marcar cada una
                    for (const alert of data.alerts) {
                        await fetch(`/api/geofence/alerts/${alert.id}/mark-read`, { method: 'POST' });
                    }
                    
                    loadAllAlerts(false);
                    showNotification('success', 'Actualizado', `${data.total} alertas marcadas como leídas`);
                    
                } catch (error) {
                    console.error('Error:', error);
                    showNotification('error', 'Error', 'No se pudieron actualizar las alertas');
                }
            }
            
            // ========== ESTADÍSTICAS ==========
            async function loadStats() {
                try {
                    const response = await fetch('/api/locations/stats');
                    const data = await response.json();
                    document.getElementById('total-locations').textContent = data.total || 0;
                } catch (error) {
                    console.error('Error al cargar estadísticas:', error);
                }
            }
            
            // ========== INICIALIZACIÓN Y AUTO-REFRESH ==========
            window.addEventListener('load', () => {
                initMap();
                loadDevices();
                loadStats();
                
                // Auto-refresh cada 30 segundos
                setInterval(() => {
                    loadDevices();
                    loadStats();
                }, 30000);
            });
            
            // Cerrar modales con ESC
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    document.querySelectorAll('.modal.show').forEach(modal => {
                        modal.classList.remove('show');
                    });
                }
            });
            
            // Cerrar modales al hacer click fuera
            document.querySelectorAll('.modal').forEach(modal => {
                modal.addEventListener('click', (e) => {
                    if (e.target === modal) {
                        modal.classList.remove('show');
                    }
                });
            });
        </script>
    </body>
    </html>
    """)

# ═══════════════════════════════════════════════════════════════════
# PÁGINA DE HISTORIAL
# ═══════════════════════════════════════════════════════════════════

# Continuación del código de history_page - Parte faltante

@app.get("/history/{phone}", response_class=HTMLResponse)
async def history_page(phone: str, username: str = Depends(get_current_user)):
    """Página de historial de ubicaciones con ruta en mapa"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Historial - """ + phone + """</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', sans-serif;
                background: #f5f7fa;
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .container {
                display: grid;
                grid-template-columns: 1fr 400px;
                gap: 20px;
                padding: 20px;
                height: calc(100vh - 80px);
            }
            #map {
                border-radius: 15px;
                height: 100%;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .timeline {
                background: white;
                border-radius: 15px;
                padding: 20px;
                overflow-y: auto;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .timeline-item {
                padding: 15px;
                margin-bottom: 15px;
                background: #f8f9fa;
                border-radius: 10px;
                border-left: 4px solid #667eea;
                cursor: pointer;
                transition: all 0.3s;
            }
            .timeline-item:hover {
                background: #e9ecef;
                transform: translateX(5px);
            }
            .btn {
                padding: 10px 20px;
                background: white;
                color: #667eea;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>📍 Historial de Ubicaciones</h1>
                <p>""" + phone + """</p>
            </div>
            <button class="btn" onclick="window.close()">← Volver</button>
        </div>
        
        <div class="container">
            <div id="map"></div>
            <div class="timeline" id="timeline">
                <p style="text-align: center; color: #666;">Cargando historial...</p>
            </div>
        </div>
        
        <script>
            let map;
            let markers = [];
            let polyline;
            const PHONE = '""" + phone + """';
            
            function initMap() {
                map = L.map('map').setView([4.6097, -74.0817], 12);
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap'
                }).addTo(map);
            }
            
            async function loadHistory() {
                try {
                    const response = await fetch('/api/locations/history', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            phone: PHONE,
                            limit: 100
                        })
                    });
                    
                    const data = await response.json();
                    const timeline = document.getElementById('timeline');
                    timeline.innerHTML = '';
                    
                    const coords = [];
                    
                    data.locations.forEach((loc, index) => {
                        const item = document.createElement('div');
                        item.className = 'timeline-item';
                        item.onclick = () => { map.setView([loc.latitude, loc.longitude], 16); };
                        item.innerHTML = `
                            <strong>${new Date(loc.timestamp).toLocaleString()}</strong><br>
                            <small>📍 ${loc.latitude.toFixed(6)}, ${loc.longitude.toFixed(6)}</small><br>
                            <small>🎯 ±${loc.accuracy ? loc.accuracy.toFixed(1) : 'N/A'}m</small><br>
                            ${loc.address ? '<small>📍 ' + loc.address + '</small>' : ''}
                        `;
                        timeline.appendChild(item);
                        
                        const marker = L.marker([loc.latitude, loc.longitude])
                            .bindPopup(`
                                <strong>#${index + 1}</strong><br>
                                ${new Date(loc.timestamp).toLocaleString()}<br>
                                📍 ${loc.latitude.toFixed(6)}, ${loc.longitude.toFixed(6)}<br>
                                🎯 ±${loc.accuracy ? loc.accuracy.toFixed(1) : 'N/A'}m<br>
                                ${loc.battery_level ? '🔋 ' + loc.battery_level + '%' : ''}
                            `)
                            .addTo(map);
                        
                        markers.push(marker);
                        coords.push([loc.latitude, loc.longitude]);
                    });
                    
                    if (coords.length > 0) {
                        if (polyline) {
                            map.removeLayer(polyline);
                        }
                        polyline = L.polyline(coords, {
                            color: '#667eea',
                            weight: 3,
                            opacity: 0.7
                        }).addTo(map);
                        
                        map.fitBounds(polyline.getBounds());
                    }
                    
                } catch (error) {
                    console.error('Error al cargar historial:', error);
                    timeline.innerHTML = '<p style="text-align: center; color: red;">Error al cargar datos</p>';
                }
            }
            
            window.addEventListener('load', () => {
                initMap();
                loadHistory();
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# ═══════════════════════════════════════════════════════════════════
# ENDPOINTS ADICIONALES
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/locations/stats")
async def get_location_stats(username: str = Depends(get_current_user)):
    """Obtener estadísticas generales de ubicaciones"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM locations')
    total_locations = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM devices WHERE is_active = 1')
    active_devices = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM geofence_alerts WHERE read = 0')
    unread_alerts = c.fetchone()[0]
    
    conn.close()
    
    return {
        "total": total_locations,
        "active_devices": active_devices,
        "unread_alerts": unread_alerts
    }

@app.delete("/api/devices/{phone}")
async def delete_device(
    phone: str,
    username: str = Depends(get_current_user)
):
    """Eliminar un dispositivo y todos sus datos"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT id FROM devices WHERE phone = ?', (phone,))
    device = c.fetchone()
    
    if not device:
        conn.close()
        raise HTTPException(404, "Dispositivo no encontrado")
    
    device_id = device[0]
    
    c.execute('DELETE FROM locations WHERE device_id = ?', (device_id,))
    c.execute('DELETE FROM geofence_zones WHERE device_id = ?', (device_id,))
    c.execute('DELETE FROM geofence_alerts WHERE device_id = ?', (device_id,))
    c.execute('DELETE FROM device_tokens WHERE device_id = ?', (device_id,))
    c.execute('DELETE FROM devices WHERE id = ?', (device_id,))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"Dispositivo {phone} eliminado"}

@app.post("/api/users/register")
async def register_user(user: UserRegister):
    """Registrar nuevo usuario"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    password_hash = hashlib.sha256(user.password.encode()).hexdigest()
    
    try:
        c.execute('''
            INSERT INTO users (username, password_hash, email, phone, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (user.username, password_hash, user.email, user.phone, 
              datetime.now().isoformat()))
        
        conn.commit()
        user_id = c.lastrowid
        
        return {
            "success": True,
            "user_id": user_id,
            "username": user.username,
            "message": "Usuario registrado exitosamente"
        }
        
    except sqlite3.IntegrityError:
        raise HTTPException(400, "El nombre de usuario ya existe")
    finally:
        conn.close()

@app.get("/", response_class=HTMLResponse)
async def root():
    """Página de inicio con redirección"""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>GeoTracker Pro V3</title>
        <meta charset="utf-8">
        <meta http-equiv="refresh" content="0; url=/dashboard">
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
                color: white;
            }
            .container {
                text-align: center;
            }
            .spinner {
                border: 4px solid rgba(255,255,255,0.3);
                border-top: 4px solid white;
                border-radius: 50%;
                width: 50px;
                height: 50px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎯 GeoTracker Pro V3</h1>
            <p>Redirigiendo al dashboard...</p>
            <div class="spinner"></div>
        </div>
    </body>
    </html>
    """)

@app.get("/health")
async def health_check():
    """Endpoint de salud para monitoreo"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "3.0.0"
    }

# ═══════════════════════════════════════════════════════════════════
# INICIO DE LA APLICACIÓN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)