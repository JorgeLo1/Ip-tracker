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
    
    @validator('phone')
    def validate_phone(cls, v):
        # Remover espacios y caracteres especiales
        phone = ''.join(filter(str.isdigit, v))
        if len(phone) < 10:
            raise ValueError('Número telefónico inválido')
        return f"+{phone}" if not v.startswith('+') else v

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
    
    # Obtener user_id
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user_id = c.fetchone()[0]
    
    try:
        c.execute('''
            INSERT INTO devices (phone, name, user_id, update_interval, auto_tracking, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (device.phone, device.name, user_id, device.update_interval, 
              device.auto_tracking, datetime.now().isoformat()))
        
        device_id = c.lastrowid
        
        # Generar token de acceso
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

@app.get("/track/{token}", response_class=HTMLResponse)
async def tracking_page(token: str):
    """Página que activa el rastreo automático en el dispositivo"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Verificar token
    c.execute('''
        SELECT d.id, d.phone, d.name, d.update_interval
        FROM device_tokens dt
        JOIN devices d ON dt.device_id = d.id
        WHERE dt.token = ? AND dt.expires_at > ?
    ''', (token, datetime.now().isoformat()))
    
    device = c.fetchone()
    conn.close()
    
    if not device:
        raise HTTPException(404, "Token inválido o expirado")
    
    device_id, phone, name, update_interval = device
    
    return HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GeoTracker - {name}</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .container {{
                background: white;
                border-radius: 20px;
                padding: 40px;
                max-width: 500px;
                width: 100%;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                text-align: center;
            }}
            h1 {{ color: #667eea; margin-bottom: 10px; }}
            .status {{
                padding: 20px;
                margin: 20px 0;
                border-radius: 10px;
                font-size: 16px;
                font-weight: 600;
            }}
            .status.active {{
                background: #d4edda;
                color: #155724;
                border: 2px solid #28a745;
            }}
            .status.waiting {{
                background: #fff3cd;
                color: #856404;
                border: 2px solid #ffc107;
            }}
            .status.error {{
                background: #f8d7da;
                color: #721c24;
                border: 2px solid #dc3545;
            }}
            .info {{
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                text-align: left;
            }}
            .info-item {{
                display: flex;
                justify-content: space-between;
                padding: 10px 0;
                border-bottom: 1px solid #dee2e6;
            }}
            .info-item:last-child {{ border-bottom: none; }}
            .label {{ color: #666; }}
            .value {{ font-weight: 600; color: #333; }}
            .btn {{
                background: #667eea;
                color: white;
                border: none;
                padding: 15px 30px;
                border-radius: 10px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                width: 100%;
                margin-top: 20px;
                transition: all 0.3s;
            }}
            .btn:hover {{
                background: #5568d3;
                transform: translateY(-2px);
            }}
            .btn:disabled {{
                background: #ccc;
                cursor: not-allowed;
                transform: none;
            }}
            .spinner {{
                border: 3px solid rgba(102, 126, 234, 0.3);
                border-top: 3px solid #667eea;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }}
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
            .updates-list {{
                max-height: 200px;
                overflow-y: auto;
                background: #f8f9fa;
                border-radius: 10px;
                padding: 10px;
                margin-top: 20px;
            }}
            .update-item {{
                padding: 10px;
                background: white;
                margin-bottom: 10px;
                border-radius: 5px;
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📍 GeoTracker Activo</h1>
            <p style="color: #666; margin-bottom: 20px;">Hola {name}</p>
            
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
                    <span class="value" id="interval">{update_interval // 60} minutos</span>
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
            </div>
            
            <button class="btn" id="manual-btn" onclick="sendLocationNow()">
                📍 Enviar Ubicación Ahora
            </button>
            
            <div class="updates-list" id="updates-list" style="display: none;">
                <strong>Últimas actualizaciones:</strong>
                <div id="updates-content"></div>
            </div>
        </div>
        
        <script>
            const PHONE = "{phone}";
            const UPDATE_INTERVAL = {update_interval} * 1000; // Convertir a ms
            let updateCount = 0;
            let trackingInterval = null;
            let batteryLevel = null;
            
            // Actualizar estado visual
            function setStatus(message, type = 'waiting') {{
                const statusEl = document.getElementById('status');
                statusEl.className = `status ${{type}}`;
                statusEl.innerHTML = message;
            }}
            
            // Agregar actualización a la lista
            function addUpdate(message) {{
                const list = document.getElementById('updates-list');
                const content = document.getElementById('updates-content');
                
                list.style.display = 'block';
                
                const item = document.createElement('div');
                item.className = 'update-item';
                item.textContent = `${{new Date().toLocaleTimeString()}} - ${{message}}`;
                
                content.insertBefore(item, content.firstChild);
                
                // Mantener solo últimas 5
                while (content.children.length > 5) {{
                    content.removeChild(content.lastChild);
                }}
            }}
            
            // Obtener información de batería
            async function getBattery() {{
                try {{
                    const battery = await navigator.getBattery();
                    batteryLevel = Math.round(battery.level * 100);
                    document.getElementById('battery').textContent = `${{batteryLevel}}%`;
                    
                    // Actualizar cuando cambie
                    battery.addEventListener('levelchange', () => {{
                        batteryLevel = Math.round(battery.level * 100);
                        document.getElementById('battery').textContent = `${{batteryLevel}}%`;
                    }});
                }} catch (e) {{
                    document.getElementById('battery').textContent = 'No disponible';
                }}
            }}
            
            // Enviar ubicación al servidor
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
                        document.getElementById('last-update').textContent = 
                            new Date().toLocaleTimeString();
                        
                        const address = data.address || 'Ubicación capturada';
                        setStatus(`✅ Ubicación enviada correctamente<br><small>${{address}}</small>`, 'active');
                        addUpdate(`Enviado: ${{latitude.toFixed(6)}}, ${{longitude.toFixed(6)}} (±${{Math.round(accuracy)}}m)`);
                        
                        return true;
                    }}
                }} catch (error) {{
                    console.error('Error al enviar ubicación:', error);
                    setStatus('❌ Error al enviar ubicación', 'error');
                    addUpdate('Error de conexión');
                    return false;
                }}
            }}
            
            // Capturar ubicación GPS
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
                            addUpdate(`Error: ${{error.message}}`);
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
            
            // Enviar ubicación manualmente
            async function sendLocationNow() {{
                const btn = document.getElementById('manual-btn');
                btn.disabled = true;
                btn.textContent = '📍 Enviando...';
                
                await captureLocation();
                
                btn.disabled = false;
                btn.textContent = '📍 Enviar Ubicación Ahora';
            }}
            
            // Iniciar rastreo automático
            async function startTracking() {{
                setStatus('🚀 Iniciando rastreo automático...', 'waiting');
                
                // Primera captura inmediata
                const success = await captureLocation();
                
                if (success) {{
                    // Configurar intervalo
                    trackingInterval = setInterval(async () => {{
                        await captureLocation();
                    }}, UPDATE_INTERVAL);
                    
                    const minutes = Math.round(UPDATE_INTERVAL / 60000);
                    addUpdate(`Rastreo automático activado (cada ${{minutes}} min)`);
                }}
            }}
            
            // Mantener la página activa (prevenir suspensión)
            function keepAlive() {{
                if ('wakeLock' in navigator) {{
                    navigator.wakeLock.request('screen')
                        .then(wakeLock => {{
                            console.log('Wake Lock activado');
                            addUpdate('Modo activo: pantalla no se suspenderá');
                        }})
                        .catch(err => {{
                            console.log('Wake Lock no disponible:', err);
                        }});
                }}
            }}
            
            // Inicializar
            window.addEventListener('load', async () => {{
                await getBattery();
                await startTracking();
                keepAlive();
                
                // Solicitar permisos de notificación
                if ('Notification' in window && Notification.permission === 'default') {{
                    Notification.requestPermission();
                }}
            }});
            
            // Manejar visibilidad de la página
            document.addEventListener('visibilitychange', () => {{
                if (document.hidden) {{
                    console.log('Página oculta, manteniendo rastreo');
                }} else {{
                    console.log('Página visible, rastreo activo');
                }}
            }});
            
            // Prevenir cierre accidental
            window.addEventListener('beforeunload', (e) => {{
                e.preventDefault();
                e.returnValue = '';
                return 'El rastreo GPS está activo. ¿Estás seguro de cerrar?';
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
    """Dashboard interactivo con mapa de ubicaciones en tiempo real"""
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
            }
            .header h1 {
                margin: 0;
                font-size: 2em;
            }
            .header .subtitle {
                opacity: 0.9;
                margin-top: 5px;
            }
            .container {
                display: grid;
                grid-template-columns: 300px 1fr;
                gap: 20px;
                padding: 20px;
                max-width: 1800px;
                margin: 0 auto;
                height: calc(100vh - 100px);
            }
            .sidebar {
                background: white;
                border-radius: 15px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                overflow-y: auto;
            }
            .sidebar h3 {
                color: #667eea;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 2px solid #667eea;
            }
            .device-card {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 10px;
                margin-bottom: 15px;
                cursor: pointer;
                transition: all 0.3s;
                border-left: 4px solid #667eea;
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
            }
            .device-status {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 12px;
                font-size: 0.8em;
                font-weight: 600;
                margin-top: 5px;
            }
            .status-active {
                background: #28a745;
                color: white;
            }
            .status-inactive {
                background: #dc3545;
                color: white;
            }
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
            .stat-icon {
                font-size: 2.5em;
                margin-bottom: 10px;
            }
            .stat-value {
                font-size: 2em;
                font-weight: bold;
                color: #667eea;
                margin-bottom: 5px;
            }
            .stat-label {
                color: #666;
                font-size: 0.9em;
            }
            #map {
                height: 100%;
                border-radius: 15px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .leaflet-popup-content {
                margin: 15px;
            }
            .popup-title {
                font-weight: 600;
                font-size: 1.1em;
                color: #667eea;
                margin-bottom: 10px;
            }
            .popup-info {
                margin: 5px 0;
                font-size: 0.9em;
            }
            .alerts-panel {
                position: fixed;
                top: 100px;
                right: 20px;
                width: 300px;
                max-height: 400px;
                background: white;
                border-radius: 15px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.2);
                padding: 20px;
                z-index: 1000;
                display: none;
            }
            .alerts-panel.show {
                display: block;
            }
            .alert-item {
                padding: 10px;
                margin-bottom: 10px;
                border-radius: 8px;
                border-left: 4px solid #ffc107;
                background: #fff3cd;
            }
            .alert-item.enter {
                border-color: #28a745;
                background: #d4edda;
            }
            .alert-item.exit {
                border-color: #dc3545;
                background: #f8d7da;
            }
            @media (max-width: 968px) {
                .container {
                    grid-template-columns: 1fr;
                    grid-template-rows: auto 1fr;
                }
                .sidebar {
                    max-height: 300px;
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🎯 GeoTracker Pro Dashboard V3</h1>
            <p class="subtitle">Sistema de Rastreo en Tiempo Real con Geofencing</p>
        </div>
        
        <div class="container">
            <div class="sidebar">
                <h3>📱 Dispositivos</h3>
                <div id="devices-list">
                    <p style="text-align: center; color: #666;">Cargando...</p>
                </div>
                
                <button style="
                    width: 100%;
                    padding: 12px;
                    background: #667eea;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    font-weight: 600;
                    margin-top: 15px;
                " onclick="window.location.href='/docs'">
                    ➕ Registrar Dispositivo
                </button>
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
        
        <div class="alerts-panel" id="alerts-panel">
            <h3 style="color: #667eea; margin-bottom: 15px;">🚨 Alertas Recientes</h3>
            <div id="alerts-content"></div>
        </div>
        
        <script>
            let map;
            let markers = {};
            let selectedDevice = null;
            
            // Inicializar mapa
            function initMap() {
                map = L.map('map').setView([4.6097, -74.0817], 12);
                
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap contributors',
                    maxZoom: 19
                }).addTo(map);
            }
            
            // Cargar dispositivos
            async function loadDevices() {
                try {
                    const response = await fetch('/api/devices/list');
                    const data = await response.json();
                    
                    const devicesList = document.getElementById('devices-list');
                    devicesList.innerHTML = '';
                    
                    document.getElementById('total-devices').textContent = data.total;
                    let activeCount = 0;
                    
                    data.devices.forEach(device => {
                        // Verificar si está activo hoy
                        const isActiveToday = device.last_update && 
                            new Date(device.last_update).toDateString() === new Date().toDateString();
                        
                        if (isActiveToday) activeCount++;
                        
                        const card = document.createElement('div');
                        card.className = 'device-card';
                        card.onclick = () => selectDevice(device);
                        
                        card.innerHTML = `
                            <div class="device-name">📱 ${device.name}</div>
                            <div class="device-info">${device.phone}</div>
                            <div class="device-info">
                                🔋 ${device.battery_level ? device.battery_level + '%' : 'N/A'}
                            </div>
                            <span class="device-status ${isActiveToday ? 'status-active' : 'status-inactive'}">
                                ${isActiveToday ? '● ACTIVO' : '○ Inactivo'}
                            </span>
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
                }
            }
            
            // Agregar marcador al mapa
            function addMarkerToMap(device) {
                if (markers[device.phone]) {
                    map.removeLayer(markers[device.phone]);
                }
                
                const marker = L.marker([device.latitude, device.longitude])
                    .bindPopup(`
                        <div class="popup-title">${device.name}</div>
                        <div class="popup-info">📱 ${device.phone}</div>
                        <div class="popup-info">📍 ${device.latitude.toFixed(6)}, ${device.longitude.toFixed(6)}</div>
                        <div class="popup-info">🎯 Precisión: ±${device.accuracy ? device.accuracy.toFixed(1) : 'N/A'}m</div>
                        <div class="popup-info">🔋 Batería: ${device.battery_level || 'N/A'}%</div>
                        <div class="popup-info">⏱️ ${new Date(device.last_update).toLocaleString()}</div>
                        <button onclick="viewHistory('${device.phone}')" style="
                            margin-top: 10px;
                            padding: 8px 15px;
                            background: #667eea;
                            color: white;
                            border: none;
                            border-radius: 5px;
                            cursor: pointer;
                            width: 100%;
                        ">Ver Historial</button>
                    `)
                    .addTo(map);
                
                markers[device.phone] = marker;
            }
            
            // Seleccionar dispositivo
            async function selectDevice(device) {
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
                
                // Cargar alertas del dispositivo
                await loadAlerts(device.phone);
            }
            
            // Cargar alertas
            async function loadAlerts(phone = null) {
                try {
                    let url = '/api/geofence/alerts?limit=10';
                    if (phone) url += `&phone=${phone}`;
                    
                    const response = await fetch(url);
                    const data = await response.json();
                    
                    document.getElementById('total-alerts').textContent = data.total;
                    
                    const alertsContent = document.getElementById('alerts-content');
                    alertsContent.innerHTML = '';
                    
                    if (data.total > 0) {
                        document.getElementById('alerts-panel').classList.add('show');
                        
                        data.alerts.slice(0, 5).forEach(alert => {
                            const item = document.createElement('div');
                            item.className = `alert-item ${alert.alert_type.toLowerCase()}`;
                            item.innerHTML = `
                                <strong>${alert.alert_type === 'ENTER' ? '➡️ ENTRADA' : '⬅️ SALIDA'}</strong><br>
                                <small>${alert.device_name}</small><br>
                                <small>Zona: ${alert.zone_name}</small><br>
                                <small>${new Date(alert.timestamp).toLocaleString()}</small>
                            `;
                            alertsContent.appendChild(item);
                        });
                    }
                } catch (error) {
                    console.error('Error al cargar alertas:', error);
                }
            }
            
            // Ver historial de dispositivo
            function viewHistory(phone) {
                window.open(`/history/${phone}`, '_blank');
            }
            
            // Cargar estadísticas generales
            async function loadStats() {
                try {
                    const response = await fetch('/api/locations/stats');
                    const data = await response.json();
                    document.getElementById('total-locations').textContent = data.total || 0;
                } catch (error) {
                    console.error('Error al cargar estadísticas:', error);
                }
            }
            
            // Inicializar
            window.addEventListener('load', () => {
                initMap();
                loadDevices();
                loadStats();
                loadAlerts();
                
                // Auto-refresh cada 30 segundos
                setInterval(() => {
                    loadDevices();
                    loadStats();
                    if (selectedDevice) {
                        loadAlerts(selectedDevice.phone);
                    }
                }, 30000);
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