import concurrent.futures
import socket
import pandas as pd
import folium
from folium.plugins import MarkerCluster
import geoip2.database

# Archivos de entrada y bases de datos locales MaxMind (.mmdb)
INPUT_FILE = 'ips.txt'
GEO_CITY_DB = 'GeoLite2-City.mmdb'
GEO_ASN_DB = 'GeoLite2-ASN.mmdb'

OUTPUT_CSV = 'ips_procesadas.csv'
OUTPUT_MAP = 'mapa_ips.html'

# Instanciar los lectores de base de datos en modo lectura global
city_reader = geoip2.database.Reader(GEO_CITY_DB)
asn_reader = geoip2.database.Reader(GEO_ASN_DB)

def get_rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

def get_ip_info_local(ip):
    rdns = get_rdns(ip)
    
    country = 'Unknown'
    city = 'Unknown'
    lat, lon = 0.0, 0.0
    asn = 'Unknown'
    isp = 'Unknown'

    # Consulta GeoIP2 City
    try:
        city_response = city_reader.city(ip)
        country = city_response.country.name or 'Unknown'
        city = city_response.city.name or 'Unknown'
        if city_response.location.latitude and city_response.location.longitude:
            lat = city_response.location.latitude
            lon = city_response.location.longitude
    except Exception:
        pass

    # Consulta GeoIP2 ASN
    try:
        asn_response = asn_reader.asn(ip)
        asn_number = asn_response.autonomous_system_number
        asn_org = asn_response.autonomous_system_organization or 'Unknown'
        
        asn = f"AS{asn_number} {asn_org}" if asn_number else asn_org
        isp = asn_org
    except Exception:
        pass

    return {
        'ip': ip,
        'rdns': rdns,
        'country': country,
        'city': city,
        'lat': lat,
        'lon': lon,
        'asn': asn,
        'isp': isp
    }

def main():
    with open(INPUT_FILE, 'r') as f:
        ip_list = [line.strip() for line in f if line.strip()]

    print(f"Procesando {len(ip_list)} IPs usando bases de datos locales MaxMind...")

    data = []
    # Usamos concurrencia principalmente para resolver el rDNS de socket sin bloquear
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(get_ip_info_local, ip_list)
        for res in results:
            data.append(res)

    # Cerrar descriptores de ficheros de MaxMind
    city_reader.close()
    asn_reader.close()

    # Guardar en CSV
    df = pd.DataFrame(data)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Datos guardados en {OUTPUT_CSV}")

    # Generar Mapa Interactivo con Folium
    mapa = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
    marker_cluster = MarkerCluster().add_to(mapa)

    for idx, row in df.iterrows():
        if row['lat'] != 0.0 and row['lon'] != 0.0:
            popup_text = f"""
            <b>IP:</b> {row['ip']}<br>
            <b>rDNS:</b> {row['rdns']}<br>
            <b>País:</b> {row['country']}<br>
            <b>Ciudad:</b> {row['city']}<br>
            <b>ASN:</b> {row['asn']}
            """
            folium.CircleMarker(
                location=[row['lat'], row['lon']],
                radius=4,
                popup=folium.Popup(popup_text, max_width=300),
                color="#3186cc",
                fill=True,
                fill_opacity=0.7
            ).add_to(marker_cluster)

    mapa.save(OUTPUT_MAP)
    print(f"Mapa interactivo guardado en {OUTPUT_MAP}")

if __name__ == '__main__':
    main()