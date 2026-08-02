import re
import folium
import geoip2.database

# Ruta a tu base de datos local GeoLite2-City.mmdb de MaxMind
GEOIP_DB_PATH = "GeoLite2-City.mmdb"

# Nombre del archivo de salida
OUTPUT_HTML = "mapa_peticiones.html"

# Datos de entrada en bruto (puedes reemplazarlo por la lectura de un archivo)
#data_input = "top_hits_ips.txt"
with open("top_hits_ips.txt", "r") as f:
    data_input = f.read()


def parse_data(text):
    """Extrae pares (peticiones, ip) del texto introducido."""
    pattern = re.compile(r"(\d+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    items = []
    for line in text.strip().splitlines():
        match = pattern.search(line)
        if match:
            requests_count = int(match.group(1))
            ip = match.group(2)
            items.append((ip, requests_count))
    return items


def main():
    parsed_items = parse_data(data_input)

    # Crear mapa centrado globalmente
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="cartodbpositron")

    # Abrir la base de datos GeoLite2
    with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
        for ip, count in parsed_items:
            try:
                response = reader.city(ip)
                lat = response.location.latitude
                lon = response.location.longitude

                if lat is None or lon is None:
                    continue

                country = response.country.name or "Desconocido"
                city = response.city.name or "Desconocida"

                # Calcular el radio visual según el número de peticiones
                # Se aplica una escala simple para que los marcadores no sean demasiado grandes ni pequeños
                radius = max(5, min(25, count / 150))

                # Definir color según nivel de tráfico / peticiones
                if count >= 2000:
                    color = "#d9534f"  # Rojo
                elif count >= 1800:
                    color = "#f0ad4e"  # Naranja
                else:
                    color = "#0275d8"  # Azul

                # HTML para el popup cuando se hace clic en el punto
                popup_html = f"""
                <div style="font-family: Arial, sans-serif; font-size: 13px; line-height: 1.5;">
                    <b style="font-size: 14px; color: #333;">IP: {ip}</b><br/>
                    <b>Peticiones:</b> <span style="color: #d9534f; font-weight: bold;">{count:,}</span><br/>
                    <b>Ubicación:</b> {city}, {country}<br/>
                    <b>Coordenadas:</b> {lat:.4f}, {lon:.4f}
                </div>
                """

                # Texto que se muestra al pasar el cursor (tooltip)
                tooltip_text = f"IP: {ip} | Peticiones: {count:,}"

                # Agregar el círculo al mapa
                folium.CircleMarker(
                    location=[lat, lon],
                    radius=radius,
                    popup=folium.Popup(popup_html, max_width=300),
                    tooltip=tooltip_text,
                    color=color,
                    fill=True,
                    fill_color=color,
                    fill_opacity=0.6,
                ).add_to(m)

            except geoip2.errors.AddressNotFoundError:
                print(f"[!] IP no encontrada en GeoLite2: {ip}")
            except Exception as e:
                print(f"[!] Error procesando {ip}: {e}")

    # Guardar el mapa generado
    m.save(OUTPUT_HTML)
    print(
        f"[+] Mapa generado con éxito: {OUTPUT_HTML} ({len(parsed_items)} IPs procesadas)"
    )


if __name__ == "__main__":
    main()