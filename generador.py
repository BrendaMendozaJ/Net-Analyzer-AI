from scapy.all import IP, TCP, send
import time

def generar_trafico_relevante(destino, protocolos, cantidad_paquetes):
    """
    Genera tráfico simulado hacia puertos específicos.
    
    Args:
        destino (str): Dirección IP del destino.
        protocolos (list): Lista de puertos de protocolos industriales.
        cantidad_paquetes (int): Número de paquetes a enviar por protocolo.
    """
    for puerto in protocolos:
        print(f"Generando tráfico hacia {destino}:{puerto}")
        for i in range(cantidad_paquetes):
            # Crear un paquete IP/TCP
            paquete = IP(dst=destino)/TCP(dport=puerto, sport=12345+i)
            send(paquete, verbose=False)
            time.sleep(0.1)  # Breve pausa para evitar saturación

    print("Tráfico simulado generado con éxito.")

if __name__ == "__main__":
    # Dirección IP del destino (puede ser localhost para pruebas)
    ip_destino = "192.168.1.10"  # Cambiar por la dirección real

    # Puertos de protocolos industriales relevantes
    puertos_protocolos = [
        502,    # Modbus
        44818,  # EtherNet/IP
        2222,   # CIP
        102,    # S7comm
        4840,   # OPC-UA
        47808,  # BACnet
        161,    # SNMP
        55000,
        20000,
        5050,
    ]

    # Número de paquetes por protocolo
    paquetes_por_protocolo = 800
    # Generar tráfico
    generar_trafico_relevante(ip_destino, puertos_protocolos, paquetes_por_protocolo)