import pandas as pd
import numpy as np
import altair as alt
import streamlit as st
from scapy.all import sniff, IP
import threading
from datetime import datetime
import logging
import time
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import IsolationForest
from keras.layers import Input, LSTM, Dense
from keras.models import Sequential
from sklearn.cluster import DBSCAN

INDUSTRIAL_PROTOCOLS = {
    502: "Modbus",        
    44818: "EtherNet/IP", 
    2222: "PROFINET",     
    102: "S7",            
    4840: "OPC-UA",       
    5050: "CIP",          
    47808: "BACnet",      
    161: "SNMP",          
    20000: "DNP3",        
    55000: "IEC 61850"    
}

logging.basicConfig(
    filename='industrial_network_security.log', 
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s: %(message)s'
)

class ContadorTiempo:
    def __init__(self, duracion, captura):
        self.duracion = duracion
        self.captura = captura

    def iniciar_contador(self):
        contador = st.empty()
        progreso = st.progress(0)

        for seg in range(self.duracion, 0, -1):
            if not self.captura.capturando:
                break
            contador.markdown(f"### Tiempo restante para finalizar la captura: **{seg} segundos**")
            progreso.progress((self.duracion - seg) / self.duracion) 
            time.sleep(1)
        contador.markdown("### Captura finalizada.")
        progreso.progress(1) 

class IndustrialProtocolAnalyzer:
    @staticmethod
    def detect_industrial_protocol(packet):
        protocol_info = {
            "name": None,
            "risk_level": "Low",
            "details": {}
        }
        
        if IP in packet:
            for port, proto_name in INDUSTRIAL_PROTOCOLS.items():
                if packet[IP].dport == port or packet[IP].sport == port:
                    protocol_info["name"] = proto_name
                    
                    risk_mapping = {
                        "Modbus": "High",
                        "S7": "Critical",
                        "PROFINET": "High",
                        "EtherNet/IP": "Medium",
                        "OPC-UA": "Medium",
                        "DNP3": "High",
                        "IEC 61850": "Critical"
                    }
                    
                    protocol_info["risk_level"] = risk_mapping.get(proto_name, "Low")
                    protocol_info["details"] = {
                        "source_ip": packet[IP].src,
                        "destination_ip": packet[IP].dst,
                        "port": port
                    }
                    
                    if protocol_info["risk_level"] in ["High", "Critical"]:
                        logging.warning(f"Detected {proto_name} communication: {protocol_info['details']}")
                    
                    break
        
        return protocol_info

    @staticmethod
    def detectar_eventos_de_seguridad(packet):
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            port = packet[IP].dport if hasattr(packet[IP], 'dport') else None

            if source_ip == "IP_RIESGOSA" or destination_ip == "IP_RIESGOSA": 
                logging.warning(f"Alerta de seguridad: Tráfico sospechoso desde {source_ip} a {destination_ip} en puerto {port}")
                return True 
        return False
        

class ProcesadorDeLogs:
    def __init__(self, archivo_log):
        self.archivo_log = archivo_log

    def leer_logs(self):
        with open(self.archivo_log, 'r') as f:
            logs = f.readlines()

        eventos = []
        for log in logs:
            if 'Alerta de seguridad' in log:
                timestamp = log.split(' - ')[0] if ' - ' in log else None
                eventos.append({'timestamp': timestamp, 'alerta': 1}) 
        return eventos
  
class CapturaDeTraficoReal:
    def __init__(self, duracion=60, archivo_log="industrial_network_security.log"):
        self.duracion = duracion
        self.datos = []
        self.capturando = False
        self.protocol_analyzer = IndustrialProtocolAnalyzer()
        self.procesador_logs = ProcesadorDeLogs(archivo_log)
        self.eventos_logs = self.procesador_logs.leer_logs()

    def capturar_paquete(self, paquete):       
        self.eventos_logs = self.procesador_logs.leer_logs()
        try:
            if IP in paquete:
                if hasattr(paquete[IP], 'dport') and hasattr(paquete[IP], 'sport'):
                    timestamp = datetime.now()
                    protocol_info = self.protocol_analyzer.detect_industrial_protocol(paquete)

                    alerta_de_seguridad = 0
                    for evento in self.eventos_logs:
                        if evento['timestamp'] and evento['timestamp'] in str(timestamp):
                            alerta_de_seguridad = evento['alerta']

                    self.datos.append({
                        "timestamp": timestamp,
                        "ip_src": paquete[IP].src,
                        "ip_dst": paquete[IP].dst,
                        "protocolo": paquete[IP].proto,
                        "longitud": len(paquete),
                        "industrial protocol": protocol_info["name"] or "No Industrial",
                        "protocol_risk": protocol_info["risk_level"],
                        "protocol_details": str(protocol_info["details"]),
                        "alerta_de_seguridad": alerta_de_seguridad 
                    })
        except Exception as e:
            logging.error(f"Error al capturar paquete: {e}")

    def iniciar_captura(self):
        try:
            self.capturando = True
            sniff(prn=self.capturar_paquete, timeout=self.duracion)
            self.capturando = False
        except Exception as e:
            logging.error(f"Error al iniciar la captura: {e}")

    def obtener_datos(self):
        try:
            return pd.DataFrame(self.datos)
        except Exception as e:
            logging.error(f"Error al obtener los datos: {e}")
            return pd.DataFrame()

class ModeloPredictivo:
    def __init__(self, datos):
        self.datos = datos
        self.modelo = None

    def preprocesar_datos(self):
        try:
            self.datos['timestamp'] = pd.to_datetime(self.datos['timestamp'])
            self.datos.set_index('timestamp', inplace=True)
            
            if len(self.datos) < 501:
                  logging.error(f"Datos insuficientes para preprocesar. Solo hay {len(self.datos)} registros.")
                  return None, None, None

            data = self.datos[['longitud', 'alerta_de_seguridad']].values
            if np.isnan(data).any() or np.isinf(data).any():
                  logging.error("Datos contienen valores nulos o infinitos")
                  return None, None, None
            
            scaler = MinMaxScaler(feature_range=(0, 1))
            data_scaled = scaler.fit_transform(data)

            X, y = [], []
            for i in range(500, len(data_scaled)): 
                X.append(data_scaled[i-500:i, :]) 
                y.append(data_scaled[i, 0])  

            if len(X) == 0 or len(y) == 0:
                  logging.error("No se pudieron crear secuencias de entrenamiento")
                  return None, None, None
            X = np.array(X)
            y = np.array(y)
            
            X = X.reshape(X.shape[0], X.shape[1], X.shape[2])  # Ajuste de dimensiones
            
            logging.info(f"Datos preprocesados. X shape: {X.shape}, y shape: {y.shape}")
            return X, y, scaler
        except Exception as e:
            logging.error(f"Error al preprocesar los datos: {e}")
            return None, None, None

    def entrenar_modelo(self):
        try:
              
            logging.info("Iniciando entrenamiento del modelo")  
            X, y, scaler = self.preprocesar_datos()
            
            if X is None or y is None or len(X) == 0:
                logging.error("Preprocesamiento de datos fallido")
                return False
          
            if len(X) == 0 or len(y) == 0:
                  logging.error("No hay datos suficientes para entrenar")
                  return False

            model = Sequential([
                  Input(shape=(500, 2)),
                  LSTM(50, return_sequences=True),
                  LSTM(50, return_sequences=False),
                  Dense(1)
            ])
            model.compile(optimizer='adam', loss='mean_squared_error')
            
            history = model.fit(
                  X, y, 
                  epochs=10, 
                  batch_size=32, 
                  verbose=1, 
                  validation_split=0.2 
            )

            self.model = model
            self.scaler = scaler
 
            logging.info(f"Entrenamiento completado. Última pérdida: {history.history['loss'][-1]}")
            return True
        except Exception as e:
                logging.error(f"Error al entrenar el modelo LSTM: {e}")
                return False

    def predecir(self, pasos=100):
        try:
              
            if not hasattr(self, 'model') or not hasattr(self, 'scaler'):
                  logging.error("El modelo no ha sido entrenado correctamente")
                  return pd.DataFrame()  
            
            if len(self.datos) < 500:
                  logging.error(f"Datos insuficientes para predicción. Solo hay {len(self.datos)} registros.")
                  return pd.DataFrame()

            last_500 = self.datos[['longitud', 'alerta_de_seguridad']].tail(500).values
            
            print("Últimos 500 datos:")
            print(last_500)
            print("Forma de last_500:", last_500.shape)
            
            last_500_scaled = self.scaler.transform(last_500)
            last_500_scaled = last_500_scaled.reshape(1, 500, 2) 

            predictions = []
            input_data = last_500_scaled
            for _ in range(pasos):
                pred_scaled = self.model.predict(input_data) 
                predictions.append(pred_scaled[0, 0]) 
                
                print(pred_scaled[0].shape)
                next_input = np.append(input_data[:, 1:, :], np.reshape(np.hstack((pred_scaled[0], 0)), (1, 1, input_data.shape[2])), axis=1)
                input_data = next_input
                
            predictions_scaled = np.array(predictions).reshape(-1, 1)
            predictions_original = self.scaler.inverse_transform(np.hstack((predictions_scaled, np.zeros((len(predictions_scaled), 1)))))[:, 0]   
            
            ultima_marca_tiempo = self.datos.index[-1]
            timestamps = pd.date_range(start=ultima_marca_tiempo, periods=pasos, freq='14.4min')     
            predicciones_df = pd.DataFrame({'timestamp': timestamps,'prediccion_longitud': predictions_original})
    
            logging.info(f"Predicción generada. {len(predicciones_df)} puntos predichos")
            return predicciones_df
        except Exception as e:
            logging.error(f"Error al realizar la predicción: {e}")
            import traceback
            logging.error(traceback.format_exc())
            return pd.DataFrame()

   
class DetectorDeAnomalias:
    def __init__(self, data):
        self.data = data.copy()

    def detectar_anomalias(self, umbral=0.02, umbral_prediccion=3):
        """
        Advanced anomaly detection with industrial context
        """
        if self.data.empty:
            return self.data
        
        if 'timestamp' in self.data.columns:
            self.data['timestamp'] = pd.to_datetime(self.data['timestamp'])
        
        length_columns = [
            'prediccion_longitud', 
            'longitud', 
            'prediccion_longitud', 
            'length', 
            'packet_length', 
            'tamaño_paquete' 
        ]
        
        length_column = None
        for col in length_columns:
            if col in self.data.columns:
                length_column = col
                break
        
        if length_column is None:
            logging.error(f"No length column found. Available columns: {list(self.data.columns)}")
            return self.data
        
        try:
            self.data[length_column] = pd.to_numeric(self.data[length_column], errors='coerce')
        except Exception as e:
            logging.error(f"Error converting length column to numeric: {e}")
            return self.data
      
        self.data = self.data.dropna(subset=[length_column])
        
        try:
            X = self.data[[length_column]]
            clf = IsolationForest(contamination=umbral, n_estimators=100, random_state=42)
            self.data['anomalia'] = clf.fit_predict(X)
            self.data['anomalia'] = self.data['anomalia'].map({1: 0, -1: 1})
        except Exception as e:
            logging.error(f"Error in anomaly detection: {e}")
        if 'prediccion_longitud' in self.data.columns:
            self.data['anomalia'] = self.data['anomalia'] | (self.data['prediccion_longitud'] > umbral_prediccion)
        return self.data

class AplicacionMonitoreoRed:
    def __init__(self):
        self.captura_trafico = CapturaDeTraficoReal()
        
    def ejecutar(self):
        st.set_page_config(
            page_title="NetAnalyzer AI",
            page_icon="📈",
            layout="wide",
            initial_sidebar_state="expanded"
        )       
        col1, col2 = st.columns([2, 1]) 
        with col1: 
            st.image('C:\\Users\\Brendaranza\\Desktop\\POO\\compu.png', use_column_width=True)
            st.markdown(
                """
                <style>
                .custom-title {
                    font-family: 'Tahoma', sans-serif;
                    font-size: 50px;
                    color: #f5f5f5;
                    text-align: center;
                }            
                .custom-subtitle {
                    font-family: 'Courier New', monospace;
                    font-size: 20px;
                    color: #36ffdb;
                    text-align: center;
                }
                </style>
                <div>
                    <h1 class="custom-title">NetAnalyzer AI</h1>
                    <h3 class="custom-subtitle">Análisis predictivo de tráfico de red con IA</h3>
                </div>
                """,
                unsafe_allow_html=True
            )        
        
        with col2:  
            st.markdown("""
            <div style="
                background-color: #33373e; 
                border-radius: 8px; 
                padding: 20px; 
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                text-align: center;
            ">
                <h3>Bienvenid@</h3>
                <p>Este sistema realiza un análisis predictivo del tráfico de red y detecta anomalías en tiempo real, fundamental para detectar posibles riesgos y mantener la seguridad de los sistemas industriales.</p>
                <h4>¿Cómo funciona?</h4>
                <ul style="text-align: left; margin-left: 20px;">
                    <li><b>Captura de tráfico:</b> Monitoreamos el tráfico de red, detectamos protocolos industriales y analizamos patrones anómalos.</li>
                    <li><b>Análisis predictivo:</b> Usamos un modelo de inteligencia artificial para predecir el volumen de tráfico futuro.</li>
                    <li><b>Detección de anomalías:</b> Identificamos tráfico sospechoso basado en patrones inusuales.</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

        duracion = st.slider("Selecciona la duración de la captura (en segundos)", min_value=30, max_value=900, value=60, step=10)

        estado_actividad = st.empty()
        chart_prediccion = None

        if "captura_en_proceso" not in st.session_state:
            st.session_state["captura_en_proceso"] = False

        if st.button("Iniciar Captura")and not st.session_state["captura_en_proceso"]:
            st.subheader("Preparando captura de tráfico...")
            estado_actividad.markdown("🟢 **Captura en progreso...**")
            
            self.captura_trafico.duracion = duracion 
            hilo_captura = threading.Thread(target=self.captura_trafico.iniciar_captura)
            hilo_captura.start()

            contador = ContadorTiempo(self.captura_trafico.duracion, self.captura_trafico)
            contador.iniciar_contador()

            while self.captura_trafico.capturando:
                estado_actividad.markdown("🟡 **Captura en curso...**")
                time.sleep(1)

            hilo_captura.join()
            data = self.captura_trafico.obtener_datos()

            if data.empty:
                st.warning("No se capturó tráfico. Intenta generar actividad de red (navegar en internet, etc.).")
                estado_actividad.markdown("🔴 **No se capturó tráfico.**")
                st.session_state["captura_en_proceso"] = False
                return
          
            col1, col2 = st.columns([1, 1])
            
            with col1:
                  st.subheader("📊 Análisis de Protocolos Industriales")
                  protocol_distribution = data['industrial protocol'].value_counts()
                  st.bar_chart(protocol_distribution, color='#e58fdc')

                  with st.expander("¿Qué significa este gráfico?"):
                        st.markdown("""
                        Este gráfico muestra la distribución de los protocolos industriales detectados en el tráfico de red.
                        - Un número alto de paquetes de un protocolo puede indicar un uso intensivo de ese protocolo.
                        - Si ves un pico inusual de tráfico en protocolos críticos, podría ser indicativo de un problema.
                        """)
      
            detector = DetectorDeAnomalias(data)
            datos_con_anomalias = detector.detectar_anomalias()

            total_anomalias = datos_con_anomalias['anomalia'].sum()
            if total_anomalias > 0:
                st.info(f"⚠️ **Se detectaron {total_anomalias} anomalías en el tráfico de red.**")
                estado_actividad.markdown("🔴 **Captura finalizada con anomalías.**")
            else:
                st.success("✅ No se detectaron anomalías en el tráfico de red.")
                estado_actividad.markdown("🟢 **Captura finalizada sin anomalías.**")
            
            with col2:
                  st.subheader("📈 Gráfico de Volumen de Tráfico")
                  chart_trafico = alt.Chart(datos_con_anomalias).mark_line(color='#52b2a1').encode(
                  x=alt.X('timestamp:T', title="⏰ Tiempo", scale=alt.Scale(zero=False)),
                  y=alt.Y('longitud:Q', title="📦 Longitud de Paquete (bytes)", scale=alt.Scale(zero=False)),
                  tooltip=['timestamp:T', 'longitud:Q']
                  ).properties(
                  width="container",
                  height=400,
                  title=" Volumen de Tráfico de Red"
                  ).interactive()

                  anomalies = alt.Chart(datos_con_anomalias[datos_con_anomalias['anomalia'] == 1]).mark_circle(size=65, color='#f5409d').encode(
                  x='timestamp:T',
                  y='longitud:Q',
                  tooltip=['timestamp:T', 'longitud:Q']
                  )
                  st.altair_chart(chart_trafico + anomalies, use_container_width=True)
                  with st.expander("Explicación de Protocolos Industriales"):
                        st.markdown("""
                        En esta sección, se proporciona una descripción de los principales protocolos industriales utilizados en el tráfico de red.

                        **Modbus (502):** Protocolo de comunicación ampliamente utilizado en la automatización industrial. Generalmente se usa para la comunicación entre dispositivos como PLCs y sistemas SCADA.

                        **EtherNet/IP (44818):** Un protocolo basado en Ethernet para la comunicación en redes industriales, especialmente utilizado en sistemas de control y automatización.

                        **PROFINET (2222):** Protocolo utilizado en la automatización industrial para comunicación en tiempo real entre dispositivos de control y máquinas.

                        **S7 (102):** Utilizado en la comunicación con los controladores lógicos programables (PLC) de Siemens, especialmente en la serie S7.

                        **OPC-UA (4840):** Plataforma de comunicación abierta y flexible, utilizada para la integración de sistemas en la automatización industrial, compatible con múltiples plataformas.

                        **CIP (5050):** Protocolo de comunicación utilizado en redes industriales para dispositivos de control como sensores y actuadores.

                        **BACnet (47808):** Protocolo utilizado para la automatización y control de edificios, especialmente en sistemas de calefacción, ventilación y aire acondicionado (HVAC).

                        **SNMP (161):** Protocolo utilizado para la gestión y monitoreo de dispositivos de red, como switches y routers.

                        **DNP3 (20000):** Protocolo de comunicación utilizado en sistemas de automatización de subestaciones eléctricas y sistemas SCADA.

                        **IEC 61850 (55000):** Un estándar internacional para la comunicación y control de equipos eléctricos en redes de energía eléctrica.
                        """)

            st.subheader("🔍 Métricas Detalladas")
            st.markdown("""
                  <style>
                  .metric-box {
                        background-color: #f1f1f1;
                        border-radius: 8px;
                        padding: 10px;
                        text-align: center;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                  }
                  .metric-box h3 {
                        margin: 0;
                        font-size: 18px;
                        color: #333;
                  }
                  .metric-box p {
                        font-size: 24px;
                        color: #4CAF50;
                        font-weight: bold;
                  }
                  </style>
            """, unsafe_allow_html=True)
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.markdown('<div class="metric-box"><h3>Total de anomalías detectadas</h3><p>{}</p></div>'.format(total_anomalias), unsafe_allow_html=True)

            with col2:
                st.markdown('<div class="metric-box"><h3>Promedio de tamaño de paquete</h3><p>{:.2f} bytes</p></div>'.format(data['longitud'].mean()), unsafe_allow_html=True)

            with col3:
                st.markdown('<div class="metric-box"><h3>Tamaño máximo de paquete</h3><p>{} bytes</p></div>'.format(data['longitud'].max()), unsafe_allow_html=True)


            with col4:
                st.markdown('<div class="metric-box"><h3>Tamaño mínimo de paquete</h3><p>{} bytes</p></div>'.format(data['longitud'].min()), unsafe_allow_html=True)

            with st.expander("¿Por qué son importantes estas métricas?"):
                st.markdown("""
                Las métricas de tráfico son cruciales para comprender el comportamiento de la red:
                - **Promedio de tamaño de paquete:** Nos indica el tamaño típico de los paquetes que circulan en la red.
                - **Tamaño máximo de paquete:** Ayuda a identificar si algún paquete es inusualmente grande, lo que podría indicar un problema.
                - **Tamaño mínimo de paquete:** Similarmente, un paquete inusualmente pequeño podría ser un indicio de una técnica de evasión utilizada en un ataque.
                """)

            porcentaje_anomalias = (total_anomalias / len(datos_con_anomalias)) * 100
            st.markdown(f"⚠️ **Porcentaje de tráfico anómalo:** {porcentaje_anomalias:.2f}%")
            
            col1, col2 = st.columns([1, 1])
            with col1:
                        # Evaluación de riesgos
                        st.subheader("🛡️ Evaluación de Riesgos por Protocolo")
                        risk_data = datos_con_anomalias[datos_con_anomalias['industrial protocol'] != 'No Industrial'].copy()


                        # Mapeo de los niveles de riesgo
                        risk_mapping = {
                              "Low": 1,
                              "Medium": 2,
                              "High": 3,
                              "Critical": 4
                        }
                        risk_data['protocol risk score'] = risk_data['protocol_risk'].map(risk_mapping)

                        risk_chart = alt.Chart(risk_data).mark_bar().encode(
                              x='industrial protocol:N',
                              y='sum(protocol risk score):Q',
                              color=alt.Color('sum(protocol risk score):Q', scale=alt.Scale(scheme='redyellowgreen')),
                              tooltip=['industrial protocol', 'sum(protocol risk score)']
                        ).properties(
                              title='Niveles de Riesgo por Protocolo Industrial'
                        ).interactive()
                              
                        st.altair_chart(risk_chart, use_container_width=True)
                  
            with st.expander("¿Qué significa el puntaje de riesgo (Risk Score)?"):
                  st.markdown("""
                        El **puntaje de riesgo** (Risk Score) se calcula para cada protocolo industrial basado en el comportamiento del tráfico y su relación con patrones históricos de tráfico. 
                        Este puntaje ayuda a evaluar el nivel de riesgo asociado con cada protocolo, lo cual es útil para identificar posibles amenazas o anomalías en el tráfico de la red. 

                        **¿Cómo se calcula?**
                        El puntaje de riesgo se asigna en función de ciertos factores, como la frecuencia de aparición del protocolo, el volumen de tráfico, y la presencia de patrones anómalos. 
                        A continuación, te explicamos los niveles de riesgo asociados:

                        - **Bajo (Low)**: Este protocolo genera tráfico de red normal y no presenta patrones inusuales. El riesgo es mínimo.
                        - **Moderado (Medium)**: Se observan algunas fluctuaciones en el tráfico o patrones inusuales, pero no hay evidencia clara de una amenaza.
                        - **Alto (High)**: Hay patrones sospechosos de tráfico que podrían indicar problemas potenciales, como picos inusuales en el volumen de tráfico.
                        - **Crítico (Critical)**: El protocolo presenta tráfico altamente anómalo, lo cual podría indicar un ataque o una anomalía grave que debe ser investigada inmediatamente.

                        **¿Por qué es importante?**
                        Al identificar el riesgo de cada protocolo, podemos priorizar los recursos para investigar aquellos con puntajes más altos. Esto permite una detección más rápida de posibles ataques o problemas en la red, mejorando así la seguridad y el rendimiento de la infraestructura industrial.
                  """)       
            
            with col2:
                  try:
                        st.subheader("🔮 Predicción de Volumen de Tráfico")
                        pasos_prediccion = 24 * (60 // 15)  
                        modelo_predictivo = ModeloPredictivo(datos_con_anomalias)
                        modelo_entrenado = modelo_predictivo.entrenar_modelo()

                        if modelo_entrenado:
                              predicciones = modelo_predictivo.predecir(pasos=pasos_prediccion)
                              
                              if predicciones.empty:
                                    st.warning("No se generaron predicciones. Verifica el modelo o los datos de entrada.")
                                    return
                              
                              if 'timestamp' not in predicciones.columns:
                                    ultima_fecha = datos_con_anomalias['timestamp'].iloc[-1] if 'timestamp' in datos_con_anomalias.columns else pd.Timestamp.now()
                                    predicciones['timestamp'] = pd.date_range(start=ultima_fecha, periods=len(predicciones), freq='15T')
                              
                              dbscan_model = DBSCAN(eps=0.8, min_samples=2)
                              predicciones['anomaly'] = dbscan_model.fit_predict(predicciones[['prediccion_longitud']])

                              chart_prediccion = alt.Chart(predicciones).mark_line(color='#ff7f0e').encode(
                                    x=alt.X('timestamp:T', title="⏰ Tiempo Futuro"),
                                    y=alt.Y('prediccion_longitud:Q', title="📦 Longitud de Paquete (bytes)"),
                                    tooltip=['timestamp:T', 'prediccion_longitud:Q']
                              ).properties(
                                    width=800,
                                    height=400,
                                    title="📈 Predicción de Volumen de Tráfico Futuro"
                              ).interactive()

                              predicciones_anomalas = alt.Chart(predicciones[predicciones['anomaly'] == -1]).mark_circle(size=60, color='red').encode(
                                    x='timestamp:T',
                                    y='prediccion_longitud:Q',
                                    tooltip=['timestamp:T', 'prediccion_longitud:Q']
                              )

                              st.altair_chart(chart_prediccion + predicciones_anomalas, use_container_width=True)

                        else:
                              st.warning("No se pudo entrenar el modelo predictivo.")

                  except Exception as e:
                        st.error(f"Error general en la sección de predicción: {e}")
                        import traceback
                        st.error(traceback.format_exc())
 
if __name__ == "__main__":
    app = AplicacionMonitoreoRed()
    app.ejecutar()
