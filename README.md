# **NetAnalyzer AI** 🖥️⚡

**NetAnalyzer AI** es un sistema de análisis predictivo de tráfico de red que utiliza **Machine Learning** para la detección de anomalías y la predicción del tráfico futuro en redes industriales. Este proyecto está diseñado para ayudar a mejorar la seguridad y optimizar el rendimiento en redes industriales mediante la detección temprana de patrones inusuales y la anticipación de problemas futuros.

## **Características del Proyecto**

- **Detección de Protocolos Industriales**: Identifica los protocolos industriales utilizados en el tráfico de red, como Modbus, EtherNet/IP, y OPC-UA.
- **Predicción de Volumen de Tráfico**: Utiliza un modelo de red neuronal **LSTM** (Long Short-Term Memory) para predecir el volumen de tráfico futuro basado en datos históricos.
- **Detección de Anomalías**: Aplica el algoritmo **Isolation Forest** para identificar puntos de tráfico de red inusuales que pueden indicar posibles amenazas.
- **Visualización Interactiva**: Ofrece gráficos en tiempo real para analizar el tráfico de red y la distribución de protocolos utilizando **Streamlit** y **Altair**.
- **Alertas de Seguridad**: Genera alertas basadas en el tráfico sospechoso y posibles riesgos detectados en el tráfico de red.

## **Tecnologías Utilizadas** 🧠💻

- **Machine Learning**: LSTM, Isolation Forest.
- **Python Libraries**: 
  - **Scikit-learn**: Para la implementación de Isolation Forest.
  - **Keras** y **TensorFlow**: Para la construcción y entrenamiento del modelo LSTM.
  - **Streamlit**: Para la creación de una interfaz de usuario interactiva.
  - **Altair**: Para la creación de gráficos y visualizaciones.
  - **Pandas**: Para el manejo y procesamiento de datos.
  - **NumPy**: Para el manejo de operaciones matemáticas y estadísticas.

### **Requisitos del Sistema**

Asegúrate de tener instalado Python 3.7 o superior. Además, se recomienda usar un entorno virtual para instalar las dependencias del proyecto.
- pip install 
streamlit
scikit-learn
tensorflow
keras
altair
pandas
numpy
scapy

## **Características de la Aplicación**
Captura de Tráfico: Puedes capturar tráfico de red en tiempo real durante un intervalo definido (por ejemplo, 60 segundos). El tráfico capturado se analizará para detectar los protocolos industriales utilizados y cualquier anomalía.

Análisis de Protocolos: Se muestra un gráfico de barras con la distribución de los protocolos industriales presentes en el tráfico de red. Además, puedes hacer clic en cada protocolo para obtener más detalles sobre el tráfico asociado.

Predicción de Tráfico Futuro: El sistema utiliza un modelo LSTM para predecir el volumen futuro del tráfico de red en base a datos históricos, lo que te permite anticipar posibles problemas o sobrecargas.

Detección de Anomalías: El algoritmo Isolation Forest se aplica para identificar puntos de tráfico que no se ajustan a los patrones normales, lo que puede indicar posibles amenazas o comportamientos inusuales.

## **Estructura del Proyecto** 🗂️

NetAnalyzer-AI/
│
├── app.py                 # Script principal que ejecuta la aplicación Streamlit
├── model.py               # Contiene el código para la construcción y entrenamiento del modelo LSTM
├── anomaly_detector.py    # Implementación de la detección de anomalías usando Isolation Forest
├── traffic_capture.py     # Código para capturar el tráfico de red en tiempo real
├── utils.py               # Funciones auxiliares para el procesamiento de datos
├── requirements.txt       # Archivo con las dependencias del proyecto
├── README.md              # Este archivo
└── logs/                  # Carpeta donde se guardan los logs generados durante la ejecución

## Hiperparámetros ⚙️

El sistema utiliza varios hiperparámetros clave para configurar los modelos de predicción y detección de anomalías. Entre ellos se encuentran:

### LSTM:
- sequence_length = 500
- units = 50
- epochs = 10
- batch_size = 32

### Isolation Forest:

- n_estimators = 100
- contamination = 0.02
- random_state = 42

Estos hiperparámetros pueden ajustarse según las necesidades del sistema y los datos disponibles.
