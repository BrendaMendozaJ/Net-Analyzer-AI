import unittest
import pandas as pd
from datetime import datetime
from avance import DetectorDeAnomalias

class TestDetectorDeAnomalias(unittest.TestCase):

    def test_detectar_anomalias(self):
        # Test para verificar la detección de anomalías en los datos de tráfico
        data = pd.DataFrame({
            'timestamp': [datetime.now(), datetime.now()],
            'ip_src': ['192.168.1.1', '192.168.1.2'],
            'ip_dst': ['192.168.1.2', '192.168.1.3'],
            'protocolo': [6, 17],
            'longitud': [100, 200]
        })
        detector = DetectorDeAnomalias(data)
        data_con_anomalias = detector.detectar_anomalias()
        self.assertIn('anomalia', data_con_anomalias.columns)

if __name__ == '__main__':
    unittest.main()
