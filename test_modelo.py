import unittest
import pandas as pd
from datetime import datetime
from avance import ModeloPredictivo

class TestModeloPredictivo(unittest.TestCase):

    def test_entrenar_modelo(self):
        # Test para verificar si el modelo se entrena correctamente
        data = pd.DataFrame({
            'timestamp': [datetime.now(), datetime.now()],
            'longitud': [100, 200]
        })
        modelo = ModeloPredictivo(data)
        modelo.entrenar_modelo()
        self.assertTrue(hasattr(modelo, 'modelo'))

    def test_predecir(self):
        # Test para verificar la predicción del modelo
        data = pd.DataFrame({
            'timestamp': [datetime.now(), datetime.now()],
            'longitud': [100, 200]
        })
        modelo = ModeloPredictivo(data)
        modelo.entrenar_modelo()
        predicciones = modelo.predecir(pasos=5)
        self.assertEqual(len(predicciones), 5)

if __name__ == '__main__':
    unittest.main()
