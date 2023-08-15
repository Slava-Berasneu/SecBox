from backend.dataManager.dataManager import DataManager
import json
from datetime import datetime

class AnomalyDetectorManager(DataManager):
    def __init__(self, socketio, db):
        super().__init__(socketio, db)

    def handle_message(self, msg):
        pass

    def process_data(self, data):
        pass

    def batch_process():
        pass