import queue 
from datetime import datetime

class DataManager:
    def __init__(self, socketio, db):
        self.sent_packages = []
        self.db = db
        self.socketio = socketio
        self.windowsize = 1000
        self.db_queue = queue.Queue(maxsize=1000)
        self.order_nos = {}
        self.time_period = 1000000000

    def handle_message(msg):
        pass

    def process_data(self, data):
        pass

    def batch_process():
        pass

    def nanos_to_time(self, nanos):
        dt = datetime.fromtimestamp(nanos / 1e9)
        hours = dt.hour
        minutes = dt.minute
        seconds = dt.second
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"