from backend.dataManager.dataManager import DataManager
from backend.modelTrainer.performanceAnomalyDetector import PerformanceAnomalyDetector
from backend.modelTrainer.syscallAnomalyDetector import SyscallAnomalyDetector
import json
import os
import pickle
import numpy as np
from datetime import datetime

class AnomalyDetectorManager(DataManager):
    def __init__(self, socketio, db):
        super().__init__(socketio, db)
        cwd = os.getcwd()
        with open(os.path.abspath('../backend/modelTrainer/models/frequency_syscall_detector_lof.pkl'), 'rb') as file:
            trained_model = pickle.load(file)
        self.syscall_anomaly_detector = SyscallAnomalyDetector(trained_model)
        with open(os.path.abspath('../backend/modelTrainer/models/performance_detector_lof.pkl'), 'rb') as file:
            trained_model = pickle.load(file)
        self.performance_anomaly_detector = PerformanceAnomalyDetector(trained_model)
        self.syscall_anomaly_detector.featureExtractor = 'frequency'

        self.syscallCollector = []
        self.performanceCollector = []

    def handle_message(self, msg, detector_type):
        if detector_type == 'syscalls':
            self.process_data(msg, "syscalls")
        elif detector_type == 'performance':
            self.process_data(msg, "performance")
        else:
            print("Anomaly Detector Error")

    #collect data into timeslices, transform and make prediction
    def process_data(self, data, detector_type):
        if detector_type == "syscalls":
            if(len(self.syscallCollector)==0 or self.syscallCollector[-1][0]-self.syscallCollector[0][0]<self.time_period):
                self.syscallCollector.append(data)
            else:
                syscall_arr = self.syscall_anomaly_detector.convertSyscallsIntoSyscallArray(self.syscallCollector)
                timestamp = self.nanos_to_time(self.syscallCollector[-1][0])
                self.syscallCollector = []
                features = self.syscall_anomaly_detector.extractFeatures(syscall_arr)
                if(len(features)>0):
                    prediction = self.syscall_anomaly_detector.predict(features).tolist()[0]
                    self.socketio.emit('anomaly_syscall_data', json.dumps([timestamp, prediction]), namespace="/live")
                else:
                    return None

        elif detector_type == "performance":
            if(len(data)>0):
                performance_arr = self.performance_anomaly_detector.convertPerformanceStatsIntoArr(data)
                self.performanceCollector.extend(performance_arr)
                timestamp = self.nanos_to_time(self.syscallCollector[-1][0])
                if len(self.performanceCollector)>0 and self.performanceCollector[-1][0] - self.performanceCollector[0][0] > self.time_period:
                    prediction = self.performance_anomaly_detector.predict(self.performanceCollector).tolist()[0]
                    self.performanceCollector = []
                    self.socketio.emit('anomaly_performance_data', json.dumps([timestamp, prediction]), namespace="/live")
                else:
                    return None
            else:
                return None
             

        else:
            print("Data Processing Error")


    def batch_process():
        pass