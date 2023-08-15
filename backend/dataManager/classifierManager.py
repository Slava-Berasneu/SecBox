from backend.dataManager.dataManager import DataManager
from backend.modelTrainer.syscallClassifier import SyscallClassifier
from backend.modelTrainer.performanceClassifier import PerformanceClassifier
import json
import os
import pickle
import numpy as np
from datetime import datetime

class ClassifierManager(DataManager):
    def __init__(self, socketio, db):
        super().__init__(socketio, db)
        cwd = os.getcwd()
        with open(os.path.abspath('../backend/modelTrainer/models/frequency_syscall_classifier_bayes.pkl'), 'rb') as file:
            trained_model = pickle.load(file)
        self.syscall_classifier = SyscallClassifier(trained_model)
        with open(os.path.abspath('../backend/modelTrainer/models/performance_classifier_bayes.pkl'), 'rb') as file:
            trained_model = pickle.load(file)
        self.performance_classifier = PerformanceClassifier(trained_model)

        self.syscallCollector = []
        self.performanceCollector = []
        self.syscall_classifier.featureExtractor = 'frequency'

    def handle_message(self, msg, classifier_type):
        if classifier_type == 'syscalls':
            self.process_data(msg, "syscalls")
        elif classifier_type == 'performance':
            self.process_data(msg, "performance")
        else:
            print("Classifier Error")

    #collect data into timeslices, transform and make prediction
    def process_data(self, data, classifier_type):
        if classifier_type == "syscalls":
             #[1692051407126947528, 'close']
            #collect syscalls until suitable time slice is reached
            if(len(self.syscallCollector)==0 or self.syscallCollector[-1][0]-self.syscallCollector[0][0]<self.time_period):
                self.syscallCollector.append(data)
            else:
                print("Outputting prediction")
                syscall_arr = self.syscall_classifier.convertSyscallsIntoSyscallArray(self.syscallCollector)
                timestamp = self.nanos_to_time(self.syscallCollector[0][0])
                #print("Converted timestamp" ,timestamp)
                self.syscallCollector = []
                features = self.syscall_classifier.extractFeatures(syscall_arr)
                if(len(features)>0):
                    prediction = self.syscall_classifier.predict(features).tolist()[0]
                    print("made prediction: ",prediction)
                    self.socketio.emit('syscall_data', json.dumps([timestamp, prediction]), namespace="/live")
                else:
                    return None

        elif classifier_type == "performance":
            #{'timestamps': ['19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', 
            # '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', 
            # '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', 
            # '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', 
            # '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', 
            # '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:57', '19:40:58', '19:40:59', '19:41:00', 
            # '19:41:01', '19:41:02'], 'percentages': [0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 
            # 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 
            # 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 
            # 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 0.1219, 
            # 0.1571, 0.0268, 0.0308, 0.0275, 0.0381]}
            for element in data.items():
                if len(self.performanceCollector)==0 or element[0] > self.performanceCollector[:-1][0]:
                    self.performanceCollector.append(element)
                if int(self.performanceCollector[:-1][0]) - int(self.performanceCollector[0][0])*1e9 >= self.time_period:
                   pass 
                
                

        else:
            print("Data Processing Error")


    def batch_process():
        pass