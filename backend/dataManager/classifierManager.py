from backend.dataManager.dataManager import DataManager
from backend.modelTrainer.syscallClassifier import SyscallClassifier
from backend.modelTrainer.performanceClassifier import PerformanceClassifier
import json
import os
import pickle
import numpy as np
from datetime import datetime

class ClassifierManager(DataManager):
    def __init__(self, socketio, db, syscall_classifier, performance_classifier):
        super().__init__(socketio, db)
        cwd = os.getcwd()
        with open('../backend/modelTrainer/models/models_list.json') as json_file:
            models = json.load(json_file)

        if(syscall_classifier is None):
            with open(os.path.abspath('../backend/modelTrainer/models/frequency_syscall_classifier_bayes.pkl'), 'rb') as file:
                trained_model = pickle.load(file)
            self.syscall_classifier = SyscallClassifier(trained_model)
            self.syscall_classifier.featureExtractor = 'frequency'
        else:
            if syscall_classifier in models["categories"]:
                matching_model = models["categories"][syscall_classifier][0]    
                with open(os.path.abspath(matching_model), 'rb') as file:
                    trained_model = pickle.load(file)
                self.syscall_classifier = SyscallClassifier(trained_model)
                if 'frequency' in syscall_classifier:
                    self.syscall_classifier.featureExtractor = 'frequency'
                else:
                    self.syscall_classifier.featureExtractor = 'sequence'

        if(performance_classifier is None):
            with open(os.path.abspath('../backend/modelTrainer/models/performance_classifier_bayes.pkl'), 'rb') as file:
                trained_model = pickle.load(file)
            self.performance_classifier = PerformanceClassifier(trained_model)
        else:
            if performance_classifier in models["categories"]:
                matching_model = models["categories"][performance_classifier][0]
                with open(os.path.abspath(matching_model), 'rb') as file:
                    trained_model = pickle.load(file)
                self.performance_classifier = PerformanceClassifier(trained_model)

        self.syscallCollector = []
        self.performanceCollector = []

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
                syscall_arr = self.syscall_classifier.convertSyscallsIntoSyscallArray(self.syscallCollector)
                timestamp = self.nanos_to_time(self.syscallCollector[-1][0])
                #print("Converted timestamp" ,timestamp)
                self.syscallCollector = []
                features = self.syscall_classifier.extractFeatures(syscall_arr)
                if(len(features)>0):
                    prediction = self.syscall_classifier.predict(features).tolist()[0]
                    self.socketio.emit('classifier_syscall_data', json.dumps([timestamp, prediction]), namespace="/live")
                else:
                    return None

        elif classifier_type == "performance":
            if(len(data)>0):
                performance_arr = self.performance_classifier.convertPerformanceStatsIntoArr(data)
                self.performanceCollector.extend(performance_arr)
                timestamp = self.nanos_to_time(self.syscallCollector[-1][0])
                if len(self.performanceCollector)>0 and self.performanceCollector[-1][0] - self.performanceCollector[0][0] > self.time_period:
                    prediction = self.performance_classifier.predict(self.performanceCollector).tolist()[0]
                    self.performanceCollector = []
                    self.socketio.emit('classifier_performance_data', json.dumps([timestamp, prediction]), namespace="/live")
                else:
                    return None
            else:
                return None
             

        else:
            print("Data Processing Error")


    def batch_process():
        pass