from sklearn import tree
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import csv
import os
import pickle
import json
from .modelTrainer import ModelTrainer
from datetime import datetime
import numpy as np

class PerformanceClassifier(ModelTrainer):
    def __init__(self, model):
        super().__init__()
        self.model = model

    def predict(self, data):
        return self.model.predict(data)
        
    def trainModel(self, dataFilePaths, modelName):
        self.dataFilePaths = dataFilePaths
        self.modelName = modelName
        
        features_combined_list = []
        marker_combined_list = []
        for path, marker in dataFilePaths:
            features = self.readFileContents(path, 'healthy')
            features_combined_list.extend(features)
            marker_combined_list.extend(['healthy' for _ in range(len(features))])

            features = self.readFileContents(path, 'infected')
            features_combined_list.extend(features)
            marker_combined_list.extend([marker for _ in range(len(features))])

        self.fitModel(features_combined_list, marker_combined_list)
        self.saveModel(modelName)

    def readFileContents(self, path, section):
        performance_arr = []
        cwd = os.getcwd()
        with open(cwd+"/"+path, "r") as json_file:
            data = json.load(json_file)

        if(section=='healthy'):
            timestamp = [self.convertTimestampStringToEpochNanos(entry["timestamp"]) for entry in json.loads(data[0]["cpu_percentages"])["healthy"]["graph"]]
            healthy_cpu = [entry["cpu_percentage"] for entry in json.loads(data[0]["cpu_percentages"])["healthy"]["graph"]]
            healthy_ram = [entry["ram_usage"] for entry in json.loads(data[0]["ram_usage"])["healthy"]["graph"]]
            healthy_received_packages = [entry["received_packages"] for entry in json.loads(data[0]["packet_counts"])["healthy"]["graph"]]
            healthy_transmitted_packages = [entry["transmitted_packages"] for entry in json.loads(data[0]["packet_counts"])["healthy"]["graph"]]
            healthy_data = np.column_stack((np.array(timestamp), np.array(healthy_cpu), np.array(healthy_ram), 
                                            np.array(healthy_received_packages), np.array(healthy_transmitted_packages)))
            performance_arr = healthy_data.tolist()

        else:
            timestamp = [self.convertTimestampStringToEpochNanos(entry["timestamp"]) for entry in json.loads(data[0]["cpu_percentages"])["infected"]["graph"]]
            infected_cpu = [entry["cpu_percentage"] for entry in json.loads(data[0]["cpu_percentages"])["infected"]["graph"]]
            infected_ram = [entry["ram_usage"] for entry in json.loads(data[0]["ram_usage"])["infected"]["graph"]]
            infected_received_packages = [entry["received_packages"] for entry in json.loads(data[0]["packet_counts"])["infected"]["graph"]]
            infected_transmitted_packages = [entry["transmitted_packages"] for entry in json.loads(data[0]["packet_counts"])["infected"]["graph"]]
            infected_data = np.column_stack((np.array(timestamp), np.array(infected_cpu), np.array(infected_ram), 
                                             np.array(infected_received_packages), np.array(infected_transmitted_packages))) 
            performance_arr = infected_data.tolist()
        
        return performance_arr
    
    def convertPerformanceStatsIntoArr(self, stats):
        timestamp = [self.convertTimestampStringToEpochNanos(entry[0]) for entry in stats]
        infected_cpu = [entry[1] for entry in stats]
        infected_ram = [entry[2] for entry in stats]
        infected_received_packages = [entry[3] for entry in stats]
        infected_transmitted_packages = [entry[4] for entry in stats]
        infected_data = np.column_stack((np.array(timestamp), np.array(infected_cpu), np.array(infected_ram), 
                                            np.array(infected_received_packages), np.array(infected_transmitted_packages))) 
        performance_arr = infected_data.tolist()
        
        return performance_arr
    
    def convertTimestampStringToEpochNanos(self, timestamp):
        datetime_obj = datetime.strptime(timestamp, "%m/%d/%Y, %H:%M:%S.%fUTC")
        unix_timestamp = datetime_obj.timestamp()
        epoch_nanos = int(unix_timestamp * 1_000_000_000)
        return epoch_nanos

    def fitModel(self, X, y):
        print(X)
        self.model.fit(X,y)

    def testModel(self):
        pass

    def saveModel(self, file_name):
        cwd = os.getcwd()

        #store trained model as pickle
        with open(cwd+'/'+'backend/modelTrainer/models/'+file_name+'.pkl', 'wb') as file:
            pickle.dump(self.model, file)

        #store parameters file for training reproducibility
        parameters = {
            "modelName": self.modelName,
            "modelType": self.model.__class__.__name__,
            "dataFilePaths": self.dataFilePaths,
            "randomState": self.model.random_state if hasattr(self.model, 'random_state') else "N/A",
        }
        json_string = json.dumps(parameters, indent=4)
        with open(cwd+'/'+'backend/modelTrainer/models/'+file_name+'.json', "w") as json_file:
            json_file.write(json_string)
        

def trainExampleModel():
    seed = 52        
    np.random.seed(seed)

    performance_file_paths = [['backend/modelTrainer/trainingData/coin_miner_performance.json', 'infected']]

    #model = tree.DecisionTreeClassifier(random_state=seed)
    model = GaussianNB()
    trainer = PerformanceClassifier(model)
    trainer.trainModel(performance_file_paths,"performance_classifier_bayes")
    #trainer.trainModel(performance_file_paths,"performance_classifier_tree")

def testExampleModel():
    cwd = os.getcwd()
    with open(cwd+'/'+'backend/modelTrainer/models/performance_classifier_bayes.pkl', 'rb') as file:
    #with open(cwd+'/'+'backend/modelTrainer/models/performance_classifier_tree.pkl', 'rb') as file:
        trained_model = pickle.load(file)

    trainer = PerformanceClassifier(trained_model)
    print(trainer.predict([[1.686810354469615e+18, 0.10134868421052631, 0.1034627536547898, 31.0, 12.0], [1.686810355483381e+18, 0.06533665835411472, 0.1034627536547898, 33.0, 12.0], [1.686810356493398e+18, 0.15833610648918467, 0.1034627536547898, 34.0, 13.0], [1.686810357503371e+18, 0.011870324189526184, 0.1034627536547898, 34.0, 13.0], [1.686810358513789e+18, 0.029148580968280463, 0.1034627536547898, 35.0, 13.0],[1.68681058251565e+18, 0.006310517529215359, 0.6206780797273546, 184.0, 55.0], [1.686810583526227e+18, 0.0072483221476510075, 0.6206780797273546, 184.0, 55.0], [1.686810584537725e+18, 0.008585690515806989, 0.6206780797273546, 184.0, 55.0]]))

#testExampleModel()
