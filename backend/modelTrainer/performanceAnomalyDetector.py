from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import csv
import os
import pickle
import json
from .modelTrainer import ModelTrainer
from datetime import datetime
import numpy as np

class PerformanceAnomalyDetector(ModelTrainer):
    def __init__(self, model):
        super().__init__()
        self.model = model

    def predict(self, data):
        return self.model.predict(data)
        
    def trainModel(self, dataFilePaths, modelName):
        self.dataFilePaths = dataFilePaths
        self.modelName = modelName
        
        features_combined_list = []
        for path in dataFilePaths:
            features = self.readFileContents(path, 'healthy')
            features_combined_list.extend(features)
            features = self.readFileContents(path, 'infected')
            features_combined_list.extend(features)

        self.fitModel(features_combined_list)
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
    
    def convertTimestampStringToEpochNanos(self, timestamp):
        datetime_obj = datetime.strptime(timestamp, "%m/%d/%Y, %H:%M:%S.%fUTC")
        unix_timestamp = datetime_obj.timestamp()
        epoch_nanos = int(unix_timestamp * 1_000_000_000)
        return epoch_nanos

    def fitModel(self, X):
        self.model.fit(X)

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
            "contamination": self.model.contamination,
            "novelty": self.model.novelty if hasattr(self.model, 'novelty') else "N/A",
            "n_neighbors": self.model.n_neighbors if hasattr(self.model, 'n_neighbors') else "N/A",
            "timePeriod": self.time_period
        }
        json_string = json.dumps(parameters, indent=4)
        with open(cwd+'/'+'backend/modelTrainer/models/'+file_name+'.json', "w") as json_file:
            json_file.write(json_string)
        

def trainExampleModel():
    seed = 52        
    np.random.seed(seed)

    performance_file_paths = ['backend/modelTrainer/trainingData/coin_miner_performance.json']

    #model = IsolationForest(contamination=0.1, random_state=seed)
    model = LocalOutlierFactor(contamination=0.1, n_neighbors=20, novelty=True)
    trainer = PerformanceAnomalyDetector(model)
    trainer.trainModel(performance_file_paths,"performance_detector_lof")
    #trainer.trainModel(performance_file_paths,"performance_detector_forest")

def testExampleModel():
    cwd = os.getcwd()
    with open(cwd+'/'+'backend/modelTrainer/models/performance_detector_lof.pkl', 'rb') as file:
    #with open(cwd+'/'+'backend/modelTrainer/models/performance_detector_forest.pkl', 'rb') as file:
        trained_model = pickle.load(file)

    trainer = PerformanceAnomalyDetector(trained_model)
    print(trainer.predict([[1.686810575451144e+18, 0.0452754590984975, 0.6206780797273546, 184.0, 55.0], [1.6868105764562609e+18, 0.010443514644351464, 0.6206780797273546, 184.0, 55.0], [1.686810577467789e+18, 0.009154228855721393, 0.6206780797273546, 184.0, 55.0], [1.686810578476995e+18, 0.017271214642262896, 0.6206780797273546, 184.0, 55.0], [1.6868105794868319e+18, 0.008785357737104826, 0.6206780797273546, 184.0, 55.0], [1.686810580496474e+18, 0.006970954356846474, 0.6206780797273546, 184.0, 55.0], [1.6868105815057981e+18, 0.007082294264339151, 0.6206780797273546, 184.0, 55.0], [1.686810354464642e+18, 0.037282518641259324, 0.0981960958807353, 21.0, 0.0], [1.686810355476162e+18, 0.010954356846473029, 0.0981960958807353, 21.0, 0.0]]))

#testExampleModel()
