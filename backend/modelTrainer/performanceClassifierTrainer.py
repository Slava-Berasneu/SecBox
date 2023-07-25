from sklearn import tree
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os
import pickle 
import json
from abstractClassifierTrainer import ClassifierTrainer

class PerformanceClassifierTrainer(ClassifierTrainer):
    def __init__(self, dataFilePath, model, featureExtractor):
        self.dataFilePath = dataFilePath
        self.model = model
        self.featureExtractor = featureExtractor
        self.readFileContents()
        super.__init__()

    def readFileContents(self):
        data_arr = []
        cwd = os.getcwd()

        self.data_arr = data_arr

    def extractFeatures(self):
        if self.featureExtractor == "frequency":
            features = self.extractFrequency()
        elif self.featureExtractor == "sequence":
            features = self.extractSequence()

        return features

    def extractFrequency(self):
        #pad vector to get same shape
        separated_features_arr = []
        features = {}
        start_time = int(self.syscall_arr[0][0])
        time_period = 1000000000
        end_time = start_time + time_period

        # Iterate through the syscall_arr
        for syscall in self.data_arr:
            timestamp = int(syscall[0])
            sysname = syscall[1]
            time_diff_nanos = int(syscall[2])

            if start_time <= timestamp < end_time:
                # Increment frequency count for sysname
                if sysname not in features:
                    features[sysname] = 0
                features[sysname] += 1

            # Move to the next time chunk, start collecting for the next data point
            if timestamp >= end_time:
                separated_features_arr.append(features)
                features = {}
                start_time += time_period
                end_time += time_period

        print(separated_features_arr)
        return separated_features_arr

    def extractSequence(self):
        separated_features_arr = []
        sequence = []
        start_time = int(self.syscall_arr[0][0])
        time_period = 100000000
        end_time = start_time + time_period

        # Iterate through the syscall_arr
        for syscall in self.syscall_arr:
            timestamp = int(syscall[0])
            sysname = syscall[1]
            time_diff_nanos = int(syscall[2])

            if start_time <= timestamp < end_time:
                sequence.append(sysname)

            # Move to the next time chunk, start collecting for the next data point
            if timestamp >= end_time:
                separated_features_arr.append(sequence)
                sequence = []
                start_time += time_period
                end_time += time_period

        #print(separated_features_arr)
        return separated_features_arr


    def trainModel(self, X, y):
        self.model.fit(X,y)

    def testModel(self):
        pass

    def saveModel(self, filepath):
        with open(filepath, 'wb') as file:
            pickle.dump(self.model, file)

performance_file_path = 'backend/modelTrainer/syscalls_infected.csv'
model_type = tree.DecisionTreeClassifier()
feature_extractor_type = 'frequency'  

trainer = PerformanceClassifierTrainer(performance_file_path, model_type, feature_extractor_type)
features = trainer.extractFeatures()


#print("features "+str(len(features)))
#print("labels "+str(len(["Monti", "Coinminer", "Uninfected"]*(len(features)//3) + ["Uninfected"]*(len(features)%3))))
#rint(str(["Monti", "Coinminer", "Uninfected"]*(len(features)//3) + ["Uninfected"]*(len(features)%3)))


#trainer.trainModel(features, ["Monti", "Coinminer", "Uninfected"]*(len(features)//3) + ["Uninfected"]*(len(features)%3))