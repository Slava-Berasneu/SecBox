#5 percent outliers

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import csv
import os
import pickle
import json
from .modelTrainer import ModelTrainer
from collections import OrderedDict
from datetime import datetime
import numpy as np

class SyscallAnomalyDetector(ModelTrainer):
    def __init__(self, model):
        super().__init__()
        self.model = model
        self.all_syscalls = ['readlink', 'mkdir', 'unlinkat', 'rt_sigaction', 'lstat', 'brk', 'recvfrom', 'ftruncate', 'read', 'mprotect',
        'close', 'setitimer', 'getgroups', 'statfs', 'select', 'geteuid', 'openat', 'nanosleep', 'execve', 'getuid',
        'unlink', 'getppid', 'chmod', 'fchmodat', 'prlimit64', 'clock_gettime', 'poll', 'exit_group', 'umask', 'getcwd',
        'write', 'getpid', 'gettid', 'clone', 'setgroups', 'sysinfo', 'mremap', 'rt_sigreturn', 'sendmmsg', 'ioctl',
        'socket', 'futex', 'fstat', 'getdents', 'getegid', 'pipe', 'flock', 'setresgid', 'rt_sigprocmask', 'faccessat',
        'stat', 'kill', 'getpgrp', 'newfstatat', 'getsockname', 'access', 'prctl', 'lchown', 'getrandom', 'munmap',
        'lseek', 'fork', 'mmap', 'fcntl', 'set_robust_list', 'set_tid_address', 'getgid', 'chdir', 'arch_prctl', 'utime',
        'clock_getres', 'chown', 'connect', 'pselect6', 'open', 'dup2', 'rename', 'dup', 'uname', 'wait4', 'pipe2',
        'setgid']

    def predict(self, data):
        return self.model.predict(data)
        
    def trainModel(self, dataFilePaths, featureExtractor, modelName):
        self.dataFilePaths = dataFilePaths
        self.featureExtractor = featureExtractor
        self.modelName = modelName

        features_combined_list = []
        for path in dataFilePaths:
            syscall_raw_list = self.readFileContents(path)
            features = self.extractFeatures(syscall_raw_list)
            features_combined_list.extend(features)

        self.fitModel(features_combined_list)
        self.saveModel(modelName)

    def readFileContents(self, path):
        syscall_arr = []
        cwd = os.getcwd()

        with open(cwd+"/"+path, 'r') as file:
            reader = csv.reader(file)
            header = next(reader, None)
            
            timestamp_index = header.index('time_ns')
            sysname_index = header.index('sysname')
            previous_timestamp = None
            
            # Extract timestamp, sysname into array
            for row in reader:
                if len(row)==8:
                    timestamp_value = row[timestamp_index]
                    sysname_value = row[sysname_index]
                    current_timestamp = timestamp_value
                    
                    #calculate time taken for the syscall in nanoseconds
                    if previous_timestamp is not None:
                        time_diff_nanos = int(current_timestamp) - int(previous_timestamp)
                        syscall_arr.append([timestamp_value, sysname_value, time_diff_nanos])
                        #print("row "+str([timestamp_value, sysname_value, time_diff_nanos]))

                    previous_timestamp = current_timestamp

        return syscall_arr

    def extractFeatures(self, syscall_raw_list):
        if self.featureExtractor == "frequency":
            features = self.extractFrequency(syscall_raw_list)
        elif self.featureExtractor == "sequence":
            features = self.extractSequence(syscall_raw_list)

        return features

    def extractFrequency(self, syscall_raw_list):
        syscall_counter = OrderedDict((syscall, 0) for syscall in self.all_syscalls)

        separated_features_arr = []
        start_time = int(syscall_raw_list[0][0])
        end_time = start_time + self.time_period

        # Iterate through the syscall_arr
        for syscall in syscall_raw_list:
            timestamp = int(syscall[0])
            sysname = syscall[1]
            time_diff_nanos = int(syscall[2])

            if start_time <= timestamp < end_time:
                # Increment frequency count for sysname
                if sysname in syscall_counter:
                    syscall_counter[sysname] += 1

            # Move to the next time chunk, start collecting for the next data point
            if timestamp >= end_time:
                syscall_counter_list = list(syscall_counter.values())

                # Check that the list is non-zero for at least one syscall
                if any(count != 0 for count in syscall_counter_list):
                    separated_features_arr.append(syscall_counter_list)

            # Reset the dict to 0
                syscall_counter = OrderedDict((syscall, 0) for syscall in self.all_syscalls)
                start_time += self.time_period
                end_time += self.time_period

        #print(separated_features_arr)
        return separated_features_arr

    def extractSequence(self, syscall_raw_list):
        syscall_occurrences = OrderedDict((syscall, OrderedDict((other_syscall, 0) for other_syscall 
                                                                in self.all_syscalls)) for syscall in self.all_syscalls)
        separated_features_arr = []
        sequence = []
        start_time = int(syscall_raw_list[0][0])
        end_time = start_time + self.time_period

        # Iterate through the syscall_arr
        for syscall in syscall_raw_list:
            timestamp = int(syscall[0])
            sysname = syscall[1]

            if start_time <= timestamp < end_time:
                sequence.append(sysname)

            # Move to the next time chunk, start collecting for the next data point
            if timestamp >= end_time:
                # Update syscall_occurrences for the current sequence
                for i, syscall_name in enumerate(sequence[:-1]):  # Exclude the last syscall in the sequence
                    for other_syscall_name in sequence[i + 1:]:
                        syscall_occurrences[syscall_name][other_syscall_name] += 1

                #convert orderedDict of orderedDicts into list of lists
                separated_features_arr = [list(inner_dict.values()) for inner_dict in syscall_occurrences.values()]

                # Reset sequence for the next timespan
                sequence = []
                start_time += self.time_period
                end_time += self.time_period

        #print(separated_features_arr)
        return separated_features_arr


    def fitModel(self, X):
        #print(y)
        #print(X)
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
            "featureExtractor": self.featureExtractor,
            "timePeriod": self.time_period,
            "syscallList": self.all_syscalls
        }
        json_string = json.dumps(parameters, indent=4)
        with open(cwd+'/'+'backend/modelTrainer/models/'+file_name+'.json', "w") as json_file:
            json_file.write(json_string)

        #write to model list
        with open(cwd+'/'+'backend/modelTrainer/models/models_list.json', 'r') as json_file:
            models = json.load(json_file)
        new_model = {
            "name": self.modelName,
            "filepath": cwd+'/'+'backend/modelTrainer/models/'+file_name+'.json'
        }
        models["categories"]["syscall_anomaly_detector"].append(new_model)
        with open('your_file.json', 'w') as json_file:
            json.dump(models, json_file, indent=4)

    def convertSyscallsIntoSyscallArray(self, array):
        previous_timestamp = None
        syscall_arr = []
        for element in array:
            current_timestamp = element[0]
            if previous_timestamp is not None:
                time_diff_nanos = int(current_timestamp) - int(previous_timestamp)
                syscall_arr.append([element[0], element[1], time_diff_nanos])
                    
            previous_timestamp = current_timestamp

        return syscall_arr
    
    def convertTimestampStringToEpochNanos(self, timestamp):
        datetime_obj = datetime.strptime(timestamp, "%m/%d/%Y, %H:%M:%S.%fUTC")
        unix_timestamp = datetime_obj.timestamp()
        epoch_nanos = int(unix_timestamp * 1_000_000_000)
        return epoch_nanos
        

def trainExampleModel():
    seed = 52        
    np.random.seed(seed)

    syscall_file_paths = ['backend/modelTrainer/trainingData/coin_miner_syscalls_infected.csv', 
                        'backend/modelTrainer/trainingData/coin_miner_syscalls_healthy.csv']

    #model = IsolationForest(contamination=0.1, random_state=seed)
    model = LocalOutlierFactor(contamination=0.1, n_neighbors=20, novelty=True)
    trainer = SyscallAnomalyDetector(model)
    trainer.trainModel(syscall_file_paths,"frequency","frequency_syscall_detector_lof")
    #trainer.trainModel(syscall_file_paths,"sequence","sequence_syscall_detector_lof")
    #trainer.trainModel(syscall_file_paths,"frequency","frequency_syscall_detector_forest")
    #trainer.trainModel(syscall_file_paths,"sequence","sequence_syscall_detector_forest")

def testExampleModel():
    cwd = os.getcwd()
    with open(cwd+'/'+'backend/modelTrainer/models/frequency_syscall_detector_lof.pkl', 'rb') as file:
    #with open(cwd+'/'+'backend/modelTrainer/models/sequence_syscall_detector_lof.pkl', 'rb') as file:
    #with open(cwd+'/'+'backend/modelTrainer/models/frequency_syscall_detector_forest.pkl', 'rb') as file:
    #with open(cwd+'/'+'backend/modelTrainer/models/sequence_syscall_detector_forest.pkl', 'rb') as file:
        trained_model = pickle.load(file)

    trainer = SyscallAnomalyDetector(trained_model)
    print(trainer.predict([[1, 0, 0, 121, 0, 9, 0, 0, 36, 32, 47, 0, 2, 0, 0, 11, 33, 0, 2, 12, 0, 1, 0, 0, 2, 6, 0, 4, 0, 1, 3, 7, 0, 4, 0, 1, 0, 4, 0, 26, 4, 0, 34, 6, 12, 2, 0, 0, 44, 7, 49, 0, 1, 0, 0, 29, 0, 0, 0, 9, 4, 0, 46, 3, 0, 0, 12, 0, 3, 0, 0, 0, 4, 1, 0, 3, 0, 1, 4, 8, 0, 0], [0, 0, 0, 9, 0, 4, 2, 0, 40, 28, 28, 2, 0, 0, 3, 0, 31, 0, 0, 2, 0, 0, 0, 0, 1, 0, 3, 0, 0, 0, 11, 14, 0, 0, 0, 1, 0, 0, 1, 5, 4, 21, 29, 0, 0, 0, 0, 0, 2, 0, 9, 0, 0, 0, 0, 15, 0, 0, 1, 3, 0, 0, 38, 0, 1, 1, 0, 0, 1, 0, 2, 0, 4, 0, 0, 0, 0, 0, 1, 0, 0, 0],[0, 0, 0, 17, 1, 8, 0, 0, 32, 4, 22, 0, 0, 0, 3, 3, 14, 0, 2, 2, 19, 1, 1, 0, 0, 0, 0, 0, 0, 1, 24, 2, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 15, 12, 1, 0, 0, 0, 2, 0, 38, 3, 0, 0, 0, 5, 0, 1, 0, 3, 6, 0, 8, 7, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 6, 0, 0], [0, 0, 3, 10, 4, 63, 0, 0, 2069, 16, 77, 0, 0, 2, 0, 2, 92, 0, 1, 1, 2, 0, 0, 0, 1, 0, 0, 4, 1, 0, 82, 2, 0, 1, 0, 0, 11, 1, 0, 2, 0, 0, 28, 4, 0, 1, 0, 0, 2, 0, 464, 0, 0, 3, 0, 8, 0, 0, 0, 3, 3, 0, 23, 35, 2, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 3, 0, 0, 1, 2, 0, 1]]))

#testExampleModel()
