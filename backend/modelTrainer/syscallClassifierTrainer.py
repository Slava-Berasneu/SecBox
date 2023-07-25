from sklearn import tree
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import OneHotEncoder
import csv
import os
import pickle 
from abstractClassifierTrainer import ClassifierTrainer
from collections import OrderedDict

class SyscallClassifierTrainer(ClassifierTrainer):
    def __init__(self, dataFilePaths, model, featureExtractor, modelName):
        super().__init__()
        self.dataFilePaths = dataFilePaths
        self.model = model
        self.featureExtractor = featureExtractor
        self.modelName = modelName

        for path, marker in dataFilePaths:
            syscall_raw_list = self.readFileContents(path)
            features = self.extractFeatures(syscall_raw_list)
            self.trainModel(features, marker)
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
        all_syscalls = ['readlink', 'mkdir', 'unlinkat', 'rt_sigaction', 'lstat', 'brk', 'recvfrom', 'ftruncate', 'read', 'mprotect',
        'close', 'setitimer', 'getgroups', 'statfs', 'select', 'geteuid', 'openat', 'nanosleep', 'execve', 'getuid',
        'unlink', 'getppid', 'chmod', 'fchmodat', 'prlimit64', 'clock_gettime', 'poll', 'exit_group', 'umask', 'getcwd',
        'write', 'getpid', 'gettid', 'clone', 'setgroups', 'sysinfo', 'mremap', 'rt_sigreturn', 'sendmmsg', 'ioctl',
        'socket', 'futex', 'fstat', 'getdents', 'getegid', 'pipe', 'flock', 'setresgid', 'rt_sigprocmask', 'faccessat',
        'stat', 'kill', 'getpgrp', 'newfstatat', 'getsockname', 'access', 'prctl', 'lchown', 'getrandom', 'munmap',
        'lseek', 'fork', 'mmap', 'fcntl', 'set_robust_list', 'set_tid_address', 'getgid', 'chdir', 'arch_prctl', 'utime',
        'clock_getres', 'chown', 'connect', 'pselect6', 'open', 'dup2', 'rename', 'dup', 'uname', 'wait4', 'pipe2',
        'setgid']
    
        
        syscall_counter = OrderedDict((syscall, 0) for syscall in all_syscalls)

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
                syscall_counter[sysname] += 1

            # Move to the next time chunk, start collecting for the next data point
            if timestamp >= end_time:
                syscall_counter_list = list(syscall_counter.values())

                # Check that the list is non-zero for at least one syscall
                if any(count != 0 for count in syscall_counter_list):
                    separated_features_arr.append(syscall_counter_list)

            # Reset the dict to 0
                syscall_counter = OrderedDict((syscall, 0) for syscall in all_syscalls)
                start_time += self.time_period
                end_time += self.time_period

        #print(separated_features_arr)
        return separated_features_arr

    def extractSequence(self, syscall_raw_list):
        all_syscalls = ['readlink', 'mkdir', 'unlinkat', 'rt_sigaction', 'lstat', 'brk', 'recvfrom', 'ftruncate', 'read', 'mprotect',
        'close', 'setitimer', 'getgroups', 'statfs', 'select', 'geteuid', 'openat', 'nanosleep', 'execve', 'getuid',
        'unlink', 'getppid', 'chmod', 'fchmodat', 'prlimit64', 'clock_gettime', 'poll', 'exit_group', 'umask', 'getcwd',
        'write', 'getpid', 'gettid', 'clone', 'setgroups', 'sysinfo', 'mremap', 'rt_sigreturn', 'sendmmsg', 'ioctl',
        'socket', 'futex', 'fstat', 'getdents', 'getegid', 'pipe', 'flock', 'setresgid', 'rt_sigprocmask', 'faccessat',
        'stat', 'kill', 'getpgrp', 'newfstatat', 'getsockname', 'access', 'prctl', 'lchown', 'getrandom', 'munmap',
        'lseek', 'fork', 'mmap', 'fcntl', 'set_robust_list', 'set_tid_address', 'getgid', 'chdir', 'arch_prctl', 'utime',
        'clock_getres', 'chown', 'connect', 'pselect6', 'open', 'dup2', 'rename', 'dup', 'uname', 'wait4', 'pipe2',
        'setgid']

        syscall_occurrences = OrderedDict((syscall, OrderedDict((other_syscall, 0) for other_syscall 
                                                                in all_syscalls)) for syscall in all_syscalls)

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


    def trainModel(self, X, y):
        y = [y for _ in range(len(X))]

        print(X)
        self.model.fit(X,y)

    def testModel(self):
        pass

    def saveModel(self, file_name):
        cwd = os.getcwd()

        with open(cwd+'/'+'backend/modelTrainer/models/'+file_name, 'wb') as file:
            pickle.dump(self.model, file)

syscall_file_paths = [['backend/modelTrainer/trainingData/coin_miner_syscalls_infected.csv', 'infected'], 
                      ['backend/modelTrainer/trainingData/coin_miner_syscalls_healthy.csv', 'healthy']]

model_type = tree.DecisionTreeClassifier()
feature_extractor_type = 'sequence'  

trainer = SyscallClassifierTrainer(syscall_file_paths, model_type, feature_extractor_type, "coin_miner_infected_classifier")

#print("features "+str(len(features)))
#print("labels "+str(len(["Monti", "Coinminer", "Uninfected"]*(len(features)//3) + ["Uninfected"]*(len(features)%3))))
#print(str(["Monti", "Coinminer", "Uninfected"]*(len(features)//3) + ["Uninfected"]*(len(features)%3)))


#trainer.trainModel(features, ["Monti", "Coinminer", "Uninfected"]*(len(features)//3) + ["Uninfected"]*(len(features)%3))