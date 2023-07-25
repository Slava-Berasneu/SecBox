from sklearn import tree
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import csv
import os
import pickle 
from abstractClassifierTrainer import ClassifierTrainer
from collections import OrderedDict

class SyscallClassifierTrainer(ClassifierTrainer):
    def __init__(self, dataFilePath, model, featureExtractor):
        self.dataFilePath = dataFilePath
        self.model = model
        self.featureExtractor = featureExtractor
        self.readFileContents()
        super().__init__()

    def readFileContents(self):
        syscall_arr = []
        cwd = os.getcwd()

        with open(cwd+"/"+self.dataFilePath, 'r') as file:
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

        self.syscall_arr = syscall_arr

    def extractFeatures(self):
        if self.featureExtractor == "frequency":
            features = self.extractFrequency()
        elif self.featureExtractor == "sequence":
            features = self.extractSequence()

        return features

    def extractFrequency(self):
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
        start_time = int(self.syscall_arr[0][0])
        end_time = start_time + self.time_period

        # Iterate through the syscall_arr
        for syscall in self.syscall_arr:
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

        print(separated_features_arr)
        return separated_features_arr

    def extractSequence(self):
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
        start_time = int(self.syscall_arr[0][0])
        end_time = start_time + self.time_period

        # Iterate through the syscall_arr
        for syscall in self.syscall_arr:
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

                # Append the syscall_occurrences for the current sequence to separated_features_arr
                syscall_occurrences_list = []
                encountered_syscalls = []
                for syscall_name in sequence:
                    #in a sequence, consider occurences only after the first instance of a syscall
                    if syscall_name not in encountered_syscalls:
                        occurrences_after_syscall = list(syscall_occurrences[syscall_name].values())
                        #list containing a value for how often each syscall appears after the currently considered one 
                        # (within the timespan sequence)
                        syscall_occurrences_list.append(occurrences_after_syscall)
                        
                        encountered_syscalls.append(syscall_name)
                
                #Ignore empty sequences
                if syscall_occurrences_list != []:
                    separated_features_arr.append(syscall_occurrences_list)

                # Reset sequence for the next timespan
                sequence = []
                start_time += self.time_period
                end_time += self.time_period

        print(separated_features_arr)
        return separated_features_arr


    def trainModel(self, X, y):
        self.model.fit(X,y)

    def testModel(self):
        pass

    def saveModel(self, filepath):
        with open(filepath, 'wb') as file:
            pickle.dump(self.model, file)

syscall_file_path = 'backend/modelTrainer/syscalls_infected.csv'
model_type = tree.DecisionTreeClassifier()
feature_extractor_type = 'sequence'  

trainer = SyscallClassifierTrainer(syscall_file_path, model_type, feature_extractor_type)
features = trainer.extractFeatures()


#print("features "+str(len(features)))
#print("labels "+str(len(["Monti", "Coinminer", "Uninfected"]*(len(features)//3) + ["Uninfected"]*(len(features)%3))))
#rint(str(["Monti", "Coinminer", "Uninfected"]*(len(features)//3) + ["Uninfected"]*(len(features)%3)))


#trainer.trainModel(features, ["Monti", "Coinminer", "Uninfected"]*(len(features)//3) + ["Uninfected"]*(len(features)%3))