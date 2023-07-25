from abc import ABC, abstractmethod

class ClassifierTrainer(ABC):
    def __init__(self):
        self.time_period = 1000000000
        pass

    @abstractmethod
    def readFileContents(self):
        pass

    @abstractmethod
    def extractFeatures(self):
        pass    

    @abstractmethod
    def extractFrequency(self):
        pass

    @abstractmethod
    def extractSequence(self):
        pass

    @abstractmethod
    def trainModel(self, X, y):
        pass

    @abstractmethod
    def testModel(self):
        pass

    @abstractmethod
    def saveModel(self, filepath):
        pass
