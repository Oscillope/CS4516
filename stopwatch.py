from datetime import datetime

class Stopwatch:
    starttime = None
    stoptime = None
    
    def start(self):
        self.starttime = datetime.now()
        self.stoptime = None
        
    def stop(self):
        if self.starttime is None:
            raise RuntimeError("Stopwatch is not running.")
        else:
            self.stoptime = datetime.now()
            return (self.stoptime - self.starttime).microseconds
        
    def gettime(self):
        if self.stoptime is None:
            curtime = datetime.now()
            return (curtime - self.starttime).microseconds
        else:
            return (self.stoptime - self.starttime).microseconds
        
    def split(self):
        if self.starttime is None or self.stoptime is not None:
            raise RuntimeError("Stopwatch is not running.")
        else:
            curtime = (datetime.now() - self.starttime).microseconds
            self.starttime = datetime.now()
            return curtime
