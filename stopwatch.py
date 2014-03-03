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
            return self._timedelta_to_microtime(self.stoptime - self.starttime)
        
    def gettime(self):
        if self.stoptime is None:
            curtime = datetime.now()
            return self._timedelta_to_microtime(curtime - self.starttime)
        else:
            return self._timedelta_to_microtime(self.stoptime - self.starttime)
        
    def split(self):
        if self.starttime is None or self.stoptime is not None:
            raise RuntimeError("Stopwatch is not running.")
        else:
            curtime = self._timedelta_to_microtime(datetime.now() - self.starttime)
            self.starttime = datetime.now()
            return curtime

    def _timedelta_to_microtime(self, td):
        return td.microseconds + (td.seconds + td.days * 86400) * 1000000
