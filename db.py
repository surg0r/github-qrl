import pickledb
import threading

# add threading.Rlock()

class Db():
    def __init__(self):
        self.dbase = pickledb.load('test.db', True)
        self.lock = threading.RLock()

    def set(self, key, value):
        with self.lock:
            return self.dbase.set(key, value)


    def get(self, key):
        with self.lock:
            return self.dbase.get(key)

print("Loading threadlocked db")
d = Db()