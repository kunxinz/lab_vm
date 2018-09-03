import time

class PF_TM(object):
    def __init__(self, seq_flag=True):
        self.start_time = 0
        self.current_time = 0
        self.seq_flag = seq_flag

    def tic(self):
        self.start_time = time.time()

    def toc(self, usr_str):
        self.current_time = time.time()
        elapse_time = self.current_time - self.start_time
        print('{} elapse time is {:.2f}'.format(usr_str, elapse_time))
        if not self.seq_flag:
            self.start_time = self.current_time
        return elapse_time
