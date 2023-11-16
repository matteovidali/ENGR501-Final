from keysight_visa_control import KeysightControl
from numpy import fft, ndarray, absolute, array, float64, argmax, random
import matplotlib.pyplot as plt
import serial as ser
import time
import json

class AttackDevice:
    '''A class for the attacked device. Should wrap the essential functions of device'''
    def __init__(self):
        pass

def setup_scope():
    scope = KeysightControl("TCPIP::192.168.0.17::INSTR", loud=False)
     
    return scope

class LabeledBytes:
    def __init__(self, nums: list, bytestring: bytes):
        self.nums: list = nums
        self.binary: bytes = bytestring
        self.cyphertext: bytes
    def out(self):
        return {"NUMS": self.nums,
                "BINARY": int.from_bytes(self.binary, 'big'),
                "CYPHERTEXT": int.from_bytes(self.ciphertext, 'big')}

class Trace:
    def __init__(self, lb: LabeledBytes, av_trace: ndarray, average_number: int=10):
        self.lb = lb
        self.av_trace = av_trace
        self.av_num = average_number

    def out(self):
        return{"LB": self.lb.out(),
               "AV_TRACE": self.av_trace.tolist(),
               "AV_NUM": self.av_num}

def gen_bytes(len=16) -> list[list, bytes]:
    nums = random.randint(0,255,len) 
    bytes_ = [int(x).to_bytes(1, byteorder="big") for x in nums]
    return LabeledBytes([int(x) for x in nums], b''.join(bytes_))

def run_encrypt(dev: ser.Serial, b: bytes) -> bytes:
    # FLUsh
    dev.write("e\n".encode('utf-8'))
    dev.write(b)
    dev.write("\n".encode('utf-8'))
    return dev.read(16)

def align_traces(sa: ndarray, sb: ndarray) -> list:
    '''Align a set of traces:
        Compute the PHASE CORRELATION between the two signals
        to align them.
        Returns shifted version of sb as a list'''
    # Save the original sb list
    o_sb = sb.tolist()
    # Zero Mean
    sa -= sa.mean()
    sb -= sb.mean()

    # Compute fourier transform
    Sa = fft.fft(sa)    
    Sb_star = fft.fft(sb).conjugate()

    # compute the cross power spectrum
    R = (Sa * Sb_star) / absolute(Sa * Sb_star)

    # compute inverse fft
    r = fft.ifft(R)

    # find position of shift
    shift = r.argmax()

    # return shifted second array
    return [*o_sb[len(o_sb) - shift:], *o_sb[:len(o_sb) - shift]]

def collect_rendered_trace(scope: KeysightControl, dev, ntraces: int=100):
    traces = []
    lb = gen_bytes()
    for i in range(ntraces):
        scope.set_trig_single()
        time.sleep(.1)
        lb.ciphertext = run_encrypt(dev, lb.binary)
        temp_trace = scope.capture_waveform()
        window = array(scope.capture_waveform(source="channel2"))
        w_min, w_max = min(window), max(window)
        w = window / (w_max-w_min)
        w -= min(w)
        for j, x in enumerate(w):
            w[j] = 0 if x < .5 else 1
        window = w.tolist()
        try:
            trace = temp_trace[window.index(1)-500:window[window.index(1):].index(0)+499]
        except ValueError:
            print("EXCEPTION")
            print(window)
            i -= 1
            continue
        print(len(trace))
        if len(trace) < 50:
            continue
        traces.append(array(scope.capture_waveform(), dtype=float64)) 


    for i, t in enumerate(traces):
        if i == 0:
            continue
        traces[i] = align_traces(traces[0], traces[i])

    s = sum(traces) 
    s /= ntraces

    return Trace(lb, s, ntraces)

def run():
    scope = setup_scope()
    dev = ser.Serial("/dev/ttyUSB0", 19200)
    traces = []
    for i in range(1000):
        print(f"TRACE {i}")
        traces.append(collect_rendered_trace(scope, dev, ntraces=50))
        with open(f"traces/trace_{i}.json", "w") as outfile:
            json.dump(traces[i].out(), outfile)
    
def test_align_traces(sa, sb):
    #sa = [1, 2, 3, 4, 5, 4, 3, 2 ,1]
    #sb = [*sa[3:], *sa[:3]]
    print(sb)

    saved_sb = align_traces(array(sa, dtype=float64), array(sb, dtype=float64))
    print(saved_sb)
    fig, ax = plt.subplots(2)
    ax[0].set_title("before")
    ax[1].set_title("after")

    ax[0].plot(sa)
    ax[0].plot(sb)

    ax[1].plot(sa)
    ax[1].plot(saved_sb)
    plt.show()

if __name__ == "__main__":
    run()

