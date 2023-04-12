from boofuzz import *

pingPacket=b"".join((b"\x00\x01", #Transaction Identifier
            b"\x00\x00", #Protocol Identifier
            b"\x00\x05", #Length
            b"\x01", # Unit Identifier
            b"\x2b", #Function Code 
            b"\x0e", #MEI Type  
            b"\x01", #Read Device ID Code (Basic)
            b"\x00"))  #Object ID (Vendor Name)
def target_alive(target:Target, fuzz_data_logger, session, sock, *args, **kwargs):
    try:
        target.open()
        target.send(pingPacket)
        data = target.recv(1000)
        if len(data) < 8:
            fuzz_data_logger.log_fail("Getting MODBUS device information failed!")
            return False    
        else:
            unit_ID = data[6].to_bytes((data[6].bit_length() + 7) // 8, byteorder='big')
            func_code = data[7]
            exception_code = data[8]
            if data[5] > 0:
                if hex(func_code) == '0x11':
                    fuzz_data_logger.log_pass(f"Getting MODBUS device information succeeded")
                elif hex(exception_code) == '0xb': # more details needed? and (hex(Func_code) == '0x91' or hex(Func_code) == '0x84')
                    fuzz_data_logger.log_info(f"Getting MODBUS device information: Gateway target device failed to respond")
                elif hex(exception_code) == '0x1':
                    fuzz_data_logger.log_info(f"Getting MODBUS device information: Illegal function")
                else:
                    fuzz_data_logger.log_info(f"Getting MODBUS device information warning")
            else:
                fuzz_data_logger.log_info(f"Getting MODBUS data error")
            return True
    except Exception as e:
        fuzz_data_logger.log_fail(f"Getting MODBUS device information failed!! Exception while receiving: {type(e).__name__}: {str(e)}")
        return False
    
session = Session(
    target=Target(
        connection=TCPSocketConnection("127.0.0.1", 5004)
    ),
    post_test_case_callbacks=[target_alive]
)

test = Request("fuzzAll", children=(
    Block("MBAP", children=(
        Word("Transaction Identifier", 0x0001, fuzzable=False),
        Word("Protocol Identifier", 0x0000, fuzzable=False),
        Word("Length", 0x0010, fuzzable=True),
        Byte("Unit Identifier", 0xff, fuzzable=False),
    )),
    Block("PDU", children=(
        Byte("Function Code", 0x01, fuzzable=True),
        RandomData("Data", b"\x00\x00\x00\x01", max_length=257, fuzzable=True)
    ))
))

session.connect(test)
session.fuzz()



class PingMonitor(BaseMonitor):
    def __init__(self, session:Session):
        self.target = session.targets[0]
        self.logger = session.logger
        super().__init__()
    def alive(self):
        return self.ping()

    def get_crash_synopsis(self):
        return super().get_crash_synopsis()
    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        return self.alive()
    def post_start_target(self, target=None, fuzz_data_logger=None, session=None):
        return super().post_start_target(target, fuzz_data_logger, session)
    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        return super().pre_send(target, fuzz_data_logger, session)
    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        return super().restart_target(target, fuzz_data_logger, session)
    def retrieve_data(self):
        return super().retrieve_data()
    def set_options(self, *args, **kwargs):
        return super().set_options(*args, **kwargs)
    def start_target(self):
        return super().start_target()
    def stop_target(self):
        return super().stop_target()
    
    def ping(self):
        try:
            self.target.open()
            self.target.send(self.pingPacket)
            data = self.target.recv(10000)
            if len(data) < 8:
                print("AAAAAAAAAAAAAAAAAAAAAAA"*500)
                return False
            return True
        except:
            return False