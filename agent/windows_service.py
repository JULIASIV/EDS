# agent/windows_service.py
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import time
import logging
from agent.core import EDRAgent

class EDRService(win32serviceutil.ServiceFramework):
    _svc_name_ = "EDRAgent"
    _svc_display_name_ = "Enterprise EDR Agent"
    _svc_description_ = "Endpoint Detection and Response Security Agent"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.agent = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        if self.agent:
            self.agent.stop()

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        # Configure logging for Windows service
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('C:\\ProgramData\\EDR\\agent.log'),
                logging.StreamHandler()
            ]
        )
        
        self.agent = EDRAgent()
        self.agent.start()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(EDRService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(EDRService)