import sys
from ctypes.wintypes import *
from ctypes import * 

kernel32 = WinDLL('kernel32', use_last_error=True)

PVOID  = c_void_p
LPVOID = PVOID
LPTSTR = c_void_p
LPBYTE = c_char_p
LPSECURITY_ATTRIBUTES = LPVOID
SIZE_T = c_size_t
SYNCHRONIZE                         = 0x00100000  # The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.
PROCESS_CREATE_PROCESS              = 0x0080 # Required to create a process.
PROCESS_CREATE_THREAD               = 0x0002 # Required to create a thread.
PROCESS_DUP_HANDLE                  = 0x0040 # Required to duplicate a handle using DuplicateHandle.
PROCESS_QUERY_INFORMATION           = 0x0400 # Required to retrieve certain information about a process, such as its token, exit code, and priority class = see OpenProcessToken #.
PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000 # Required to retrieve certain information about a process = see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName #. A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.  Windows Server 2003 and Windows XP:  This access right is not supported.
PROCESS_SET_INFORMATION             = 0x0200 # Required to set certain information about a process, such as its priority class = see SetPriorityClass #.
PROCESS_SET_QUOTA                   = 0x0100 # Required to set memory limits using SetProcessWorkingSetSize.
PROCESS_SUSPEND_RESUME              = 0x0800 # Required to suspend or resume a process.
PROCESS_TERMINATE                   = 0x0001 # Required to terminate a process using TerminateProcess.
PROCESS_VM_OPERATION                = 0x0008 # Required to perform an operation on the address space of a process = see VirtualProtectEx and WriteProcessMemory #.
PROCESS_VM_READ                     = 0x0010 # Required to read memory in a process using ReadProcessMemory.
PROCESS_VM_WRITE                    = 0x0020 # Required to write to memory in a process using WriteProcessMemory.
PROCESS_ALL_ACCESS                  = (PROCESS_CREATE_PROCESS
                                     | PROCESS_CREATE_THREAD
                                     | PROCESS_DUP_HANDLE
                                     | PROCESS_QUERY_INFORMATION
                                     | PROCESS_QUERY_LIMITED_INFORMATION
                                     | PROCESS_SET_INFORMATION
                                     | PROCESS_SET_QUOTA
                                     | PROCESS_SUSPEND_RESUME
                                     | PROCESS_TERMINATE
                                     | PROCESS_VM_OPERATION
                                     | PROCESS_VM_READ
                                     | PROCESS_VM_WRITE
                                     | SYNCHRONIZE)

# Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
                                                            # https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
class STARTUPINFO(Structure):                              # typedef struct _STARTUPINFO
    _fields_ = [                                               # {
           ('cb',               DWORD),                    # DWORD  cb;
           ('lpReserved',       LPTSTR),                   # LPTSTR lpReserved;
           ('lpDesktop',        LPTSTR),                   # LPTSTR lpDesktop;
           ('lpTitle',          LPTSTR),                   # LPTSTR lpTitle;
           ('dwX',              DWORD),                    # DWORD  dwX;
           ('dwY',              DWORD),                    # DWORD  dwY;
           ('dwXSize',          DWORD),                    # DWORD  dwXSize;
           ('dwYSize',          DWORD),                    # DWORD  dwYSize;
           ('dwXCountChars',    DWORD),                    # DWORD  dwXCountChars;
           ('dwYCountChars',    DWORD),                    # DWORD  dwYCountChars;
           ('dwFillAttribute',  DWORD),                    # DWORD  dwFillAttribute;
           ('dwFlags',          DWORD),                    # DWORD  dwFlags;
           ('wShowWindow',       WORD),                    # WORD   wShowWindow;
           ('cbReserved2',       WORD),                    # WORD   cbReserved2;
           ('lpReserved2',     LPBYTE),                    # LPBYTE lpReserved2;
           ('hStdInput',       HANDLE),                    # HANDLE hStdInput;
           ('hStdOutput',      HANDLE),                    # HANDLE hStdOutput;
           ('hStdError',       HANDLE)                     # HANDLE hStdError;
           ]                                               # }

class PROC_THREAD_ATTRIBUTE_ENTRY(Structure):                  # typedef struct _PROC_THREAD_ATTRIBUTE_ENTRY
    _fields_ = [                                               # {
               ("Attribute",     DWORD),                       # DWORD_PTR   Attribute;  // PROC_THREAD_ATTRIBUTE_xxx # https://msdn.microsoft.com/en-us/library/windows/desktop/ms686880(v=vs.85).aspx
               ("cbSize",       SIZE_T),                       # SIZE_T      cbSize;
               ("lpValue",       PVOID)                        # PVOID       lpValue
               ] 

class PROC_THREAD_ATTRIBUTE_LIST(Structure):                   # typedef struct _PROC_THREAD_ATTRIBUTE_LIST
    _fields_ = [                                               # {
               ("dwFlags", DWORD),                             # DWORD                      dwFlags;
               ("Size",    ULONG),                             # ULONG                      Size;
               ("Count",   ULONG),                             # ULONG                      Count;
               ("Reserved",ULONG),                             # ULONG                      Reserved;
               ("Unknown", PULONG),                            # PULONG                     Unkown;
               ("Entries", PROC_THREAD_ATTRIBUTE_ENTRY * 1)    # PROC_THREAD_ATTRIBUTE_LIST Entries[ANYSIZE_ARRAY]
               ]  

# Contains information about a newly created process and its primary thread. It is used with the CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, or CreateProcessWithTokenW function.
                                                            # https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
class PROCESS_INFORMATION(Structure):                      # typedef struct _PROCESS_INFORMATION
    _fields_ = [                                               # {
           ("hProcess",    HANDLE),                        # HANDLE hProcess;
           ("hThread",     HANDLE),                        # HANDLE hThread;
           ("dwProcessId",  DWORD),                        # DWORD  dwProcessId;
           ("dwThreadId",   DWORD)                         # DWORD  dwThreadId;
           ]                                               # }

class STARTUPINFOEX(Structure):                                #   typedef struct _STARTUPINFOEX
    _fields_ = [                                               #   {
               ('StartupInfo',     STARTUPINFO),               #   STARTUPINFO                 StartupInfo;
               ('lpAttributeList', LPVOID),                    # PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList; # lpStartupInfo = STARTUPINFOEX(); lpStartupInfo.lpAttributeList = addressof(AttributeList)
               ]  
PPROC_THREAD_ATTRIBUTE_LIST = POINTER(PROC_THREAD_ATTRIBUTE_LIST)
LPPROC_THREAD_ATTRIBUTE_LIST = PPROC_THREAD_ATTRIBUTE_LIST
PSIZE_T = POINTER(SIZE_T)

InitializeProcThreadAttributeList = kernel32.InitializeProcThreadAttributeList        # https://msdn.microsoft.com/en-us/library/windows/desktop/ms683481(v=vs.85).aspx
InitializeProcThreadAttributeList.restype = BOOL                                     # BOOL WINAPI InitializeProcThreadAttributeList
InitializeProcThreadAttributeList.argtypes = [                                       # (
                  LPPROC_THREAD_ATTRIBUTE_LIST,                                      # LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
                  DWORD,                                                             # DWORD                        dwAttributeCount,
                  DWORD,                                                             # DWORD                        dwFlags,
                  PSIZE_T                                                            # PSIZE_T                      lpSize
                  ]

# Updates the specified attribute in a list of attributes for process and thread creation.
UpdateProcThreadAttribute = kernel32.UpdateProcThreadAttribute                        # https://msdn.microsoft.com/en-us/library/windows/deLPSECURITY_ATTRIBUTES lpProcessAttributes,sktop/ms686880(v=vs.85).aspx
UpdateProcThreadAttribute.restype = BOOL                                             # BOOL WINAPI UpdateProcThreadAttribute
UpdateProcThreadAttribute.argtypes = [                                               # (
                  LPPROC_THREAD_ATTRIBUTE_LIST,                                      # LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
                  DWORD,                                                             # DWORD                        dwFlags,
                  DWORD,                                                             # DWORD_PTR                    Attribute,
                  PVOID,                                                             # PVOID                        lpValue,
                  SIZE_T,                                                            # SIZE_T                       cbSize,
                  PVOID,                                                             # PVOID                        lpPreviousValue,
                  PSIZE_T                                                            # PSIZE_T                      lpReturnSize
                  ]

# Opens an existing local process object
OpenProcess = kernel32.OpenProcess                                                    # https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
OpenProcess.restype = HANDLE                                                         # HANDLE WINAPI OpenProcess
OpenProcess.argtypes = [                                                             # (
                 DWORD,                                                              # DWORD dwDesiredAccess,
                 BOOL,                                                               # BOOL  bInheritHandle,
                 DWORD                                                               # DWORD dwProcessId
                 ]

# Creates a new process and its primary thread. The new process runs in the security context of the calling process.
CreateProcess = kernel32.CreateProcessW                    # https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
CreateProcess.restype = BOOL                               # BOOL WINAPI CreateProcess
CreateProcess.argtypes = [                                 # (
               LPCWSTR,                                    # LPCTSTR               lpApplicationName,
               LPWSTR,                                     # LPTSTR                lpCommandLine,
               LPSECURITY_ATTRIBUTES,                      # LPSECURITY_ATTRIBUTES lpProcessAttributes,
               LPSECURITY_ATTRIBUTES,                      # LPSECURITY_ATTRIBUTES lpThreadAttributes,
               BOOL,                                       # BOOL                  bInheritHandles,
               DWORD,                                      # DWORD                 dwCreationFlags,
               LPVOID,                                     # LPVOID                lpEnvironment,
               LPCWSTR,                                    # LPCTSTR               lpCurrentDirectory,
               POINTER(STARTUPINFOEX),                       # LPSTARTUPINFO         lpStartupInfo,
               POINTER(PROCESS_INFORMATION)                # LPPROCESS_INFORMATION lpProcessInformation
               ]

# Process creation flags | https://msdn.microsoft.com/en-us/library/windows/desktop/ms684863(v=vs.85).aspx
CREATE_NEW_CONSOLE           = 0x00000010 # The new process has a new console, instead of inheriting its parent's console (the default).
EXTENDED_STARTUPINFO_PRESENT = 0x00080000  # The process is created with extended startup information; the lpStartupInfo parameter specifies a STARTUPINFOEX structure.
AttributeList = PROC_THREAD_ATTRIBUTE_LIST()
ProcThreadAttributeParentProcess    = 0
PROC_THREAD_ATTRIBUTE_INPUT         = 0x00020000
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS= ProcThreadAttributeParentProcess | PROC_THREAD_ATTRIBUTE_INPUT # Handle of the Parent Process

class ppid_spoof():

    def __init__(self):
        self.command = None
        self.ppid = None

    def spoof(self, inheritHandle = False, ppid = None, command = None):
        # Where lpApplicationName is the path of the executable 
        if command:
            self.command = command
        if ppid:
            self.ppid = ppid
        Size = SIZE_T(0)
        lpStartupInfo = STARTUPINFO()
        lpStartupInfoEx = STARTUPINFOEX()
        lpStartupInfoEx.StartupInfo.cb = sizeof(lpStartupInfoEx) 
        lpStartupInfoEx.lpAttributeList = addressof(AttributeList)
        lpProcessInformation = PROCESS_INFORMATION()
        handle = OpenProcess(
                                    PROCESS_ALL_ACCESS,                          # _In_      dwDesiredAccess       The access to the process object. This access right is checked against the security descriptor for the process. If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.
                                    inheritHandle,                               # _In_      bInheritHandle        If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle
                                    int(self.ppid))                              # _In_      dwProcessId           The identifier of the local process to be opened.
        if not handle:
            raise RuntimeError("Error in OpenProcess: %s" %GetLastError())
        lpvalue = PVOID(handle)
        initAttrList = InitializeProcThreadAttributeList(
                                    None,                                        # _Out_opt_ lpAttributeList       The attribute list. This parameter can be NULL to determine the buffer size required to support the specified number of attributes.
                                    1,                                           # _In_      dwAttributeCount      The count of attributes to be added to the list.
                                    0,                                           # _Reserved_dwFlags               This parameter is reserved and must be zero.
                                    byref(Size))
        if initAttrList:
            print("[*] Error: 0x%08x." % (kernel32.GetLastError()))

        initAttrList2 = InitializeProcThreadAttributeList(
                                    AttributeList,                               # _Out_opt_ lpAttributeList       The attribute list. This parameter can be NULL to determine the buffer size required to support the specified number of attributes.
                                    1,                                           # _In_      dwAttributeCount      The count of attributes to be added to the list.
                                    0,                                           # _Reserved_dwFlags               This parameter is reserved and must be zero.
                                    byref(Size))
        if not initAttrList2:
            print("[*] Error: 0x%08x." % (kernel32.GetLastError()))

        updateProcAttr = UpdateProcThreadAttribute(
                                    AttributeList,                               # _Inout_   lpAttributeList       A pointer to an attribute list created by the InitializeProcThreadAttributeList function.
                                    0,                                           # _In_      dwFlags               This parameter is reserved and must be zero.
                                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,        # _In_      Attribute             The attribute key to update in the attribute list. ~-> PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
                                    byref(lpvalue),                              # _In_      lpValue               A pointer to the attribute value. This value should persist until the attribute is destroyed using the DeleteProcThreadAttributeList function.
                                    sizeof(lpvalue),                             # _In_      cbSize                The size of the attribute value specified by the lpValue parameter.
                                    None,                                        # _Out_opt_ lpPreviousValue       This parameter is reserved and must be NULL.
                                    None)
        if not updateProcAttr:
            print("Error in UpdateProcThreadAttribute: 0x%08x." % (kernel32.GetLastError()))

        lpStartupInfoEx.StartupInfo.cb = sizeof(STARTUPINFOEX)

        proc = CreateProcess(
                    None,                                                # _In_opt_  lpApplicationName     The lpApplicationName parameter can be NULL. In that case, the module name must be the first white spaceâ€“delimited token in the lpCommandLine string.
                    self.command,                                        # _Inout_opt lpCommandLine        The command line to be executed  
                    None,                                                # _In_opt_  pProcessAttributes    A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new process object can be inherited by child processes. If lpProcessAttributes is NULL, the handle cannot be inherited.
                    None,                                                # _In_opt_  lpThreadAttributes    A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new thread object can be inherited by child processes. If lpThreadAttributes is NULL, the handle cannot be inherited.
                    0,                                                   # _In_      bInheritHandles       If this parameter is TRUE, each inheritable handle in the calling process is inherited by the new process. If the parameter is FALSE, the handles are not inherited. Note that inherited handles have the same value and access rights as the original handles.
                    (CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT), #_In_dwCreationFlags       The flags that control the priority class and the creation of the process # To specify these attributes when creating a process, specify EXTENDED_STARTUPINFO_PRESENT in the dwCreationFlag parameter and a STARTUPINFOEX structure in the lpStartupInfo parameter
                    None,                                                # _In_opt_  lpEnvironment         A pointer to the environment block for the new process. If this parameter is NULL, the new process uses the environment of the calling process.
                    None,                                                # _In_opt_  lpCurrentDirectory    The full path to the current directory for the process. If this parameter is NULL, the new process will have the same current drive and directory as the calling process
                    byref(lpStartupInfoEx),                              # _In_      lpStartupInfo         A pointer to a STARTUPINFO or STARTUPINFOEX structure.To set extended attributes, use a STARTUPINFOEX structure and specify EXTENDED_STARTUPINFO_PRESENT in the dwCreationFlags parameter.
                    byref(lpProcessInformation)) 
        if not proc:
            print("[*] Error in CreateProc: 0x%08x." % (kernel32.GetLastError()))

if __name__ == '__main__':
    spoof = ppid_spoof()
    try:
        int(sys.argv[1])
        spoof.spoof(ppid=sys.argv[1], command=' '.join(sys.argv[2:]))
    except:
        inherit = sys.argv[1].lower() == "true"
        spoof.spoof(inheritHandle=inherit, ppid=sys.argv[2], command=' '.join(sys.argv[3:]))
