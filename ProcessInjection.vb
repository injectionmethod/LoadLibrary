Module ProcessInjection
    Private Declare Function VirtualAllocEx Lib "kernel32.dll" (ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByVal dwSize As IntPtr, ByVal flAllocationType As UInteger, ByVal flProtect As UInteger) As IntPtr
    Private Declare Function WriteProcessMemory Lib "kernel32.dll" (ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, ByVal lpBuffer As Byte(), ByVal nSize As IntPtr, ByRef lpNumberOfBytesWritten As IntPtr) As Boolean
    Private Declare Function GetProcAddress Lib "kernel32.dll" (ByVal hModule As IntPtr, ByVal lpProcName As String) As IntPtr
    Private Declare Function LoadLibrary Lib "kernel32.dll" Alias "LoadLibraryA" (ByVal lpLibFileName As String) As IntPtr
    Private Declare Function CreateRemoteThread Lib "kernel32.dll" (ByVal hProcess As IntPtr, ByVal lpThreadAttributes As IntPtr, ByVal dwStackSize As IntPtr, ByVal lpStartAddress As IntPtr, ByVal lpParameter As IntPtr, ByVal dwCreationFlags As UInteger, ByVal lpThreadId As IntPtr) As IntPtr
    Private Declare Function WaitForSingleObject Lib "kernel32.dll" (ByVal hHandle As IntPtr, ByVal dwMilliseconds As UInteger) As UInteger
    Private Declare Function VirtualFreeEx Lib "kernel32.dll" (ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByVal dwSize As IntPtr, ByVal dwFreeType As UInteger) As Boolean
    Private Declare Function OpenProcess Lib "kernel32.dll" (ByVal dwDesiredAccess As UInteger, ByVal bInheritHandle As Boolean, ByVal dwProcessId As Integer) As IntPtr
    Private Declare Function CloseHandle Lib "kernel32.dll" (ByVal hObject As IntPtr) As Boolean

    Private Const MEM_COMMIT As UInteger = &H1000
    Private Const PAGE_READWRITE As UInteger = &H4
    Private Const PAGE_EXECUTE_READ As UInteger = &H20
    Private Const PROCESS_CREATE_THREAD As UInteger = &H2
    Private Const PROCESS_QUERY_INFORMATION As UInteger = &H400
    Private Const PROCESS_VM_OPERATION As UInteger = &H8
    Private Const PROCESS_VM_WRITE As UInteger = &H20
    Private Const PROCESS_VM_READ As UInteger = &H10
    Private Const INFINITE As UInteger = &HFFFFFFFFUI

    Public Function InjectDLL(ByVal processName As String, ByVal dllPath As String) As Boolean
        Try
            Dim proc As Process = Process.GetProcessesByName(processName)(0)
            Dim hProcess As IntPtr = OpenProcess(PROCESS_CREATE_THREAD Or PROCESS_QUERY_INFORMATION Or PROCESS_VM_OPERATION Or PROCESS_VM_WRITE Or PROCESS_VM_READ, False, proc.Id)

            Dim dllBytes As Byte() = System.Text.Encoding.ASCII.GetBytes(dllPath)
            Dim dllPathAlloc As IntPtr = VirtualAllocEx(hProcess, IntPtr.Zero, CType(dllBytes.Length, IntPtr), MEM_COMMIT, PAGE_READWRITE)
            WriteProcessMemory(hProcess, dllPathAlloc, dllBytes, CType(dllBytes.Length, IntPtr), IntPtr.Zero)

            Dim kernel32 As IntPtr = LoadLibrary("kernel32.dll")
            Dim loadLibraryAddr As IntPtr = GetProcAddress(kernel32, "LoadLibraryA")

            Dim threadId As IntPtr
            Dim hThread As IntPtr = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, dllPathAlloc, 0, threadId)

            WaitForSingleObject(hThread, INFINITE)

            VirtualFreeEx(hProcess, dllPathAlloc, CType(dllBytes.Length, IntPtr), &H8000)
            CloseHandle(hThread)
            CloseHandle(hProcess)

            Return True
        Catch ex As Exception
            Return False
        End Try
    End Function
End Module
