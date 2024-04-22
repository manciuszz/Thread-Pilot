class Threader {
	/*
		 Enable, disable or eliminate privileges for the process access token.
		 Parameters:
			 hToken: an identifier to the access token containing the privileges to be modified, the /PID or process name.
			 Newstate: It should be used in one of the following ways:
				 An object with the new state for thick privileges. The key is the name of privilege, and the value must be one of the following values:
					 0x00000000 = SE_PRIVILEGE_DISABLED -> The function disables privilege.
					 0x00000002 = SE_PRIVILEGE_ENABLED -> The function enables privilege.
					 0x00000004 = SE_PRIVILEGE_REMOVED -> The function eliminates privilege. Once a privilege is eliminated, it cannot be restored anymore.
				 If specified -1 - the function disables all privileges.
		 Return Value:
			 -4 = The parameter is invalid.
			 -3 = An error has occurred when trying to open the access token associated with the process.
			 -2 = an error has occurred when trying to open the process.
			 -1 = an error has occurred when trying to adjust the privileges in the process.
			  0 = privileges have changed correctly.
		 Required access:
			 0x0020 = TOKEN_ADJUST_PRIVILEGES.
		 Example:
			AdjustTokenPrivileges(ProcessExist(), {"SeDebugPrivilege": 2, "SeCreateSymbolicLinkPrivilege": 2})
			AdjustTokenPrivileges(ProcessExist(), {"SeDebugPrivilege": 0})
			AdjustTokenPrivileges(ProcessExist(), {"SeDebugPrivilege": 4})
	*/
	AdjustTokenPrivileges(pid, privileges) {
		; Constants from Windows API
		static SE_PRIVILEGE_DISABLED := 0x00000000
		static SE_PRIVILEGE_ENABLED := 0x00000002
		static SE_PRIVILEGE_REMOVED := 0x00000004
		static SE_PRIVILEGE_REMOVE_ALL := 0xFFFFFFFF
		
		static TOKEN_ADJUST_PRIVILEGES := 0x0020
		static TOKEN_QUERY := 0x0008
		
		static PROCESS_QUERY_INFORMATION := 0x0400
		static PROCESS_VM_READ := 0x0010
		
		static PRIVILEGE_MAP := { "SE_PRIVILEGE_DISABLED": SE_PRIVILEGE_DISABLED, "DISABLED": SE_PRIVILEGE_DISABLED, "SE_PRIVILEGE_ENABLED": SE_PRIVILEGE_ENABLED, "ENABLED": SE_PRIVILEGE_ENABLED, "SE_PRIVILEGE_REMOVED": SE_PRIVILEGE_REMOVED, "REMOVED": SE_PRIVILEGE_REMOVED, "SE_PRIVILEGE_REMOVE_ALL": SE_PRIVILEGE_REMOVE_ALL, "REMOVE_ALL": SE_PRIVILEGE_REMOVE_ALL }

		; Open the process
		hProcess := DllCall("OpenProcess", "UInt", PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, "Int", false, "UInt", pid)
		if (!hProcess) {
			MsgBox Failed to open process with PID %pid%.
			return false
		}

		; Open the process token
		DllCall("advapi32\OpenProcessToken", "Ptr", hProcess, "UInt", TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, "Ptr*", hToken)
		if (!hToken) {
			this.CloseHandle(hProcess)
			MsgBox Failed to open process token for PID %pid%.
			return false
		}

		; Iterate through the privileges and adjust them
		for privilege, attribute in privileges {
			LUID := 0
			if (!DllCall("advapi32\LookupPrivilegeValue", "Ptr", 0, "Str", privilege, "Int64*", LUID)) {
				this.CloseHandle(hToken)
				this.CloseHandle(hProcess)
				MsgBox Failed to lookup privilege %privilege%.
				return false
			}

			VarSetCapacity(TOKEN_PRIVILEGES, 16, 0)
			NumPut(1, TOKEN_PRIVILEGES, 0, "uint")
			NumPut(LUID, TOKEN_PRIVILEGES, 4, "int64")
			NumPut(PRIVILEGE_MAP.HasKey(attribute) ? PRIVILEGE_MAP[attribute] : attribute, TOKEN_PRIVILEGES, 12, "uint")			
			if (!DllCall("advapi32\AdjustTokenPrivileges", "Ptr", hToken, "Int", false, "Ptr", &TOKEN_PRIVILEGES, "UInt", 0, "Ptr", 0, "UInt*", 0)) {
				this.CloseHandle(hToken)
				this.CloseHandle(hProcess)
				MsgBox Failed to adjust privilege %privilege%.
				return false
			}
		}

		; Clean up and close handles
		this.CloseHandle(hToken)
		this.CloseHandle(hProcess)
		return true
	}

	FindModuleName(ProcessID, ThreadStartAddr, ModuleNames) {
		static MODULE_ENTRY_SIZE := (A_PtrSize = 8 ? 568 : 548)
		static MODULE_NAME_OFFSET := (A_PtrSize = 8 ? 48 : 32)
		static MODULE_ADDRESS_OFFSET := (A_PtrSize = 8 ? 24 : 20)
		static MODULE_SIZE_OFFSET := (A_PtrSize = 8 ? 32 : 24)
		
		if (ModuleNames == "*")
			return true	
		else if (ModuleNames.Length() == "")
			ModuleNames := [ModuleNames]
						
		if !(hSnapshot := DllCall("CreateToolhelp32Snapshot", "uint", 0x18, "uint", ProcessID))
			throw Exception(Format("Error in CreateToolhelp32Snapshot"))

		NumPut(VarSetCapacity(MODULEENTRY32, MODULE_ENTRY_SIZE, 0), MODULEENTRY32, "uint")
		if !(DllCall("Module32First", "ptr", hSnapshot, "ptr", &MODULEENTRY32))
			throw Exception(Format("Error in Module32First"))

		while (DllCall("Module32Next", "ptr", hSnapshot, "ptr", &MODULEENTRY32)) {
			ADDR := NumGet(MODULEENTRY32, MODULE_ADDRESS_OFFSET, "uptr")
			SIZE := NumGet(MODULEENTRY32, MODULE_SIZE_OFFSET, "uint")
			
			if (ThreadStartAddr >= ADDR && ThreadStartAddr <= ADDR + SIZE) {
				MODULE_NAME := StrGet(&MODULEENTRY32 + MODULE_NAME_OFFSET, 256, "cp0")
				for idx, moduleName in ModuleNames
					if (MODULE_NAME = moduleName)
						return true
			}
		}		
	
		return false, DllCall("CloseHandle", "ptr", hSnapshot)
	}
	
	GetModuleThreads(ProcessID, ModuleNames) {
		static ThreadQuerySetWin32StartAddress := 9
		static THREAD_QUERY_INFORMATION := 0x0040
		static TH32CS_SNAPTHREAD := 0x4
		
		if (ProcessID == 0)
			return []
		
		hModule := DllCall("LoadLibrary", "str", "ntdll.dll", "uptr")

		if !(hSnapshot := DllCall("CreateToolhelp32Snapshot", "uint", TH32CS_SNAPTHREAD, "uint", ProcessID))
			throw Exception(Format("Error in CreateToolhelp32Snapshot"))

		NumPut(VarSetCapacity(THREADENTRY32, 28, 0), THREADENTRY32, "uint")
		if !(DllCall("Thread32First", "ptr", hSnapshot, "ptr", &THREADENTRY32))
			throw Exception(Format("Error in Thread32First"))
		
		Threads := []
		while (DllCall("Thread32Next", "ptr", hSnapshot, "ptr", &THREADENTRY32)) {
			if (NumGet(THREADENTRY32, 12, "uint") = ProcessID) {
				if (ModuleNames == "*") {
					Threads.Push(NumGet(THREADENTRY32, 8, "uint"))
				} else {
					hThread := DllCall("OpenThread", "uint", THREAD_QUERY_INFORMATION, "int", 0, "uint", NumGet(THREADENTRY32, 8, "uint"), "ptr")
					if (DllCall("ntdll\NtQueryInformationThread", "ptr", hThread, "uint", ThreadQuerySetWin32StartAddress, "ptr*", ThreadStartAddr, "uint", A_PtrSize, "uint*", 0) != 0)
						throw Exception(Format("Error in NtQueryInformationThread: ({1}, {2})", hThread, ProcessID))
					
					if (this.FindModuleName(ProcessID, ThreadStartAddr, ModuleNames))
						Threads.Push(NumGet(THREADENTRY32, 8, "uint"))

					DllCall("CloseHandle", "ptr", hThread)
				}			
			}
		}

		return Threads, DllCall("CloseHandle", "ptr", hSnapshot) && DllCall("FreeLibrary", "ptr", hModule)
	}
	
	GetProcessThreadInfo(ProcessID) {
		static BUFFER_SIZE := 0x100

		static ThreadIdealProcessorEx := 0x21
		static ThreadNameInformation := 0x26

		static THREAD_QUERY_INFORMATION := 0x0040
		; static THREAD_QUERY_LIMITED_INFORMATION := 0x0800
		static TH32CS_SNAPTHREAD := 0x4
		
		if (ProcessID == 0)
			return []
		
		hModule := DllCall("LoadLibrary", "STR", "ntdll.dll", "UPTR")

		if !(hSnapshot := DllCall("CreateToolhelp32Snapshot", "UInt", TH32CS_SNAPTHREAD, "UInt", ProcessID))
			throw Exception(Format("Error in CreateToolhelp32Snapshot"))

		NumPut(VarSetCapacity(THREADENTRY32, 28, 0), THREADENTRY32, "UInt")
		if !(DllCall("Thread32First", "PTR", hSnapshot, "PTR", &THREADENTRY32))
			throw Exception(Format("Error in Thread32First"))
		

		aThreads := []
		while (DllCall("Thread32Next", "PTR", hSnapshot, "PTR", &THREADENTRY32)) {
			if (NumGet(THREADENTRY32, 12, "UInt") = ProcessID) {
				hThread := DllCall("OpenThread", "UInt", THREAD_QUERY_INFORMATION, "INT", 0, "UInt", NumGet(THREADENTRY32, 8, "UInt"), "PTR")
				
				VarSetCapacity(buffer, BUFFER_SIZE, 0)
				if ((result := DllCall("ntdll\NtQueryInformationThread", "PTR", hThread, "UInt", ThreadNameInformation, "PTR", &buffer, "UInt", BUFFER_SIZE, "UInt*", 0)) != 0)
					throw Exception(Format("Error in NtQueryInformationThread (ThreadNameInformation): ({1}, {2}, {3})", hThread, ProcessID, NumGet(THREADENTRY32, 8, "UInt")))
				
				VarSetCapacity(processorNumber, 4, 0)
				if (DllCall("ntdll\NtQueryInformationThread", "PTR", hThread, "UInt", ThreadIdealProcessorEx, "PTR", &processorNumber, "UInt", 4, "UInt*", 0) != 0) 
					throw Exception(Format("Error in NtQueryInformationThread (ThreadIdealProcessorEx): ({1}, {2}, {3})", hThread, ProcessID, NumGet(THREADENTRY32, 8, "UInt")))
				
				; group := NumGet(&processorNumber + 0, "UShort")
				threadProcessor := NumGet(&processorNumber + 2, "UChar")
				; reserved := NumGet(&processorNumber + 3, "UChar")
								
				threadName := StrGet(&buffer + 16, "UTF-16")
				aThreads.Push({ ThreadID: NumGet(THREADENTRY32, 8, "UInt"), Name: threadName, IdealProcessor: threadProcessor })

				DllCall("CloseHandle", "PTR", hThread)
			}
		}

		return aThreads, DllCall("CloseHandle", "PTR", hSnapshot) && DllCall("FreeLibrary", "PTR", hModule)
	}
	
	GetThreadName(threadId) {
		static THREAD_QUERY_INFORMATION := 0x0040
		static ThreadNameInformation := 0x26
		static BUFFER_SIZE := 0x100

		if !(hThread := DllCall("OpenThread", "UInt", THREAD_QUERY_INFORMATION, "INT", 0, "UInt", threadId, "PTR"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
		
		VarSetCapacity(buffer, bufferSize, 0)
		if ((result := DllCall("ntdll\NtQueryInformationThread", "PTR", hThread, "UInt", ThreadNameInformation, "PTR", &buffer, "UInt", bufferSize, "UInt*", 0)) != 0)
			throw Exception(Format("Error in NtQueryInformationThread: ({1}, {2})", hThread, threadId))
			
		threadName := StrGet(&buffer + 16, "UTF-16")
		return threadName, DllCall("CloseHandle", "PTR", hThread)
	}
	
	GetThreadIdealProcessor(threadId) {
		static THREAD_QUERY_INFORMATION := 0x0040
		static ThreadIdealProcessorEx := 0x21

		if !(hThread := DllCall("OpenThread", "UInt", THREAD_QUERY_INFORMATION, "INT", 0, "UInt", threadId, "Ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
		
		VarSetCapacity(processorNumber, 4, 0)
		if (DllCall("ntdll\NtQueryInformationThread", "Ptr", hThread, "UInt", ThreadIdealProcessorEx, "Ptr", &processorNumber, "UInt", 4, "UInt*", 0) != 0) 
			throw Exception(Format("Error in NtQueryInformationThread: ({1}, {2})", hThread, threadId))
				
		; group := NumGet(&processorNumber + 0, "UShort")
		number := NumGet(&processorNumber + 2, "UChar")
		; reserved := NumGet(&processorNumber + 3, "UChar")
				
		return number, DllCall("CloseHandle", "Ptr", hThread)
	}
	
	GetProcessIdOfThread(threadId) {
		static THREAD_QUERY_INFORMATION := 0x0040
		
		if !(hThread := DllCall("OpenThread", "UInt", THREAD_QUERY_INFORMATION, "INT", 0, "UInt", threadId, "Ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
			
		PID := DllCall("GetProcessIdOfThread", "Ptr", hThread, "UInt")

		return PID, DllCall("CloseHandle", "Ptr", hThread)
	}

/* 
	GetThreadCycleTime(threadId) {
		static THREAD_QUERY_INFORMATION := 0x0040
		static ThreadCycleTime := 0x17

		if !(hThread := DllCall("OpenThread", "UInt", THREAD_QUERY_INFORMATION, "INT", 0, "UInt", threadId, "Ptr"))
			throw Exception("Error in OpenThread")
		
		; typedef struct _THREAD_CYCLE_TIME_INFORMATION
		; {
			; ULONGLONG AccumulatedCycles;
			; ULONGLONG CurrentCycleCount;
		; } THREAD_CYCLE_TIME_INFORMATION, *PTHREAD_CYCLE_TIME_INFORMATION;
		
		VarSetCapacity(cycleTimeInfo, 16, 0)
		if ((STATUS_CODE := DllCall("ntdll\NtQueryInformationThread", "Ptr", hThread, "UInt", ThreadCycleTime, "Ptr", &cycleTimeInfo, "UInt", 16, "UInt*", 0)) != 0) 
			throw Exception(Format("Error in NtQueryInformationThread: ({1}, {2}, {3}, {4})", hThread, threadId, STATUS_CODE, DllCall("GetLastError")))
		; https://www.simonv.fr/TypesConvert/?integers
		; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
				
		AccumulatedCycles := NumGet(&cycleTimeInfo + 0, "UInt")
		CurrentCycleCount := NumGet(&cycleTimeInfo + 4, "UInt")
		
		return [AccumulatedCycles, CurrentCycleCount], DllCall("CloseHandle", "Ptr", hThread)
	}
*/	

	GetThreadCycles(threadId) {
		static THREAD_QUERY_INFORMATION := 0x0040

		if !(hThread := DllCall("OpenThread", "uint", THREAD_QUERY_INFORMATION, "int", 0, "uint", threadId, "ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
		if (result := DllCall("QueryThreadCycleTime", "UInt", hThread, "PTR*", CycleTime) = 0)
			throw Exception(Format("Error in QueryThreadCycleTime"))	
			
		return 0 + CycleTime, DllCall("CloseHandle", "ptr", hThread)
	}
	
	TerminateThread(threadId) {
		static THREAD_TERMINATE := 0x0001
		
		hThread := DllCall("OpenThread", "uint", THREAD_TERMINATE, "int", 0, "uint", threadId)
		if (!hThread)
			throw Exception(Format("Error in OpenThread: ({1})", threadId))

		DllCall("TerminateThread", "ptr", hThread, "int", 0)
		DllCall("CloseHandle", "ptr", hThread)
	}
	
	SetThreadPriority(PriorityLevel, threadId) {
		static THREAD_SET_INFORMATION := 0x0020
		
		if !(hThread := DllCall("OpenThread", "uint", THREAD_SET_INFORMATION, "int", 0, "uint", threadId, "ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
		if (DllCall("SetThreadPriority", "UInt", hThread, "Int", PriorityLevel) = 0)
			throw Exception(Format("Error in SetThreadPriority"))
		return true, DllCall("CloseHandle", "ptr", hThread)
	}
	
	SetThreadIdealProcessor(dwIdealProcessor, threadId) {
		static THREAD_SET_INFORMATION := 0x0020

		if !(hThread := DllCall("OpenThread", "UInt", THREAD_SET_INFORMATION, "Int", 0, "UInt", threadId, "Ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
			
		if ((result := DllCall("SetThreadIdealProcessor", "Ptr", hThread, "Ptr", dwIdealProcessor)) = 0)
			throw Exception(Format("Error in SetThreadIdealProcessor"))			
		return true, DllCall("CloseHandle", "Ptr", hThread)
	}
	
	SetThreadIdealProcessorEx(idealProcessor, threadId) {
		static THREAD_SET_INFORMATION := 0x0020

		if !(hThread := DllCall("OpenThread", "UInt", THREAD_SET_INFORMATION, "Int", 0, "UInt", threadId, "Ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
		
		VarSetCapacity(lpPreviousIdealProcessor, 4, 0)
		
		VarSetCapacity(lpIdealProcessor, 4, 0)
		; NumPut(0, &processorNumber + 0, "UShort") ; group
		NumPut(idealProcessor, &lpIdealProcessor + 2, "UChar") ; number
		; NumPut(0, &processorNumber + 3, "UChar") ; reserved
		
		if ((result := DllCall("SetThreadIdealProcessorEx", "Ptr", hThread, "Ptr", &lpIdealProcessor, "Ptr", &lpPreviousIdealProcessor, "Int")) = 0)
			throw Exception(Format("Error in SetThreadIdealProcessorEx: ({1}, {2})", result, DllCall("GetLastError")))	
			
		; TODO: NumGet 'number' from 'lpPreviousIdealProcessor'
		
		return true, DllCall("CloseHandle", "Ptr", hThread)
	}
	
/* 		 		
	SetThreadIdealProcessorEx(idealProcessor, threadId) {
		static THREAD_SET_INFORMATION := 0x0020
		static ThreadIdealProcessorEx := 0x21

		if !(hThread := DllCall("OpenThread", "UInt", THREAD_SET_INFORMATION, "INT", 0, "UInt", threadId, "Ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
		
		VarSetCapacity(processorNumber, 4, 0)
		; NumPut(0, &processorNumber + 0, "UShort") ; group
		NumPut(idealProcessor, &processorNumber + 2, "UChar") ; number
		; NumPut(0, &processorNumber + 3, "UChar") ; reserved
		
		; Bin_BytesView(&processorNumber, 4)
		; MsgBox % processorNumber

		if ((STATUS_CODE := DllCall("ntdll\NtSetInformationThread", "Ptr", hThread, "UInt", ThreadIdealProcessorEx, "Ptr", &processorNumber, "UInt", 4, "UInt*", 0, "UInt")) != 0) 
			throw Exception(Format("Error in NtSetInformationThread: ({1}, {2}, {3}, {4}, {5})", hThread, threadId, idealProcessor, DllCall("GetLastError"), Format("0x{:X}", STATUS_CODE)))
				
		return true, DllCall("CloseHandle", "Ptr", hThread)
	} 
*/

	SetProcessPriority(processId, priorityClass) {
		static adjustedPrivileges
		
		static PROCESS_QUERY_LIMITED_INFORMATION := 0x1000
		static PROCESS_SET_INFORMATION := 0x0200
	
		static PROCESS_INFO_CLASS := 0x12 ; ProcessPriorityClass	
		
		if !(hProcess := DllCall("OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION, "Int", 0, "UInt", processId, "Ptr"))
			throw Exception(Format("Error in OpenProcess: ({1})", processId))
		
		VarSetCapacity(ProcessInformation, 2)
		NumPut(0, ProcessInformation, 0, "Char")
		NumPut(priorityClass, ProcessInformation, 1, "Char")
				
		if (!adjustedPrivileges)
			adjustedPrivileges := this.AdjustTokenPrivileges(DllCall("GetCurrentProcessId"), { "SeIncreaseBasePriorityPrivilege": 0x2 })
			
		if ((NTSTATUS := DllCall("ntdll\NtSetInformationProcess", "Ptr", hProcess, "UInt", PROCESS_INFO_CLASS, "Ptr", &ProcessInformation, "UInt", 2, "UInt")) != 0)
			throw Exception(Format("Error in NtSetInformationProcess: ({1})", Format("0x{:X}", NTSTATUS)))
		
		return true, DllCall("CloseHandle", "Ptr", hProcess)
	}

	SetProcessPowerThrottlingState(processId, controlMask, stateMask) {
		static PROCESS_QUERY_LIMITED_INFORMATION := 0x1000
		static PROCESS_SET_INFORMATION := 0x0200
	
		static POWER_THROTTLING_PROCESS_STATE := 0x4D
		static POWER_THROTTLING_PROCESS_CURRENT_VERSION := 0x1
		
		if !(hProcess := DllCall("OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION, "Int", 0, "UInt", processId, "Ptr"))
			throw Exception(Format("Error in OpenProcess: ({1})", processId))
		
		ProcessInformationLength := VarSetCapacity(ProcessInformation, 12)
		NumPut(POWER_THROTTLING_PROCESS_CURRENT_VERSION, ProcessInformation, 0, "UInt")
		NumPut(controlMask, ProcessInformation, 4, "UInt") ; This field enables the caller to take control of the power throttling mechanism.
		NumPut(stateMask, ProcessInformation, 8, "UInt") ; Manages the power throttling mechanism on/off state.
						
		if ((NTSTATUS := DllCall("ntdll\NtSetInformationProcess", "Ptr", hProcess, "UInt", POWER_THROTTLING_PROCESS_STATE, "Ptr", &ProcessInformation, "UInt", ProcessInformationLength, "UInt")) != 0)
			throw Exception(Format("Error in NtSetInformationProcess: ({1})", Format("0x{:X}", NTSTATUS)))
				
		return true, DllCall("CloseHandle", "Ptr", hProcess)
	}
	
	SetThreadPowerThrottlingState(threadId, controlMask, stateMask) {
		static THREAD_QUERY_INFORMATION := 0x0040
		static THREAD_SET_INFORMATION := 0x0020
	
		static THREAD_POWER_THROTTLING_STATE := 0x31
		static THREAD_POWER_THROTTLING_CURRENT_VERSION := 0x1
		
		if !(hThread := DllCall("OpenThread", "UInt", THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, "Int", 0, "UInt", threadId, "Ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
		
		ThreadInformationLength := VarSetCapacity(ThreadInformation, 12)
		NumPut(THREAD_POWER_THROTTLING_CURRENT_VERSION, ThreadInformation, 0, "UInt")
		NumPut(controlMask, ThreadInformation, 4, "UInt") ; This field enables the caller to take control of the power throttling mechanism.
		NumPut(stateMask, ThreadInformation, 8, "UInt") ; Manages the power throttling mechanism on/off state.
						
		if ((NTSTATUS := DllCall("ntdll\NtSetInformationThread", "Ptr", hThread, "UInt", THREAD_POWER_THROTTLING_STATE, "Ptr", &ThreadInformation, "UInt", ThreadInformationLength, "UInt")) != 0)
			throw Exception(Format("Error in NtSetInformationThread: ({1}, {2})", Format("0x{:X}", NTSTATUS), DllCall("GetLastError")))
				
		return true, DllCall("CloseHandle", "Ptr", hThread)
	}

	SetProcessAffinityMask(processId, dwProcessAffinityMask) { ; CPU0=1 CPU1=2 | to use both, CPU should be 3
		static PROCESS_SET_INFORMATION := 0x0200
	
		if !(hProcess := DllCall("OpenProcess", "Int", PROCESS_SET_INFORMATION, "Int", 0, "Int", processId))
			throw Exception(Format("Error in OpenProcess: ({1})", processId))
		
		if ((result := DllCall("SetProcessAffinityMask", "Ptr", hProcess, "Ptr", dwProcessAffinityMask)) = 0)
			throw Exception(Format("Error in SetProcessAffinityMask"))
		
		return true, DllCall("CloseHandle", "Ptr", hProcess)
	}
	
	SetThreadAffinity(affinityMask, threadId) {
		static THREAD_SET_INFORMATION := 0x0020
		static THREAD_QUERY_INFORMATION := 0x0040

		if !(hThread := DllCall("OpenThread", "uint", THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, "int", 0, "uint", threadId, "ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
			
		if (result := DllCall("SetThreadAffinityMask", "UInt", hThread, "PTR", affinityMask) = 0)
			throw Exception(Format("Error in SetThreadAffinityMask"))				
		return true, DllCall("CloseHandle", "ptr", hThread)
	}
	
	; Methods below are from - https://www.autohotkey.com/boards/viewtopic.php?t=19323
	GetThreadStartAddr(ProcessID) {
		static ThreadQuerySetWin32StartAddress := 9
		static THREAD_QUERY_INFORMATION := 0x0040
		static TH32CS_SNAPTHREAD := 0x4

		hModule := DllCall("LoadLibrary", "str", "ntdll.dll", "uptr")

		if !(hSnapshot := DllCall("CreateToolhelp32Snapshot", "uint", TH32CS_SNAPTHREAD, "uint", ProcessID))
			throw Exception(Format("Error in CreateToolhelp32Snapshot")) 

		NumPut(VarSetCapacity(THREADENTRY32, 28, 0), THREADENTRY32, "uint")
		if !(DllCall("Thread32First", "ptr", hSnapshot, "ptr", &THREADENTRY32))
			throw Exception(Format("Error in Thread32First"))

		Addr := {}, cnt := 1
		while (DllCall("Thread32Next", "ptr", hSnapshot, "ptr", &THREADENTRY32)) {
			if (NumGet(THREADENTRY32, 12, "uint") = ProcessID) {
				hThread := DllCall("OpenThread", "uint", THREAD_QUERY_INFORMATION, "int", 0, "uint", NumGet(THREADENTRY32, 8, "uint"), "ptr")
				if (DllCall("ntdll\NtQueryInformationThread", "ptr", hThread, "uint", ThreadQuerySetWin32StartAddress, "ptr*", ThreadStartAddr, "uint", A_PtrSize, "uint*", 0) != 0)
					throw Exception(Format("Error in NtQueryInformationThread"))
				Addr[cnt, "StartAddr"] := Format("{:#016x}", ThreadStartAddr)
				Addr[cnt, "ThreadID"]  := NumGet(THREADENTRY32, 8, "uint")
				DllCall("CloseHandle", "ptr", hThread), cnt++
			}
		}

		return Addr, DllCall("CloseHandle", "ptr", hSnapshot) && DllCall("FreeLibrary", "ptr", hModule)
	}
	
	GetModuleBaseAddr(ModuleName, ProcessID) {
		static MODULE_ENTRY_SIZE := (A_PtrSize = 8 ? 568 : 548)
		static MODULE_NAME_OFFSET := (A_PtrSize = 8 ? 48 : 32)
		static MODULE_ADDRESS_OFFSET := (A_PtrSize = 8 ? 24 : 20)
		static MODULE_SIZE_OFFSET := (A_PtrSize = 8 ? 32 : 24)
		
		if !(hSnapshot := DllCall("CreateToolhelp32Snapshot", "uint", 0x18, "uint", ProcessID))
			throw Exception(Format("Error in CreateToolhelp32Snapshot"))

		NumPut(VarSetCapacity(MODULEENTRY32, MODULE_ENTRY_SIZE, 0), MODULEENTRY32, "uint")
		if !(DllCall("Module32First", "ptr", hSnapshot, "ptr", &MODULEENTRY32))
			throw Exception(Format("Error in Module32First"))

		ME32 := {}
		while (DllCall("Module32Next", "ptr", hSnapshot, "ptr", &MODULEENTRY32)) {
			if (ModuleName = StrGet(&MODULEENTRY32 + MODULE_NAME_OFFSET, 256, "cp0")) {
				ME32.Addr := Format("{:#016x}", NumGet(MODULEENTRY32, MODULE_ADDRESS_OFFSET, "uptr"))
				ME32.Size := Format("{:#016x}", NumGet(MODULEENTRY32, MODULE_SIZE_OFFSET, "uint"))
			}
		}

		return ME32, DllCall("CloseHandle", "ptr", hSnapshot)
	}
	
	GetProcessThreads(ProcessID) {
		static TH32CS_SNAPTHREAD := 0x4
		
		if !(hSnapshot := DllCall("CreateToolhelp32Snapshot", "uint", TH32CS_SNAPTHREAD, "uint", ProcessID))
			throw Exception(Format("Error in CreateToolhelp32Snapshot"))

		NumPut(VarSetCapacity(THREADENTRY32, 28, 0), THREADENTRY32, "uint")
		if !(DllCall("Thread32First", "ptr", hSnapshot, "ptr", &THREADENTRY32))
			throw Exception(Format("Error in Thread32First"))

		Threads := []
		while (DllCall("Thread32Next", "ptr", hSnapshot, "ptr", &THREADENTRY32))
			if (NumGet(THREADENTRY32, 12, "uint") = ProcessID)
				Threads.Push(NumGet(THREADENTRY32, 8, "uint"))

		return Threads, DllCall("CloseHandle", "ptr", hSnapshot)
	}
	
	IsProcessElevated(ProcessID) {
		static PROCESS_QUERY_LIMITED_INFORMATION := 0x1000
		static TOKEN_QUERY := 0x0008
		static TOKEN_ELEVATION := 20
		
		if !(hProcess := DllCall("OpenProcess", "uint", PROCESS_QUERY_LIMITED_INFORMATION, "int", 0, "uint", ProcessID, "ptr"))
			throw Exception("OpenProcess failed", -1)
		if !(DllCall("advapi32\OpenProcessToken", "ptr", hProcess, "uint", TOKEN_QUERY, "ptr*", hToken))
			throw Exception("OpenProcessToken failed", -1)
		if !(DllCall("advapi32\GetTokenInformation", "ptr", hToken, "int", TOKEN_ELEVATION, "uint*", IsElevated, "uint", 4, "uint*", size))
			throw Exception("GetTokenInformation failed", -1)
		return IsElevated, DllCall("CloseHandle", "ptr", hToken) && DllCall("CloseHandle", "ptr", hProcess)
	}

	GetProcessorCount() {
		VarSetCapacity(sysInfo, 64)
		DllCall("kernel32\GetSystemInfo", "Ptr", &sysInfo)
		
		totalCores := NumGet(sysInfo, 32, "UInt")
		return totalCores
	}
	
	NtSuspendThread(threadId) {
		static THREAD_SUSPEND_RESUME := 0x0002
		
		if !(hThread := DllCall("OpenThread", "UInt", THREAD_SUSPEND_RESUME, "Int", 0, "UInt", threadId, "Ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
		
		if ((NTSTATUS := DllCall("ntdll\NtSuspendThread", "Ptr", hThread, "Ptr", 0, "UInt")) != 0)
			throw Exception(Format("Error in NtSuspendThread: ({1}, {2})", Format("0x{:X}", NTSTATUS), DllCall("GetLastError")))
				
		return true, DllCall("CloseHandle", "Ptr", hThread)
	}
	
	NtResumeThread(threadId) {
		static THREAD_SUSPEND_RESUME := 0x0002
		
		if !(hThread := DllCall("OpenThread", "UInt", THREAD_SUSPEND_RESUME, "Int", 0, "UInt", threadId, "Ptr"))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
					
		if ((NTSTATUS := DllCall("ntdll\NtResumeThread", "Ptr", hThread, "Ptr", 0, "UInt")) != 0)
			throw Exception(Format("Error in NtResumeThread: ({1}, {2})", Format("0x{:X}", NTSTATUS), DllCall("GetLastError")))
				
		return true, DllCall("CloseHandle", "Ptr", hThread)
	}
 
	SetProcessDefaultCpuSetMasks(ProcessID, CpuSetMasks) {
		static PROCESS_SET_LIMITED_INFORMATION := 0x00002000

		if !(hProcess := DllCall("OpenProcess", "uint", PROCESS_SET_LIMITED_INFORMATION, "int", 0, "uint", ProcessID, "ptr"))
			throw Exception("OpenProcess failed", -1)
		
		VarSetCapacity(pCpuSetMasks, 2 * 4, 0)
		NumPut(CpuSetMasks, pCpuSetMasks, 0, "UInt")
		NumPut(CpuSetGroup := 0, pCpuSetMasks, 4, "UChar")
		
		success := DllCall("kernel32\SetProcessDefaultCpuSetMasks", "Ptr", hProcess, "Ptr", &pCpuSetMasks, "UShort", (CpuSetMaskCount := 1), "Int")
		return success, DllCall("CloseHandle", "ptr", hProcess)
	}	
	
	SetProcessDefaultCpuSets(ProcessID, CpuSetIds) {
		static PROCESS_SET_LIMITED_INFORMATION := 0x00002000

		if !(hProcess := DllCall("OpenProcess", "uint", PROCESS_SET_LIMITED_INFORMATION, "int", 0, "uint", ProcessID, "ptr"))
			throw Exception("OpenProcess failed", -1)
		
		CpuSetIdCount := CpuSetIds.MaxIndex()	
		VarSetCapacity(pCpuSetIds, CpuSetIdCount * 4, 0)
		for idx, SetId in CpuSetIds {
			NumPut(0x100 + SetId, pCpuSetIds, (idx - 1) * 4, "UInt")
		}
		
		success := DllCall("kernel32\SetProcessDefaultCpuSets", "Ptr", hProcess, "Ptr", &pCpuSetIds, "UInt", CpuSetIdCount, "Int")
		return success, DllCall("CloseHandle", "ptr", hProcess)
	}
	
	SetThreadSelectedCpuSetMasks(CpuSetMasks, threadId) {
		static THREAD_SET_LIMITED_INFORMATION := 0x0400

		if !(hThread := DllCall("OpenThread", "uint", THREAD_SET_LIMITED_INFORMATION, "int", 0, "uint", threadId))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))
		
		VarSetCapacity(pCpuSetMasks, 2 * 4, 0)
		NumPut(CpuSetMasks, pCpuSetMasks, 0, "UInt")
		NumPut(CpuSetGroup := 0, pCpuSetMasks, 4, "UChar")
		
		success := DllCall("kernel32\SetThreadSelectedCpuSetMasks", "Ptr", hThread, "Ptr", &pCpuSetMasks, "UShort", (CpuSetMaskCount := 1), "Int")
		return success, DllCall("CloseHandle", "ptr", hThread)
	}	
	
	SetThreadSelectedCpuSets(CpuSetIds, threadId) {
		static THREAD_SET_LIMITED_INFORMATION := 0x0400

		if !(hThread := DllCall("OpenThread", "uint", THREAD_SET_LIMITED_INFORMATION, "int", 0, "uint", threadId))
			throw Exception(Format("Error in OpenThread: ({1})", threadId))

		CpuSetIdCount := CpuSetIds.MaxIndex()	
		VarSetCapacity(pCpuSetIds, CpuSetIdCount * 4, 0)
		for idx, SetId in CpuSetIds {
			NumPut(0x100 + SetId, pCpuSetIds, (idx - 1) * 4, "UInt")
		}
		
		success := DllCall("kernel32\SetThreadSelectedCpuSets", "Ptr", hThread, "Ptr", &pCpuSetIds, "UInt", CpuSetIdCount, "Int")
		return success, DllCall("CloseHandle", "ptr", hThread)
	}
	
	SystemAllowedCpuSets(CpuSetBitmask) {
		static adjustedPrivileges
	
		static SystemAllowedCpuSetsInformation := 0xA8

		VarSetCapacity(pSet, (pSetSize := 8), 0)
		NumPut(CpuSetBitmask, pSet, 0, "UInt64")
				
		if (!adjustedPrivileges)
			adjustedPrivileges := this.AdjustTokenPrivileges(DllCall("GetCurrentProcessId"), { "SeIncreaseBasePriorityPrivilege": 0x2 })
		
		status := DllCall("ntdll\NtSetSystemInformation", "Int", SystemAllowedCpuSetsInformation, "Ptr", &pSet, "UInt", pSetSize, "Ptr")
		if (status != 0)
			throw Exception("Failed to set system information. Status: " . Format("0x{:X}", status))
		
		return true
	}
	
	SystemInterruptCpuSets(Gsiv, CpuSetBitmask) {
		static adjustedPrivileges
	
		static SystemInterruptCpuSetsInformation := 0xAA
		
		; Interesting read - https://community.osr.com/t/interrupt-service-routine-not-called-by-the-framework/57504
		
/* 
		typedef struct _SYSTEM_INTERRUPT_CPU_SET_INFORMATION
		{
		  ULONG Gsiv;
		  USHORT Group;
		  ULONG64 CpuSets;
		} SYSTEM_INTERRUPT_CPU_SET_INFORMATION, *PSYSTEM_INTERRUPT_CPU_SET_INFORMATION;
 */
		VarSetCapacity(SYSTEM_INTERRUPT_CPU_SET_INFORMATION, (INFORMATION_SIZE := 16), 0)
		NumPut(Gsiv, SYSTEM_INTERRUPT_CPU_SET_INFORMATION, 0, "UInt") ; Possible values span from 0 to 2^32 (32-bit) or 2^64 (64-bit)
		NumPut(Group := 0, SYSTEM_INTERRUPT_CPU_SET_INFORMATION, 4, "UShort")
		NumPut(CpuSetBitmask, SYSTEM_INTERRUPT_CPU_SET_INFORMATION, 8, "UInt64")
		
		if (!adjustedPrivileges)
			adjustedPrivileges := this.AdjustTokenPrivileges(DllCall("GetCurrentProcessId"), { "SeIncreaseBasePriorityPrivilege": 0x2 })
			
		status := DllCall("ntdll\NtSetSystemInformation", "Int", SystemInterruptCpuSetsInformation, "Ptr", &SYSTEM_INTERRUPT_CPU_SET_INFORMATION, "UInt", INFORMATION_SIZE, "Ptr")
		if (status != 0)
			throw Exception("Failed to set system information. Status: " . Format("0x{:X}", status))
		
		return true
	}
	
	SystemWorkloadAllowedCpuSets(CpuSetBitmask) {
		static adjustedPrivileges
		
		static SystemWorkloadAllowedCpuSetsInformation := 0xCC
		
/* 
		typedef struct _SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
		{
		  ULONG64 WorkloadClass;
		  ULONG64 CpuSets[1];
		} SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION, *PSYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION; 
 */
 
		VarSetCapacity(pSet, (pSetSize := 16), 0) ; Adjust the size as necessary
		NumPut(0, pSet, 0, "UInt64") ; Example: Setting WorkloadClass to 0
		
		VarSetCapacity(CpuSets, 8, 0) ; Allocate space for the CpuSets array
		NumPut(CpuSetBitmask, CpuSets, 0, "UInt64") ; Set the CpuSetBitmask as the first element of the CpuSets array
		
		DllCall("RtlMoveMemory", "Ptr", &pSet + 8, "Ptr", &CpuSets, "UInt", 8) ; Copy the CpuSets array into the pSet variable starting at offset 8
				
		if (!adjustedPrivileges)
			adjustedPrivileges := this.AdjustTokenPrivileges(DllCall("GetCurrentProcessId"), { "SeIncreaseBasePriorityPrivilege": 0x2 })
		
		status := DllCall("ntdll\NtSetSystemInformation", "Int", SystemWorkloadAllowedCpuSetsInformation, "Ptr", &pSet, "UInt", pSetSize, "Ptr")
		if (status != 0)
			throw Exception("Failed to set system information. Status: " . Format("0x{:X}", status))
				
		return true
	}
	
}