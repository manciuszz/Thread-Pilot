#NoEnv
#NoTrayIcon
; #Persistent
; #ErrorStdOut UTF-8
#SingleInstance, Force
#KeyHistory, 0

ListLines Off
SetBatchLines, -1
Process, Priority,, H 

; #Include <Debugging>
#Include <Utility>
#Include <Threader>

class ThreadPilot {

	class Metadata {		
		static _ := ThreadPilot.Metadata := new ThreadPilot.Metadata()
		
		__New() {
			this.__metadata := {}
					
			return ObjBindMethod(this, "Register")
		}
		
		Register(__customScope, metadata := "") {
			if (!metadata)
				return this.Retrieve()
			
			this.__metadata[metadata.boundSwitch] := metadata
		}
		
		Retrieve() {
			return this.__metadata
		}
	}

	class Utility {
		GetCachedProcessID(processName) {
			static cache := {}
			
			if (!cache[processName])
				cache[processName] := GetProcessID(processName)
				
			return cache[processName]
		}
		
		SortThreads(ThreadInfo) {
			threadCycleData := []
			for idx, info in ThreadInfo {
				threadCycle := [info, Threader.GetThreadCycles(info.ThreadID)]
				
				currentIndex := threadCycleData.MaxIndex()
				loop % currentIndex { 
					currentIndex := A_Index
					if (threadCycleData[currentIndex].2 < threadCycle.2) {
						threadCycleData.InsertAt(currentIndex, threadCycle)
						break
					}
				}
				
				if (currentIndex >= threadCycleData.MaxIndex()) {
					threadCycleData.Push(threadCycle)
				}
			}
			
			return threadCycleData
		}
	}

	class API extends ThreadPilot.Utility {
	
		/*
			ThreadedProcessAffinity sets the processor affinity for all threads of a specified process.
			It takes two parameters:
			- processName: The name of the process for which to set the affinity.
			- bitMask: A bitmask indicating which CPU cores the process's threads can use.
			Returns true if the operation is successful, false otherwise.
		*/
		ThreadedProcessAffinity(processName, bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/pta", fn: "ThreadedProcessAffinity", args: "<processName> <bitMask>", desc: "Set Process Thread Affinity" })

			processId := this.GetCachedProcessID(processName)
			if (!processId)
				return false
			
			ThreadInfo := Threader.GetProcessThreadInfo(processId)
			threadCycleData := this.SortThreads(ThreadInfo)
			
			for busyNum, threadData in threadCycleData {
				info := threadData.1
				
				Threader.SetThreadAffinity(bitMask, info.ThreadID)
			}
			
			return true
		}
		
		/*
			SetIdealProcessors sets the ideal processor for each thread of a specified process in a round-robin fashion. The ideal processor is constrained within a specific set of cores.
			It takes two parameters:
			- processName: The name of the process for which to set the ideal processors.
			- bitMask: A bitmask indicating which CPU cores the process's threads can ideally use.
			Returns true if the operation is successful, false otherwise.
		*/
		SetIdealProcessors(processName, bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/pip", fn: "SetIdealProcessors", args: "<processName> <bitMask>", desc: "Set Process Ideal Processors" })
			
			processId := this.GetCachedProcessID(processName)
			if (!processId)
				return false
			
			idealProcessors := BitmaskToProcessorNumbers(bitMask)
			idealProcessorCount := idealProcessors.MaxIndex()

			ThreadInfo := Threader.GetProcessThreadInfo(processId)
			threadCycleData := this.SortThreads(ThreadInfo)
			
			for busyNum, threadData in threadCycleData {
				info := threadData.1
				
				; Threader.SetThreadIdealProcessor(idealProcessors[(Mod(idx - 1, idealProcessorCount) + 1)], info.ThreadID) ; Will not work on protected processes
				this.SetIdealProcessor(info.ThreadID, idealProcessors[(Mod(busyNum - 1, idealProcessorCount) + 1)])
			}
			
			return true
		}

		ThreadedProcessCpuSetBitmask(processName, bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/pts", fn: "ThreadedProcessCpuSetBitmask", args: "<processName> <bitMask>", desc: "Set Process Thread CpuSet" })
			
			processId := this.GetCachedProcessID(processName)
			if (!processId)
				return false
			
			ThreadInfo := Threader.GetProcessThreadInfo(processId)
			threadCycleData := this.SortThreads(ThreadInfo)
			
			for busyNum, threadData in threadCycleData {
				info := threadData.1
				
				Threader.SetThreadSelectedCpuSetMasks(bitMask, info.ThreadID)
			}

			return true			
		}
		
		DefaultProcessCpuSetBitmask(processName, bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/ps", fn: "DefaultProcessCpuSetBitmask", args: "<processName> <bitMask>", desc: "Set Process CpuSet" })
			
			processId := this.GetCachedProcessID(processName)
			if (!processId)
				return false
				
			return Threader.SetProcessDefaultCpuSetMasks(processId, bitMask)
		}
		
		SetProcessAffinityMask(processName, bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/pa", fn: "SetProcessAffinityMask", args: "<processName> <bitMask>", desc: "Set Process Affinity" })
			
			processId := this.GetCachedProcessID(processName)
			if (!processId)
				return false
				
			return Threader.SetProcessAffinityMask(processId, bitMask)
		}			
		
		SetProcessPriority(processName, priorityClass) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/pp", fn: "SetProcessPriority", args: "<processName> <priorityClass>", desc: "Set Process Priority" })

			static PROCESS_PRIORITIES := {
			(Join
				PROCESS_PRIORITY_CLASS_UNKNOWN: 0,
				PROCESS_PRIORITY_CLASS_IDLE: 1,
				PROCESS_PRIORITY_CLASS_NORMAL: 2,
				PROCESS_PRIORITY_CLASS_HIGH: 3,
				PROCESS_PRIORITY_CLASS_REALTIME: 4,
				PROCESS_PRIORITY_CLASS_BELOW_NORMAL: 5,
				PROCESS_PRIORITY_CLASS_ABOVE_NORMAL: 6
			)}
			
			processId := this.GetCachedProcessID(processName)
			if (!processId)
				return false
				
			return Threader.SetProcessPriority(processId, (PROCESS_PRIORITIES[priorityClass] != "" ? PROCESS_PRIORITIES[priorityClass] : priorityClass))
		}
		
		SetIdealProcessor(threadId, idealProcessor) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/tip", fn: "SetIdealProcessor", args: "<threadId> <idealProcessor>", desc: "Set Thread Ideal Processor" })
			
			static ALL_CORE_BITMASK := (1 << Threader.GetProcessorCount()) - 1
			
			Threader.SetThreadAffinity(1 << idealProcessor, threadId)

			return Threader.SetThreadAffinity(ALL_CORE_BITMASK, threadId)
		}
		
		SetOffloadIdealProcessor(threadId) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/top", fn: "SetOffloadIdealProcessor", args: "<threadId>", desc: "Set Thread Offloaded Ideal Processor" })
			
			static EXCLUDED_BUSY_THREAD_COUNT := 3
			static ALL_CORE_BITMASK := (1 << Threader.GetProcessorCount()) - 1
		
			idealProcessor := Threader.GetThreadIdealProcessor(threadId)
			isPhysicalCore := Mod(idealProcessor, 2) == 0
			
			processId := Threader.GetProcessIdOfThread(threadId)
			threadCycleData := this.SortThreads(Threader.GetProcessThreadInfo(processId))
			
			topThreeBusyCores := 0
			for busyNum, threadData in threadCycleData {
				info := threadData.1
				
				topThreeBusyCores |= (1 << info.IdealProcessor)
				if (A_Index > EXCLUDED_BUSY_THREAD_COUNT)
					break
			}
			
			offloadedProcessorMask := ALL_CORE_BITMASK & ~((1 << idealProcessor) | (1 << (idealProcessor + (isPhysicalCore ? 1 : -1))) | topThreeBusyCores)
			
			Threader.SetThreadAffinity(offloadedProcessorMask, threadId)
			return Threader.SetThreadAffinity(ALL_CORE_BITMASK, threadId)
		}

		SetProcessEcoMode(processName, bEnableEcoMode) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/pe", fn: "SetProcessEcoMode", args: "<processName> <bEnableEcoMode>", desc: "Set Process Efficiency Mode" })
		
			processId := this.GetCachedProcessID(processName)
			if (!processId)
				return false
			
			bEnableEcoMode := (bEnableEcoMode == "true" || bEnableEcoMode == 1)
			
			if (bEnableEcoMode) {
				this.SetProcessPriority(processName, "PROCESS_PRIORITY_CLASS_IDLE")
				this.SetProcessPowerThrottlingState(processName, 0x1, 0x1)
			} else {
				this.SetProcessPriority(processName, "PROCESS_PRIORITY_CLASS_NORMAL")
				this.SetProcessPowerThrottlingState(processName, 0x0, 0x0)
			}
			
			return true
		}
		
		SetProcessPowerThrottlingState(processName, controlMask, stateMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/ppt", fn: "SetProcessPowerThrottlingState", args: "<processName> <controlMask> <stateMask>", desc: "Set Process Power Throttling State" })
			
			processId := this.GetCachedProcessID(processName)
			if (!processId)
				return false
				
			return Threader.SetProcessPowerThrottlingState(processId, controlMask, stateMask)
		}

		SetThreadPowerThrottlingState(threadId, controlMask, stateMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/tpt", fn: "SetThreadPowerThrottlingState", args: "<threadId> <controlMask> <stateMask>", desc: "Set Thread Power Throttling State" })
			
			return Threader.SetThreadPowerThrottlingState(threadId, controlMask, stateMask)
		}		
		
		SetThreadAffinity(threadId, bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/ta", fn: "SetThreadAffinity", args: "<threadId> <bitMask>", desc: "Set Thread Affinity" })
			
			return Threader.SetThreadAffinity(bitMask, threadId)
		}
		
		SetThreadSelectedCpuSetMasks(threadId, bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/tsm", fn: "SetThreadSelectedCpuSetMasks", args: "<threadId> <bitMask>", desc: "Set Thread CpuSet" })
			
			return Threader.SetThreadSelectedCpuSetMasks(bitMask, threadId)
		}
		
		SetThreadPriority(threadId, priorityLevel) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/tp", fn: "SetThreadPriority", args: "<threadId> <priorityLevel>", desc: "Set Thread Priority" })
			
			static THREAD_PRIORITIES := { ; https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities
			(Join
				THREAD_MODE_BACKGROUND_BEGIN: 0x00010000,
				THREAD_MODE_BACKGROUND_END: 0x00020000,
				THREAD_PRIORITY_IDLE: -15,
				THREAD_PRIORITY_LOWEST: -2,
				THREAD_PRIORITY_BELOW_NORMAL: -1,
				THREAD_PRIORITY_NORMAL: 0,
				THREAD_PRIORITY_ABOVE_NORMAL: 1,
				THREAD_PRIORITY_HIGHEST: 2,
				THREAD_PRIORITY_TIME_CRITICAL: 15
			)}
						
			return Threader.SetThreadPriority((THREAD_PRIORITIES[priorityLevel] != "" ? THREAD_PRIORITIES[priorityLevel] : priorityLevel), threadId)
		}
		
		SetSystemAllowedCpuSets(bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/sa", fn: "SetSystemAllowedCpuSets", args: "<bitMask>", desc: "Set System Allowed CpuSets" })
			
			return Threader.SystemAllowedCpuSets(bitMask)
		}
		
		SetSystemWorkloadAllowedCpuSets(bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/sw", fn: "SetSystemWorkloadAllowedCpuSets", args: "<bitMask>", desc: "Set System Workload Allowed CpuSets" })
		
			return Threader.SystemWorkloadAllowedCpuSets(bitMask)
		}	

		SetSystemInterruptCpuSets(bitMask) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/si", fn: "SetSystemInterruptCpuSets", args: "<bitMask>", desc: "Set System Interrupt CpuSets (Experimental)" })
			
			; static MAXIMUM_POSSIBLE_GSIVS := 2 ** 32
						
			; NOTICE: No idea how to get the actual GSIV numbers, so we just try to brute force them atm.

			VALID_GSIV_NUMBERS := []
			
			TOTAL_ITERATIONS := 1024
			MIDDLE := TOTAL_ITERATIONS // 2

			currentIteration1 := 0
			currentIteration2 := MIDDLE
			currentIteration3 := MIDDLE
			currentIteration4 := TOTAL_ITERATIONS
			
			t1 := A_TickCount
			while(currentIteration1 < MIDDLE) {
				currentIteration1++
				currentIteration2--
				currentIteration3++
				currentIteration4--
								
				if (currentIteration1 < currentIteration2) {
					try {
						Threader.SystemInterruptCpuSets(currentIteration1, bitMask)
						VALID_GSIV_NUMBERS.Push(currentIteration1)
					}
				}				
				
				if (currentIteration2 > currentIteration1) {
					try {
						Threader.SystemInterruptCpuSets(currentIteration2, bitMask)
						VALID_GSIV_NUMBERS.Push(currentIteration2)
					}
				}				
				
				if (currentIteration3 < currentIteration4) {
					try {
						Threader.SystemInterruptCpuSets(currentIteration3, bitMask)
						VALID_GSIV_NUMBERS.Push(currentIteration3)
					} 
				}
								
				if (currentIteration4 > currentIteration3) {
					try {
						Threader.SystemInterruptCpuSets(currentIteration4, bitMask)
						VALID_GSIV_NUMBERS.Push(currentIteration4)
					}
				}				
				
				if (GetKeyState("F12", "P"))
					break
			}
			
			MsgBox % Format("Modified GSIVs: {1}`n`nElapsed time: {2}ms.`nTotal GSIVS Checked: {3} from {4} ({5:.3f}%)`nIteration Counters: {6}", JSON.Dump(VALID_GSIV_NUMBERS), (A_TickCount - t1), currentIteration1, MIDDLE, (currentIteration1 / MIDDLE) * 100, JSON.Dump([currentIteration1, currentIteration2, currentIteration3, currentIteration4])) 
			
			return true
		}
		
		SuspendThread(threadId) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/ts", fn: "SuspendThread", args: "<threadId>", desc: "Set Thread Suspend" })
			
			return Threader.NtSuspendThread(threadId)
		}		
		
		ResumeThread(threadId) {
			static @ := ThreadPilot.Metadata({ boundSwitch: "/tr", fn: "ResumeThread", args: "<threadId>", desc: "Set Thread Resume" })
			
			return Threader.NtResumeThread(threadId)
		}
	}
	
	class Linker extends ThreadPilot.API {
		static _ := @RequireAdmin() := ThreadPilot.Linker := new ThreadPilot.Linker()
		
		__New() {
			this.EnableErrorHandling()
			this.AttachToConsole()
						
			this.RegisterSwitches()
			this.ExecuteSwitches()
			
			this.CloseApp()
		}
		
		AttachToConsole() {
			this.Console := new this.__ConsoleLogger()
		}
		
		EnableErrorHandling() {
			OnError(ObjBindMethod(this, "OnErrors", { printType: "WriteLine", exitOnError: true }))
		}
		
		OnErrors(errorHandlerOptions, ExceptionObj) {
			switch % errorHandlerOptions.printType  {
				Case "MsgBox":
					MsgBox % "Error on line " ExceptionObj.Line ": `nReason: " ExceptionObj.Message "`n" 
				Case "WriteLine":
					this.Console.WriteLine(Format("Error on line {1}: `nReason: {2}`n", ExceptionObj.Line, ExceptionObj.Message))
			}
			
			if (errorHandlerOptions.exitOnError)
				this.CloseApp()
		}
		
		RegisterSwitches() {
			this.switchTable := ThreadPilot.Metadata()
			
			this.switchesMap := {}
			for boundSwitch, switchObj in this.switchTable {
				this.switchesMap[boundSwitch] := ObjBindMethod(this, switchObj.fn)
			}
			
			; Map "/switch" to "-switch" for accessibility
			for boundSwitch, functionName in this.switchesMap {
				this.switchesMap[ StrReplace(boundSwitch, "/", "-") ] := this.switchesMap[boundSwitch]
			}
		}
		
		ExecuteSwitches() { 
			totalArgs := A_Args.Length()
			if (totalArgs = 0)
				return this.PrintHelp()
		
			processedArguments := []
		
			argPosition := 1
			while (argPosition <= totalArgs) {
				argument := A_Args[ argPosition ]
				if (this.switchesMap.HasKey(argument)) {
					args := []
					argPosition++
					while (argPosition <= totalArgs && !this.switchesMap.HasKey(A_Args[ argPosition ])) {
						args.Push(A_Args[ argPosition ])
						argPosition++
					}
					
					processedArguments.Push({ boundSwitch: argument, arguments: args })
				} else {
					argPosition++
				}
			}
			
			for idx, argumentObject in processedArguments {
				boundSwitch := argumentObject.boundSwitch
				arguments := argumentObject.arguments
				
				if (!this.switchesMap[boundSwitch].Call(arguments*)) {
					usageString := Format("Expected Usage: ThreadPilot {1} {2}`nDescription: {3}", boundSwitch, this.switchTable[boundSwitch].args, this.switchTable[boundSwitch].desc)
					if (arguments.Length() > 0) {
						usageString := Format("Function '{1}' failed on switch '{2}' with arguments: {3}`n{4}", this.switchTable[boundSwitch].fn, boundSwitch, RegExReplace(JSON.Dump(arguments), "\[?`""([^`""]*)`""\,?\]?", "<$1>"), usageString)
					}
					
					this.Console.WriteLine(usageString)
				}
			}
		}
		
		PrintHelp() {
			maxLength := MaxDictStringLength(this.switchTable, "desc")		
			
			switchArray := []
			for boundSwitch, switchObj in this.switchTable {
				switchArray.Push(Format("{1} {2} |`t`b{3}`t`b`b{4}", switchObj.desc, StrRepeat(" ", maxLength - StrLen(switchObj.desc)), boundSwitch, switchObj.args))
			}
			
			VERSION := 0.420
			INTRO := Format("`t`t`t`t<< Thread Pilot v{1} >>", VERSION)		
			USAGE := Format("Usage: ThreadPilot /switch <arguments>")
			NOTICE := Format("NOTICE: Some functions might not work on protected processes/threads due to lack of permissions.")
						
			EXAMPLE_1 := "Example: ThreadPilot /ta 1234 0x1 -> Assign 0x1 CPU Affinity to THREAD 1234."
			EXAMPLE_2 := "Example: ThreadPilot /pts ExampleProcess.exe 0xFFFC -> Iterate through all ExampleProcess.exe threads and assign 0xFFFC CPU Set."
			EXAMPLE_3 := "Example: ThreadPilot /pts E*ampleProcess 0xFFFC /ta 1234 0x1 -> Do everything above in a single call. NOTE: process name pattern matching is possible."
			
			EXAMPLES := Format("`n{1}`n{2}`n`n{3}", USAGE, NOTICE, Format("{1}`n{2}`n{3}", EXAMPLE_1, EXAMPLE_2, EXAMPLE_3))
			
			this.Console.WriteLine(Format("`n{1}`nAvailable switches: {2}`n{3}", INTRO, RegExReplace(RegExReplace(JSON.Dump(switchArray, true), "`""|\,|\\b", "`b`b`b"), "`t|\\t", "`t"), EXAMPLES))
		}
		
		CloseApp() {
			ExitApp
		}
				
		class __ConsoleLogger {			
			__New() {
				this.Init()
				
				OnExit(ObjBindMethod(this, "Free"))
			}
			
			Init() {				
				DllCall("AttachConsole", "UInt", -1)
				this.stdout := FileOpen("CONOUT$", "w")
			}
			
			Free() {
				DllCall("FreeConsole")
				this.stdout.Close()
			}
			
			Flush() {
				this.stdout.__Handle
				ControlSend,, {Enter}, % "A"
			}

			Write(txt) {
				this.stdout.Write("`n" . txt)
				this.Flush()
			}
			
			WriteLine(txt) {
				this.stdout.WriteLine("`n" . txt)
				this.Flush()
			}
		}
	}
}
