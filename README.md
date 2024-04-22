# Thread Pilot!

A simple to use tool for managing system and process threads 

### Features

```console
                                << Thread Pilot v0.420 >>
Available switches: [
     Set Process Affinity                         |  /pa  <processName> <bitMask>
     Set Process Efficiency Mode                  |  /pe  <processName> <bEnableEcoMode>
     Set Process Ideal Processors                 |  /pip <processName> <bitMask>
     Set Process Priority                         |  /pp  <processName> <priorityClass>
     Set Process Power Throttling State           |  /ppt <processName> <controlMask> <stateMask>
     Set Process CpuSet                           |  /ps  <processName> <bitMask>
     Set Process Thread Affinity                  |  /pta <processName> <bitMask>
     Set Process Thread CpuSet                    |  /pts <processName> <bitMask>
     Set System Allowed CpuSets                   |  /sa  <bitMask>
     Set System Interrupt CpuSets (Experimental)  |  /si  <bitMask>
     Set System Workload Allowed CpuSets          |  /sw  <bitMask>
     Set Thread Affinity                          |  /ta  <threadId> <bitMask>
     Set Thread Ideal Processor                   |  /tip <threadId> <idealProcessor>
     Set Thread Offloaded Ideal Processor         |  /top <threadId>
     Set Thread Priority                          |  /tp  <threadId> <priorityLevel>
     Set Thread Power Throttling State            |  /tpt <threadId> <controlMask> <stateMask>
     Set Thread Resume                            |  /tr  <threadId>
     Set Thread Suspend                           |  /ts  <threadId>
     Set Thread CpuSet                            |  /tsm <threadId> <bitMask>
]

Usage: ThreadPilot /switch <arguments>
NOTICE: Some functions might not work on protected processes/threads due to lack of permissions.

Example: ThreadPilot /ta 1234 0x1 -> Assign 0x1 CPU Affinity to THREAD 1234.
Example: ThreadPilot /pts ExampleProcess.exe 0xFFFC -> Iterate through all ExampleProcess.exe threads and assign 0xFFFC CPU Set.
Example: ThreadPilot /pts E*ampleProcess 0xFFFC /ta 1234 0x1 -> Do everything above in a single call. NOTE: process name pattern matching is possible.
```
