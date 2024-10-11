# Sentinel Threat Hunter

This is the prototype of and EDR for a college work, focused to catch two malwares that I have reverse engineered. 

* The first one is [Ransomware](https://github.com/cristianrossettliotto/malware_analysis/tree/master/e5f60df786e9da9850b7f01480ebffced3be396618c230fa94b5cbc846723553)

* The second one is `Trojan` (not uploaded yet).



There are four pieces for this to work:


* Driver running in kernel mode, responsible for create an Event and to listen to all process creation.

* DLL that is using [Detours](https://github.com/microsoft/Detours) to hook applications syscalls and if necessary kill the application
that is showing malicious behavior

* Client that will listen to file/folder modifications and realyzes static analysis using [Yara](https://github.com/VirusTotal/yara), listen to the Kernel Event and inject the DLL into 64 bit applications using functions like `VirtualAllocEx`,`WriteProcessMemory` and `CreateRemoteThread`.

* For last an injector just to inject the DLL into 32 bit applications.