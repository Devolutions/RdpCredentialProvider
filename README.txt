
Build:
Build as release for the proper target architecture (32/64 bit).

Install:
copy RdpCredentialProvider.dll %systemroot%\System32 /Y

Use Register.reg to register credential provider, and Unregister.reg to unregister.

Credential providers registered at boot time are locked and cannot be changed. To avoid this problem, unregister before rebooting the system.

Testing:

Launch RdpCredUI.exe
