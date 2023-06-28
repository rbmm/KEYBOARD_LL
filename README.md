EKL_INJ.exe inject EKL.dll to processes with same bitness, from same terminal session, by default only to High+ Mandatory Level (with * in cmdline - to all )
after messagebox closed - hook will be removed and EKL.dll unloaded
log in \systemroot\temp\ekl.log
dll set hook on __fnHkINLPKBDLLHOOKSTRUCT and monitor calls to WH_KEYBOARD_LL hook callback
with ? in cmdline exe simply set WH_KEYBOARD_LL hook for test
 
