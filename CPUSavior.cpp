/*
Copyright (c) 2008 r1ch.net

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software
    in a product, an acknowledgment in the product documentation would be
    appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

    3. This notice may not be removed or altered from any source
    distribution.
*/

#include <cstring>

#include <Windows.h>

#define BWLAPI 4
#define STARCRAFTBUILD 11

/*  STARCRAFTBUILD
	-1   All
	0   1.04
	1   1.08b
	2   1.09b
	3   1.10
	4   1.11b
	5   1.12b
	6   1.13f
	7   1.14
	8   1.15
*/

#ifdef _MANAGED
#pragma managed(push, off)
#endif

struct ExchangeData
{
	int iPluginAPI;
	int iStarCraftBuild;
	bool bConfigDialog;                 //Is Configurable
	bool bNotSCBWmodule;                //Inform user that closing BWL will shut down your plugin
};

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                )
{
	//Is this DLL also StarCraft module?
	
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			return TRUE;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}

	return TRUE;
}
//
//GET Functions for BWLauncher
//
//
extern "C" __declspec(dllexport) void GetPluginAPI(ExchangeData &Data)
{
	//BWL Gets version from Resource - VersionInfo
	Data.iPluginAPI = BWLAPI;
	Data.iStarCraftBuild = STARCRAFTBUILD;
	Data.bConfigDialog = false;
	Data.bNotSCBWmodule = false;
}

extern "C" __declspec(dllexport) void GetData(char *name, char *description, char *updateurl)
{
	//if necessary you can add Initialize function here
	//possibly check CurrentCulture (CultureInfo) to localize your DLL due to system settings
	std::strcpy(name,      "CPU Savior (1.15.3)");
	std::strcpy(description, "Reduces CPU usage.");
	std::strcpy(updateurl,   "");
}


//
//Functions called by BWLauncher
//
//
extern "C" __declspec(dllexport) bool OpenConfig()
{
	//If you set "Data.bConfigDialog = true;" at function GetPluginAPI then
	//BWLauncher will call this function if user clicks Config button

	//Youll need to make your own Window here
	return true; //everything OK

	//return false; //something went wrong
}

extern "C" __declspec(dllexport) bool ApplyPatchSuspended(HANDLE hProcess, DWORD dwProcessID)
{
	return true;
}


//004D1309   > 6A 00          push 0
//004D1309     6A 01          push 1
//004D4131  |. 6A 00          |push 0
//0041A095  |> A1 185E6D00    /mov eax,dword ptr ds:[6D5E18]

/*
004D18BB     68 E8030000    push 3E8
004D18C0     FF15 0CE14F00  call dword ptr ds:[<&KERNEL32.Sleep>]    ;  kernel32.Sleep
004D18C6     90             nop
004D18C7     90             nop
004D18C8     90             nop
004D18C9  |> FF15 C4E04F00  call dword ptr ds:[<&KERNEL32.GetTickCou>; [GetTickCount

004D18BB     68 E8030000    push 3E8
004D18C0     FF15 0CE14F00  call dword ptr ds:[<&KERNEL32.Sleep>]    ;  kernel32.Sleep
004D18C6     90             nop
004D18C7     90             nop
004D18C8     90             nop
004D18C9  |> FF15 C4E04F00  call dword ptr ds:[<&KERNEL32.GetTickCou>; [GetTickCount

.text:0041CB18 A1 0C 5E 6D 00                                mov     eax, dword_6D5E0C
.text:0041CB1D 85 C0                                         test    eax, eax
.text:0041CB1F 74 10                                         jz      short loc_41CB31
.text:0041CB21 50                                            push    eax
.text:0041CB22 E8 35 53 FF FF                                call    storm_525
.text:0041CB27 C7 05 0C 5E 6D 00 00 00 00 00                 mov     dword_6D5E0C, 0
.text:0041CB31
.text:0041CB31                               loc_41CB31:                             ; CODE XREF: sub_41C9F0+12Fj
.text:0041CB31 8B E5                                         mov     esp, ebp
.text:0041CB33 5D                                            pop     ebp
.text:0041CB34 C3                                            retn
.text:0041CB34                               sub_41C9F0      endp
.text:0041CB34
.text:0041CB34                               ; ---------------------------------------------------------------------------
.text:0041CB35 CC CC CC CC CC CC CC CC CC CC+                align 10h
E8 35 53 FF FF C7 05 0C 5E 6D 00 00 00 00 00 8B E5 5D C3

0041CB1F     74 18          je short StarCraf.0041CB39
0041CB21  |. 50             push eax
0041CB22     6A 01          push 1
0041CB24     FF15 0CE14F00  call dword ptr ds:[<&KERNEL32.Sleep>]    ;  kernel32.Sleep
0041CB2A     E8 2D53FFFF    call <jmp.&storm.#525>
0041CB2F     C705 0C5E6D00 >mov dword ptr ds:[6D5E0C],0
0041CB39     8BE5           mov esp,ebp
0041CB3B     5D             pop ebp
0041CB3C     C3             retn


*/

extern "C" __declspec(naked) void tickCountStub (void)
{
	__asm
	{
		__emit 0xE8	//call GetTickCount
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC

		//cmp dword ptr [esp], 004D94B9h //1.15.2
		cmp dword ptr [esp], 004D9519h
		je doSleep
		//cmp dword ptr [esp], 004D18CFh //1.15.2
		cmp dword ptr [esp], 004D191Fh
		jne noSleep

		/*__emit 0x3B	//cmp eax, [addr]
		__emit 0x05
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC

		jne noSleep*/
doSleep:
		push eax
		push 1

		__emit 0xFF	//call IAT:Sleep
		__emit 0x15

		__emit 0x0C	//IAT for Sleep 1.15.x
		__emit 0xE1
		__emit 0x4F
		__emit 0x00
		pop eax
noSleep:

		/*__emit 0xA3	//mov [addr], eax
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC*/

		retn
	}
}

extern "C" __declspec (naked) void tickCountStubEnd (void)
{
	__asm int 3;
}

extern "C" __declspec(naked) void getPropStub (void)
{
	__asm
	{
		//for safety, we only sleep if we were called from storm.dll address
		//cmp dword ptr [esp], 15013E55h
		cmp dword ptr [esp], 150135C5h
		jne SkipSleep
		push 1
		__emit 0xFF
		__emit 0x15
		__emit 0x0C
		__emit 0xE1
		__emit 0x4F
		__emit 0x00
SkipSleep:
		__emit 0xE9
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC
	}
}

extern "C" __declspec (naked) void getPropStubEnd (void)
{
	__asm int 4;
}

/*
15013E48  |> E8 43C4FFFF    /call storm.15010290
15013E4D  |. 68 6C2C0515    |push storm.15052C6C                     ;  ASCII "SDlg_EndDialog"
15013E52  |. 56             |push esi
15013E53  |. FFD3           |call ebx
15013E55  |. 85C0           |test eax,eax
15013E57  |.^74 EF          \je short storm.15013E48
*/

extern "C" __declspec(naked) void LoadDLLstub (void)
{
	__asm
	{
		push 0xCCCCCCCC		//addr of WINMM
		_emit 0xE8			//call LoadLibraryW
		_emit 0xcc
		_emit 0xcc
		_emit 0xcc
		_emit 0xcc
		test eax, eax		//check DLL loaded
		jz noProc			//if not, abort
		push 0xCCCCCCCC		//addr of timeBeginPeriod
		push eax			//handle to WINMM
		_emit 0xE8			//call GetProcAddress
		_emit 0xcc
		_emit 0xcc
		_emit 0xcc
		_emit 0xcc
		test eax, eax		//check we got proc
		jz noProc			//if not, abort
		push 1
		call eax			//call timeBeginPeriod(1)
noProc:
		retn 4				//return (and exit) thread
	}
}

extern "C" __declspec (naked) void LoadDLLstubEnd (void)
{
	__asm int 5;
}

DWORD WINAPI DelayedPatch (VOID *arg)
{
	BYTE	*buff;
	DWORD	ret;
	DWORD	getTickAddr, scAddr, getPropAddr;
	HANDLE	hProcess;

	//for some reason, the loading screen calls GetTickCount insanely often and injecting early
	//just causes it to take 20+ seconds to load. hopefully 5 seconds is enough to get to the main menu
	Sleep (5000);

	hProcess = (HANDLE)arg;
	if (!hProcess)
		return 1;

	//get address of functions we want to patch
	getTickAddr = (DWORD)GetTickCount;
	getPropAddr = (DWORD)GetPropA;

	//read current IAT entry for GetTickCount 1.15.x
	ReadProcessMemory (hProcess, (LPVOID)0x004FE0C4, &scAddr, 4, &ret);
	if (ret != 4)
		return 1;

	buff = (BYTE *)VirtualAllocEx (hProcess, NULL, 256, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!buff)
		return 1;
	
	//modify our patch stub
	VirtualProtect ((LPVOID)tickCountStub, (DWORD)tickCountStubEnd - (DWORD)tickCountStub, PAGE_EXECUTE_READWRITE, &ret);

	*(DWORD *)((BYTE *)tickCountStub + 1) = (long)scAddr - ((long)buff + 1 + 5);

	//*(DWORD *)((BYTE *)tickCountStub + 7) = ((long)buff + 64);
	//*(DWORD *)((BYTE *)tickCountStub + 24) = ((long)buff + 64);

	//write it in
	WriteProcessMemory (hProcess, buff, tickCountStub, (DWORD)tickCountStubEnd - (DWORD)tickCountStub, &ret);
	if (ret != (DWORD)tickCountStubEnd - (DWORD)tickCountStub)
		return 1;

	//patch IAT 1.15.x
	DWORD addr = (DWORD)buff;
	VirtualProtectEx (hProcess, (LPVOID)0x004FE0C4, 4, PAGE_READWRITE, &ret);
	WriteProcessMemory (hProcess, (LPVOID)0x004FE0C4, &addr, 4, &ret);
	if (ret != 4)
		return 1;

	//same as before, but for GetProp
	ReadProcessMemory (hProcess, (LPVOID)0x150452A4, &scAddr, 4, &ret);
	if (ret != 4)
		return 1;

	buff = (BYTE *)VirtualAllocEx (hProcess, NULL, 256, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!buff)
		return 1;
	
	VirtualProtect ((LPVOID)getPropStub, (DWORD)getPropStubEnd - (DWORD)getPropStub, PAGE_EXECUTE_READWRITE, &ret);

	*(DWORD *)((BYTE *)getPropStub + 18) = (long)scAddr - ((long)buff + 18 + 5);

	WriteProcessMemory (hProcess, buff, getPropStub, (DWORD)getPropStubEnd - (DWORD)getPropStub, &ret);
	if (ret != (DWORD)getPropStubEnd - (DWORD)getPropStub)
		return 1;

	addr = (DWORD)buff;
	VirtualProtectEx (hProcess, (LPVOID)0x150452A4, 4, PAGE_READWRITE, &ret);
	WriteProcessMemory (hProcess, (LPVOID)0x150452A4, &addr, 4, &ret);
	if (ret != 4)
		return 1;

	//here we inject a code stub to load WINMM and call timeBeginPeriod (1) to increase Sleep resolution
	char	*pInit = (char *)VirtualAllocEx (hProcess, NULL, 256, MEM_COMMIT, PAGE_READWRITE);
	char	*pDLL = (char *)VirtualAllocEx (hProcess, NULL, 256, MEM_COMMIT, PAGE_READWRITE);
	BYTE	*pCode = (BYTE *)VirtualAllocEx (hProcess, NULL, 256, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!pInit)
		return 1;

	if (!pDLL)
		return 1;

	if (!pCode)
		return 1;

	//function name
	WriteProcessMemory (hProcess, pInit, "timeBeginPeriod", 16, &ret);
	if (ret != 16)
		return 1;

	//dll name
	char	*ptWinMM = "WINMM";
	WriteProcessMemory (hProcess, pDLL, ptWinMM, 12, &ret);
	if (ret != 12)
		return 1;

	//fix up our image patch
	VirtualProtect ((LPVOID)LoadDLLstub, (DWORD)LoadDLLstubEnd - (DWORD)LoadDLLstub, PAGE_EXECUTE_READWRITE, &ret);

	*(DWORD *)((BYTE *)LoadDLLstub + 1) = (DWORD)pDLL;
	*(DWORD *)((BYTE *)LoadDLLstub + 6) = (long)LoadLibraryW - ((long)pCode + 5 + 5);

	*(DWORD *)((BYTE *)LoadDLLstub + 15) = (DWORD)pInit;
	*(DWORD *)((BYTE *)LoadDLLstub + 21) = (long)GetProcAddress - ((long)pCode + 20 + 5);

	//write the patch
	WriteProcessMemory (hProcess, pCode, LoadDLLstub, (DWORD)LoadDLLstubEnd - (DWORD)LoadDLLstub, &ret);
	if (ret != (DWORD)LoadDLLstubEnd - (DWORD)LoadDLLstub)
		return false;

	//run it
	HANDLE hThread;
	hThread = CreateRemoteThread (hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pCode, NULL, 0, NULL);
	if (!hThread || hThread == INVALID_HANDLE_VALUE)
		return FALSE;

	ResumeThread (hThread);

	//good practice :)
	FlushInstructionCache (hProcess, NULL, 0);

	return 0;
}

extern "C" __declspec(dllexport) bool ApplyPatch(HANDLE hProcess, DWORD dwProcessID)
{
	/*static const BYTE	sleepCode[] = {
		//0x74, 0x18,
		//0x50,
		0x6A, 0x01,													//push 1
		0xFF, 0x15, 0x0C, 0xE1, 0x4F, 0x00,							//call sleep
		0xA1, 0x0C, 0x5E, 0x6D, 0x00,								//mov eax
		0x85, 0xC0,													//test eax
		0x74, 16,													//jmp ret
		0x50,														//push eax
		0xE8, 0x2D, 0x53, 0xFF, 0xFF,								//jmp storm
		0xC7, 0x05, 0x0C, 0x5E, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x00,	//zero thingy
		0x8B, 0xE5,
		0x5D,
		0xC3
	};

	buff = 1;

	WriteProcessMemory (hProcess, (LPVOID)0x004D130A, &buff, 1, &ret);
	if (ret != 1)
		return false;

	WriteProcessMemory (hProcess, (LPVOID)0x004D4132, &buff, 1, &ret);
	if (ret != 1)
		return false;

	WriteProcessMemory (hProcess, (LPVOID)0x0041CB18, sleepCode, sizeof(sleepCode), &ret);
	if (ret != sizeof(sleepCode))
		return false;*/

	DWORD	threadID;
	HANDLE	hProcessCloned;

	DuplicateHandle (GetCurrentProcess(), hProcess, GetCurrentProcess(), &hProcessCloned, 0,  FALSE, DUPLICATE_SAME_ACCESS);
	CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE)DelayedPatch, hProcessCloned, 0, &threadID);

	return true;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif
