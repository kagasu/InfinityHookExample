/*
*	Module Name:
*		entry.cpp
*
*	Abstract:
*		Sample driver that implements infinity hook to detour
*		system calls.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#include "stdafx.h"
#include "entry.h"
#include "infinityhook.h"

static wchar_t IfhMagicFileName[] = L"ifh--";

static UNICODE_STRING StringNtOpenProcess = RTL_CONSTANT_STRING(L"NtOpenProcess");
static NtOpenProcess_t OriginalNtOpenProcess = NULL;

/*
*	The entry point of the driver. Initializes infinity hook and
*	sets up the driver's unload routine so that it can be gracefully 
*	turned off.
*/
extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	//
	// Figure out when we built this last for debugging purposes.
	//
	kprintf("[+] infinityhook: Loaded.\n");
	
	//
	// Let the driver be unloaded gracefully. This also turns off 
	// infinity hook.
	//
	DriverObject->DriverUnload = DriverUnload;

	//
	// Demo detouring of nt!NtOpenProcess
	//
	OriginalNtOpenProcess = (NtOpenProcess_t)MmGetSystemRoutineAddress(&StringNtOpenProcess);
	if (!OriginalNtOpenProcess)
	{
		kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtOpenProcess);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	//
	// Initialize infinity hook. Each system call will be redirected
	// to our syscall stub.
	//
	NTSTATUS Status = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(Status))
	{
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status);
	}

	return Status;
}

/*
*	Turns off infinity hook.
*/
void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	//
	// Unload infinity hook gracefully.
	//
	IfhRelease();

	kprintf("\n[!] infinityhook: Unloading... BYE!\n");
}

/*
*	For each usermode syscall, this stub will be invoked.
*/
void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex, 
	_Inout_ void** SystemCallFunction)
{
	// 
	// Enabling this message gives you VERY verbose logging... and slows
	// down the system. Use it only for debugging.
	//
	
#if 0
	kprintf("[+] infinityhook: SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
#endif

	UNREFERENCED_PARAMETER(SystemCallIndex);

	//
	// In our demo, we care only about nt!OpenProcess calls.
	//
	if (*SystemCallFunction == OriginalNtOpenProcess)
	{
		//
		// We can overwrite the return address on the stack to our detoured
		// NtOpenProcess.
		//
		*SystemCallFunction = DetourNtOpenProcess;
	}
}

/*
*	This function is invoked instead of nt!NtCreateFile. It will 
*	attempt to filter a file by the "magic" file name.
*/
NTSTATUS DetourNtOpenProcess(
	_Out_ PHANDLE             ProcessHandle,
	_In_ ACCESS_MASK          DesiredAccess,
	_In_ POBJECT_ATTRIBUTES   ObjectAttributes,
	_In_ PCLIENT_ID           ClientId)
{
	//
	// We're going to filter for our "magic" file name.
	//
	if (ClientId->UniqueProcess == reinterpret_cast<HANDLE>(3900))
	{
		DesiredAccess = 0x8; // PROCESS_VM_OPERATION
	}

	//
	// We're uninterested, call the original.
	//
	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
