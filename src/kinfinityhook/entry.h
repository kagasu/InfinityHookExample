/*
*	Module Name:
*		entry.h
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

#pragma once

///
/// Structures and typedefs.
///

typedef NTSTATUS(*NtOpenProcess_t)(
	_Out_ PHANDLE             ProcessHandle,
	_In_ ACCESS_MASK          DesiredAccess,
	_In_ POBJECT_ATTRIBUTES   ObjectAttributes,
	_In_ PCLIENT_ID           ClientId);

///
/// Forward declarations.
///

extern "C" DRIVER_INITIALIZE DriverEntry;

void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject);

void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex, 
	_Inout_ void** SystemCallFunction);

NTSTATUS DetourNtOpenProcess(
	_Out_ PHANDLE             ProcessHandle,
	_In_ ACCESS_MASK          DesiredAccess,
	_In_ POBJECT_ATTRIBUTES   ObjectAttributes,
	_In_ PCLIENT_ID           ClientId);
