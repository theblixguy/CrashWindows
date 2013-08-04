#pragma once

/*

crashdriver.c

A tiny system driver that wreaks havoc in kernel mode

 || Written by: Suyash Srijan
 || suyashsrijan@outlook.com
 || Tested on: Win7, Win8, Win8.1

*/
 
#include "ntddk.h"
#define SIZE_ALLOC 2048
#define TYPE_DEVICE_CRASH 0x00008336

// List of IOCTLs used by our driver
#define BUFFER_OVERFLOW_IOCTL      (ULONG)CTL_CODE(TYPE_DEVICE_CRASH, 0x00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FAST_MUTEX_DEADLOCK_IOCTL  (ULONG)CTL_CODE(TYPE_DEVICE_CRASH, 0x03, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DPC_HANG_IOCTL             (ULONG)CTL_CODE(TYPE_DEVICE_CRASH, 0x07, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define STACK_OVERFLOW_IOCTL       (ULONG)CTL_CODE(TYPE_DEVICE_CRASH, 0x11, METHOD_BUFFERED, FILE_ANY_ACCESS)

//-------------------------------------------------------------------------
// Grab a fast mutex (which we already have grabbed) and create a deadlock
//-------------------------------------------------------------------------

FAST_MUTEX _mtx1;
FAST_MUTEX _mtx2;
KDPC _hngDPC;
CCHAR x;

VOID doDeadlock(VOID)
{
	ExInitializeFastMutex(&_mtx1);
	ExInitializeFastMutex(&_mtx2);
	ExAcquireFastMutex(&_mtx1);
	ExAcquireFastMutex(&_mtx2);
	ExReleaseFastMutex(&_mtx1);
	ExAcquireFastMutex(&_mtx2);
}

//--------------------------------------------------------------------------------------
// Execute a DPC that executes infinite loop at IRQL (raised), thus crashing the system
//--------------------------------------------------------------------------------------

VOID doDPCHangRoutine(PKDPC Dpc,PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2)
{
	while(1);
}

VOID doHang(VOID)
{
	for (x = 0; x < KeNumberProcessors; x++) {
	KeInitializeDpc(&_hngDPC, doDPCHangRoutine, NULL);
	KeSetTargetProcessorDpc(&_hngDPC, x);
    KeInsertQueueDpc(&_hngDPC, NULL, NULL); }
}


//-------------------------------
// Overflow the fucking buffer! 
//-------------------------------
VOID doBufferOverflow(VOID)
{
	PCHAR buf;
	int z = 0;
	CHAR mountain[] = "MOUNTAIN";
	buf = ExAllocatePool(NonPagedPool, SIZE_ALLOC);
	for (z < SIZE_ALLOC + 40; z++) {
	strcpy(&buf[i], mountain);
	}
}

//-----------------------------
// Overflow the fucking stack!
//-----------------------------
VOID doStackOverflow(VOID)
{
	while (1) {
	StackOverflow();
}
}

//----------------
// Device control
//----------------
NTSTATUS CrashDeviceControl(IN PFILE_OBJECT FileObject, IN BOOLEAN Wait, IN PVOID InputBuffer, IN ULONG InputBufferLength, OUT PVOID OutputBuffer, IN ULONG OutputBufferLength, IN ULONG IoControlCode, OUT PIO_STATUS_BLOCK IoStatus, IN PDEVICE_OBJECT DeviceObject
	)
{
	IoStatus->Status = STATUS_SUCCESS;
	IoStatus->Information = 0;
	switch (IoControlCode) {

	case BUFFER_OVERFLOW_IOCTL:

		doBufferOverflow();
		break;

	case FAST_MUTEX_DEADLOCK_IOCTL:

		doDeadlock();
		break;

	case DPC_HANG_IOCTL:

		doHang();
		break;

	case STACK_OVERFLOW_IOCTL:

		doStackOverflow();
		break;

	default:

		IoStatus->Status = STATUS_NOT_SUPPORTED;
		break;
	}
	return IoStatus->Status;
}

//------------------
// Dispatch handler
//------------------
NTSTATUS CrashDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION piosl;
	PVOID iptBuf;
	PVOID optBuf;
	ULONG iptBufLen;
	ULONG optBufLen;
	ULONG ioCtrlCd;
	NTSTATUS status;

	piosl = IoGetCurrentIrpStackLocation(Irp);

	switch (piosl->MajorFunction) {
	case IRP_MJ_CREATE:
		status = STATUS_SUCCESS;
		break;

	case IRP_MJ_CLOSE:
		status = STATUS_SUCCESS;
		FreePoolLeak();
		break;

	case IRP_MJ_DEVICE_CONTROL:

		iptBuf = Irp->AssociatedIrp.SystemBuffer;
		iptBufLen = piosl->Parameters.DeviceIoControl.InputBufferLength;
		optBuf = Irp->AssociatedIrp.SystemBuffer;
		optBufLen = piosl->Parameters.DeviceIoControl.OutputBufferLength;
		ioCtrlCd = piosl->Parameters.DeviceIoControl.IoControlCode;

		status = CrashDeviceControl(piosl->FileObject, TRUE, iptBuf, iptBufLen, optBuf, optBufLen, ioCtrlCd, &Irp->IoStatus, DeviceObject);
		break;

	default:

		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

//---------------
// Driver unload
//---------------
VOID CrashUnload(IN PDRIVER_OBJECT DriverObject)
{
	WCHAR dlBuf [] = L"\\DosDevices\Crash";
	UNICODE_STRING dlUnicodeStr;
	RtlInitUnicodeString(&dlUnicodeStr, dlBuf);
	IoDeleteSymbolicLink(&dlUnicodeStr);
	IoDeleteDevice(DriverObject->DeviceObject);
}

//--------------------
// Driver entry point
//--------------------
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WCHAR dnBuf [] = L"\\Device\\Crash";
	UNICODE_STRING dnUnicodeStr;
	WCHAR dlBuf [] = L"\\DosDevices\\Crash";
	UNICODE_STRING dlUnicodeStr;
	PDEVICE_OBJECT intDev = NULL;

	RtlInitUnicodeString(&dnUnicodeStr, dnBuf);
	status = IoCreateDevice(DriverObject, 0, &dnUnicodeStr, TYPE_DEVICE_CRASH, 0, TRUE, &intDev);
	if (NT_SUCCESS(status)) {

	RtlInitUnicodeString(&dlUnicodeStr, dlBuf);
	status = IoCreateSymbolicLink(&dlUnicodeStr, &dnUnicodeStr);
	DriverObject->MajorFunction[IRP_MJ_CREATE] =
	DriverObject->MajorFunction[IRP_MJ_CLOSE] =
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CrashDispatch;
	DriverObject->DriverUnload = CrashUnload;
	}

	if (!NT_SUCCESS(status)) {
		if (intDev) {
			IoDeleteDevice(intDev);
		}
	}

	return status;
}
