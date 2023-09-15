# ebpf summit 2023 CTF writeup

## Overview

This CTF challenge requires us to find the PID of a userland program that is hidden using eBPF. This program is continually reading from `/etc/passwd` and updating `/ebpf.summit`.

After identifying the PID of the userland program, we need to terminate it and then read the contents of /ebpf.summit to obtain the flag.

Then, we have to determine the encoding scheme of the flag and decode it to reveal the hidden message. 

This writeup applies to both the easy and hard version of the challenge. 


## Steps to Solve

### Step 1: Naive Approaches

#### lsof

The first thing I tried was using `lsof` on `/ebpf.summit` and `/etc/passwd` to identify which process was interacting with these files. 

```bash
tks@lima-hard:~$ sudo lsof /etc/passwd
tks@lima-hard:~$ sudo lsof /ebpf.summit
tks@lima-hard:~$
```

There was no output, so the eBPF "malware" is probably hiding the file descriptors for the user-land program.

#### strace

Next, I ran strace on all processes while using grep to filter for "ebpf" and "passwd." My goal was to identify any file read/write-related system calls associated with the process that was reading /etc/passwd and writing to /ebpf.summit.

```bash
tks@lima-hard:~$ for pid in $(ps -e -o pid=); do sudo strace -p $pid -e trace=file 2>&1 & done | grep --line-buffered -E "passwd|ebpf"
```

This did not yield any results, so I moved onto use ebpf related techniques. 

### Step 2: bpftool

#### List all eBPF programs loaded in kernel

Next, I turned to `bpftool prog show` to get a closer look at the eBPF programs loaded into the kernel

```bash
tks@lima-hard:~$ sudo bpftool prog show
106: cgroup_device  tag ee0e253c78993a24  gpl
	loaded_at 2023-09-14T23:25:06+0000  uid 0
	xlated 416B  jited 400B  memlock 4096B
... 

(omitted 107-117 for brevity)

119: tracepoint  name handle_getdents  tag 6d77f37136bf2f5c  gpl
	loaded_at 2023-09-14T23:25:10+0000  uid 0
	xlated 296B  jited 328B  memlock 4096B  map_ids 6,7
	btf_id 94
120: tracepoint  name handle_getdents  tag 3da1705dc803ad56  gpl
	loaded_at 2023-09-14T23:25:10+0000  uid 0
	xlated 1784B  jited 1652B  memlock 4096B  map_ids 7,8,9,6,10,11
	btf_id 99
121: tracepoint  name handle_getdents  tag 97c6fdabf49fbe34  gpl
	loaded_at 2023-09-14T23:25:10+0000  uid 0
	xlated 520B  jited 500B  memlock 4096B  map_ids 11
	btf_id 100
```

Programs 119-121 were all attached to a tracepoint called handle_getdents. Each of these programs also had associated eBPF maps.

The getdents system call is commonly used by programs to list the contents of a directory. It seemed plausible that the eBPF "malware" was attaching or hooking into this system call, potentially concealing user-space programs from listing or interacting with any file related to it. (this was true!) 

#### Dump contents of eBPF maps for programs 119-121

Next, I used `bpftool map dump` to dump the contents of the eBPF maps for programs 119-121. 

```bash
for id in {6..11}; do sudo bpftool map dump id $id; done
[{
        "value": {
            ".rodata": [{
                    "target_ppid": 0
                },{
                    "handle_getdents_exit.____fmt": "[found] filename -> %s, looking for-> %s"
                }
            ]
        }
    }
]
[{
        "key": 14873471749511,
        "value": 187651614621392
    },{
        "key": 24202140718595,
        "value": 187650683166416
    },{
        "key": 45299020081459,
        "value": 187650297698128
... (most of map 8 is omitted for brevity)
[{
        "key": 0,
        "value": {
            "pid_string_len": 4,
            "pid_string": [51,49,57,55,0,0,0,0,0,0
            ]
        }
    }
]
[{
        "key": 1,
        "value": 120
    },{
        "key": 2,
        "value": 121
    }
]
[]
```
#### Getting the process id
Map ID 9 contains information about process IDs, and the value "pid_string": [51, 49, 57, 55, 0, 0, 0, 0, 0, 0] corresponds to the ASCII characters for 3197. This value likely represents the process ID for the hidden user space process. 

#### Investigating process 3197

I then tried to use some tools to investigate more about process 3197. I tried using ps, top, and even looking in proc for a directory corresponding to the pid, but with no luck. 

```bash 
tks@lima-hard:~$ sudo ps -p 3197
    PID TTY          TIME CMD
tks@lima-hard:~$ sudo top | grep 3197
tks@lima-hard:~$ sudo ls /proc/ | grep "3197"
tks@lima-hard:~$
```

It was very strange that under proc, the directory for process 3197 was not present. Then I remembered that the ebpf program for the process was attached to getdents, which is related to listing directories. Could the ebpf program be hiding the process 3197 directory?

I then tried listing the process status directly

```bash
tks@lima-hard:~$ sudo cat /proc/3197/status
Name:	ebpf.summit.202
Umask:	0022
State:	S (sleeping)
Tgid:	3194
Ngid:	0
Pid:	3197
PPid:	1
TracerPid:	0
....
```

This worked! And confirms that pid 3197 is the userspace process we are looking for. The eBPF program must be intercepting the getdents systemcall to conceal user space processes like my shell from being able to list directories related to the process. 



### Step 3: Killing the process and getting the flag

Finally, I killed the process and then catted the /ebpf.summit file to get the flag. 

```bash
tks@lima-hard:~$ sudo cat /ebpf.summit
I've been in your kernel for [2762.568963 seconds]
tks@lima-hard:~$ sudo kill 3197
tks@lima-hard:~$ sudo cat /ebpf.summit

You purged the computers of the malware - and not a second too late. Congratula
tions! The location of the base remains a secret. Maybe not for long though, wh
ile everyone was focusing on the computers, Bajeroff Lake, the traitor, managed
 to escape from his cell and stole a shuttle to escape the base. On the radars,
you only see him jump into hyperspace. There's no doubt your paths will cross a
gain one day. Before that, you'll take a day or three off to enjoy a well-deser
ved rest. How about checking in on your giant bees, for a change?

Oh wait, they're just calling all hands on deck: a Rebel squadron fell into an
ambush and is fighting their way out... You'll relax another week!

-------------------------------------------------------------------------------

Thanks for playing the eBPF Summit 2023 Capture the Flag, paste the below code
in the CTF channel on the eBPF Slack!

GJ4xMFOoFRSFES5XFFq7MFO8LKZtnJ9trJ46pvOeMKWhMJjtMz4lVSflAmp5YwLkZGNlAFOmMJAiozEmKDb=
```

### Step 4: Decoding the flag to get the hidden message

With the flag in hand, the next task was to decode it to reveal the concealed message.

I initially attempted to decode it using base64, but this method did not yield any results. It appears that this flag is encoded using a different scheme.

```
tks@lima-hard:~$ echo "GJ4xMFOoFRSFES5XFFq7MFO8LKZtnJ9trJ46pvOeMKWhMJjtMz4lVSflAmp5YwLkZGNlAFOmMJAiozEmKDb=" | base64 -d
�10S��.WZ�0S�,�m��m��:��0��0��3>%U'�jyc�dceS�0�"�1&(6tks@lima-hard:~$
```

When I was running `strace`, I discovered a reference to a binary file located at `/tmp/ebpf.summit.2023`. This binary appears to be the user-space program responsible for writing the flag when it is terminated.

I ran the strings command on this binary and was pleasantly surprised to find that it was not obfuscated. It contained symbols for the Go binary. I carefully examined these symbols in an attempt to locate any references to encoding functions.

After some scouring, I found a symbol called `main.rot13rot5`

```bash
tks@lima-hard:~$ strings /tmp/ebpf.summit.2023 | grep "main.rot13rot5"
main.rot13rot5
main.rot13rot5
```

A quick google-search reveals this is a rots18 implementation in Go https://www.socketloop.com/tutorials/golang-rot13-and-rot5-algorithms-example

We can use tr to implement a rots18 decoder where each character is replaced by the character 18 positions forward in the alphabet (with wrapping), and digits are replaced by digits shifted by 5 positions. Other characters that are not in the specified ranges will remain unchanged.

Decoding it revealed what looked to be a base64 encoded string which when decoded reveals our hidden message. 

```bash
tks@lima-hard:~$ echo "GJ4xMFOoFRSFES5XFFq7MFO8LKZtnJ9trJ46pvOeMKWhMJjtMz4lVSfkAGVhAQt9ZGD7VUAyL74hMUAqPt==" | tr 'A-Za-z0-9' 'N-ZA-Mn-za-m5-90-4'
TW9kZSBbSEFSRF0KSSd2ZSB3YXMgaW4geW91ciBrZXJuZWwgZm9yIFsxNTIuNDg4MTQ2IHNlY29uZHNdCg==
tks@lima-hard:~$ echo "GJ4xMFOoFRSFES5XFFq7MFO8LKZtnJ9trJ46pvOeMKWhMJjtMz4lVSfkAGVhAQt9ZGD7VUAyL74hMUAqPt==" | tr 'A-Za-z0-9' 'N-ZA-Mn-za-m5-90-4' | base64 -d
Mode [HARD]
I've was in your kernel for [152.488146 seconds]
```

This was a really fun challenge! Huge thanks to the ebpf summit folks for creating and hosting it. 