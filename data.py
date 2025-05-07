question_data = [
    {

        'question' : 'What protocol operates on port 389?' ,
        'answer' : 'LDAP (Lightweight Directory Access Protocol)' ,
        'options' : ['A. LDAP' , 'B. RDP', 'C. SNMP' , 'D. SMTP'] ,
        'correct' : 'a'
    },

    {

        'question': 'Which of the following best describes a malicious program stored in the first sector of a hard'
                    ' drive which'
                    'is then loaded into memory when the computer boots up?',
        'answer': 'Boot Sector Virus',
        'options': ['A. Sector Worm', 'B. First Sector Virus', 'C. Boot Sector Virus', 'D. Boot Sector Trojan'],
        'correct': 'c'
    },

    {

        'question' : 'Which of the following is not a hashing algorithm?' ,
        'answer' : 'RSA (Rivest-Shamir-Adleman)' ,
        'options' : ['A. HMAC' , 'B. RSA', 'C. MD5' , 'D. SHA-1'] ,
        'correct' : 'b'
    },

    {

        'question' : 'EAP-TTLS is an authentication protocol that can use an optional client certificate, while the '
                     'server certificate is required. True or False.' ,
        'answer' : 'LDAP (Lightweight Directory Access Protocol)' ,
        'options' : ['A. True' , 'B. False'] ,
        'correct' : 'a'
    },

    {

        'question' : 'What protocol operates on port 389?' ,
        'answer' : 'LDAP (Lightweight Directory Access Protocol)' ,
        'options' : ['A. LDAP' , 'B. RDP', 'C. SNMP' , 'D. SMTP'] ,
        'correct' : 'a'
    },

    {

        'question' : 'Which role in data management is responsible for the oversight of any kind of privacy related'
                     'data, like PII, SPII, or PHI?' ,
        'answer' : 'Privacy Officer' ,
        'options' : ['A. Data Processor' , 'B. Data Controller', 'C. Data Steward' , 'D. Privacy Officer'] ,
        'correct' : 'd'
    },

    {

        'question' : 'What role in data management is responsible for the quality of the data and its associated'
                     'meta data?' ,
        'answer' : 'Data Steward' ,
        'options' : ['A. Data Processor' , 'B. Data Controller', 'C. Data Steward' , 'D. Privacy Officer'] ,
        'correct' : 'c'
    },

    {

        'question': 'What role best describes the group or individual hired by the data controller to help with tasks'
                    'like collecting, storing, or analyzing data?',
        'answer': 'Data Processor',
        'options': ['A. Data Processor' , 'B. Data Controller', 'C. Data Owner' , 'D. Privacy Officer'],
        'correct': 'a'
    },

    {

        'question': 'which role best describes the entity that holds responsibility for deciding the purpose and '
                    'methods of data storage, collection, usage, and the legality of the various data processes.',
        'answer': 'Data Controller',
        'options': ['A. Data Processor' , 'B. Data Controller', 'C. Data Steward' , 'D. Privacy Officer'],
        'correct': 'b'
    },

    {

        'question': 'The senior executive role that has the responsibility of maintaining the CIA of data assets',
        'answer': 'Data Owner. The data owner has a variety of responsibilities when it comes to data including'
                  'defining who can access the data, making decisions about how data will be protected, ensuring'
                  'compliance with laws and data regulations like the GDPR, classifying data (public, confidential, '
                  'secret, top secret, etc), and authorizing changes, backups, and recovery plans',
        'options': ['A. Data Processor' , 'B. Data Controller', 'C. Data Steward' , 'D. Data Owner'],
        'correct': 'd'
    },

    {

        'question': 'What type of malicious software is designed to protect itself from being analyzed?',
        'answer': 'Armored Virus. Armored viruses use various tactics to prevent analyzation. These tactics include'
                  'code obfuscation, encryption, anti-debugging, and fake error messages or/and fake code paths.',
        'options': ['A. Boot Sector Virus', 'B. Undetectable Virus', 'C. Armored Virus', 'D. Spoof Virus'],
        'correct': 'c'
    },

    {

        'question': 'What protocol operates on port 110?',
        'answer': 'POP3 (Post Office Protocol) is unencrypted and typically operates on port 110. Post Office Protocol'
                  ' over SSL/TLS typically operates on port 995',
        'options': ['A. POP3', 'B. POPS', 'C. SMTP', 'D. IMAP'],
        'correct': 'a'
    },

    {

        'question': 'What service typically operates on port 88?',
        'answer': 'Kerberos. Kerberos is a network authentication protocol that operates on port 88 using UDP.',
        'options': ['A. Radius', 'B. Kerberos', 'C. TACACS+', 'D. LDAP'],
        'correct': 'b'
    },

    {

        'question': 'What port does the Trivial File Transfer Protocol typically operate on?',
        'answer': 'Port 69',
        'options': ['A. 222', 'B. 175', 'C. 169', 'D. 69'],
        'correct': 'd'
    },

    {

        'question': 'What port is typically the default for the service that translates IP Addresses into'
                    ' Domain Names?',
        'answer': 'DNS, Port 53',
        'options': ['A. 75', 'B. 53', 'C. 75', 'D. 153'],
        'correct': 'b'
    },

    {

        'question': 'What type of service typically operates on port 25?',
        'answer': 'Email Gateway. Port 25 typically hosts Simple Mail Transfer Protocol over TCP',
        'options': ['A. Email Gateway', 'B. Authentication Protocol', 'C. Domain Name System',
                    'D. File Transfer Protocol'],
        'correct': 'a'
    },

    {

        'question': 'What notoriously insecure legacy protocol defaults to port 23?',
        'answer': 'Telnet, the remote desktop protocol typically operates over port 23',
        'options': ['A. RDP', 'B. SSH', 'C. Telnet', 'D. VNC'],
        'correct': 'c'
    },

    {

        'question': 'What exercise combines both offensive and defensive testing into a single penetration test',
        'answer': 'Purple Team',
        'options': ['A. Blue Team', 'B. Purple Team', 'C. Red Team', 'D. Black Team'],
        'correct': 'b'
    },

    {

        'question': 'Which term best describes a specific malware type that is designed to deliver and install'
                    'additional malicious software?',
        'answer': 'Dropper. The dropper is typically delivered through an infected email attachment, compromised '
                  'website, or malicious download. Its primary job is to deliver and install the real malware payload'
                  'like ransomware, keylogger. The dropper may create files, modify system settings, and establish'
                  'connections with command and control servers. Basically, it is sent to the user first, as the end'
                  'malware might be picked up by AV.',
        'options': ['A. Seeker', 'B. Downloader', 'C. Shellcode', 'D. Dropper'],
        'correct': 'd'
    },

    {

        'question': 'What best describes the technique used to run arbitrary code within the address space of another'
                    'process by forcing it to load a library?',
        'answer': 'DLL injection is a technique used by attackers (or sometimes legitimate software) to manipulate or '
                  'alter the behavior of a running program by inserting a Dynamic Link Library (DLL) into its memory '
                  'space. This allows the injected DLL to interact with or control the target program in unintended '
                  'ways',
        'options': ['A. Library Attack', 'B. DLL Injection', 'C. Shell Injection', 'D. Lib Forcing'],
        'correct': 'b'
    },

    {

        'question': 'What type of Firewall inspects HTTP/HTTPS traffic and applies rule sets to prevent common '
                    'web-based'
                    'attacks?',
        'answer': 'WAF (Web Application Firewall)',
        'options': ['A. WAF', 'B. NGFW', 'C. IPS', 'D. IDS'],
        'correct': 'a'
    },

    {

        'question': 'IMAP typically operates on which port?',
        'answer': 'Port 143',
        'options': ['A. 145', 'B. 155', 'C. 143', 'D. 275'],
        'correct': 'c'
    },

    {

        'question': 'Which of the following is a technique used to mitigate a weaker key by increasing the time needed'
                    ' to crack it?',
        'answer': 'Key Stretching. This technique is used by WPA and WPA2',
        'options': ['A. Key Padding', 'B. Hashing', 'C. Tokenization', 'D. Key Stretching'],
        'correct': 'd'
    },

    {

        'question': 'Which of the following is part of an IP packet offers connectionless data integrity and data'
                    'origin authentication for  IP datagrams using cryptographic hashes as identification information?',
        'answer': 'Authentication Header (AH)',
        'options': ['A. Fragmentation Offset', 'B. Authentication Header', 'C. IPSec', 'D. Flags'],
        'correct': 'b'
    },

    {

        'question': 'Which of the following is a software vulnerability that occurs when the code attempts to to remove'
                    'the relationship between a pointer and the object that pointer was pointing to in memory?',
        'answer': 'Dereferencing',
        'options': ['A. DLL Injection', 'B. Buffer Overflow', 'C. Dereferencing', 'D. RAM Attack'],
        'correct': 'c'
    },

    {

        'question': 'Which of the following is a type of race condition that occurs when an attacker can change the'
                    'state of a system resource between the time it is checked and the time it is used?',
        'answer': 'Time of Evaluation/Time of check (T.o.E/T.o.C) is a type of side-channel attack where an attacker'
                  ' tries to gain information about a system by analyzing the time it takes to perform certain '
                  'operations. ',
        'options': ['A. T.o.E', 'B. Race Condition Attack', 'C. Transaction Race Condition', 'D. F.S.R.C'],
        'correct': 'a'
    },

    {

        'question': 'Which of the following is not a symmetric encryption algorithm?',
        'answer': 'ECC (Elliptic Curve Cryptography)',
        'options': ['A. Blowfish', 'B. ECC', 'C. RC4', 'D. ECC'],
        'correct': 'd'
    },

    {

        'question': 'Which of the following attacks modifies the contents of a cookie to be sent to a client\'s browser'
                    'and exploit vulnerabilities in an application?',
        'answer': 'Cookie Poisoning',
        'options': ['A. Cookie Stealing', 'B. Cookie Poisoning', 'C. Cookie Stuffing', 'D. Cookie Injection'],
        'correct': 'b'
    },

    {

        'question': 'What web-based attack exploits the client\'s web browser using client side scripts to modify'
                    'the content and layer of the web page?',
        'answer': 'DOM XSS (DOM Cross Site Scripting Attack)',
        'options': ['A. Reflected XSS', 'B. Persistent XSS', 'C. DOM XSS', 'D. Cross Site Scripting'],
        'correct': 'c'
    },

    {

        'question': 'Which of the following best describes a DoS attack where the attacker attempts to overwhelm a '
                    'targeted device with ICMP echo-request packets??',
        'answer': 'LDAP (Lightweight Directory Access Protocol)',
        'options': ['A. ICMP DoS', 'B. DDoS', 'C. Ping Flood', 'D. IP DoS'],
        'correct': 'c'
    },

    {

        'question': 'What type of web-based attack embeds a request for a local resource?',
        'answer': 'XML External Entity',
        'options': ['A. XML External Entity', 'B. DOM XSS', 'C. XML Bomb', 'D. XML Poisoning'],
        'correct': 'a'
    },

    {

        'question': 'What type of analysis focuses on analyzing an applications source code for vulnerabilities,'
                    'without executing the code?',
        'answer': 'Static Analysis is performed by analyzing source code for vulnerabilities without executing the code'
                  'It can be done manually or with automated analysis tools.',
        'options': ['A. LDAP', 'B. Static Analysis', 'C. Manual Code Review', 'D. Active Code Analysis'],
        'correct': 'b'
    },

    {

        'question': 'Which term describes XML encoded entities that expand to exponential sizes, consuming memory on '
                    'the hose and potentially crashing it?',
        'answer': 'LDAP (Lightweight Directory Access Protocol)',
        'options': ['A. XML DoS', 'B. XML Nuke Attack', 'C. XML Laugh Attack', 'D. XML Bomb'],
        'correct': 'd'
    },

    {

        'question': 'What technique uses the DNS protocol over port 53 to encase non-DNS traffic in an attempt to '
                    'evade firewall rules for command and control or data exfiltration?',
        'answer': 'DNS Tunneling',
        'options': ['A. DNS Attack', 'B. DNS Tunneling', 'C. DNS Port Exfiltration', 'D. DNS Amplification Attack'],
        'correct': 'b'
    },

    {

        'question': 'What describes an attacker attempting to overload a target system with DNS response traffic by '
                    'exploiting the DNS resolution process?',
        'answer': 'DNS Amplification Attack',
        'options': ['A. DNS DoS Attack', 'B. DNS Flood Attack', 'C. DNS Amplification', 'D. DNS Bomb'],
        'correct': 'c'
    },

    {

        'question': 'Which of the following is NOT a commonly used method to prevent/stop DoS attacks?',
        'answer': 'Reboot',
        'options': ['A. Blackhole/Sinkhole', 'B. Cloud Infrastructure', 'C. IPS', 'D. Reboot'],
        'correct': 'd'
    },

    {

        'question': 'What attack involves corrupting the DNS cache data of a DNS resolver with false information?',
        'answer': 'DNS Cache Poisoning',
        'options': ['A. DNS Cache Poisoning', 'B. DNS Cache Injection', 'C. DNS Resolver Corruption', 'D. DNS Cache '
                                                                                                      'Overflow'],
        'correct': 'a'
    },

    {

        'question': 'What term best describes the security strategy that integrates multiple protection technologies'
                    'into a single platform to improve detection accuracy and simplify the incident response process?',
        'answer': 'XDR (Extended Detection and Response',
        'options': ['A. Extended Detection and Response', 'B. Endpoint Detection and Response', 'C. Cloud EDR',
                    'D. NGFW'],
        'correct': 'a'
    },

    {

        'question': 'This type of attack occurs when an attacker tries to execute a script to inject a remote file.',
        'answer': 'Remote File Inclusion',
        'options': ['A. Remote File Injection', 'B. Remote File Inclusion', 'C. Local File Poisoning',
                    'D. Local File Corruption'],
        'correct': 'b'
    },

    {

        'question': 'This type of network-based attack involves maliciously repeating or delaying valid data '
                    'transmissions.',
        'answer': 'Replay Attack. Typically these attacks are performed by capturing network traffic using a tool like'
                  'WireShark or TCPDump, analyzing the packets for valuable information like session information'
                  'authentication headers, API keys, etc. Then using either a custom tool, or cURL, or a custom script'
                  'to resend the data back to the target system. Using a Flipper Zero to capture a RF signal, and then '
                  'repeating it to open a gate, is an example of a type of Replay Attack.',
        'options': ['A. Packet Spoofing', 'B. Traffic Spoofing', 'C. Replay Attack', 'D. Repeat Attack'],
        'correct': 'c'
    },

    {

        'question': 'Which of the following represents unique pieces of data that prevent session replay attacks?',
        'answer': 'LDAP (Lightweight Directory Access Protocol)',
        'options': ['A. Session ID', 'B. Transport Header', 'C. Connection Handshake', 'D. Session Token'],
        'correct': 'a'
    },

    {

        'question': 'This type of arbitrary code execution allows an attacker to transmit code from a remote location?',
        'answer': 'Remote Code Execution',
        'options': ['A. Arbitrary Code Injection', 'B. Remote Code Execution', 'C. Remote Code Injection',
                    'D. Code Injection'],
        'correct': 'b'
    },

    {

        'question': 'Which of the following is a type of spoofing attack where the host is disconnected and replaced '
                    'by the attacker?',
        'answer': 'Session Hijacking.',
        'options': ['A. Session Poisoning', 'B. Session Hijacking', 'C. Token Stealing', 'D. Session Stealing'],
        'correct': 'b'
    },

    {

        'question': 'Which of the following is a specific type of SQL database encryption that automatically encrypts '
                    'the entire database without needing application changes, as the system itself handles encryption '
                    'and decryption?',
        'answer': 'TDE (Transparent Data Encryption). TDE is a security feature used in SQL databases to encrypt data'
                  ' at rest.',
        'options': ['A. SQL Total Encryption', 'B. Data at Rest Encryption',
                    'C. EDR Next Generation Encryption', 'D. Transparent Data Encryption'],
        'correct': 'd'
    },

    {

        'question': 'What general security framework scans devices for their security status before granting them access'
                    'to the network, safe guarding against both known, and unknown devices?',
        'answer': 'NAC (Network Access Control). NAC is a security framework that may use various wireless protocols'
                  ' such as RADIUS, 802.1X, or SNMP, to verify devices are clean before giving them access to crucial'
                  'business or organization infrastructure',
        'options': ['A. RBAC', 'B. DAC', 'C. NAC', 'D. NAT'],
        'correct': 'c'
    },

    {

        'question': 'This web-based exploit focuses on an attacker who attempts to trick a user into performing an '
                    'action on a web application that they are authenticated to use.',
        'answer': 'XSRF (Cross Site Request Forgery). XSRF attacks exploit the application\'s trust in the user\'s'
                  ' authenticated browser to make unauthorized requests on the attackers behalf, like transferring '
                  'money or changing settings.',
        'options': ['A. XSRF', 'B. DOM XSS', 'C. Session Stealing', 'D. Cookie Poisoning'],
        'correct': 'a'
    },

    {

        'question': 'This term describes when a lock remains in place because the process it\'s waiting for is '
                    'terminated, crashes, or doesn\'t finish properly, despite the process being completed?',
        'answer': 'Deadlock.',
        'options': ['A. Not Responding', 'B. Crash', 'C. Deadlock', 'D. Process Lock'],
        'correct': 'c'
    },

    {

        'question': 'This type of IDS analyzes traffic and compares it to a normal baseline to determine whether'
                    ' a threat is occurring.',
        'answer': 'Anomaly Based IDS',
        'options': ['A. Next Generation IDS', 'B. Behavior Analysis IDS', 'C. AI IDS', 'D. Anomaly Based IDS'],
        'correct': 'd'
    },

    {

        'question': 'A Hardware Security Module is a physical device that safeguards and manages digital keys. True'
                    ' or False?',
        'answer': 'True',
        'options': ['A. True', 'B. False'],
        'correct': 'a'
    },

    {

        'question': 'This is the virtualized approach to managing and optimizing wide area network connections to '
                    'efficiently route traffic between remote sites, data centers, and cloud environments.',
        'answer': 'SDWAN. SDWAN is a type of software defined network, but specifically mentioning moving traffic'
                  'between remote sites for the same organization, makes the correct answer SDWAN',
        'options': ['A. WAN', 'B. Software Defined Network', 'C. SDWAN', 'D. Infrastructure as Code'],
        'correct': 'c'
    },

    {

        'question': 'Which of the following refers to a dedicated hardware device with pro-installed software that is '
                    'designed to provide specific networking services?',
        'answer': 'Network Appliance',
        'options': ['A. SDN', 'B. Network Appliance', 'C. Line Conditioner', 'D. Network Toolbox'],
        'correct': 'b'
    },

    {

        'question': 'Which of the following terms describe a mutually exclusive flag that acts as a \"gatekeeper\" to '
                    'a section of code so that only one thread can be processed at a time?',
        'answer': 'Mutex. Short for mutual exclusion, is a programming object that is used to prevent multiple threads'
                  ' from accessing a shared resource at the same time.',
        'options': ['A. Semaphore Switch', 'B. Thread Manager', 'C. Thread Forker', 'D. Mutex'],
        'correct': 'd'
    },

    {

        'question': 'What popular 2016 exploit showcased a Race Condition?',
        'answer': 'Dirty Cow. This is unlikely to come up on the exam, but it\'s good to know.',
        'options': ['A. Dirty Cow', 'B. Billion Laugh Attack', 'C. Blue Eternal', 'D. Dragon\'s Blood'],
        'correct': 'a'
    },

    {

        'question': 'This technique is specifically designed to prevent buffer overflow and other memory based'
                    ' attacks?',
        'answer': 'ASLR (Address Space Layout Randomization. This works to prevent Buffer Overflow Attacks, by '
                  'randomizing memory locations, making it harder for attackers to predict the location of critical'
                  ' functions, buffers or data structures in memory.',
        'options': ['A. Hashing', 'B. ASLR', 'C. ARLS', 'D. Tokenization'],
        'correct': 'b'
    },

    {

        'question': 'This type of spoofing attack involves the attacker attempting to predict the session token in '
                    'order to hijack the legitimate users session.',
        'answer': 'Session Prediction is typically performed using brute force attacks or intelligent guesswork based'
                  'upon common patterns.',
        'options': ['A. Session Injection', 'B. Session Hijacking', 'C. Session Stealing', 'D. Session Prediction'],
        'correct': 'd'
    },

    {

        'question': 'What aspect of an application enables web application to uniquely identify a user across several'
                    'different actions and requests?',
        'answer': 'Session Management',
        'options': ['A. Encryption', 'B. Session Management', 'C. Token Management', 'D. Cookie Management'],
        'correct': 'b'
    },

    {

        'question': 'Which of the following describes when an attacker is able to put their machine logically inbetween'
                    'two hosts during communication?',
        'answer': 'On-Path Attack. ARP Poisoning, DNS Poisoning, Rogue WAP, and Rogue Switch attacks, are all examples'
                  ' of On-Path attacks.',
        'options': ['A. Session Stealing', 'B. On-Path Attack', 'C. Monkey in the Middle', 'D. Spoofing Attack'],
        'correct': 'b'
    },

    {

        'question': 'What protocol operates on port 389?',
        'answer': 'LDAP (Lightweight Directory Access Protocol)',
        'options': ['A. LDAP', 'B. RDP', 'C. SNMP', 'D. SMTP'],
        'correct': 'a'
    },

    {

        'question': 'This occurs when a user/attacker accesses or modifies specific resources that they are not '
                    'entitled to normally access.',
        'answer': 'Privilege escalation is one of the fundamental aspects of penetration testing and hacking in'
                  ' general.'
                  'Once an attacker finds a way in on a lower privilege user\'s account, they may need to gain higher'
                  'level access to perform various actions like install malware or ransomware.',
        'options': ['A. Privilege Escalation', 'B. VM Escape', 'C. Hacking', 'D. Indicator of Compromise'],
        'correct': 'a'
    },

    {

        'question': 'This attack occurs when an attacker tries to add a file that already exists.',
        'answer': 'Local File Inclusion',
        'options': ['A. Local Directory Attack', 'B. File Spoofing', 'C. Local File Inclusion',
                    'D. Remote File Inclusion'],
        'correct': 'c'
    },

    {

        'question': 'This authentication protocol secures EAP within an encrypted and authenticated TLS tunnel.?',
        'answer': 'PEAP stands for Protected Extensible Authentication Protocol. PEAP encapsulates the EAP within a'
                  'secure TLS tunnel, which helps protect the authentication process and user credentials from'
                  'being intercepted',
        'options': ['A. EAP', 'B. PEAP', 'C. EAPTLS', 'D. SEAP'],
        'correct': 'b'
    },

    {

         'question': 'What is the primary goal of risk management?',
        'answer': 'To identify, assess, and reduce risks to acceptable levels.',
        'options': ['C. Manage vulnerabilities', 'A. Increase profits', 'B. Reduce downtime', 'D. Risk mitigation'],
        'correct': 'd'
    },

    {

        'question': 'Which protocol is used to securely browse the web?',
        'answer': 'HTTPS ensures the security of the communication between the client and the web server.',
        'options': ['A. HTTP', 'B. FTP', 'C. HTTPS', 'D. SMTP'],
        'correct': 'c'
    },

    {

        'question': 'What does VPN stand for?',
        'answer': 'VPN stands for Virtual Private Network, which allows a secure connection over the internet.',
        'options': ['A. Virtual Personal Network', 'B. Virtual Private Network', 'C. Verified Protected Network',
                    'D. Virtual Protected Node'],
        'correct': 'b'
    },

    {

        'question': 'Which of the following is a type of malware?',
        'answer': 'A Trojan horse is a type of malware that tricks users into installing it by disguising itself'
                  ' as legitimate software.',
        'options': ['A. Worm', 'B. Trojan horse', 'C. Firewall', 'D. VPN'],
        'correct': 'b'
    },

    {

        'question': 'What does the acronym DNS stand for?',
        'answer': 'DNS stands for Domain Name System, which translates domain names to IP addresses.',
        'options': ['A. Domain Name Server', 'B. Dynamic Network Service', 'C. Domain Name System',
                    'D. Dynamic Network System'],
        'correct': 'c'
    },

    {

        'question': 'Which type of attack involves overwhelming a network with traffic to make it unavailable?',
        'answer': 'A DDoS attack floods a network or server with traffic, making it unavailable to users.',
        'options': ['A. Phishing', 'B. DDoS', 'C. SQL injection', 'D. Man-in-the-middle'],
        'correct': 'b'
    },

    {

        'question': 'Which tool is used to protect a network by filtering traffic?',
        'answer': 'A firewall is used to filter and monitor incoming and outgoing network traffic.',
        'options': ['A. VPN', 'B. IDS', 'C. Firewall', 'D. Proxy'],
        'correct': 'c'
    },

    {

        'question': 'What is the purpose of a password manager?',
        'answer': 'A password manager securely stores and manages your passwords, helping you generate strong,'
                  ' unique ones.',
        'options': ['A. Encrypts passwords', 'B. Manages passwords securely',
                    'C. Tracks login attempts', 'D. Monitors malware'],
        'correct': 'b'
    },

    {

        'question': 'Which of the following is an example of a two-factor authentication method?',
        'answer': 'SMS codes sent to a phone are an example of two-factor authentication.',
        'options': ['A. Password only', 'B. Security questions', 'C. SMS codes', 'D. Fingerprint recognition'],
        'correct': 'c'
    },

    {

        'question': 'Which protocol is used to send email securely?',
        'answer': 'SMTP over SSL/TLS is used for secure email transmission.',
        'options': ['A. IMAP', 'B. POP3', 'C. SMTP', 'D. FTP'],
        'correct': 'c'
    },

    {

        'question': 'What is phishing?',
        'answer': 'Phishing is a cyber attack that involves tricking individuals into revealing sensitive information'
                  ' through deceptive emails or websites.',
        'options': ['A. SQL injection', 'B. Phishing', 'C. DDoS', 'D. Spoofing'],
        'correct': 'b'
    },

    {

        'question': 'What does an SSL certificate provide?',
        'answer': 'An SSL certificate encrypts the communication between a website and the user, ensuring data '
                  'security.',
        'options': ['A. Data encryption', 'B. Data compression', 'C. Data integrity', 'D. Authentication'],
        'correct': 'a'
    },

    {

        'question': 'Which of the following is a characteristic of a strong password?',
        'answer': 'A strong password is long, unique, and contains a mix of uppercase, lowercase, numbers, and special'
                  ' characters.',
        'options': ['A. Short and simple', 'B. Long and complex', 'C. Only lowercase letters', 'D. Only numbers'],
        'correct': 'b'
    },

    {

        'question': 'Which of the following is used for encrypting data at rest?',
        'answer': 'Full disk encryption (FDE) is used to encrypt data stored on a device, protecting it if the device '
                  'is stolen.',
        'options': ['A. SSL', 'B. FDE', 'C. WPA2', 'D. WEP'],
        'correct': 'b'
    },

    {

        'question': 'What is the purpose of an antivirus program?',
        'answer': 'An antivirus program scans and removes malicious software from a computer to protect against '
                  'infections.',
        'options': ['A. Encrypt data', 'B. Prevent network attacks', 'C. Remove malware', 'D. Monitor website traffic'],
        'correct': 'c'
    },

    {

        'question': 'Which of the following is a secure method to access a remote system?',
        'answer': 'SSH (Secure Shell) is used to securely access remote systems over a network.',
        'options': ['A. Telnet', 'B. HTTP', 'C. SSH', 'D. FTP'],
        'correct': 'c'
    },

    {

        'question': 'What does the term \"malware\" refer to?',
        'answer': 'Malware is malicious software designed to harm, exploit, or compromise a computer system.',
        'options': ['A. Software', 'B. Network protocol', 'C. Malicious software', 'D. Backup software'],
        'correct': 'c'
    },

    {

        'question': 'Which of the following protocols is used for secure communication between web browsers and '
                    'servers?',
        'answer': 'HTTPS ensures secure communication by encrypting data between a web browser and server.',
        'options': ['A. FTP', 'B. HTTP', 'C. HTTPS', 'D. SMTP'],
        'correct': 'c'
    },

    {

        'question': 'What does the acronym \"RAT\" stand for in cybersecurity?',
        'answer': 'RAT stands for Remote Access Trojan, a type of malware that allows remote control of a victim\'s '
                  'computer.',
        'options': ['A. Remote Attack Trojan', 'B. Remote Access Trojan',
                    'C. Remote Automated Trojan', 'D. Rapid Access Tool'],
        'correct': 'b'
    },

    {

        'question': 'What does the term \"zero-day exploit\" refer to?',
        'answer': 'A zero-day exploit refers to a security vulnerability that is unknown to the software vendor and can'
                  ' be exploited by attackers.',
        'options': ['A. A known vulnerability', 'B. A day of the week for attacks',
                    'C. A vulnerability exploited on the day it’s discovered', 'D. A routine patch update'],
        'correct': 'c'
    },

    {

        'question': 'What is the purpose of network segmentation?',
        'answer': 'Network segmentation improves security by dividing a network into smaller, isolated segments to'
                  ' limit the spread of attacks.',
        'options': ['A. Prevents DDoS attacks', 'B. Improves bandwidth',
                    'C. Reduces complexity', 'D. Enhances security'],
        'correct': 'd'
    },

    {
        'question': 'Which technology is used to separate different virtual machines on the same host?',
        'answer': 'Virtualization technology allows multiple virtual machines to run on the same physical host, '
                  'isolated from each other.',
        'options': ['A. Hypervisors', 'B. Firewalls', 'C. VPNs', 'D. Load balancers'],
        'correct': 'a'
    },

    {

        'question': 'Which type of encryption is used for securing symmetric key systems?',
        'answer': 'AES (Advanced Encryption Standard) is the most common algorithm for symmetric encryption.',
        'options': ['A. RSA', 'B. AES', 'C. ECC', 'D. DES'],
        'correct': 'b'
    },

    {

        'question': 'What is the main advantage of using multi-factor authentication (MFA)?',
        'answer': 'MFA increases security by requiring more than one form of verification, making it harder for '
                  'attackers to gain access.',
        'options': ['A. It only requires a password', 'B. It simplifies login procedures',
                    'C. It prevents DDoS attacks', 'D. It provides multiple layers of security'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following is used to verify the integrity of a file?',
        'answer': 'A hash function generates a fixed-size string from input data and can be used to check if a file has'
                  ' been altered.',
        'options': ['A. Symmetric Key', 'B. Hash Function', 'C. Firewall', 'D. Public Key'],
        'correct': 'b'
    },

    {
        'question': 'What kind of malware disguises itself as a legitimate software?',
        'answer': 'A Trojan hides within a seemingly legitimate program and executes malicious actions once installed.',
        'options': ['A. Rootkit', 'B. Worm', 'C. Trojan', 'D. Spyware'],
        'correct': 'c'
    },

    {
        'question': 'What device is typically used to separate different network segments?',
        'answer': 'A router connects and separates different networks, controlling traffic between them.',
        'options': ['A. Switch', 'B. Router', 'C. Modem', 'D. Hub'],
        'correct': 'b'
    },

    {
        'question': 'Which security concept ensures data is not altered or tampered with?',
        'answer': 'Integrity ensures that data remains unaltered from its original state.',
        'options': ['A. Availability', 'B. Confidentiality', 'C. Integrity', 'D. Redundancy'],
        'correct': 'c'
    },

    {
        'question': 'What does multi-factor authentication (MFA) require?',
        'answer': 'MFA requires two or more authentication factors, such as something you know, have, or are.',
        'options': ['A. Two passwords', 'B. Two usernames', 'C. A backup email', 'D. Two different factor types'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following is an example of social engineering?',
        'answer': 'Social engineering attacks manipulate people into revealing confidential information, like through '
                  'phishing emails.',
        'options': ['A. Virus', 'B. Phishing', 'C. Firewall Misconfiguration', 'D. DNS Poisoning'],
        'correct': 'b'
    },

    {
        'question': 'What is the main goal of a VPN?',
        'answer': 'A VPN encrypts data between the user and the destination to ensure privacy and secure access over '
                  'the internet.',
        'options': ['A. Speed up the connection', 'B. Block malware', 'C. Encrypt communication', 'D. Host websites'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol is used to send email?',
        'answer': 'SMTP (Simple Mail Transfer Protocol) is used to send email messages to a server or between servers.',
        'options': ['A. FTP', 'B. HTTP', 'C. SMTP', 'D. SNMP'],
        'correct': 'c'
    },

    {
        'question': 'Which of these best describes a botnet?',
        'answer': 'A botnet is a network of infected computers controlled by an attacker, often used to launch '
                  'large-scale attacks.',
        'options': ['A. Data breach tool', 'B. Authentication system', 'C. Network switch',
                    'D. Infected computer network'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following is considered a strong password?',
        'answer': 'A strong password uses a mix of uppercase, lowercase, numbers, and symbols to make guessing'
                  ' difficult.',
        'options': ['A. password123', 'B. qwerty', 'C. P@55w0rd!', 'D. abc123'],
        'correct': 'c'
    },

    {
        'question': 'Which security goal is focused on ensuring that only authorized users can access data?',
        'answer': 'Confidentiality is about protecting data from unauthorized access.',
        'options': ['A. Integrity', 'B. Availability', 'C. Confidentiality', 'D. Redundancy'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following best describes a denial-of-service (DoS) attack?',
        'answer': 'A DoS attack aims to make a system or network resource unavailable to its intended users by'
                  ' overwhelming it with traffic.',
        'options': ['A. Stealing data', 'B. Sending spam', 'C. Overloading a service', 'D. Eavesdropping on traffic'],
        'correct': 'c'
    },

    {
        'question': 'What does an antivirus program do?',
        'answer': 'Antivirus software scans for and removes malicious software from a system.',
        'options': ['A. Speeds up the computer', 'B. Installs updates', 'C. Blocks pop-ups',
                    'D. Detects and removes malware'],
        'correct': 'd'
    },

    {
        'question': 'Which type of attack relies on exploiting human trust rather than technical flaws?',
        'answer': 'Social engineering tricks individuals into giving away confidential information, bypassing '
                  'technical safeguards.',
        'options': ['A. Brute Force', 'B. Social Engineering', 'C. Zero-Day', 'D. SQL Injection'],
        'correct': 'b'
    },

    {
        'question': 'Which type of device is used to detect unauthorized access or attacks on a network?',
        'answer': 'An IDS (Intrusion Detection System) monitors network traffic for suspicious activity and alerts'
                  ' administrators.',
        'options': ['A. Router', 'B. Firewall', 'C. IDS', 'D. Proxy'],
        'correct': 'c'
    },

    {
        'question': 'What is the primary risk of using default usernames and passwords on network devices?',
        'answer': 'Default credentials are well-known and easy for attackers to guess, making devices vulnerable.',
        'options': ['A. They cause slow performance', 'B. They limit device features', 'C. They increase security',
                    'D. They are easily guessed by attackers'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following provides secure remote access to a computer over an insecure network?',
        'answer': 'SSH (Secure Shell) provides encrypted remote command-line access to systems.',
        'options': ['A. FTP', 'B. Telnet', 'C. SSH', 'D. SMTP'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following would be considered a physical security control?',
        'answer': 'Security badges help ensure that only authorized personnel can enter restricted areas.',
        'options': ['A. Passwords', 'B. Encryption', 'C. Security Badge', 'D. VPN'],
        'correct': 'c'
    },

    {
        'question': 'What is the main function of a proxy server?',
        'answer': 'A proxy server acts as an intermediary between users and the internet, often providing caching '
                  'and anonymity.',
        'options': ['A. Host DNS records', 'B. Forward email', 'C. Filter internet traffic', 'D. Block viruses'],
        'correct': 'c'
    },

    {
        'question': 'What is a common method used to protect data stored on a hard drive?',
        'answer': 'Encryption ensures that even if the drive is stolen, the data cannot be read without the key.',
        'options': ['A. Formatting', 'B. Backup', 'C. Encryption', 'D. Compression'],
        'correct': 'c'
    },

    {
        'question': 'Which type of attack intercepts communication between two parties without their knowledge?',
        'answer': 'A man-in-the-middle attack secretly relays and possibly alters communication between two parties.',
        'options': ['A. Buffer Overflow', 'B. Phishing', 'C. Man-in-the-middle', 'D. Spoofing'],
        'correct': 'c'
    },

    {
        'question': 'Which device connects multiple devices in a LAN and forwards traffic based on MAC addresses?',
        'answer': 'A switch operates at Layer 2 and forwards data based on MAC address.',
        'options': ['A. Router', 'B. Switch', 'C. Hub', 'D. Modem'],
        'correct': 'b'
    },

    {
        'question': 'What is the purpose of two-factor authentication?',
        'answer': 'It adds an extra layer of security by requiring two forms of identification.',
        'options': ['A. To store passwords', 'B. To avoid user input', 'C. To use biometrics only',
                    'D. To combine two types of verification'],
        'correct': 'd'
    },

    {
        'question': 'What does a digital certificate primarily provide in a secure connection?',
        'answer': 'A digital certificate validates the identity of the website and helps establish a '
                  'secure connection.',
        'options': ['A. Storage space', 'B. Speed', 'C. Identity verification', 'D. Virus protection'],
        'correct': 'c'
    },

    {
        'question': 'What is a brute-force attack?',
        'answer': 'It systematically tries every possible password combination until the correct one is found.',
        'options': ['A. Malware installation', 'B. Man-in-the-middle', 'C. Exploiting trust',
                    'D. Trying many password combinations'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following is a common characteristic of ransomware?',
        'answer': 'Ransomware locks or encrypts data and demands payment for access.',
        'options': ['A. Deletes system files', 'B. Monitors browsing habits',
                    'C. Encrypts data and demands payment', 'D. Slows down the computer'],
        'correct': 'c'
    },

    {
        'question': 'Why is patch management important for system security?',
        'answer': 'Patches fix known vulnerabilities that attackers might exploit.',
        'options': ['A. Adds new features', 'B. Improves battery life',
                    'C. Fixes security flaws', 'D. Removes user data'],
        'correct': 'c'
    },

    {
        'question': 'Which of these is a benefit of using a strong passphrase over a short password?',
        'answer': 'A strong passphrase is harder to guess or crack due to its length and complexity.',
        'options': ['A. Easier to remember', 'B. Uses less memory', 'C. Harder to crack', 'D. Loads faster'],
        'correct': 'c'
    },

    {
        'question': 'What is the main risk of using public Wi-Fi without a VPN?',
        'answer': 'Without encryption, your data can be intercepted by attackers on the same network.',
        'options': ['A. Faster connection', 'B. Firewall bypassing', 'C. Data interception risk', 'D. Legal issues'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following best defines phishing?',
        'answer': 'Phishing tricks users into providing sensitive data via fake emails or websites.',
        'options': ['A. Hardware failure', 'B. Social engineering via email', 'C. DNS resolution',
                    'D. Brute force attack'],
        'correct': 'b'
    },

    {
        'question': 'Which security feature helps ensure only authorized software runs on a system?',
        'answer': 'Application whitelisting only allows pre-approved software to run, reducing the risk of malware.',
        'options': ['A. Software updater', 'B. Whitelisting', 'C. File sharing', 'D. Caching'],
        'correct': 'b'
    },

    {
        'question': 'Why is it important to have strong physical security in data centers?',
        'answer': 'Physical security prevents unauthorized access to critical hardware and systems.',
        'options': ['A. Increases internet speed', 'B. Improves cable management',
                    'C. Stops network congestion', 'D. Protects hardware from intruders'],
        'correct': 'd'
    },

    {
        'question': 'Which of these best describes two-way authentication?',
        'answer': 'Two-way authentication verifies both parties in a communication, adding trust.',
        'options': ['A. Only the server is verified', 'B. Only the user is verified',
                    'C. Both server and user are verified', 'D. All emails are encrypted'],
        'correct': 'c'
    },

    {
        'question': 'What does the CIA triad stand for in cybersecurity?',
        'answer': 'It stands for Confidentiality, Integrity, and Availability — the core principles of security.',
        'options': ['A. Control, Identity, Authentication', 'B. Confidentiality, Integrity, Availability',
                    'C. Cloud, Internal, Access', 'D. Communication, Integration, Access'],
        'correct': 'b'
    },

    {
        'question': 'What is the purpose of a security policy in an organization?',
        'answer': 'Security policies define rules and procedures for all individuals accessing IT resources and'
                  ' assets.',
        'options': ['A. Manage electricity use', 'B. Determine salary levels', 'C. Set security guidelines',
                    'D. Handle vacation time'],
        'correct': 'c'
    },

    {
        'question': 'What does the term \"least privilege\" refer to in security?',
        'answer': 'Least privilege means giving users the minimum access needed to perform their job, reducing '
                  'potential damage.',
        'options': ['A. Giving everyone admin rights', 'B. Limiting bandwidth', 'C. Minimal access necessary',
                    'D. Blocking software updates'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following is considered multifactor authentication?',
        'answer': 'Multifactor authentication uses two or more types of credentials, like a password and a '
                  'fingerprint.',
        'options': ['A. Password and PIN', 'B. Username and password', 'C. Password and fingerprint',
                    'D. Two passwords'],
        'correct': 'c'
    },

    {
        'question': 'What kind of malware disguises itself as legitimate software?',
        'answer': 'A Trojan horse looks like a legitimate program but delivers malicious actions.',
        'options': ['A. Worm', 'B. Ransomware', 'C. Trojan', 'D. Rootkit'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following best describes encryption?',
        'answer': 'Encryption converts data into unreadable format to prevent unauthorized access.',
        'options': ['A. Compressing files', 'B. Scrambling data for protection', 'C. Backing up data',
                    'D. Formatting disks'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is used to detect and respond to security events in real-time?',
        'answer': 'SIEM systems collect, analyze, and alert on security events across the organization.',
        'options': ['A. DLP', 'B. SIEM', 'C. DNS', 'D. NTP'],
        'correct': 'b'
    },

    {
        'question': 'What is the role of a firewall?',
        'answer': 'A firewall filters incoming and outgoing traffic based on predefined security rules.',
        'options': ['A. Encrypts data', 'B. Scans files', 'C. Filters network traffic', 'D. Stores passwords'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following is a good example of something you have in authentication?',
        'answer': 'A smart card is a physical object you have, used to prove identity.',
        'options': ['A. Password', 'B. Smart card', 'C. Fingerprint', 'D. Username'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following protocols is used to securely browse websites?',
        'answer': 'HTTPS encrypts data sent between a web browser and a website.',
        'options': ['A. FTP', 'B. DNS', 'C. HTTPS', 'D. SMTP'],
        'correct': 'c'
    },

    {
        'question': 'What does the term \"vulnerability\" mean in cybersecurity?',
        'answer': 'A vulnerability is a weakness in a system that can be exploited.',
        'options': ['A. A backup method', 'B. A security strength', 'C. A system upgrade', 'D. A weakness or flaw'],
        'correct': 'd'
    },

    {
        'question': 'What is the purpose of a demilitarized zone (DMZ) in network security?',
        'answer': 'A DMZ separates public-facing services from the internal network to add a layer of protection.',
        'options': ['A. Encrypts files', 'B. Speeds up routing', 'C. Isolates public services', 'D. Blocks spam'],
        'correct': 'c'
    },

    {
        'question': 'Which form of malware replicates itself to spread across systems?',
        'answer': 'A worm is a self-replicating piece of malware that spreads without user interaction.',
        'options': ['A. Rootkit', 'B. Worm', 'C. Trojan', 'D. Adware'],
        'correct': 'b'
    },

    {
        'question': 'Which of these is considered a strong password?',
        'answer': 'A strong password combines letters, numbers, and symbols to resist guessing and brute-force'
                  ' attacks.',
        'options': ['A. password123', 'B. abcdefg', 'C. P@55w0rd!', 'D. qwerty'],
        'correct': 'c'
    },

    {
        'question': 'What is social engineering?',
        'answer': 'Social engineering involves manipulating people into giving up confidential information.',
        'options': ['A. Coding error', 'B. Automated script', 'C. Human deception tactic', 'D. Malware infection'],
        'correct': 'c'
    },

    {
        'question': 'What is the function of a VPN (Virtual Private Network)?',
        'answer': 'A VPN encrypts your internet traffic and hides your IP address for secure communication.',
        'options': ['A. Speeds up downloads', 'B. Hosts websites', 'C. Encrypts network traffic', 'D. Manages email'],
        'correct': 'c'
    },

    {
        'question': 'What is a hash function used for?',
        'answer': 'Hashing ensures data integrity by creating a fixed-length string that changes if the '
                  'input changes.',
        'options': ['A. Encrypting traffic', 'B. Transmitting data', 'C. Verifying integrity', 'D. Hiding data'],
        'correct': 'c'
    },

    {
        'question': 'Which of these is a risk of weak passwords?',
        'answer': 'Weak passwords can be easily guessed or cracked, leading to unauthorized access.',
        'options': ['A. Lower resolution', 'B. Faster logins', 'C. Unauthorized access', 'D. More ads'],
        'correct': 'c'
    },

    {
        'question': 'Why are regular backups important for cybersecurity?',
        'answer': 'Backups help recover lost or encrypted data after incidents like ransomware attacks.',
        'options': ['A. Speed up browsing', 'B. Save memory', 'C. Help restore lost data', 'D. Disable viruses'],
        'correct': 'c'
    },

    {
        'question': 'What is the main purpose of a digital signature?',
        'answer': 'Digital signatures verify the authenticity and integrity of digital messages or documents.',
        'options': ['A. Add animations', 'B. Reduce file size', 'C. Verify authenticity', 'D. Store passwords'],
        'correct': 'c'
    },

    {
        'question': 'Which one of these best defines malware?',
        'answer': 'Malware is any software designed to harm, exploit, or illegally access a device or network.',
        'options': ['A. A file compressor', 'B. Malicious software', 'C. A secure program', 'D. A software license'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is a common indicator of a phishing email?',
        'answer': 'Unexpected links or requests for personal information are signs of phishing.',
        'options': ['A. Proper grammar', 'B. Company logo', 'C. Suspicious links', 'D. Short subject lines'],
        'correct': 'c'
    },

    {
        'question': 'Which of these attacks involves flooding a system with traffic to disrupt service?',
        'answer': 'DoS (Denial of Service) attacks overload a system to make it unavailable.',
        'options': ['A. Phishing', 'B. DoS', 'C. Rootkit', 'D. Man-in-the-middle'],
        'correct': 'b'
    },

    {
        'question': 'What does patching a system usually fix?',
        'answer': 'Patches are released to fix bugs and close security vulnerabilities.',
        'options': ['A. Add advertisements', 'B. Create malware', 'C. Fix security issues', 'D. Disable encryption'],
        'correct': 'c'
    },

    {
        'question': 'What is a risk of clicking on links in unsolicited emails?',
        'answer': 'These links may lead to phishing sites or download malware.',
        'options': ['A. Increase speed', 'B. Improve Wi-Fi', 'C. Trigger malware or scams', 'D. Block firewalls'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following represents \"something you are\" in authentication?',
        'answer': 'Biometrics like fingerprints are considered \"something you are\".',
        'options': ['A. Password', 'B. Security token', 'C. Fingerprint', 'D. Username'],
        'correct': 'c'
    },

    {
        'question': 'Why are administrative accounts high-value targets?',
        'answer': 'They have elevated privileges, making them ideal for attackers seeking full system access.',
        'options': ['A. They load faster', 'B. They have limited access', 'C. They contain hardware specs',
                    'D. They have elevated privileges'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following best describes a man-in-the-middle attack?',
        'answer': 'A man-in-the-middle (MITM) attack occurs when a malicious actor intercepts communication between'
                  ' two parties to eavesdrop or modify the data.',
        'options': ['A. Replay Attack', 'B. Man-in-the-middle Attack', 'C. Brute Force Attack', 'D. Denial of Service'],
        'correct': 'b'
    },

    {
        'question': 'What is the primary goal of a Business Impact Analysis (BIA)?',
        'answer': 'A BIA identifies and evaluates the effects of disruptions to business operations to prioritize '
                  'recovery strategies.',
        'options': ['A. To analyze IT policies', 'B. To mitigate network attacks',
                    'C. To determine the cost of a data breach',
                    'D. To identify critical functions and the impact of their disruption'],
        'correct': 'd'
    },

    {
        'question': 'Which protocol is used to secure email communications through encryption?',
        'answer': 'S/MIME (Secure/Multipurpose Internet Mail Extensions) is used to encrypt and digitally sign email'
                  ' messages.',
        'options': ['A. SMTP', 'B. POP3', 'C. IMAP', 'D. S/MIME'],
        'correct': 'd'
    },

    {
        'question': 'What type of control is a firewall considered?',
        'answer': 'A firewall is a technical control that helps enforce access restrictions at the network level.',
        'options': ['A. Management Control', 'B. Operational Control', 'C. Technical Control', 'D. Physical Control'],
        'correct': 'c'
    },

    {
        'question': 'What is a risk associated with allowing employees to use their own devices for work?',
        'answer': 'BYOD (Bring Your Own Device) can lead to data leakage if proper security controls aren’t in place.',
        'options': ['A. System Overheating', 'B. Increased Payroll Costs', 'C. Data Leakage',
                    'D. Slower Network Speeds'],
        'correct': 'c'
    },

    {
        'question': 'What does the principle of least privilege entail?',
        'answer': 'Users should be granted the minimum access necessary to perform their job functions.',
        'options': ['A. All access all the time', 'B. Elevated rights for new employees',
                    'C. Minimum access needed for tasks', 'D. Full access after training'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of multifactor authentication (MFA)?',
        'answer': 'MFA improves security by requiring multiple forms of verification such as something you know,'
                  ' have, or are.',
        'options': ['A. To back up passwords', 'B. To store biometrics',
                    'C. To require more than one form of authentication', 'D. To encrypt data'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following helps prevent SQL injection attacks?',
        'answer': 'Input validation or sanitization ensures input is treated as data, not code.',
        'options': ['A. Buffer Overflow Protection', 'B. Code Injection', 'C. Input Sanitization/Validation',
                    'D. Network Segmentation'],
        'correct': 'c'
    },

    {
        'question': 'Which term refers to the ability to restore data after a loss or corruption?',
        'answer': 'Data recovery is the process of restoring data that has been lost or corrupted.',
        'options': ['A. Data Masking', 'B. Data Loss Prevention', 'C. Data Recovery', 'D. Data Aggregation'],
        'correct': 'c'
    },

    {
        'question': 'What is a security risk of using default credentials on network devices?',
        'answer': 'Default credentials are commonly known and can be exploited by attackers to gain unauthorized'
                  ' access.',
        'options': ['A. Slow connections', 'B. Incompatibility with routers', 'C. Easy exploitation by attackers',
                    'D. Poor password complexity'],
        'correct': 'c'
    },

    {
        'question': 'What does a digital certificate verify?',
        'answer': 'A digital certificate verifies the identity of an entity and contains the public key used '
                  'in encryption.',
        'options': ['A. Email address', 'B. Credit score', 'C. MAC address', 'D. Identity and public key of an entity'],
        'correct': 'd'
    },

    {
        'question': 'Which type of malware disguises itself as legitimate software?',
        'answer': 'A Trojan horse appears to be useful software but performs malicious actions in the background.',
        'options': ['A. Worm', 'B. Logic Bomb', 'C. Trojan', 'D. Rootkit'],
        'correct': 'c'
    },

    {
        'question': 'What does SIEM stand for?',
        'answer': 'Security Information and Event Management systems aggregate and analyze security events across systems.',
        'options': ['A. Security Integration and Equipment Management', 'B. Secure Internet and Email Management',
                    'C. Security Information and Event Management', 'D. System Integrity and Environment Monitoring'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following is a strong method of secure data disposal?',
        'answer': 'Degaussing disrupts the magnetic field on storage media, rendering data unrecoverable.',
        'options': ['A. Password Reset', 'B. Degaussing', 'C. Data Compression', 'D. Data Masking'],
        'correct': 'b'
    },

    {
        'question': 'What is the key difference between symmetric and asymmetric encryption?',
        'answer': 'Symmetric uses the same key to encrypt and decrypt, while asymmetric uses a public/private key pair.',
        'options': ['A. Only symmetric encrypts data', 'B. Asymmetric uses two keys', 'C. Symmetric is slower',
                    'D. Asymmetric does not decrypt data'],
        'correct': 'b'
    },

    {
        'question': 'Which access control model enforces security labels like \"confidential\" and \"top secret\"?',
        'answer': 'Mandatory Access Control (MAC) uses labels to restrict access based on policy, not user discretion.',
        'options': ['A. Discretionary Access Control', 'B. Role-Based Access Control', 'C. Mandatory Access Control',
                    'D. Rule-Based Access Control'],
        'correct': 'c'
    },

    {
        'question': 'What kind of attack floods a system with traffic to make it unavailable?',
        'answer': 'A Denial-of-Service (DoS) attack overwhelms a system’s resources to make it unavailable to users.',
        'options': ['A. MITM', 'B. SQL Injection', 'C. DoS', 'D. DNS Spoofing'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of a security baseline?',
        'answer': 'A security baseline provides a minimum security standard that all systems must meet.',
        'options': ['A. Tracks patch history', 'B. Identifies software licenses',
                    'C. Defines minimum security standards', 'D. Monitors bandwidth'],
        'correct': 'c'
    },

    {
        'question': 'Which of these best describes a zero-day vulnerability?',
        'answer': 'A zero-day is a previously unknown vulnerability that has no available patch.',
        'options': ['A. Software update', 'B. Unpatched known bug', 'C. New exploit with no fix',
                    'D. Social engineering method'],
        'correct': 'c'
    },

    {
        'question': 'What is the function of a hardware security module (HSM)?',
        'answer': 'An HSM is a physical device that securely stores cryptographic keys.',
        'options': ['A. Manages Wi-Fi signals', 'B. Compresses logs', 'C. Secures cryptographic keys',
                    'D. Encrypts entire servers'],
        'correct': 'c'
    },

    {
        'question': 'Which type of backup includes only files that have changed since the last backup?',
        'answer': 'An incremental backup saves time and space by copying only data that has changed since the last backup.',
        'options': ['A. Full Backup', 'B. Mirror Backup', 'C. Differential Backup', 'D. Incremental Backup'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following attacks involves intercepting and altering communication between two '
                    'parties without their knowledge?',
        'answer': 'Man-in-the-middle (MITM) attacks occur when an attacker secretly intercepts and potentially alters '
                  'communication between two parties.',
        'options': ['A. Phishing', 'B. Man-in-the-middle', 'C. Brute force', 'D. DNS poisoning'],
        'correct': 'b'
    },

    {
        'question': 'Which encryption algorithm is symmetric and designed to replace DES with improved security?',
        'answer': 'AES (Advanced Encryption Standard) is a symmetric block cipher that replaced DES due to its'
                  ' superior security.',
        'options': ['A. RSA', 'B. ECC', 'C. AES', 'D. MD5'],
        'correct': 'c'
    },

    {
        'question': 'What is the best method to verify the integrity of a file?',
        'answer': 'Hashing provides a fixed output that changes if the file is altered, making it ideal for integrity'
                  ' checks.',
        'options': ['A. Encryption', 'B. Compression', 'C. Hashing', 'D. Authentication'],
        'correct': 'c'
    },

    {
        'question': 'Which type of malware locks users out of their systems or data and demands payment?',
        'answer': 'Ransomware encrypts a user’s data or locks them out, then demands payment to restore access.',
        'options': ['A. Worm', 'B. Spyware', 'C. Ransomware', 'D. Rootkit'],
        'correct': 'c'
    },

    {
        'question': 'What does the principle of least privilege help prevent?',
        'answer': 'Least privilege ensures users only have access necessary for their role, reducing the attack '
                  'surface.',
        'options': ['A. System downtime', 'B. Insider threats', 'C. Malware installation',
                    'D. Firewall misconfiguration'],
        'correct': 'b'
    },

    {
        'question': 'Which type of social engineering attack involves a fraudulent email that appears to come from a'
                    ' trusted source?',
        'answer': 'Phishing is the practice of sending fake emails to trick users into revealing sensitive '
                  'information.',
        'options': ['A. Spear phishing', 'B. Vishing', 'C. Phishing', 'D. Shoulder surfing'],
        'correct': 'c'
    },

    {
        'question': 'What security control is most effective at preventing tailgating?',
        'answer': 'Mantraps are physical security controls that prevent unauthorized individuals from following someone'
                  ' into a secure area.',
        'options': ['A. Mantrap', 'B. Firewall', 'C. Security badge', 'D. Surveillance camera'],
        'correct': 'a'
    },

    {
        'question': 'Which layer of the OSI model is responsible for ensuring reliable transmission with error'
                    ' correction?',
        'answer': 'The Transport layer (Layer 4) manages end-to-end transmission and reliability using protocols'
                  ' like TCP.',
        'options': ['A. Session', 'B. Network', 'C. Transport', 'D. Application'],
        'correct': 'c'
    },

    {
        'question': 'Which wireless security protocol is considered the most secure for modern Wi-Fi networks?',
        'answer': 'WPA3 is the latest and most secure wireless encryption protocol for protecting Wi-Fi networks.',
        'options': ['A. WEP', 'B. WPA2', 'C. WPA3', 'D. TKIP'],
        'correct': 'c'
    },

    {
        'question': 'What is the function of a digital signature?',
        'answer': 'Digital signatures verify the authenticity and integrity of a message or file using cryptographic'
                  ' techniques.',
        'options': ['A. Encrypt the message', 'B. Mask IP addresses',
                    'C. Verify integrity and authenticity', 'D. Compress data'],
        'correct': 'c'
    },

    {
        'question': 'Which access control model uses roles assigned to users to determine access rights?',
        'answer': 'RBAC (Role-Based Access Control) assigns permissions based on user roles within an organization.',
        'options': ['A. DAC', 'B. RBAC', 'C. MAC', 'D. ABAC'],
        'correct': 'b'
    },

    {
        'question': 'Which cloud model provides users with access to hardware and networking resources only?',
        'answer': 'IaaS (Infrastructure as a Service) delivers computing infrastructure such as servers and storage.',
        'options': ['A. SaaS', 'B. IaaS', 'C. PaaS', 'D. DBaaS'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is a preventative physical security control?',
        'answer': 'Security guards are preventative controls that deter unauthorized physical access.',
        'options': ['A. Audit logs', 'B. CCTV', 'C. Security guards', 'D. Incident response plans'],
        'correct': 'c'
    },

    {
        'question': 'Which term refers to an agreement on minimum security measures between two parties?',
        'answer': 'A Memorandum of Understanding (MOU) defines mutually accepted terms including security '
                  'responsibilities.',
        'options': ['A. SLA', 'B. NDA', 'C. MOU', 'D. BPA'],
        'correct': 'c'
    },

    {
        'question': 'What kind of test simulates real-world attacks to assess security posture?',
        'answer': 'Penetration testing simulates attacks to find and exploit vulnerabilities.',
        'options': ['A. Risk assessment', 'B. Vulnerability scan',
                    'C. Penetration test', 'D. Business continuity test'],
        'correct': 'c'
    },

    {
        'question': 'Which authentication factor is something the user has?',
        'answer': 'A smart card is an example of something the user has—one of the multi-factor authentication types.',
        'options': ['A. Password', 'B. Smart card', 'C. Fingerprint', 'D. Facial scan'],
        'correct': 'b'
    },

    {
        'question': 'What type of policy defines acceptable use of organizational resources?',
        'answer': 'An AUP (Acceptable Use Policy) outlines acceptable and prohibited behaviors when using company'
                  ' systems.',
        'options': ['A. Privacy policy', 'B. Security policy', 'C. Acceptable Use Policy', 'D. Retention policy'],
        'correct': 'c'
    },


    {
        'question': 'Which protocol secures email messages using certificates and public key encryption?',
        'answer': 'S/MIME provides encryption and digital signatures for email communication.',
        'options': ['A. POP3', 'B. IMAP', 'C. SMTP', 'D. S/MIME'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following ensures accountability by recording who accessed what and when?',
        'answer': 'Auditing tracks user activities and helps ensure accountability in a system.',
        'options': ['A. Encryption', 'B. Tokenization', 'C. Auditing', 'D. Obfuscation'],
        'correct': 'c'
    },

    {
        'question': 'What type of attack attempts to guess a password by trying every possible combination?',
        'answer': 'A brute force attack systematically tries every combination until the correct password is found.',
        'options': ['A. Phishing', 'B. Rainbow table', 'C. Brute force', 'D. SQL injection'],
        'correct': 'c'
    },

    {
        'question': 'What does data at rest refer to?',
        'answer': 'Data at rest refers to data stored on a disk or storage medium and not actively moving through '
                  'the network.',
        'options': ['A. Data in motion', 'B. Encrypted data', 'C. Stored data', 'D. Data in transit'],
        'correct': 'c'
    },

    {
        'question': 'What is the primary purpose of a honeypot in cybersecurity?',
        'answer': 'A honeypot is designed to lure attackers away from critical systems and to collect intelligence on '
                  'attack techniques.',
        'options': ['A. Increase network speed', 'B. Encrypt sensitive data', 'C. Lure and analyze attackers',
                    'D. Authenticate users'],
        'correct': 'c'
    },

    {
        'question': 'Which cryptographic algorithm is commonly used in public key infrastructure (PKI) for digital'
                    ' signatures?',
        'answer': 'RSA is a widely-used asymmetric algorithm that supports encryption and digital signatures in PKI.',
        'options': ['A. MD5', 'B. AES', 'C. RSA', 'D. DES'],
        'correct': 'c'
    },

    {
        'question': 'What does the principle of \"least privilege\" refer to in access control?',
        'answer': 'It refers to granting users the minimum level of access — or permissions — they need to perform '
                  'their jobs.',
        'options': ['A. Giving full admin access to all users', 'B. Allowing access to any device on the network',
                    'C. Assigning minimal required access', 'D. Rotating user credentials daily'],
        'correct': 'c'
    },

    {
        'question': 'What type of attack involves sending unsolicited messages to Bluetooth-enabled devices?',
        'answer': 'Bluejacking is the act of sending unsolicited messages to Bluetooth devices.',
        'options': ['A. Bluesnarfing', 'B. Phishing', 'C. Bluejacking', 'D. Smishing'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol is used to securely browse websites over the internet?',
        'answer': 'HTTPS uses SSL/TLS to secure communication between the browser and the server.',
        'options': ['A. HTTP', 'B. FTP', 'C. DNS', 'D. HTTPS'],
        'correct': 'd'
    },

    {
        'question': 'What is the function of a digital certificate in PKI?',
        'answer': 'A digital certificate verifies the identity of the certificate holder and binds it to a public key.',
        'options': ['A. Encrypts hard drives', 'B. Provides anonymous browsing', 'C. Verifies identity in PKI',
                    'D. Blocks malware'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following best describes a logic bomb?',
        'answer': 'A logic bomb is malicious code that is triggered by a specific condition or event.',
        'options': ['A. Code that replicates itself', 'B. Scheduled backup script',
                    'C. Malicious code triggered by conditions', 'D. Security audit routine'],
        'correct': 'c'
    },

    {
        'question': 'Which attack involves intercepting communication between two systems to steal data?',
        'answer': 'A man-in-the-middle (MITM) attack intercepts and possibly alters communication between two parties.',
        'options': ['A. Spoofing', 'B. MITM', 'C. Phishing', 'D. Shoulder surfing'],
        'correct': 'b'
    },

    {
        'question': 'Which component of a computer is typically targeted in a rootkit attack?',
        'answer': 'Rootkits often target the operating system kernel or privileged system functions to hide malware.',
        'options': ['A. Web browser', 'B. Graphics card', 'C. Operating system kernel', 'D. Email client'],
        'correct': 'c'
    },
    {
        'question': 'Which type of malware is specifically designed to spread across networks without user '
                    'interaction?',
        'answer': 'Worms are self-replicating malware that spread automatically across networks.',
        'options': ['A. Virus', 'B. Rootkit', 'C. Worm', 'D. Trojan'],
        'correct': 'c'
    },

    {
        'question': 'What does the term “zero-day” refer to in cybersecurity?',
        'answer': 'A zero-day is a previously unknown vulnerability that has not yet been patched by developers.',
        'options': ['A. Bug discovered after release', 'B. Patch available for old systems',
                    'C. Known issue with a fix', 'D. Undisclosed, unpatched vulnerability'],
        'correct': 'd'
    },

    {
        'question': 'What is the function of a VPN in network security?',
        'answer': 'A VPN encrypts data and provides secure remote access over public networks.',
        'options': ['A. Opens firewalls', 'B. Encrypts remote connections', 'C. Removes malware',
                    'D. Improves download speeds'],
        'correct': 'b'
    },

    {
        'question': 'What type of security control is a firewall considered?',
        'answer': 'Firewalls are considered a technical control because they are systems that enforce access policies.',
        'options': ['A. Physical control', 'B. Management control', 'C. Technical control',
                    'D. Administrative control'],
        'correct': 'c'
    },

    {
        'question': 'What is shoulder surfing in the context of physical security?',
        'answer': 'Shoulder surfing is the act of spying on someone’s screen or keyboard to steal information.',
        'options': ['A. Keylogging', 'B. Network sniffing', 'C. Visual spying for credentials',
                    'D. Shoulder pressing passwords'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following best defines social engineering?',
        'answer': 'Social engineering manipulates people into revealing confidential information.',
        'options': ['A. Installing spyware', 'B. Spoofing IP addresses', 'C. Manipulating individuals',
                    'D. Running exploit scripts'],
        'correct': 'c'
    },

    {
        'question': 'Which type of test simulates a real-world attack scenario without prior knowledge?',
        'answer': 'Black box testing involves simulating an attack with no prior knowledge of the system.',
        'options': ['A. White box', 'B. Red team', 'C. Gray box', 'D. Black box'],
        'correct': 'd'
    },

    {
        'question': 'Which port number is typically associated with secure shell (SSH) protocol?',
        'answer': 'SSH operates on TCP port 22 for secure remote login and command execution.',
        'options': ['A. 20', 'B. 22', 'C. 25', 'D. 80'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is a method for securely removing data from a hard drive?',
        'answer': 'Degaussing uses a strong magnetic field to wipe data from storage media.',
        'options': ['A. Archiving', 'B. Formatting', 'C. Degaussing', 'D. Compressing'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of hashing in cybersecurity?',
        'answer': 'Hashing verifies data integrity by creating a unique fixed-size output for a given input.',
        'options': ['A. Encrypts data for transport', 'B. Stores data in the cloud', 'C. Converts data to binary',
                    'D. Ensures data integrity'],
        'correct': 'd'
    },

    {
        'question': 'Which concept ensures that data cannot be altered without detection?',
        'answer': 'Integrity ensures data is not tampered with or altered without detection.',
        'options': ['A. Confidentiality', 'B. Availability', 'C. Non-repudiation', 'D. Integrity'],
        'correct': 'd'
    },

    {
        'question': 'What is the function of an IDS (Intrusion Detection System)?',
        'answer': 'An IDS monitors network or system activity for malicious actions or policy violations.',
        'options': ['A. Encrypts data', 'B. Blocks incoming traffic', 'C. Detects suspicious activity',
                    'D. Allocates network bandwidth'],
        'correct': 'c'
    },

    {
        'question': 'What is a botnet typically used for?',
        'answer': 'A botnet is a network of infected devices used for coordinated cyber attacks, such as DDoS.',
        'options': ['A. Building firewalls', 'B. Patching systems', 'C. Performing coordinated attacks',
                    'D. Monitoring system logs'],
        'correct': 'c'
    },

    {
        'question': 'Which type of attack tricks a DNS server into pointing to a malicious IP address?',
        'answer': 'DNS poisoning corrupts the DNS cache so users are redirected to malicious sites.',
        'options': ['A. ARP flooding', 'B. DNS poisoning', 'C. MITM attack', 'D. URL spoofing'],
        'correct': 'b'
    },

    {
        'question': 'Which type of cloud service model offers software applications over the internet?',
        'answer': 'SaaS (Software as a Service) delivers software applications to users over the internet.',
        'options': ['A. IaaS', 'B. PaaS', 'C. SaaS', 'D. DBaaS'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of an air gap in cybersecurity?',
        'answer': 'An air gap is a physical security measure that isolates a computer or network from unsecured '
                  'networks, such as the internet, to prevent unauthorized access.',
        'options': ['A. Network Sniffer', 'B. Air Gap', 'C. Demilitarized Zone', 'D. VLAN'],
        'correct': 'b'
    },

    {
        'question': 'Which type of malware pretends to be a legitimate application but performs malicious actions in '
                    'the background?',
        'answer': 'A Trojan horse disguises itself as a normal application but performs harmful actions once '
                  'installed.',
        'options': ['A. Worm', 'B. Ransomware', 'C. Trojan Horse', 'D. Rootkit'],
        'correct': 'c'
    },
    {
        'question': 'What is a primary risk of using default credentials on network devices?',
        'answer': 'Default credentials are widely known and often published, making devices vulnerable to unauthorized'
                  ' access.',
        'options': ['A. They cause compatibility issues', 'B. They increase latency',

                    'C. They invite brute-force attacks', 'D. They are publicly known and easily exploitable'],
        'correct': 'd'
    },

    {
        'question': 'Which cryptographic concept ensures that data has not been altered in transit?',
        'answer': 'Integrity ensures that data remains unchanged during transmission, protecting it from unauthorized'
                  ' alteration..',
        'options': ['A. Confidentiality', 'B. Integrity', 'C. Availability', 'D. Obfuscation'],
        'correct': 'b'
    },

    {
        'question': 'What is a risk of shared accounts in a secure environment?',
        'answer': 'Shared accounts make it difficult to track user activity and assign accountability, weakening '
                  'security controls.',
        'options': ['A. Increased network speed', 'B. Reduced licensing cost',
                    'C. Lack of user accountability', 'D. Enhanced logging capabilities'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following is a benefit of full disk encryption (FDE)?',
        'answer': 'Full disk encryption ensures that data on a drive cannot be accessed if the device is lost or'
                  ' stolen.',
        'options': ['A. Faster boot times', 'B. Prevents network sniffing',
                    'C. Protects lost or stolen devices', 'D. Improves antivirus scanning'],
        'correct': 'c'
    },

    {
        'question': 'What does the principle of least functionality require?',
        'answer': 'It requires systems to be configured with only the functions necessary for their purpose, reducing '
                  'the attack surface.',
        'options': ['A. All ports should be open', 'B. Only essential services should run',
                    'C. Users must share accounts', 'D. Enable all plugins by default'],
        'correct': 'b'
    },

    {
        'question': 'What does a digital signature provide?',
        'answer': 'It verifies the authenticity and integrity of a message, assuring the recipient it came from the '
                  'stated sender.',
        'options': ['A. Confidentiality', 'B. Anonymity', 'C. Non-repudiation', 'D. Redundancy'],
        'correct': 'c'
    },

    {
        'question': 'Which attack involves manipulating a user into clicking on a malicious link disguised as a '
                    'legitimate one?',
        'answer': 'Clickjacking tricks users into clicking something different from what they perceive, often hiding'
                  ' malicious links.',
        'options': ['A. DNS Spoofing', 'B. Phishing', 'C. Clickjacking', 'D. Session Hijacking'],
        'correct': 'c'
    },

    {
        'question': 'What does endpoint detection and response (EDR) primarily provide?',
        'answer': 'EDR offers continuous monitoring and response to threats at endpoint devices such as computers and '
                  'mobile phones.',
        'options': ['A. Email scanning', 'B. Cloud traffic shaping',
                    'C. Endpoint threat monitoring', 'D. Network routing'],
        'correct': 'c'
    },
    {
        'question': 'Which of the following best describes a rogue access point?',
        'answer': 'It is an unauthorized wireless access point installed on a network, often used to bypass security'
                  ' controls.',
        'options': ['A. Wi-Fi booster', 'B. Rogue Access Point', 'C. Repeater Node', 'D. Load Balancer'],
        'correct': 'b'
    },

    {
        'question': 'What security concept involves restricting access to only what is necessary for a user to perform '
                    'their job?',
        'answer': 'The principle of least privilege ensures users have only the access they need, minimizing risk.',
        'options': ['A. Access Aggregation', 'B. Separation of Duties', 'C. Least Privilege', 'D. Role Hopping'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of salting in password hashing?',
        'answer': 'Salting adds random data to passwords before hashing to make precomputed attacks like rainbow tables '
                  'ineffective.',
        'options': ['A. To make hashing faster', 'B. To weaken brute force protection', 'C. To prevent hash collisions',
                    'D. To defend against precomputed attacks'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following best defines a zero-day vulnerability?',
        'answer': 'A zero-day vulnerability is a flaw in software that is unknown to the vendor and exploited before a'
                  ' patch is available.',
        'options': ['A. Exploit with a known patch', 'B. Flaw that is logged and ignored',
                    'C. Unpatched and unknown vulnerability', 'D. Hardware compatibility bug'],
        'correct': 'c'
    },

    {
        'question': 'Which type of attack attempts to guess passwords by trying every possible combination?',
        'answer': 'A brute-force attack systematically tries all possible password combinations until the correct one '
                  'is found.',
        'options': ['A. Replay Attack', 'B. Brute-Force Attack', 'C. Phishing', 'D. Man-in-the-middle'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is a form of social engineering?',
        'answer': 'Tailgating is when someone gains unauthorized physical access by following an authorized person into'
                  ' a restricted area.',
        'options': ['A. Keylogging', 'B. Phishing', 'C. Tailgating', 'D. Spoofing'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of a data loss prevention (DLP) solution?',
        'answer': 'DLP systems monitor and control data transfers to prevent unauthorized access or leaks of sensitive '
                  'information.',
        'options': ['A. Backup automation', 'B. Phishing detection',
                    'C. Malware analysis', 'D. Prevent data exfiltration'],
        'correct': 'd'
    },

    {
        'question': 'Which tool is used to analyze packets on a network to detect malicious behavior?',
        'answer': 'A protocol analyzer (packet sniffer) captures and analyzes traffic to identify suspicious or '
                  'malicious activity.',
        'options': ['A. Firewall', 'B. IDS', 'C. Packet Sniffer', 'D. Load Balancer'],
        'correct': 'c'
    },

    {
        'question': 'Which method provides secure remote access over an unsecured network?',
        'answer': 'A Virtual Private Network (VPN) encrypts traffic between the user and the remote network for secure '
                  'access.',
        'options': ['A. Telnet', 'B. FTP', 'C. VPN', 'D. SNMP'],
        'correct': 'c'
    },

    {
        'question': 'Which security control type is a CCTV camera system?',
        'answer': 'A CCTV system is a detective control, used to detect and record events for security monitoring.',
        'options': ['A. Preventive', 'B. Detective', 'C. Corrective', 'D. Compensating'],
        'correct': 'b'
    },
    {
        'question': 'Which term refers to unsolicited, bulk email typically sent for advertising or phishing?',
        'answer': 'Spam refers to unsolicited bulk messages often used for advertising or to launch phishing attacks.',
        'options': ['A. Spoofing', 'B. Smishing', 'C. Spam', 'D. Sniffing'],
        'correct': 'c'
    },
    {
        'question': 'Which of the following best describes the concept of network segmentation?',
        'answer': 'Network segmentation divides a network into smaller sections to improve security and performance.',
        'options': ['A. Eliminates routing tables', 'B. Hides IP addresses',
                    'C. Separates networks to reduce attack surface', 'D. Encrypts all data by default'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following technologies uses behavior analysis to detect anomalies in system '
                    'activity?',
        'answer': 'UEBA (User and Entity Behavior Analytics) uses machine learning to detect unusual user or system '
                  'behaviors.',
        'options': ['A. EDR', 'B. UEBA', 'C. IPS', 'D. WAF'],
        'correct': 'b'
    },

    {
        'question': 'What is the primary function of a hot site in disaster recovery?',
        'answer': 'A hot site is a fully operational backup facility that can take over operations almost immediately'
                  ' after a failure.',
        'options': ['A. Stores paper backups', 'B. Offers delayed failover',
                    'C. Immediate operational continuity', 'D. Hosts development systems'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following best defines a phishing attack?',
        'answer': 'Phishing is a social engineering attack where attackers trick users into divulging sensitive '
                  'information through deceptive emails or websites.',
        'options': ['A. A type of malware infection', 'B. A brute-force attack on passwords',
                    'C. Deceptive emails or websites designed to steal information', 'D. A denial of service attack'],
        'correct': 'c'
    },

    {
        'question': 'What type of encryption algorithm uses the same key for both encryption and decryption?',
        'answer': 'Symmetric encryption uses the same key for both the encryption and decryption processes, ensuring '
                  'secure communication.',
        'options': ['A. Asymmetric', 'B. Symmetric', 'C. Hashing', 'D. Elliptic Curve'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following protocols is used to securely access a network device over an unsecured'
                    ' network?',
        'answer': 'SSH (Secure Shell) is used to securely access and manage network devices over an unsecured network.',
        'options': ['A. Telnet', 'B. FTP', 'C. SSH', 'D. SNMP'],
        'correct': 'c'
    },

    {
        'question': 'What is the main purpose of an intrusion prevention system (IPS)?',
        'answer': 'An IPS is designed to detect and actively block potential intrusions or malicious activities on a'
                  ' network.',
        'options': ['A. Encrypt data packets', 'B. Block unauthorized IP addresses',
                    'C. Detect and block attacks in real-time', 'D. Provide user authentication'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of a security information and event management (SIEM) system?',
        'answer': 'A SIEM system collects, analyzes, and correlates security event data from various sources to detect'
                  ' and respond to potential security threats.',
        'options': ['A. Backup data storage', 'B. Real-time monitoring of network traffic',
                    'C. Collecting and analyzing security data for threat detection',
                    'D. Managing authentication tokens'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following is the most secure method of two-factor authentication (2FA)?',
        'answer': 'Using a hardware token for 2FA is one of the most secure methods as it generates a one-time passcode '
                  'independent of the device used to log in.',
        'options': ['A. SMS code', 'B. Email code', 'C. Hardware token', 'D. Biometric authentication'],
        'correct': 'c'
    },

    {
        'question': 'Which attack is designed to flood a network with excess traffic to exhaust system resources?',
        'answer': 'A Denial-of-Service (DoS) attack floods a network with traffic, rendering it unavailable to '
                  'legitimate users.',
        'options': ['A. Phishing', 'B. DoS', 'C. Man-in-the-middle', 'D. Worm'],
        'correct': 'b'
    },

    {
        'question': 'What is the main purpose of a public key infrastructure (PKI)?',
        'answer': 'PKI is used to manage and store digital keys for secure communications, ensuring that data can be '
                  'encrypted and verified.',
        'options': ['A. Secure physical network access', 'B. Manage encryption keys and digital certificates',
                    'C. Provide firewall protection', 'D. Encrypt network traffic in real time'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is a commonly used tool for vulnerability scanning?',
        'answer': 'Nessus is a widely used tool for vulnerability scanning that helps identify weaknesses in '
                  'systems and networks.',
        'options': ['A. Wireshark', 'B. Nessus', 'C. Nmap', 'D. Metasploit'],
        'correct': 'b'
    },

    {
        'question': 'What does the acronym SSL stand for in the context of cybersecurity?',
        'answer': 'SSL (Secure Sockets Layer) is a protocol used to encrypt data transmitted over the internet, '
                  'providing secure communication channels.',
        'options': ['A. Secure Socket Layer', 'B. Secure Synchronous Layer',
                    'C. Simple Secure Link', 'D. Secure State Link'],
        'correct': 'a'
    },

    {
        'question': 'What is a vulnerability assessment?',
        'answer': 'A vulnerability assessment involves identifying and analyzing weaknesses in a system to determine '
                  'potential security risks.',
        'options': ['A. Real-time network monitoring', 'B. Identifying and analyzing system weaknesses',
                    'C. Encrypting sensitive data', 'D. Reconfiguring network routers'],
        'correct': 'b'
    },

    {
        'question': 'What does a business continuity plan (BCP) focus on?',
        'answer': 'A business continuity plan (BCP) outlines procedures and strategies for ensuring that essential '
                  'business functions continue during and after a disaster.',
        'options': ['A. Hardware optimization', 'B. Ensuring critical business operations continue during disruptions',
                    'C. Identifying legal and regulatory compliance', 'D. Improving user productivity'],
        'correct': 'b'
    },

    {
        'question': 'What is the role of a DNS server in network communication?',
        'answer': 'A DNS (Domain Name System) server translates domain names into IP addresses, enabling users to '
                  'access websites using human-readable addresses.',
        'options': ['A. Secure user authentication', 'B. Block malicious websites',
                    'C. Translate domain names into IP addresses', 'D. Store encrypted data for users'],
        'correct': 'c'
    },

    {
        'question': 'What is the function of a Web Application Firewall (WAF)?',
        'answer': 'A WAF is used to protect web applications by filtering and monitoring HTTP traffic to detect and '
                  'block malicious requests.',
        'options': ['A. Filter network traffic', 'B. Encrypt user data',
                    'C. Protect web applications by blocking malicious requests', 'D. Monitor email traffic'],
        'correct': 'c'
    },

    {
        'question': 'What is a key difference between symmetric and asymmetric encryption?',
        'answer': 'In symmetric encryption, the same key is used for both encryption and decryption, while asymmetric'
                  ' encryption uses a public and private key pair.',
        'options': ['A. Symmetric uses public keys, asymmetric uses private keys',
                    'B. Symmetric uses the same key for both, asymmetric uses a key pair',
                    'C. Symmetric is slower than asymmetric', 'D. Asymmetric is only used in physical security'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following represents a method of protecting sensitive data at rest?',
        'answer': 'Encryption of data at rest ensures that stored data is unreadable without the proper decryption key,'
                  ' preventing unauthorized access.',
        'options': ['A. VPN encryption', 'B. Full disk encryption', 'C. Endpoint detection', 'D. IDS logging'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is a goal of multi-factor authentication (MFA)?',
        'answer': 'MFA aims to enhance security by requiring users to provide two or more forms of verification before'
                  ' granting access.',
        'options': ['A. Simplify user login', 'B. Reduce network traffic',
                    'C. Increase security by requiring multiple verifications', 'D. Collect user data for analysis'],
        'correct': 'c'
    },

    {
        'question': 'Which type of attack uses deceptive emails to trick users into divulging sensitive information?',
        'answer': 'Phishing is a form of social engineering where attackers send fraudulent emails to steal sensitive'
                  'information.',
        'options': ['A. DoS attack', 'B. Phishing', 'C. Trojan horse', 'D. Buffer overflow'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is an example of a preventive security control?',
        'answer': 'Firewalls are a preventive control because they block unauthorized network access before any damage'
                  ' occurs.',
        'options': ['A. Encryption', 'B. Firewalls', 'C. IDS', 'D. Incident response plan'],
        'correct': 'b'
    },

    {
        'question': 'Which attack intercepts and potentially alters communication between two parties without their '
                    'knowledge?',
        'answer': 'A man-in-the-middle (MITM) attack occurs when an attacker secretly intercepts and possibly alters '
                  'communications between two parties.',
        'options': ['A. Phishing', 'B. Man-in-the-middle', 'C. Denial of Service', 'D. Brute Force'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is an example of a compensating security control?',
        'answer': 'A compensating control is an alternative measure that reduces risk when the primary control is not '
                  'feasible. For example, using stronger password policies when biometric authentication is '
                  'unavailable.',
        'options': ['A. Anti-virus software', 'B. Firewalls', 'C. Strong password policies', 'D. Encryption'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following best describes the principle of least privilege?',
        'answer': 'The principle of least privilege states that users should only have the minimum level of access '
                  'necessary to perform their job functions.',
        'options': ['A. Deny all access until approved', 'B. Grant admin rights to all users',
                    'C. Give users access to everything by default', 'D. Provide minimal necessary access rights'],
        'correct': 'd'
    },

    {
        'question': 'What type of attack exploits a vulnerability in a system before it is known to the vendor?',
        'answer': 'A zero-day attack exploits a previously unknown vulnerability before a patch or fix is available '
                  'from the vendor.',
        'options': ['A. Logic bomb', 'B. Zero-day', 'C. SQL injection', 'D. Social engineering'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following is considered a physical security control?',
        'answer': 'Security cameras are a physical control that help deter and monitor physical access to sensitive '
                  'areas.',
        'options': ['A. Firewall', 'B. Security camera', 'C. Intrusion detection system', 'D. Antivirus software'],
        'correct': 'b'
    },

    {
        'question': 'Which port does HTTPS typically use?',
        'answer': 'HTTPS typically uses port 443 for secure web communication over SSL/TLS.',
        'options': ['A. 80', 'B. 21', 'C. 443', 'D. 110'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following describes a logic bomb?',
        'answer': 'A logic bomb is malicious code triggered by specific conditions, such as a date or user action.',
        'options': ['A. A phishing scam', 'B. B. Malicious code triggered by time or event',
                    'C. A worm that spreads automatically', 'D. Code that activates when conditions are met'],
        'correct': 'd'
    },

    {
        'question': 'Which of the following best describes a buffer overflow?',
        'answer': 'A buffer overflow occurs when a program writes more data to a memory buffer than it can hold, '
                  'potentially allowing code execution.',
        'options': ['A. A type of firewall bypass', 'B. Sending excessive network traffic',
                    'C. Writing beyond allocated memory space', 'D. Logging too much user activity'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of port security on a switch?',
        'answer': 'Port security restricts access to switch ports by limiting which devices can connect, helping'
                  ' prevent unauthorized access.',
        'options': ['A. Block internet traffic', 'B. Limit administrative access',
                    'C. Restrict which MAC addresses can connect to a port', 'D. Filter DNS traffic'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following tools is used for protocol analysis and network troubleshooting?',
        'answer': 'Wireshark is a protocol analyzer that captures and inspects network traffic in real-time.',
        'options': ['A. Aircrack-ng', 'B. Nessus', 'C. Wireshark', 'D. Metasploit'],
        'correct': 'c'
    },

    {
        'question': 'What type of malware disguises itself as legitimate software?',
        'answer': 'A Trojan horse is malware that appears legitimate but performs malicious actions once executed.',
        'options': ['A. Worm', 'B. Rootkit', 'C. Trojan horse', 'D. Botnet'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following is an example of a biometric factor for authentication?',
        'answer': 'A fingerprint scan is a biometric factor used to authenticate users based on physical characteristics.',
        'options': ['A. Password', 'B. Smart card', 'C. PIN', 'D. Fingerprint scan'],
        'correct': 'd'
    },

    {
        'question': 'Which layer of the OSI model does a router operate at?',
        'answer': 'Routers operate at Layer 3 (the Network layer) of the OSI model, making routing decisions based on'
                  ' IP addresses.',
        'options': ['A. Layer 1 – Physical', 'B. Layer 2 – Data Link',
                    'C. Layer 3 – Network', 'D. Layer 4 – Transport'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following can help prevent brute-force login attempts?',
        'answer': 'Account lockout policies temporarily disable accounts after too many failed attempts, mitigating '
                  'brute-force attacks.',
        'options': ['A. Using SSH', 'B. Enabling VPNs', 'C. Account lockout policies', 'D. Multi-threading'],
        'correct': 'c'
    },

    {
        'question': 'What is the primary goal of social engineering attacks?',
        'answer': 'The goal of social engineering is to manipulate people into revealing confidential information or '
                  'performing actions that compromise security.',
        'options': ['A. Exploit code vulnerabilities', 'B. Capture wireless signals',
                    'C. Trick users into giving up information', 'D. Crack encryption keys'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following is a function of a proxy server?',
        'answer': 'A proxy server acts as an intermediary for client requests, often used for content filtering and'
                  ' anonymity.',
        'options': ['A. Hosts DNS records', 'B. Blocks TCP connections',
                    'C. Forwards client requests to the internet', 'D. Encrypts email attachments'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following is a common indicator of a rogue access point?',
        'answer': 'An unauthorized wireless device broadcasting a legitimate-looking SSID could indicate a rogue access'
                  ' point.',
        'options': ['A. Slow internet speeds', 'B. Duplicate SSIDs with different MAC addresses',
                    'C. Sudden firewall errors', 'D. Inaccurate DNS resolution'],
        'correct': 'b'
    },

    {
        'question': 'Which term describes the process of transforming readable data into an unreadable format?',
        'answer': 'Encryption is the process of converting plaintext into ciphertext to protect data confidentiality.',
        'options': ['A. Hashing', 'B. Signing', 'C. Encryption', 'D. Encoding'],
        'correct': 'c'
    },

    {
        'question': 'What is steganography primarily used for?',
        'answer': 'Steganography hides data within other files, like images or audio, to conceal its existence.',
        'options': ['A. Encrypt data with AES', 'B. Perform digital forensics',
                    'C. Hide data within other files', 'D. Split data into blocks'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following is used to ensure availability in the CIA triad?',
        'answer': 'Load balancing distributes traffic across servers, reducing downtime and ensuring availability.',
        'options': ['A. Load balancing', 'B. File encryption', 'C. Audit logging', 'D. Packet sniffing'],
        'correct': 'a'
    },

    {
        'question': 'Which of the following security measures is designed to identify unauthorized changes to files?',
        'answer': 'File integrity monitoring detects unauthorized modifications to critical system files.',
        'options': ['A. IDS', 'B. Firewall', 'C. File integrity monitoring', 'D. DLP'],
        'correct': 'c'
    },

    {
        'question': 'What is the role of SAML in access control?',
        'answer': 'SAML allows for federated identity management by enabling single sign-on (SSO) between identity '
                  'providers and service providers.',
        'options': ['A. Encrypts SSL traffic', 'B. Provides password rotation',
                    'C. Enables SSO via identity federation', 'D. Logs unauthorized access'],
        'correct': 'c'
    },

    {
        'question': 'Which of the following provides the most comprehensive visibility into security events?',
        'answer': 'SIEM systems collect, correlate, and analyze logs from multiple sources to give a centralized view '
                  'of security events.',
        'options': ['A. VPN', 'B. SIEM', 'C. HIPS', 'D. DLP'],
        'correct': 'b'
    },

    {
        'question': 'What security principle ensures that users only have the access necessary to perform their job '
                    'functions?',
        'answer': 'The principle of least privilege limits user access rights to only what is required to perform their'
                  ' duties, reducing the risk of misuse.',
        'options': ['A. Job Rotation', 'B. Need to Know', 'C. Least Privilege', 'D. Separation of Duties'],
        'correct': 'c'
    },

    {
        'question': 'Which type of physical security control uses biometrics to verify identity?',
        'answer': 'A biometric lock uses characteristics like fingerprints or retinal scans to authenticate a user, '
                  'making it harder to forge than a key or card.',
        'options': ['A. Keypad lock', 'B. Swipe card', 'C. Biometric scanner', 'D. Security camera'],
        'correct': 'c'
    },

    {
        'question': 'What is the main function of a data loss prevention (DLP) system?',
        'answer': 'DLP systems monitor and prevent unauthorized data transfers to protect sensitive information from '
                  'being leaked or stolen.',
        'options': ['A. Firewall configuration', 'B. Email filtering',
                    'C. Data Loss Prevention', 'D. Patch management'],
        'correct': 'c'
    },

    {
        'question': 'Which cloud service model provides hardware and networking resources to users?',
        'answer': 'IaaS (Infrastructure as a Service) provides virtualized computing infrastructure over the internet, '
                  'such as servers and networking.',
        'options': ['A. SaaS', 'B. PaaS', 'C. IaaS', 'D. DRaaS'],
        'correct': 'c'
    },

    {
        'question': 'What type of attack involves intercepting and potentially altering communication between two '
                    'parties?',
        'answer': 'A Man-in-the-Middle (MitM) attack secretly relays and possibly alters communication between two '
                  'parties.',
        'options': ['A. DDoS', 'B. Man-in-the-Middle', 'C. Buffer Overflow', 'D. Replay Attack'],
        'correct': 'b'
    },

    {
        'question': 'Which of the following refers to unauthorized data leaving the organization’s network?',
        'answer': 'Data exfiltration is the unauthorized transfer of data from a system, often associated with a data '
                  'breach or malware.',
        'options': ['A. Data Degaussing', 'B. Data Masking', 'C. Data Exfiltration', 'D. Data Sanitization'],
        'correct': 'c'
    },

    {
        'question': 'Which control type is an air gap considered?',
        'answer': 'An air gap is a physical security control that ensures a system is isolated and not connected to '
                  'any other networks.',
        'options': ['A. Detective', 'B. Corrective', 'C. Preventive', 'D. Compensating'],
        'correct': 'c'
    },

    {
        'question': 'What is the goal of a tabletop exercise in incident response?',
        'answer': 'Tabletop exercises simulate emergency scenarios to test incident response plans without impacting '
                  'actual systems.',
        'options': ['A. Test physical locks', 'B. Simulate live hacks',
                    'C. Practice incident response', 'D. Audit server logs'],
        'correct': 'c'
    },

    {
        'question': 'Which technology uses GPS or Wi-Fi location to enforce access control?',
        'answer': 'Geofencing uses geographic boundaries to control access to systems or data depending on user'
                  ' location.',
        'options': ['A. Beaconing', 'B. Geofencing', 'C. Triangulation', 'D. Network zoning'],
        'correct': 'b'
    },

    {
        'question': 'What is an embedded system in cybersecurity?',
        'answer': 'An embedded system is a dedicated computer system within a larger device, often with limited '
                  'computing power and tailored security needs.',
        'options': ['A. Mainframe', 'B. Virtual Machine', 'C. Embedded System', 'D. Workstation'],
        'correct': 'c'
    },

    {
        'question': 'Which security approach focuses on securing systems even if they are compromised?',
        'answer': 'Zero Trust assumes no system is inherently trusted, requiring strict identity verification and'
                  ' continuous monitoring.',
        'options': ['A. Open Trust', 'B. Default Deny', 'C. Zero Trust', 'D. Passive Security'],
        'correct': 'c'
    },

    {
        'question': 'What does the CIA triad stand for in information security?',
        'answer': 'Confidentiality, Integrity, and Availability form the core principles of information security.',
        'options': ['A. Code, Identity, Access', 'B. Confidentiality, Integrity, Availability',
                    'C. Compliance, Inspection, Accountability', 'D. Control, Isolation, Authentication'],
        'correct': 'b'
    },

    {
        'question': 'What type of backup copies only files that changed since the last full backup?',
        'answer': 'An incremental backup stores only data changed since the last full or incremental backup,'
                  ' optimizing storage.',
        'options': ['A. Full Backup', 'B. Differential Backup', 'C. Incremental Backup', 'D. Snapshot'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of tokenization in data protection?',
        'answer': 'Tokenization replaces sensitive data with a non-sensitive equivalent (token), reducing risk during '
                  'storage or transmission.',
        'options': ['A. Encrypting data', 'B. Generating passwords', 'C. Hashing data', 'D. Tokenization'],
        'correct': 'd'
    },

    {
        'question': 'Which protocol is primarily used to secure emails?',
        'answer': 'S/MIME (Secure/Multipurpose Internet Mail Extensions) provides encryption and digital signing for'
                  ' secure email communication.',
        'options': ['A. HTTPS', 'B. S/MIME', 'C. FTP', 'D. SSH'],
        'correct': 'b'
    },

    {
        'question': 'Which cybersecurity law mandates breach notification in the healthcare sector?',
        'answer': 'HIPAA requires organizations to notify affected individuals and regulators of data breaches '
                  'involving health information.',
        'options': ['A. PCI DSS', 'B. SOX', 'C. GDPR', 'D. HIPAA'],
        'correct': 'd'
    },

    {
        'question': 'Which type of attack is specifically designed to use up all resources of a system to crash it?',
        'answer': 'A DoS (Denial of Service) attack floods a system with traffic or requests, exhausting its resources '
                  'and causing it to crash.',
        'options': ['A. Spoofing', 'B. Brute Force', 'C. DoS', 'D. Phishing'],
        'correct': 'c'
    },

    {
        'question': 'What is the goal of red team exercises in cybersecurity?',
        'answer': 'Red teams simulate real-world attackers to test an organization’s detection and response '
                  'capabilities.',
        'options': ['A. Improve compliance', 'B. Review documentation',
                    'C. Simulate attackers', 'D. Conduct user training'],
        'correct': 'c'
    },

    {
        'question': 'Which attack leverages weaknesses in Bluetooth connections to gain access to a device?',
        'answer': 'Bluejacking and Bluesnarfing exploit Bluetooth vulnerabilities to send unsolicited messages or '
                  'steal data.',
        'options': ['A. Bluejacking', 'B. Smishing', 'C. Doxxing', 'D. Vishing'],
        'correct': 'a'
    },

    {
        'question': 'Which network device monitors for malicious activity and can block it in real time?',
        'answer': 'An Intrusion Prevention System (IPS) actively monitors and blocks malicious activity as it occurs.',
        'options': ['A. IDS', 'B. IPS', 'C. Firewall', 'D. Router'],
        'correct': 'b'
    },

    {
        'question': 'Which control type is implemented after a security event has occurred?',
        'answer': 'Corrective controls are used after an incident to reduce its impact and restore normal operations.',
        'options': ['A. Detective', 'B. Preventive', 'C. Corrective', 'D. Deterrent'],
        'correct': 'c'
    },

    {
        'question': 'Which concept describes hiding internal IP addresses from the external network?',
        'answer': 'NAT (Network Address Translation) masks internal IP addresses by using a public IP, improving '
                  'security.',
        'options': ['A. DHCP', 'B. ARP', 'C. NAT', 'D. DNS'],
        'correct': 'c'
    },

    {
        'question': 'What does hashing provide in cybersecurity?',
        'answer': 'Hashing ensures data integrity by generating a unique fixed-size value based on the original '
                  'input data.',
        'options': ['A. Encryption', 'B. Steganography', 'C. Integrity', 'D. Obfuscation'],
        'correct': 'c'
    },

    {
        'question': 'Which cybersecurity framework was developed by NIST for managing risk?',
        'answer': 'The NIST Cybersecurity Framework provides guidelines to help organizations manage and reduce '
                  'cybersecurity risk.',
        'options': ['A. ISO 27001', 'B. COBIT', 'C. NIST CSF', 'D. SOC 2'],
        'correct': 'c'
    },

    {
        'question': 'What does the principle of "least functionality" refer to in system security?',
        'answer': 'It means configuring systems to run only the functions necessary for business purposes, reducing'
                  ' attack surfaces.',
        'options': ['A. Allowing admin access by default', 'B. Disabling firewall for speed',
                    'C. Running all possible services', 'D. Limiting system features to necessary ones'],
        'correct': 'd'
    },

    {
        'question': 'What is the function of a hardware security module (HSM)?',
        'answer': 'An HSM securely stores and manages cryptographic keys and performs encryption operations in '
                  'hardware.',
        'options': ['A. Block malicious IPs', 'B. Store public Wi-Fi credentials',
                    'C. Securely manage cryptographic keys', 'D. Monitor server uptime'],
        'correct': 'c'
    },

    {
        'question': 'Which attack manipulates DNS records to redirect users to malicious sites?',
        'answer': 'DNS poisoning alters DNS data so that users are redirected to fraudulent websites.',
        'options': ['A. Smurf attack', 'B. DNS poisoning', 'C. Buffer overflow', 'D. Port scanning'],
        'correct': 'b'
    },

    {
        'question': 'What is a cold site in disaster recovery?',
        'answer': 'A cold site is a backup facility with minimal equipment and no immediate operational capability.',
        'options': ['A. Fully operational backup center', 'B. Facility with no equipment or data',
                    'C. Data-only storage site', 'D. An instantly usable offsite location'],
        'correct': 'b'
    },

    {
        'question': 'Which access control model is based on pre-defined rules set by a central authority?',
        'answer': 'Mandatory Access Control (MAC) is rule-based and strictly enforced by a central authority.',
        'options': ['A. Role-Based Access Control', 'B. Discretionary Access Control',
                    'C. Mandatory Access Control', 'D. Attribute-Based Access Control'],
        'correct': 'c'
    },

    {
        'question': 'What does geofencing use to trigger security controls?',
        'answer': 'Geofencing uses GPS or RFID to define virtual boundaries and trigger actions when those are'
                  ' crossed.',
        'options': ['A. Biometric data', 'B. Port scanning', 'C. IP range only', 'D. GPS-defined virtual perimeters'],
        'correct': 'd'
    },

    {
        'question': 'Which type of malware encrypts a victim’s data and demands payment?',
        'answer': 'Ransomware locks user files via encryption and demands a ransom to restore access.',
        'options': ['A. Spyware', 'B. Worm', 'C. Ransomware', 'D. Rootkit'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of a null session in network security?',
        'answer': 'Null sessions allow anonymous connections to Windows systems and can be exploited if not disabled.',
        'options': ['A. Encrypt network sessions', 'B. Initiate secure VPNs',
                    'C. Allow unauthorized access via anonymous connections', 'D. Scan for system uptime'],
        'correct': 'c'
    },

    {
        'question': 'Which technology is used to detect unauthorized changes in system files?',
        'answer': 'File integrity monitoring (FIM) detects and alerts on unauthorized changes to files.',
        'options': ['A. Data loss prevention', 'B. File integrity monitoring',
                    'C. Endpoint encryption', 'D. Web filtering'],
        'correct': 'b'
    },

    {
        'question': 'What is the role of a jump server in secure network architecture?',
        'answer': 'A jump server is a hardened system used to access and manage devices in a separate security zone.',
        'options': ['A. Transmit jump-start packets', 'B. Enforce encryption policies',
                    'C. Serve as a proxy for public web traffic', 'D. Provide controlled access to segmented systems'],
        'correct': 'd'
    },

    {
        'question': 'Which authentication factor category does a retina scan belong to?',
        'answer': 'A retina scan is a biometric and falls under "something you are."',
        'options': ['A. Something you have', 'B. Something you know', 'C. Something you are', 'D. Somewhere you are'],
        'correct': 'c'
    },

    {
        'question': 'Which term describes verifying a digital message’s origin and integrity?',
        'answer': 'A digital signature confirms the message came from the sender and hasn’t been altered.',
        'options': ['A. Firewall', 'B. Digital certificate', 'C. Digital signature', 'D. VPN tunnel'],
        'correct': 'c'
    },

    {
        'question': 'Which component in PKI issues digital certificates?',
        'answer': 'A Certificate Authority (CA) issues and manages digital certificates in PKI.',
        'options': ['A. Token server', 'B. Certificate Authority', 'C. Hash generator', 'D. Authentication proxy'],
        'correct': 'b'
    },

    {
        'question': 'What does endpoint detection and response (EDR) primarily focus on?',
        'answer': 'EDR monitors and responds to threats on individual endpoints in real time.',
        'options': ['A. Encrypt network data', 'B. Patch operating systems',
                    'C. Detect endpoint threats and respond', 'D. Balance network load'],
        'correct': 'c'
    },

    {
        'question': 'What is a logic bomb in cybersecurity?',
        'answer': 'A logic bomb is code that triggers a malicious action when specific conditions are met.',
        'options': ['A. Encrypted virus', 'B. Unpatched vulnerability',
                    'C. Time-triggered malware', 'D. Unauthorized firmware'],
        'correct': 'c'
    },

    {
        'question': 'Why are rootkits difficult to detect?',
        'answer': 'Rootkits operate at the kernel level, hiding their presence from standard detection tools.',
        'options': ['A. Use encrypted connections', 'B. Change user permissions',
                    'C. Hide in plain sight at OS kernel level', 'D. Attack DNS records'],
        'correct': 'c'
    },

    {
        'question': 'Which type of attack tricks users into entering sensitive information on a fake site?',
        'answer': 'Pharming redirects users to a fake website that looks legitimate to steal credentials.',
        'options': ['A. DDoS', 'B. Brute force', 'C. Pharming', 'D. Port scanning'],
        'correct': 'c'
    },

    {
        'question': 'Which method ensures that only intended recipients can read a transmitted message?',
        'answer': 'Encryption protects message confidentiality during transmission.',
        'options': ['A. Hashing', 'B. Encryption', 'C. Port blocking', 'D. Firewall rules'],
        'correct': 'b'
    },

    {
        'question': 'What is a primary feature of secure boot?',
        'answer': 'Secure boot ensures only trusted software is executed during startup.',
        'options': ['A. Encrypts hard drives', 'B. Blocks booting from USB',
                    'C. Verifies digital signatures of bootloaders', 'D. Logs failed boot attempts'],
        'correct': 'c'
    },

    {
        'question': 'Which backup method copies only files that have changed since the last backup of any type?',
        'answer': 'Incremental backups save storage by copying only changed files since the last backup.',
        'options': ['A. Differential', 'B. Full', 'C. Incremental', 'D. Redundant'],
        'correct': 'c'
    },

    {
        'question': 'What is the main purpose of a mantrap in physical security?',
        'answer': 'A mantrap controls access by requiring authentication at two points, preventing piggybacking.',
        'options': ['A. Boost signal', 'B. Prevent malware injection',
                    'C. Monitor power usage', 'D. Control physical entry'],
        'correct': 'd'
    },

    {
        'question': 'Which protocol is used for securely logging into remote systems?',
        'answer': 'SSH provides secure encrypted communication for remote login.',
        'options': ['A. FTP', 'B. RDP', 'C. SSH', 'D. Telnet'],
        'correct': 'c'
    },

    {
        'question': 'Which type of attack relies on overwhelming a system with traffic to make it unavailable?',
        'answer': 'A DDoS attack floods a system with traffic to make it unavailable to legitimate users.',
        'options': ['A. Zero-day', 'B. DDoS', 'C. Logic bomb', 'D. SQL injection'],
        'correct': 'b'
    },

    {
        'question': 'Which concept ensures that an action or change can be traced to an individual?',
        'answer': 'Non-repudiation provides proof of action, preventing denial by the originator.',
        'options': ['A. Obfuscation', 'B. Confidentiality', 'C. Least privilege', 'D. Non-repudiation'],
        'correct': 'd'
    },

    {
        'question': 'What is the primary purpose of a honeypot in cybersecurity?',
        'answer': 'A honeypot is used to detect and analyze intrusion attempts by acting as a decoy system for'
                  ' attackers.',
        'options': ['A. Store backup data', 'B. Attract and analyze malicious activity',
                    'C. Authenticate users', 'D. Encrypt sensitive information'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol is used to securely synchronize time across network devices?',
        'answer': 'Network Time Protocol (NTP) ensures accurate time synchronization across devices.',
        'options': ['A. FTP', 'B. NTP', 'C. SMTP', 'D. SNMP'],
        'correct': 'b'
    },

    {
        'question': 'What is the function of a sandbox in malware analysis?',
        'answer': 'A sandbox provides an isolated environment to safely execute and analyze suspicious code.',
        'options': ['A. Encrypts data', 'B. Isolates and analyzes suspicious code',
                    'C. Manages user permissions', 'D. Monitors network traffic'],
        'correct': 'b'
    },

    {
        'question': 'Which type of attack involves intercepting and potentially altering communication between '
                    'two parties?',
        'answer': 'A man-in-the-middle attack intercepts and possibly alters communication between two parties.',
        'options': ['A. Phishing', 'B. Man-in-the-middle', 'C. Denial-of-service', 'D. Brute force'],
        'correct': 'b'
    },

    {
        'question': 'What is the primary goal of a risk assessment in information security?',
        'answer': 'To identify, evaluate, and prioritize potential threats to an organization’s assets.',
        'options': ['A. Implement firewalls', 'B. Identify and prioritize potential threats',
                    'C. Train employees', 'D. Monitor network traffic'],
        'correct': 'b'
    },

    {
        'question': 'Which security model focuses on maintaining data confidentiality and is commonly used in '
                    'government systems?',
        'answer': 'The Bell-LaPadula model emphasizes data confidentiality and access control.',
        'options': ['A. Bell-LaPadula', 'B. Biba', 'C. Clark-Wilson', 'D. Brewer-Nash'],
        'correct': 'a'
    },

    {
        'question': 'What is the purpose of a digital certificate in a PKI environment?',
        'answer': 'To associate a public key with an entity’s identity, verified by a Certificate Authority.',
        'options': ['A. Encrypt data', 'B. Verify user passwords', 'C. Associate a public key with an identity',
                    'D. Manage firewall settings'],
        'correct': 'c'
    },

    {
        'question': 'Which type of malware replicates itself to spread to other systems without user intervention?',
        'answer': 'A worm is a self-replicating malware that spreads without user action.',
        'options': ['A. Virus', 'B. Trojan', 'C. Worm', 'D. Spyware'],
        'correct': 'c'
    },

    {
        'question': 'Which authentication method uses multiple factors from different categories?',
        'answer': 'Multi-factor authentication (MFA) requires two or more authentication factors from different'
                  ' categories.',
        'options': ['A. Single sign-on', 'B. Multi-factor authentication', 'C. Biometrics', 'D. Passwords'],
        'correct': 'b'
    },

    {
        'question': 'What is the primary purpose of a security information and event management (SIEM) system?',
        'answer': 'To collect, analyze, and report on security-related data from various sources.',
        'options': ['A. Manage user accounts', 'B. Collect and analyze security data',
                    'C. Encrypt sensitive files', 'D. Monitor physical access'],
        'correct': 'b'
    },

    {
        'question': 'Which type of social engineering attack involves leaving infected USB drives in public places?',
        'answer': 'Baiting involves leaving malicious devices to exploit human curiosity.',
        'options': ['A. Phishing', 'B. Baiting', 'C. Pretexting', 'D. Tailgating'],
        'correct': 'b'
    },

    {
        'question': 'What is the function of a certificate revocation list (CRL)?',
        'answer': 'A CRL lists digital certificates that have been revoked before their expiration dates.',
        'options': ['A. Issue new certificates', 'B. Store user passwords',
                    'C. List revoked digital certificates', 'D. Encrypt email messages'],
        'correct': 'c'
    },

    {
        'question': 'Which security principle ensures that users have only the access necessary to perform their '
                    'job functions?',
        'answer': 'The principle of least privilege restricts user access rights to the minimum necessary.',
        'options': ['A. Separation of duties', 'B. Least privilege', 'C. Need to know', 'D. Role-based access'],
        'correct': 'b'
    },

    {
        'question': 'What is the purpose of a vulnerability scanner?',
        'answer': 'To identify and report on known vulnerabilities in systems and applications.',
        'options': ['A. Encrypt data', 'B. Identify known vulnerabilities',
                    'C. Monitor user activity', 'D. Manage firewall rules'],
        'correct': 'b'
    },

    {
        'question': 'Which type of attack involves overwhelming a system with traffic to render it unavailable?',
        'answer': 'A denial-of-service (DoS) attack floods a system with traffic to disrupt services.',
        'options': ['A. Phishing', 'B. Denial-of-service', 'C. Man-in-the-middle', 'D. SQL injection'],
        'correct': 'b'
    },

    {
        'question': 'What is the primary function of a firewall in network security?',
        'answer': 'To monitor and control incoming and outgoing network traffic based on security rules.',
        'options': ['A. Encrypt data', 'B. Monitor employee activity',
                    'C. Control network traffic based on rules', 'D. Store backup files'],
        'correct': 'c'
    },

    {
        'question': 'Which type of backup captures all selected data regardless of previous backups?',
        'answer': 'A full backup copies all selected data every time it is performed.',
        'options': ['A. Incremental', 'B. Differential', 'C. Full', 'D. Snapshot'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of a security baseline?',
        'answer': 'To provide a set of minimum security standards for systems and applications.',
        'options': ['A. Encrypt data', 'B. Set minimum security standards',
                    'C. Monitor network traffic', 'D. Manage user accounts'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol is commonly used to secure email communications?',
        'answer': 'Secure/Multipurpose Internet Mail Extensions (S/MIME) is used to secure email messages.',
        'options': ['A. FTP', 'B. S/MIME', 'C. HTTP', 'D. SNMP'],
        'correct': 'b'
    },

    {
        'question': 'What is the function of a proxy server in network security?',
        'answer': 'A proxy server acts as an intermediary between clients and servers to filter requests.',
        'options': ['A. Store backup data', 'B. Encrypt files',
                    'C. Filter client requests', 'D. Monitor physical access'],
        'correct': 'c'
    },

    {
        'question': 'Which type of malware is designed to provide unauthorized access to a user’s system?',
        'answer': 'A backdoor allows unauthorized access to a system, bypassing normal authentication.',
        'options': ['A. Virus', 'B. Worm', 'C. Backdoor', 'D. Spyware'],
        'correct': 'c'
    },

    {
        'question': 'What is the purpose of a security audit?',
        'answer': 'To evaluate an organization’s adherence to security policies and procedures.',
        'options': ['A. Encrypt data', 'B. Evaluate adherence to security policies',
                    'C. Monitor network traffic', 'D. Manage user accounts'],
        'correct': 'b'
    },

    {
        'question': 'Which type of control is implemented to reduce the impact of a security incident?',
        'answer': 'Corrective controls are designed to reduce the impact of an incident.',
        'options': ['A. Preventive', 'B. Detective', 'C. Corrective', 'D. Deterrent'],
        'correct': 'c'
    },

    {
        'question': 'What is the function of a security token in authentication?',
        'answer': 'A security token provides a one-time password or code for user authentication.',
        'options': ['A. Encrypt data', 'B. Provide one-time passwords',
                    'C. Monitor user activity', 'D. Store backup files'],
        'correct': 'b'
    },

    {
        'question': 'What service typically uses TCP port 21?',
        'answer': 'TCP port 21 is used by FTP (File Transfer Protocol) for control commands during file transfers.',
        'options': ['A. SSH', 'B. FTP', 'C. Telnet', 'D. SMTP'],
        'correct': 'b'
    },

    {
        'question': 'Which port number is used by DNS for resolving domain names?',
        'answer': 'DNS primarily uses UDP port 53 to resolve hostnames to IP addresses.',
        'options': ['A. 25', 'B. 53', 'C. 80', 'D. 110'],
        'correct': 'b'
    },

    {
        'question': 'What service runs on TCP port 22 and is used for secure remote login?',
        'answer': 'TCP port 22 is used by SSH (Secure Shell) for encrypted remote command-line access.',
        'options': ['A. FTP', 'B. RDP', 'C. SSH', 'D. Telnet'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol commonly uses TCP port 23 for unencrypted remote sessions?',
        'answer': 'Telnet uses TCP port 23 to provide command-line access without encryption.',
        'options': ['A. SSH', 'B. Telnet', 'C. FTP', 'D. SNMP'],
        'correct': 'b'
    },

    {
        'question': 'Which port is typically used by SMTP to send email?',
        'answer': 'SMTP uses TCP port 25 for sending email between mail servers.',
        'options': ['A. 25', 'B. 143', 'C. 110', 'D. 69'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses TCP port 80 for delivering web pages?',
        'answer': 'HTTP uses TCP port 80 as the standard port for web traffic.',
        'options': ['A. HTTPS', 'B. FTP', 'C. HTTP', 'D. POP3'],
        'correct': 'c'
    },

    {
        'question': 'What port does HTTPS use to provide secure web communication?',
        'answer': 'HTTPS uses TCP port 443 to encrypt HTTP traffic using SSL/TLS.',
        'options': ['A. 80', 'B. 22', 'C. 443', 'D. 110'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by POP3 for receiving email?',
        'answer': 'POP3 uses TCP port 110 to allow clients to download emails from a server.',
        'options': ['A. 993', 'B. 110', 'C. 25', 'D. 995'],
        'correct': 'b'
    },

    {
        'question': 'What port number is used by IMAP?',
        'answer': 'IMAP uses TCP port 143 to allow clients to access and manage their email on the server.',
        'options': ['A. 110', 'B. 143', 'C. 25', 'D. 69'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses port 69 and operates without a connection?',
        'answer': 'TFTP uses UDP port 69 and is a simplified version of FTP without authentication or encryption.',
        'options': ['A. FTP', 'B. SFTP', 'C. TFTP', 'D. Telnet'],
        'correct': 'c'
    },

    {
        'question': 'Which port is commonly used by LDAP for directory services?',
        'answer': 'LDAP uses TCP port 389 for unencrypted access to directory services.',
        'options': ['A. 636', 'B. 389', 'C. 25', 'D. 3389'],
        'correct': 'b'
    },

    {
        'question': 'What protocol uses TCP port 3389 for remote desktop connections?',
        'answer': 'RDP (Remote Desktop Protocol) uses TCP port 3389 to allow remote access to Windows desktops.',
        'options': ['A. SSH', 'B. RDP', 'C. VNC', 'D. SNMP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses UDP port 161 for monitoring network devices?',
        'answer': 'SNMP uses UDP port 161 for gathering and organizing information about managed devices.',
        'options': ['A. SMTP', 'B. SNMP', 'C. FTP', 'D. IMAP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 445 for file sharing on Windows networks?',
        'answer': 'SMB (Server Message Block) uses TCP port 445 for file and printer sharing on Windows systems.',
        'options': ['A. SMB', 'B. FTP', 'C. RDP', 'D. HTTP'],
        'correct': 'a'
    },

    {
        'question': 'Which port is used by NetBIOS for session services?',
        'answer': 'NetBIOS Session Service typically runs on TCP port 139 for Windows file and printer sharing.',
        'options': ['A. 135', 'B. 139', 'C. 445', 'D. 161'],
        'correct': 'b'
    },

    {
        'question': 'Which service uses TCP port 135 for remote procedure calls?',
        'answer': 'TCP port 135 is used by Microsoft RPC (Remote Procedure Call) for managing DCOM services.',
        'options': ['A. SMB', 'B. RPC', 'C. SNMP', 'D. Telnet'],
        'correct': 'b'
    },

    {
        'question': 'Which port is used by LDAPS for secure directory access?',
        'answer': 'LDAPS uses TCP port 636 to provide encrypted access to directory services.',
        'options': ['A. 389', 'B. 636', 'C. 443', 'D. 53'],
        'correct': 'b'
    },

    {
        'question': 'What service uses TCP port 514 for remote log collection?',
        'answer': 'Syslog uses TCP or UDP port 514 for sending event notification messages across a network.',
        'options': ['A. SNMP', 'B. Syslog', 'C. LDAP', 'D. NTP'],
        'correct': 'b'
    },

    {
        'question': 'What protocol uses UDP port 123 to synchronize time across systems?',
        'answer': 'NTP (Network Time Protocol) uses UDP port 123 to sync clocks over packet-switched networks.',
        'options': ['A. SNTP', 'B. FTP', 'C. NTP', 'D. SMTP'],
        'correct': 'c'
    },

    {
        'question': 'Which port is associated with the BOOTP/DHCP server protocol?',
        'answer': 'BOOTP and DHCP servers typically use UDP port 67 to receive client requests for IP configuration.',
        'options': ['A. 68', 'B. 67', 'C. 53', 'D. 161'],
        'correct': 'b'
    },

    {
        'question': 'Which port is used by the DHCP client to receive responses from the server?',
        'answer': 'UDP port 68 is used by DHCP clients to receive configuration responses from servers.',
        'options': ['A. 68', 'B. 67', 'C. 53', 'D. 139'],
        'correct': 'a'
    },

    {
        'question': 'What protocol operates on TCP port 514 for remote shell access?',
        'answer': 'RSH (Remote Shell) uses TCP port 514 for executing shell commands on remote machines.',
        'options': ['A. Telnet', 'B. SSH', 'C. RSH', 'D. FTP'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by the NNTP protocol to distribute news articles?',
        'answer': 'NNTP (Network News Transfer Protocol) uses TCP port 119 for newsgroup communications.',
        'options': ['A. 110', 'B. 119', 'C. 143', 'D. 25'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 989 for secure FTP data transfer?',
        'answer': 'FTPS (FTP Secure) uses TCP port 989 for encrypted data channel communication.',
        'options': ['A. SFTP', 'B. FTPS', 'C. TFTP', 'D. Telnet'],
        'correct': 'b'
    },

    {
        'question': 'Which port is used by HTTPS alternate secure traffic (commonly on proxies)?',
        'answer': 'TCP port 8443 is often used as an alternative to 443 for HTTPS traffic, especially on proxy setups.',
        'options': ['A. 443', 'B. 8443', 'C. 80', 'D. 22'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 20 for data transfer?',
        'answer': 'FTP uses TCP port 20 for data transfer, separate from its control commands on port 21.',
        'options': ['A. FTP', 'B. TFTP', 'C. SFTP', 'D. SCP'],
        'correct': 'a'
    },

    {
        'question': 'What port number is used by the Kerberos authentication protocol?',
        'answer': 'Kerberos uses TCP and UDP port 88 for authentication services.',
        'options': ['A. 88', 'B. 110', 'C. 143', 'D. 389'],
        'correct': 'a'
    },

    {
        'question': 'Which service uses UDP port 123?',
        'answer': 'NTP (Network Time Protocol) uses UDP port 123 to synchronize clocks over a network.',
        'options': ['A. NTP', 'B. SNMP', 'C. FTP', 'D. SMTP'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses TCP port 119 for retrieving newsgroup articles?',
        'answer': 'NNTP (Network News Transfer Protocol) uses TCP port 119 for reading and posting Usenet articles.',
        'options': ['A. NNTP', 'B. SMTP', 'C. POP3', 'D. IMAP'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses UDP port 161 for network management?',
        'answer': 'SNMP (Simple Network Management Protocol) uses UDP port 161 for monitoring network devices.',
        'options': ['A. SNMP', 'B. SMTP', 'C. FTP', 'D. IMAP'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses TCP port 514 for remote shell access?',
        'answer': 'RSH (Remote Shell) uses TCP port 514 to execute shell commands on remote machines.',
        'options': ['A. Telnet', 'B. SSH', 'C. RSH', 'D. FTP'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by the NetBIOS Name Service?',
        'answer': 'NetBIOS Name Service uses UDP port 137 to register and resolve NetBIOS names.',
        'options': ['A. 137', 'B. 138', 'C. 139', 'D. 445'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses TCP port 179 for routing information exchange?',
        'answer': 'BGP (Border Gateway Protocol) uses TCP port 179 to exchange routing information between systems.',
        'options': ['A. OSPF', 'B. RIP', 'C. BGP', 'D. EIGRP'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by the Internet Printing Protocol (IPP)?',
        'answer': 'IPP uses TCP port 631 for network printing services.',
        'options': ['A. 515', 'B. 631', 'C. 9100', 'D. 25'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 993 for secure email retrieval?',
        'answer': 'IMAPS (IMAP over SSL) uses TCP port 993 to securely retrieve emails.',
        'options': ['A. POP3S', 'B. IMAPS', 'C. SMTP', 'D. HTTP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 995 for secure email retrieval?',
        'answer': 'POP3S (POP3 over SSL) uses TCP port 995 to securely retrieve emails.',
        'options': ['A. POP3S', 'B. IMAPS', 'C. SMTP', 'D. HTTP'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses UDP port 69 for file transfers?',
        'answer': 'TFTP (Trivial File Transfer Protocol) uses UDP port 69 for simple file transfers.',
        'options': ['A. FTP', 'B. TFTP', 'C. SFTP', 'D. SCP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 636 for secure directory services?',
        'answer': 'LDAPS (LDAP over SSL) uses TCP port 636 for encrypted directory services.',
        'options': ['A. LDAP', 'B. LDAPS', 'C. SMB', 'D. RDP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 443 for secure web traffic?',
        'answer': 'HTTPS uses TCP port 443 to encrypt HTTP traffic using SSL/TLS.',
        'options': ['A. HTTP', 'B. FTP', 'C. HTTPS', 'D. SSH'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol uses TCP port 80 for web traffic?',
        'answer': 'HTTP uses TCP port 80 as the standard port for web traffic.',
        'options': ['A. HTTPS', 'B. FTP', 'C. HTTP', 'D. POP3'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol uses TCP port 23 for unencrypted remote sessions?',
        'answer': 'Telnet uses TCP port 23 to provide command-line access without encryption.',
        'options': ['A. SSH', 'B. Telnet', 'C. FTP', 'D. SNMP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 22 for secure remote login?',
        'answer': 'SSH (Secure Shell) uses TCP port 22 for encrypted remote command-line access.',
        'options': ['A. FTP', 'B. RDP', 'C. SSH', 'D. Telnet'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol uses TCP port 21 for control commands during file transfers?',
        'answer': 'FTP uses TCP port 21 for control commands during file transfers.',
        'options': ['A. SSH', 'B. FTP', 'C. Telnet', 'D. SMTP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 25 for sending email?',
        'answer': 'SMTP uses TCP port 25 for sending email between mail servers.',
        'options': ['A. SMTP', 'B. SNMP', 'C. POP', 'D. POP3'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses TCP port 110 for receiving email?',
        'answer': 'POP3 uses TCP port 110 to allow clients to download emails from a server.',
        'options': ['A. 993', 'B. 110', 'C. 25', 'D. 995'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 143 for accessing and managing email on the server?',
        'answer': 'IMAP uses TCP port 143 to allow clients to access and manage their email on the server.',
        'options': ['A. 110', 'B. 143', 'C. 25', 'D. 69'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 3389 for remote desktop connections?',
        'answer': 'RDP (Remote Desktop Protocol) uses TCP port 3389 to allow remote access to Windows desktops.',
        'options': ['A. SSH', 'B. RDP', 'C. VNC', 'D. SNMP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 445 for file and printer sharing on Windows systems?',
        'answer': 'SMB (Server Message Block) uses TCP port 445 for file and printer sharing on Windows systems.',
        'options': ['A. SMB', 'B. FTP', 'C. RDP', 'D. HTTP'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses TCP port 135 for remote procedure calls?',
        'answer': 'TCP port 135 is used by Microsoft RPC (Remote Procedure Call) for managing DCOM services.',
        'options': ['A. SMB', 'B. RPC', 'C. SNMP', 'D. Telnet'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 389 for unencrypted access to directory services?',
        'answer': 'LDAP uses TCP port 389 for unencrypted access to directory services.',
        'options': ['A. FTPS', 'B. LDAP', 'C. SNMP', 'D. RDP'],
        'correct': 'b'
    },

    {
        'question': 'Which service uses TCP port 23 by default?',
        'answer': 'Telnet uses TCP port 23 for remote command-line access, though it is considered insecure due to '
                  'lack of encryption.',
        'options': ['A. SSH', 'B. FTP', 'C. Telnet', 'D. RDP'],
        'correct': 'c'
    },

    {
        'question': 'What port does the POP3 email retrieval protocol typically use?',
        'answer': 'POP3 typically uses TCP port 110 to retrieve emails from a server.',
        'options': ['A. 143', 'B. 110', 'C. 25', 'D. 993'],
        'correct': 'b'
    },

    {
        'question': 'Which port is used by HTTPS?',
        'answer': 'HTTPS uses TCP port 443 to provide secure web browsing using SSL/TLS encryption.',
        'options': ['A. 80', 'B. 21', 'C. 443', 'D. 8080'],
        'correct': 'c'
    },

    {
        'question': 'What protocol typically operates on UDP port 69?',
        'answer': 'TFTP, or Trivial File Transfer Protocol, uses UDP port 69 and offers simple file transfers'
                  ' without authentication.',
        'options': ['A. FTP', 'B. TFTP', 'C. SFTP', 'D. SCP'],
        'correct': 'b'
    },

    {
        'question': 'Which service uses TCP port 22 for secure remote access?',
        'answer': 'SSH (Secure Shell) uses TCP port 22 to allow encrypted remote login and command execution.',
        'options': ['A. Telnet', 'B. FTP', 'C. SSH', 'D. SFTP'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by the Lightweight Directory Access Protocol (LDAP)?',
        'answer': 'LDAP uses TCP port 389 for directory services like user and resource lookup.',
        'options': ['A. 636', 'B. 389', 'C. 3268', 'D. 88'],
        'correct': 'b'
    },

    {
        'question': 'What protocol runs on port 514 using UDP for sending system logs?',
        'answer': 'Syslog uses UDP port 514 to send system event messages to a logging server.',
        'options': ['A. SNMP', 'B. NTP', 'C. Syslog', 'D. LDAP'],
        'correct': 'c'
    },

    {
        'question': 'Which email protocol uses TCP port 143?',
        'answer': 'IMAP uses TCP port 143 to allow email clients to retrieve and manage emails stored on a mail'
                  ' server.',
        'options': ['A. SMTP', 'B. IMAP', 'C. POP3', 'D. MAPI'],
        'correct': 'b'
    },

    {
        'question': 'What is the default port number for DNS over TCP?',
        'answer': 'DNS can use TCP port 53 for larger queries like zone transfers, though it typically uses UDP.',
        'options': ['A. 80', 'B. 110', 'C. 443', 'D. 53'],
        'correct': 'd'
    },

    {
        'question': 'Which protocol uses port 88 and is used for authentication services?',
        'answer': 'Kerberos uses TCP and UDP port 88 to perform network authentication in secure systems.',
        'options': ['A. RADIUS', 'B. Kerberos', 'C. LDAP', 'D. TACACS+'],
        'correct': 'b'
    },

    {
        'question': 'Which service uses port 445 for file and printer sharing in Windows environments?',
        'answer': 'SMB (Server Message Block) uses TCP port 445 for direct access to file shares and printers.',
        'options': ['A. FTP', 'B. SMB', 'C. SNMP', 'D. NetBIOS'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol typically uses TCP port 3389?',
        'answer': 'Remote Desktop Protocol (RDP) uses TCP port 3389 to allow remote GUI access to Windows systems.',
        'options': ['A. VNC', 'B. RDP', 'C. SSH', 'D. Telnet'],
        'correct': 'b'
    },

    {
        'question': 'What port is used by SNMP for monitoring network devices?',
        'answer': 'SNMP uses UDP port 161 to manage and monitor networked devices like routers and switches.',
        'options': ['A. 162', 'B. 161', 'C. 514', 'D. 389'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol communicates on port 123?',
        'answer': 'NTP (Network Time Protocol) uses UDP port 123 to synchronize clocks between devices.',
        'options': ['A. SNMP', 'B. LDAP', 'C. NTP', 'D. HTTPS'],
        'correct': 'c'
    },

    {
        'question': 'Which secure email retrieval protocol uses TCP port 993?',
        'answer': 'IMAPS (IMAP Secure) uses TCP port 993 to securely retrieve emails over SSL/TLS.',
        'options': ['A. POP3S', 'B. SMTPS', 'C. IMAPS', 'D. IMAP'],
        'correct': 'c'
    },

    {
        'question': 'Which service operates on UDP port 67 and is used during IP address assignment?',
        'answer': 'DHCP uses UDP port 67 to offer IP addresses to clients on the network.',
        'options': ['A. DNS', 'B. DHCP', 'C. SNMP', 'D. TFTP'],
        'correct': 'b'
    },

    {
        'question': 'What port does the secure version of LDAP (LDAPS) use?',
        'answer': 'LDAPS uses TCP port 636 to provide encrypted LDAP directory access.',
        'options': ['A. 389', 'B. 443', 'C. 636', 'D. 993'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol uses port 20 for active mode data transfers?',
        'answer': 'FTP uses TCP port 20 for data transfer in active mode.',
        'options': ['A. TFTP', 'B. FTPS', 'C. FTP', 'D. SCP'],
        'correct': 'c'
    },

    {
        'question': 'Which port is commonly associated with secure email submission (SMTP over SSL)?',
        'answer': 'SMTP over SSL commonly uses TCP port 465 to send email securely.',
        'options': ['A. 25', 'B. 110', 'C. 465', 'D. 587'],
        'correct': 'c'
    },

    {
        'question': 'What is the default port for NetBIOS Name Service?',
        'answer': 'NetBIOS Name Service uses UDP port 137 to resolve NetBIOS names to IP addresses.',
        'options': ['A. 135', 'B. 138', 'C. 137', 'D. 139'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol uses port 514 with TCP instead of UDP?',
        'answer': 'Syslog is a standard protocol that uses UDP port 514 to send event and log messages from devices to'
                  ' a centralized logging server.',
        'options': ['A. SNMP', 'B. Syslog', 'C. NetFlow', 'D. ICMP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 548 and is primarily used on macOS systems?',
        'answer': 'Apple Filing Protocol (AFP) uses TCP port 548 for file services in macOS environments.',
        'options': ['A. SMB', 'B. AFP', 'C. NFS', 'D. FTP'],
        'correct': 'b'
    },

    {
        'question': 'Which port does Secure Copy Protocol (SCP) use?',
        'answer': 'SCP uses TCP port 22 as it operates over SSH.',
        'options': ['A. 21', 'B. 22', 'C. 69', 'D. 80'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses UDP port 161 and is often used with port 162 for traps?',
        'answer': 'SNMP uses UDP port 161 for requests and 162 for receiving trap messages.',
        'options': ['A. LDAP', 'B. SNMP', 'C. SMTP', 'D. DNS'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol is typically associated with TCP port 119 for reading newsgroups?',
        'answer': 'NNTP (Network News Transfer Protocol) uses TCP port 119 to read and post to Usenet newsgroups.',
        'options': ['A. SMTP', 'B. IMAP', 'C. NNTP', 'D. SNMP'],
        'correct': 'c'
    },

    {
        'question': 'Which service uses TCP port 25 by default?',
        'answer': 'SMTP (Simple Mail Transfer Protocol) uses TCP port 25 for sending emails.',
        'options': ['A. POP3', 'B. SMTP', 'C. IMAP', 'D. SNMP'],
        'correct': 'b'
    },

    {
        'question': 'What port number is assigned to the WHOIS protocol?',
        'answer': 'WHOIS uses TCP port 43 to query domain name information.',
        'options': ['A. 43', 'B. 53', 'C. 63', 'D. 73'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol operates on UDP port 161 for network management?',
        'answer': 'SNMP (Simple Network Management Protocol) uses UDP port 161 for managing devices on IP networks.',
        'options': ['A. SNMP', 'B. SMTP', 'C. FTP', 'D. Telnet'],
        'correct': 'a'
    },

    {
        'question': 'What service runs on TCP port 80?',
        'answer': 'HTTP (Hypertext Transfer Protocol) uses TCP port 80 for web traffic.',
        'options': ['A. HTTPS', 'B. FTP', 'C. HTTP', 'D. SSH'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol uses UDP port 67 for DHCP server communication?',
        'answer': 'DHCP servers use UDP port 67 to receive client requests for IP address assignment.',
        'options': ['A. DNS', 'B. DHCP', 'C. SNMP', 'D. TFTP'],
        'correct': 'b'
    },

    {
        'question': 'What port does the NetBIOS Name Service use?',
        'answer': 'NetBIOS Name Service uses UDP port 137 for name resolution.',
        'options': ['A. 137', 'B. 138', 'C. 139', 'D. 140'],
        'correct': 'a'
    },

    {
        'question': 'Which service operates on TCP port 443?',
        'answer': 'HTTPS (Hypertext Transfer Protocol Secure) uses TCP port 443 for secure web traffic.',
        'options': ['A. HTTP', 'B. FTP', 'C. HTTPS', 'D. SSH'],
        'correct': 'c'
    },

    {
        'question': 'What protocol uses TCP port 110 for email retrieval?',
        'answer': 'POP3 (Post Office Protocol version 3) uses TCP port 110 to retrieve emails from a server.',
        'options': ['A. IMAP', 'B. SMTP', 'C. POP3', 'D. MAPI'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by the Kerberos authentication protocol?',
        'answer': 'Kerberos uses TCP and UDP port 88 for authentication services.',
        'options': ['A. 88', 'B. 89', 'C. 90', 'D. 91'],
        'correct': 'a'
    },

    {
        'question': 'What service uses TCP port 143?',
        'answer': 'IMAP (Internet Message Access Protocol) uses TCP port 143 for accessing email on a remote server.',
        'options': ['A. POP3', 'B. SMTP', 'C. IMAP', 'D. MAPI'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol uses UDP port 69 for simple file transfers?',
        'answer': 'TFTP (Trivial File Transfer Protocol) uses UDP port 69 for transferring files without '
                  'authentication.',
        'options': ['A. FTP', 'B. TFTP', 'C. SFTP', 'D. SCP'],
        'correct': 'b'
    },

    {
        'question': 'What port does the Secure Shell (SSH) protocol use?',
        'answer': 'SSH uses TCP port 22 for secure remote login and command execution.',
        'options': ['A. 21', 'B. 22', 'C. 23', 'D. 24'],
        'correct': 'b'
    },

    {
        'question': 'Which service operates on TCP port 21?',
        'answer': 'FTP (File Transfer Protocol) uses TCP port 21.',
        'options': ['A. FTP', 'B. TFTP', 'C. SFTP', 'D. SCP'],
        'correct': 'a'
    },

    {
        'question': 'What protocol uses UDP port 123?',
        'answer': 'NTP (Network Time Protocol) uses UDP port 123 to synchronize clocks over a network.',
        'options': ['A. SNMP', 'B. NTP', 'C. SMTP', 'D. DNS'],
        'correct': 'b'
    },

    {
        'question': 'Which port is used by the Remote Desktop Protocol (RDP)?',
        'answer': 'RDP uses TCP port 3389 to provide remote desktop access.',
        'options': ['A. 3389', 'B. 3390', 'C. 3391', 'D. 3392'],
        'correct': 'a'
    },

    {
        'question': 'What service uses TCP port 53?',
        'answer': 'DNS (Domain Name System) uses TCP port 53 for zone transfers.',
        'options': ['A. DNS', 'B. DHCP', 'C. SNMP', 'D. FTP'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses UDP port 514 for log messages?',
        'answer': 'Syslog uses UDP port 514 to send log messages to a central server.',
        'options': ['A. SNMP', 'B. Syslog', 'C. LDAP', 'D. NTP'],
        'correct': 'b'
    },

    {
        'question': 'What port is used by the Lightweight Directory Access Protocol (LDAP)?',
        'answer': 'LDAP uses TCP and UDP port 389 for directory services.',
        'options': ['A. 389', 'B. 390', 'C. 391', 'D. 392'],
        'correct': 'a'
    },

    {
        'question': 'Which service uses TCP port 445?',
        'answer': 'SMB (Server Message Block) uses TCP port 445 for file sharing over a network.',
        'options': ['A. FTP', 'B. SMB', 'C. NFS', 'D. AFP'],
        'correct': 'b'
    },

    {
        'question': 'What protocol uses TCP port 993?',
        'answer': 'IMAPS (IMAP Secure) uses TCP port 993 for secure email retrieval.',
        'options': ['A. POP3S', 'B. SMTPS', 'C. IMAPS', 'D. MAPI'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by the Secure POP3 protocol?',
        'answer': 'POP3S uses TCP port 995 for secure email retrieval.',
        'options': ['A. 993', 'B. 994', 'C. 995', 'D. 996'],
        'correct': 'c'
    },

    {
        'question': 'What service uses TCP port 587?',
        'answer': 'SMTP (Simple Mail Transfer Protocol) uses TCP port 587 for email submission with authentication.',
        'options': ['A. POP3', 'B. SMTP', 'C. IMAP', 'D. SNMP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses UDP port 162 for trap messages?',
        'answer': 'SNMP (Simple Network Management Protocol) uses UDP port 162 for receiving trap messages.',
        'options': ['A. SNMP', 'B. SMTP', 'C. FTP', 'D. Telnet'],
        'correct': 'a'
    },

    {
        'question': 'What port does the Secure LDAP (LDAPS) protocol use?',
        'answer': 'LDAPS uses TCP port 636 for secure directory services.',
        'options': ['A. 636', 'B. 637', 'C. 638', 'D. 639'],
        'correct': 'a'
    },

    {
        'question': 'Which service uses TCP port 49?',
        'answer': 'TACACS+ (Terminal Access Controller Access-Control System Plus) uses TCP port 49 for authentication '
                  'services.',
        'options': ['A. RADIUS', 'B. TACACS+', 'C. LDAP', 'D. Kerberos'],
        'correct': 'b'
    },

    {
        'question': 'Which service uses TCP port 23 by default?',
        'answer': 'Telnet uses TCP port 23 for unencrypted remote login sessions.',
        'options': ['A. SSH', 'B. Telnet', 'C. FTP', 'D. RDP'],
        'correct': 'b'
    },

    {
        'question': 'What port number is assigned to the Finger protocol?',
        'answer': 'The Finger protocol uses TCP port 79 to retrieve user information.',
        'options': ['A. 79', 'B. 89', 'C. 99', 'D. 109'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol operates on UDP port 514 for log messages?',
        'answer': 'Syslog uses UDP port 514 to send log messages to a central server.',
        'options': ['A. SNMP', 'B. Syslog', 'C. LDAP', 'D. NTP'],
        'correct': 'b'
    },

    {
        'question': 'What service runs on TCP port 20?',
        'answer': 'FTP (File Transfer Protocol) uses TCP port 20 for data transfer.',
        'options': ['A. FTP', 'B. TFTP', 'C. SFTP', 'D. SCP'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses UDP port 68 for DHCP client communication?',
        'answer': 'DHCP clients use UDP port 68 to receive IP address assignments from DHCP servers.',
        'options': ['A. DNS', 'B. DHCP', 'C. SNMP', 'D. TFTP'],
        'correct': 'b'
    },

    {
        'question': 'What port does the NetBIOS Datagram Service use?',
        'answer': 'NetBIOS Datagram Service uses UDP port 138 for communication.',
        'options': ['A. 137', 'B. 138', 'C. 139', 'D. 140'],
        'correct': 'b'
    },

    {
        'question': 'Which service operates on TCP port 139?',
        'answer': 'NetBIOS Session Service uses TCP port 139 for file and printer sharing over a network.',
        'options': ['A. FTP', 'B. SMB', 'C. NetBIOS', 'D. AFP'],
        'correct': 'c'
    },

    {
        'question': 'What protocol uses TCP port 119 for newsgroup access?',
        'answer': 'NNTP (Network News Transfer Protocol) uses TCP port 119 to access Usenet newsgroups.',
        'options': ['A. IMAP', 'B. SMTP', 'C. NNTP', 'D. MAPI'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by the Gopher protocol?',
        'answer': 'Gopher uses TCP port 70 for distributing, searching, and retrieving documents.',
        'options': ['A. 70', 'B. 80', 'C. 90', 'D. 100'],
        'correct': 'a'
    },

    {
        'question': 'What service uses TCP port 113?',
        'answer': 'Ident protocol uses TCP port 113 to identify the user of a particular TCP connection.',
        'options': ['A. POP3', 'B. SMTP', 'C. Ident', 'D. MAPI'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol uses UDP port 161 for SNMP agent communication?',
        'answer': 'SNMP agents use UDP port 161 to receive requests from the SNMP manager.',
        'options': ['A. SNMP', 'B. SMTP', 'C. FTP', 'D. Telnet'],
        'correct': 'a'
    },

    {
        'question': 'What port does the NetBIOS Name Service use?',
        'answer': 'NetBIOS Name Service uses UDP port 137 for name resolution.',
        'options': ['A. 137', 'B. 138', 'C. 139', 'D. 140'],
        'correct': 'a'
    },

    {
        'question': 'Which service operates on TCP port 445?',
        'answer': 'SMB (Server Message Block) uses TCP port 445 for file sharing over a network.',
        'options': ['A. FTP', 'B. SMB', 'C. NFS', 'D. AFP'],
        'correct': 'b'
    },

    {
        'question': 'What protocol uses TCP port 143 for email retrieval?',
        'answer': 'IMAP (Internet Message Access Protocol) uses TCP port 143 to retrieve emails from a server.',
        'options': ['A. POP3', 'B. SMTP', 'C. IMAP', 'D. MAPI'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by the Kerberos authentication protocol?',
        'answer': 'Kerberos uses TCP and UDP port 88 for authentication services.',
        'options': ['A. 88', 'B. 89', 'C. 90', 'D. 91'],
        'correct': 'a'
    },

    {
        'question': 'What service uses TCP port 110?',
        'answer': 'POP3 (Post Office Protocol version 3) uses TCP port 110 to retrieve emails from a server.',
        'options': ['A. IMAP', 'B. SMTP', 'C. POP3', 'D. MAPI'],
        'correct': 'c'
    },

    {
        'question': 'Which protocol uses UDP port 69 for simple file transfers?',
        'answer': 'TFTP (Trivial File Transfer Protocol) uses UDP port 69 for transferring files without '
                  'authentication.',
        'options': ['A. FTP', 'B. TFTP', 'C. SFTP', 'D. SCP'],
        'correct': 'b'
    },

    {
        'question': 'What port does the Secure Shell (SSH) protocol use?',
        'answer': 'SSH uses TCP port 22 for secure remote login and command execution.',
        'options': ['A. 21', 'B. 22', 'C. 23', 'D. 24'],
        'correct': 'b'
    },

    {
        'question': 'Which service operates on TCP port 21?',
        'answer': 'FTP (File Transfer Protocol) uses TCP port 21 for control commands.',
        'options': ['A. FTP', 'B. TFTP', 'C. SFTP', 'D. SCP'],
        'correct': 'a'
    },

    {
        'question': 'What protocol uses UDP port 123?',
        'answer': 'NTP (Network Time Protocol) uses UDP port 123 to synchronize clocks over a network.',
        'options': ['A. SNMP', 'B. NTP', 'C. SMTP', 'D. DNS'],
        'correct': 'b'
    },

    {
        'question': 'Which port is used by the Remote Desktop Protocol (RDP)?',
        'answer': 'RDP uses TCP port 3389 to provide remote desktop access.',
        'options': ['A. 3389', 'B. 3390', 'C. 3391', 'D. 3392'],
        'correct': 'a'
    },

    {
        'question': 'What service uses TCP port 53?',
        'answer': 'DNS (Domain Name System) uses TCP port 53 for zone transfers.',
        'options': ['A. DNS', 'B. DHCP', 'C. SNMP', 'D. FTP'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses UDP port 162 for trap messages?',
        'answer': 'SNMP (Simple Network Management Protocol) uses UDP port 162 for receiving trap messages.',
        'options': ['A. SNMP', 'B. SMTP', 'C. FTP', 'D. Telnet'],
        'correct': 'a'
    },

    {
        'question': 'What port does the Secure LDAP (LDAPS) protocol use?',
        'answer': 'LDAPS uses TCP port 636 for secure directory services.',
        'options': ['A. 636', 'B. 637', 'C. 638', 'D. 639'],
        'correct': 'a'
    },

    {
        'question': 'Which service uses TCP port 49?',
        'answer': 'TACACS+ (Terminal Access Controller Access-Control System Plus) uses TCP port 49 for authentication '
                  'services.',
        'options': ['A. RADIUS', 'B. TACACS+', 'C. LDAP', 'D. Kerberos'],
        'correct': 'b'
    },

    {
        'question': 'What service uses UDP port 520 to exchange routing information between routers?',
        'answer': 'RIP (Routing Information Protocol) uses UDP port 520 for exchanging routing information.',
        'options': ['A. RIP', 'B. OSPF', 'C. BGP', 'D. EIGRP'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol uses TCP port 636 for secure communication?',
        'answer': 'LDAPS (LDAP over SSL) uses TCP port 636 for secure directory access.',
        'options': ['A. LDAP', 'B. LDAPS', 'C. Kerberos', 'D. SAML'],
        'correct': 'b'
    },

    {
        'question': 'What port does the SQLnet protocol use for Oracle databases?',
        'answer': 'Oracle SQLnet typically uses TCP port 1521 to connect to Oracle database services.',
        'options': ['A. 1433', 'B. 1521', 'C. 3306', 'D. 5432'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 135 for remote procedure calls?',
        'answer': 'Microsoft RPC (Remote Procedure Call) uses TCP port 135 for initial communication.',
        'options': ['A. SMB', 'B. LDAP', 'C. RPC', 'D. NetBIOS'],
        'correct': 'c'
    },

    {
        'question': 'Which port is associated with the X11 windowing system?',
        'answer': 'X11 uses TCP port 6000 by default for graphical windowing systems on UNIX/Linux.',
        'options': ['A. 6000', 'B. 5900', 'C. 5800', 'D. 5500'],
        'correct': 'a'
    },

    {
        'question': 'Which service typically operates on TCP port 1433?',
        'answer': 'Microsoft SQL Server uses TCP port 1433 to accept incoming database connections.',
        'options': ['A. MySQL', 'B. PostgreSQL', 'C. MSSQL', 'D. Oracle'],
        'correct': 'c'
    },

    {
        'question': 'Which port does the MySQL database server use by default?',
        'answer': 'MySQL uses TCP port 3306 as the default port for client connections.',
        'options': ['A. 3306', 'B. 1433', 'C. 1521', 'D. 5432'],
        'correct': 'a'
    },

    {
        'question': 'Which protocol operates on TCP port 989 and 990 for secure file transfers?',
        'answer': 'FTPS (FTP Secure) uses TCP port 989 for data and 990 for control.',
        'options': ['A. FTP', 'B. SFTP', 'C. FTPS', 'D. SCP'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by PostgreSQL by default?',
        'answer': 'PostgreSQL uses TCP port 5432 by default for database access.',
        'options': ['A. 1521', 'B. 1433', 'C. 5432', 'D. 3306'],
        'correct': 'c'
    },

    {
        'question': 'What protocol uses UDP port 1812 for authentication requests?',
        'answer': 'RADIUS uses UDP port 1812 for authentication and authorization requests.',
        'options': ['A. TACACS+', 'B. LDAP', 'C. RADIUS', 'D. Kerberos'],
        'correct': 'c'
    },

    {
        'question': 'Which port does the Remote Framebuffer protocol use (used by VNC)?',
        'answer': 'RFB protocol, used by VNC, typically uses TCP port 5900 for remote desktop connections.',
        'options': ['A. 5900', 'B. 5800', 'C. 6000', 'D. 3389'],
        'correct': 'a'
    },

    {
        'question': 'What protocol operates over UDP port 1813 for accounting?',
        'answer': 'RADIUS uses UDP port 1813 for accounting messages.',
        'options': ['A. TACACS+', 'B. SNMP', 'C. RADIUS', 'D. LDAP'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by the Apple Filing Protocol (AFP)?',
        'answer': 'AFP typically uses TCP port 548 for file sharing on Apple networks.',
        'options': ['A. 137', 'B. 548', 'C. 445', 'D. 427'],
        'correct': 'b'
    },

    {
        'question': 'What port is used by the Secure Copy Protocol (SCP)?',
        'answer': 'SCP uses TCP port 22, as it operates over SSH for secure transfers.',
        'options': ['A. 21', 'B. 22', 'C. 23', 'D. 25'],
        'correct': 'b'
    },

    {
        'question': 'Which port does the Simple Service Discovery Protocol (SSDP) use?',
        'answer': 'SSDP uses UDP port 1900 for device discovery in UPnP environments.',
        'options': ['A. 1900', 'B. 2399', 'C. 1800', 'D. 1700'],
        'correct': 'a'
    },

    {
        'question': 'What protocol uses TCP port 989?',
        'answer': 'FTPS uses TCP port 989 for encrypted data channel connections. FTPS uses port 990 for the control'
                  ' channel.',
        'options': ['A. FTP', 'B. SCP', 'C. FTPS', 'D. TFTP'],
        'correct': 'c'
    },

    {
        'question': 'Which port is used by Lightweight Directory Access Protocol (LDAP)?',
        'answer': 'LDAP uses TCP and UDP port 389 for directory services.',
        'options': ['A. 636', 'B. 389', 'C. 3268', 'D. 500'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses TCP port 3268 for global catalog searches in Active Directory?',
        'answer': 'Global Catalog in Active Directory uses TCP port 3268 for LDAP queries across domains.',
        'options': ['A. LDAP', 'B. LDAPS', 'C. GC', 'D. SMB'],
        'correct': 'c'
    },

    {
        'question': 'What service uses TCP port 500 for IPsec negotiation?',
        'answer': 'ISAKMP (Internet Security Association and Key Management Protocol) uses port 500 for IPsec.',
        'options': ['A. HTTPS', 'B. ISAKMP', 'C. SSL', 'D. L2TP'],
        'correct': 'b'
    },

    {
        'question': 'Which protocol uses UDP port 500 for establishing VPN tunnels?',
        'answer': 'IPsec with IKE (Internet Key Exchange) uses UDP port 500 for VPN setup.',
        'options': ['A. PPTP', 'B. IPsec', 'C. SSL', 'D. GRE'],
        'correct': 'b'
    }

]


