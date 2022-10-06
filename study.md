```
What are the best practices for authentication?
-	Encourage use lengthy passphrase and emoji
-	Limit unsuccessful attempts
-	Multi-factor authentication
-	Do not set default logins

What are best practices to prevent session hijacking?
-	Use high quality random number generator to generate session tokens
-	Set http only for session id
-	Time out for inactive logins
-	Use HTTPS for all web traffic

What are best practices for using good encryption methods?
-	Use well established algorithms and protocols
-	Use strong random number generators
-	Verify certificate principles
-	Check revocation lists

How to protect secrets in RAM?
-	Overwrite secret information in RAM
-	Do not use immutable objects

What are best practices to protect passwords?
-	Use out of band confirmation for password changes

Which of the following are true related to XXE vulnerability and attacks?
-	Input validation
-	Prefer JSON over XML

What are best practices for access control?
-	Do not make sensitive web pages available to the internet, dispatch to these pages after ascertaining authorization
-	Use capability based authorization
-	Do not hard code logic for authorization in the application
-	Use authorization provision service that can be provisioned dynamically

What are best practices for applying least privilege for application security?
-	Least privilege for java applications can be enforced through a policy by JVM
-	Specify security policy for the application enforced by the container container

Which of following are true with respect to misconfiguration vulnerabilities?
-	New technology often comes with vulnerable defaults
-	Exception not handed by application must be handled without leaking system information
 
-	No default accounts
-	Disable unnecessary features

What are common misconfigurations for cloud applications?
-	Remote server access should not be open to internet
-	Access credentials in open repository and images
-	Unintended source code disclosure
-	Sensitive data in open storage

Which of the following are attacks of access control?
-	SQL injection
-	Direct object reference
-	Access token manipulation

Which of the following concepts are related to access control?
-	Relationship between subject, object and access action
-	Authentication of subject
-	Defense in depth design
-	Default access credentials

Which of the following are related to preventing direct object reference attacks?
-	Assign ids to resources

Why capability-based dynamic access provision is a preferred way to implement access control?
-	Access control requirements change frequently
-	Hard-coded access control policy is difficult to maintain

What XXE parser configuration teaches us?
-	We don't often know what the best security default should be in new technology
-	Infrequently used function that carry security risks should be turned off by default
-	As product matures, configurations tend to default to more security settings.

What are best practices to handle exceptions?
-	Release resources no longer needed as part exception handling
-	Do not print sensitive information, including stack traces as part of exception handler
-	Include a "finally" block to release unneeded resources

What are best practices to handle exceptions?
-	Release resources no longer needed as part exception handling
-	Do not print sensitive information, including stack traces as part of exception handler
-	Include a "finally" block to release unneeded resources

What some of the common misconfigurations for cloud based applications?
 
-	Access credentials left in GitHub
-	Screen shots contain access credentials are publicly accessible
-	Server Side Crosssite Forgery vulnerabilities

What are common attacks against object deserialization?
-	Command injection
-	Change access permission to gain privileged access
-	XSS

What valid examples for security risks introduced by a software component?
-	Component has a failure to sanitize data
-	Component has a command interpreter leading to command injection risks

What are good practices to reduce security risks introduced by using software components?
-	Track vulnerabilities in components and keep up security updates
-	Disable unused functions if possible
-	Execute application in a contain with least privilege configuration

What suspicious events should be investigated to mitigate against attacks on applications?
-	Change / removal of logs
-	High frequency of denied access
-	High frequency of invalid input

Which of the following might be logged to monitor attacks on application?
-	Successful and failed login attempts
-	IP addresses of incoming traffic
-	Password reset requests

Which of the following can lead to leakage of stored sensitive information?
-	SQL injection
-	Path manipulation
-	Session Hijacking

Which of following would enable the attacker to modify content of your database?
-	Cross site request forgery
-	Clickjacking
-	SQL injection

How would an attacker launch a XSS attack?
-	Insert malicious JavaScript into databases via SQL injection
-	Send JavaScript via links in email

How could an attacker obtain the session token to launch session hijacking attack?
-	Use man-in-the-middle attack defeat https protection
 
-	Path manipulation to gain access to files with current sessions
-	Forced browsing of logs

Which of the following techniques might be used to exploit an access control vulnerability?
-	Path manipulation
-	Forced browsing

What an attacker might be able to achieve by exploiting a buffer overflow vulnerability?
-	Escalate privilege via remote code execution
-	Remote shell commend execution
-	Steel sensitive information
-	Remove files from the server

Which statements about stack guard is/are true?
-	Uses a bit pattern referred to as a "digital canary"
-	Integrity of the stack guard is checked at run time
-	It is generated by a compiler by default

Which statements about Data Execution Prevention (DEP) is/are true?
-	It is enforced by the OS by default

Which statements about Address Space Layout Randomization (ASLR) is/are true?
-	It makes it difficult for an attacker to write automated scripts to exploit buffer overflow vulnerabilities
-	A given library may be at different memory locations for different applications

Which statements about Control Flow Integrity (CFI) is/are true?
-	It mitigates returned oriented programming (ROP) attacks
-	It incurs runtime overhead

Which of the following is/are commonly associated with a use after free vulnerability?
-	Heap spray attack
-	Attack program written in C (Originally not a correct answer, regraded)
-	Attack program written in Javascript

A proxy could be used to launch a man-in-the-middle attack against either a web or mobile application.
-	True

Application security risk is determined by the combination of: vulnerability, how easy to find and exploit the vulnerability.
-	False

End-to-end encryption must be used throughout a website to prevent session hijacking attacks.
 
-	True

Cross site request forgery attack can be used to modify settings of your web account
-	True

Every known software vulnerability will eventually be assigned a CVE number
-	True

A justification for releasing an unpatched vulnerability is that it is the best way to educate the public, provided the software vendor has been given the chance to provide a patch.
-	True

According to the responsible disclosure policy, the software owner has two weeks to respond to a report of a potential vulnerability in a software product.
-	False

Clickjacking can be prevented by making the user to provide password for re-authentication.
-	False

Is there a missing key justification for civil electronic disobedience: ethical cause, no harm to properties, and nonviolence?
-	Yes

SQL injection vulnerability could be used to launch reflective cross site scripting attack.
-	False

Clickjacking, coupled with social media sites, can lead to identifying users browsing anonymously.
-	True

CSRF attacks can be used to phish login credentials
-	False

CSRF attacks may be used to obtain session ids and use them in session hijacking attacks
-	False

The integrity of the stack guard is checked at run time.
-	True

Data Execution Prevention (DEP) is generated by compiler by default
-	False

Address Space Layout Randomization (ASLR) are by default on all major operating systems
-	True
 
Control Flow Integrity shuffles stack addresses
-	False

Programs written in Java are not susceptible to use after free attacks because Java does automatic garbage collection.
-	True

Phishing attack exploits configuration vulnerabilities.
-	False

Attackers may perform reconnaissance on your website by changing parameters using a proxy.
-	True

Session hijacking can be used to perform keylogging attacks.
-	False

Covering tracks is a step in the standard penetration testing model by an attacker
-	True

You can effectively demonstrate to a business audience about the impact of a XSS vulnerability by showing an alert(1) box pop up.
-	False

Effective application security controls must be placed on the server side of the application.
-	True

A stored XSS vulnerability can be exploited to launch phishing attacks.
-	True

A SQL vulnerability can be used to launch phishing attacks.
-	True

Session hijacking may be used by an attacker to steal sensitive information.
-	True

An attacker may be able obtain valid session ids in logs by exploiting an access control vulnerability
-	True

Clickjacking can be used to exploit an access control vulnerability.
-	False

Which of the following are common types of security vulnerabilities?
-	Human vulnerability
 
-	Configuration vulnerability
-	Application vulnerability

In the context of Security First, which of the following is part of Reconnaissance?
-	Parameter manipulation

What attack techniques can be used to perform key logging?
-	XSS

Find all steps that appear in the standard model for penetration testing.
-	Scanning
-	Reconnaissance
-	Covering tracks

Which of the following are best strategy to present your XSS finding?
-	Demonstrate how it can be used to steal password through key logging
-	Demonstrate how it can be used for phishing

Security control can be effectively placed on both client side as well as the server side of the application.
-	False

Which of the following attacks can be stopped by network firewall?
-	None

Stored XSS attack: SQL injection Stored XSS attack: Phishing Reflective XSS attack: Phishing

What do injection attacks have in common?
-	Cannot be easily fixed because fixing would involve reinventing the underlying computer language
-	Command and data can be mixed in the same input channel
-	The underlying system architecture is vulnerable

Which of the following are injection attacks?
-	XSS
-	Path manipulation

Injection vulnerabilities can be fixed by adopting the separation of domain design principle. Which of the following are examples of successful implementations of this design principle?
-	Content Security Policy (CSP)
-	Angular JS
-	Embedded SQL statement
 
Which of the following are preferred data sanitization methods?
-	Pick an input from a list of approved values
-	Convert a string of digits to integer
-	Encoding for web output

Which of the following APIs should be part of the trust boundary that brings untrusted data into the application?
-	getParameter()
-	System.getenv()
-	Registry.GetValue()

Which of the following are good approaches to implement data sanitization?
-	Minimize length of user input wherever possible
-	Apply filters in forms
-	Standardize APIs that implement data sanitization by default

A sink rule in static analysis corresponds to part of
-	Security sensitive operations

A source rule in static analysis corresponds to part of
-	Trust boundary

A cleansing rule in static analysis correspond to part of
-	Data sanitization

A propagating rule in static analysis corresponds to part of
-	Lack of source code

Which of the following is/are legitimate reason why source code is required for static analysis
-	To identify constants
-	To perform taint propagation
-	To trace control flow

Which of the following is/are legitimate reason for false positives in static analysis results
-	Unreachable code for application input
-	Incomplete knowledge of cleansing rules

Which of the following is/are legitimate reason for false negatives in static analysis results
-	Pointer aliasing
-	Incomplete knowledge of sink rules
-	Incomplete knowledge of source rules

Which of the following is/are legitimate reason for risk prioritization of static analysis results and delay fixing a vulnerability
 
-	Low business impact

What is the difference between pattern matching based on program structure and regex string matching?
-	it is easier to write regex than to write structural analysis rules
-	Structural analysis can differentiate the name of a method from a constant value
-	Structural analysis is based on program grammar

Which statements is/are true?
-	Dynamic analysis is mostly agnostic to programming languages
-	Both static analysis and dynamic analysis can have high false positives and false negatives
-	Static analysis lead to less expensive bug fix because it detects vulnerabilities earlier in
the development cycle
-	Static analysis cannot identify timing related vulnerabilities

Which statements about program analysis is/are true?
-	Model checking is difficult to scale to complex applications
-	Symbolic execution requires source code
-	Binary analysis can discover violation of using vulnerable libraries

Which statements about sandbox is/are true?
-	Sandbox enforces access policies through the use of API hooking
-	Sandbox can be used enforce least privilege for an application through use of policies
-	Sandbox can be used to implement isolation of applications

Which of the following are true about the Threat Modeling process?
-	Context diagram, Data Flow Diagram decomposition and application architecture are often used to set the stage for threat modeling
-	Threat modeling should consider laws and regulations that impact the application
-	Results of threat modeling can be used to develop penetration testing plans

Which of the following are true with regard to NIST recommended password policy?
-	Using a sentence for a password is a good practice
-	Password does not have to contain digits and special characters, but must be at least 8 characters long, preferably longer

Match the following for prevention of session hijacking.
-	Stealing session cookie via XSS: http only
-	Sniffing session id over network traffic: TLS/SSI/HTTPS
-	Predicting session ids based on observed session ids: Use cryptographically strong random number generator

Which of the following are true?
 
-	A digital certificate uses digital signature to certify that a named organization is the owner of a public key
-	When using TLS/SSL, one must match the named organization on the digital certificate
and the target entity
-	Password salt is to prevent bruteforce attack using rainbow tables

Which of the following could have prevented the Heartbleed vulnerability?
-	Write over memory used to store encryption key
-	Check array bounds in SSL implementation

```
