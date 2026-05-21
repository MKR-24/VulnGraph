"""
rag.py = Retrieval Augmented Generation for VulnGraph

Flow:
1. Seed: Load CWE definitions, OWASP Top 10, and Bandit rules into ChromaDB.
2. Retrieve: Given a finding, embed it and fetch top- K relevant documents from ChromaDB.
3. Augment: Return context string injected into llm.py prompts

"""
import os
import json
from pathlib import Path
from dotenv import load_dotenv
import chromadb

load_dotenv()

#Configuration
CHROMA_DIR = os.getenv("CHROMA_DIR" , str(Path(__file__).parent.parent/"data/chroma"))
COLLECTION_NAME = "vulngraph_knowledge"
TOP_K = 3 # Number of relevant documents to retrieve
EMBED_MODEL = "all-MiniLM-L6-v2" # SentenceTransformer model for embeddings

#CHROMADB client
_collection = None
def get_collection():
    """ Get Else Create ChromaDB collection with sentence transformer embeddings"""
    import chromadb
    from chromadb.utils import embedding_functions

    client = chromadb.PersistentClient(path=CHROMA_DIR)
    ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"}
        )
    return collection

def is_seeded() -> bool:
    """ Check if KB has documents or not"""
    try:
        collection = get_collection()
        return collection.count() > 0
    except Exception :
        return False
    
#KNowledge Base Seeding
# CWE Top 25
CWE_DOCS = [
    {"id": "cwe-79",  "text": "CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting). Allows attackers to inject client-side scripts into web pages viewed by other users. Can lead to session hijacking, credential theft, and malware distribution.", "source": "cwe"},
    {"id": "cwe-89",  "text": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection). Allows attackers to manipulate SQL queries by injecting malicious SQL code. Can lead to unauthorized data access, data modification, and authentication bypass.", "source": "cwe"},
    {"id": "cwe-352",  "text": "CWE-352: Cross-Site Request Forgery (CSRF). Allows attackers to perform unauthorized actions on behalf of a user who is authenticated with a web application. Common in forms without anti-CSRF tokens.", "source": "cwe"},
    {"id": "cwe-862",  "text": "CWE-862: Missing Authorization. Failure to properly enforce authorization checks allows unauthorized access to protected resources or functionality.", "source": "cwe"},
    {"id": "cwe-787", "text": "CWE-787: Out-of-bounds Write. Writing to memory outside the bounds of a buffer can lead to crashes, data corruption, or arbitrary code execution.", "source": "cwe"},
    {"id": "cwe-22", "text": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'). Allows attackers to access files outside the intended directory by manipulating file paths.", "source": "cwe"},
    {"id": "cwe-416", "text": "CWE-416: Use After Free. Accessing memory after it has been freed can lead to crashes, data corruption, or arbitrary code execution.", "source": "cwe"},
    {"id": "cwe-125", "text": "CWE-125: Out-of-bounds Read. Reading memory outside the bounds of a buffer can lead to crashes, data corruption, or information disclosure.", "source": "cwe"},
    {"id": "cwe-78", "text": "CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection). Allows attackers to execute arbitrary OS commands by injecting shell metacharacters into application input. Common in subprocess calls, shell=True usage, and unsanitized user input passed to system commands.", "source": "cwe"},
    {"id": "cwe-94", "text": "CWE-94: Improper Control of Generation of Code (Code Injection). Allows attackers to inject and execute arbitrary code. Includes eval() misuse, dynamic code generation from user input, and template injection vulnerabilities.", "source": "cwe"},
    {"id": "cwe-120", "text": "CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow').Copying data into a buffer without checking its size can overwrite memory, allowing attackers to crash the program or execute arbitrary code. ", "source": "cwe"},
    {"id": "cwe-434", "text": "CWE-434: Unrestricted Upload of File with Dangerous Type. Allowing upload of executable files or scripts without validation, enabling attackers to upload and execute malicious code.", "source": "cwe"},
    {"id": "cwe-476", "text": "CWE-476: NULL Pointer Dereference. Dereferencing a null pointer causes application crashes and potential denial of service.", "source": "cwe"},
    {"id": "cwe-121", "text": "CWE-121: Stack-based Buffer Overflow. Overflowing a stack buffer can overwrite control data like return addresses, enabling attackers to hijack execution flow and run malicious code.", "source": "cwe"},
    {"id": "cwe-502", "text": "CWE-502: Deserialization of Untrusted Data. Deserializing attacker-controlled data can lead to remote code execution. Common with pickle, yaml.load(), and Java ObjectInputStream.", "source": "cwe"},
    {"id": "cwe-122", "text": "CWE-122: Heap-based Buffer Overflow. Overflowing a heap buffer can corrupt dynamically allocated memory and management structures, allowing attackers to manipulate program behavior or execute arbitrary code.", "source": "cwe"},
    {"id": "cwe-863", "text": "CWE-863: Incorrect Authorization. It allows users to perform actions or access resources without proper permission checks, potentially leading to unauthorized data exposure or privilege escalation.", "source": "cwe"},
    {"id": "cwe-20", "text":  "CWE-20: Improper Input Validation. Failing to properly validate input allows malformed or malicious data to alter program behavior, potentially leading to security breaches, crashes, or code execution.", "source": "cwe"},
    {"id": "cwe-284", "text": "CWE-284:  Improper Access Control. Weak or missing access control can let attackers access, modify, or delete resources they should not be allowed to touch.", "source": "cwe"},
    {"id": "cwe-200", "text": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor. Unintended disclosure of sensitive data including credentials, PII, internal system details, or cryptographic keys through logs, error messages, or API responses.", "source": "cwe"},
    {"id": "cwe-306", "text": "CWE-306: Missing Authentication for Critical Function. Critical operations performed without verifying the identity of the requester, allowing unauthorized access to sensitive functionality.", "source": "cwe"},
    {"id": "cwe-918", "text": "CWE-918: Server-Side Request Forgery (SSRF). Allowing attackers to induce the server to make requests to unintended locations, potentially accessing internal services or cloud metadata endpoints.", "source": "cwe"},
    {"id": "cwe-77", "text": "CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection'). Failing to neutralize special command characters allows attackers to inject and execute arbitrary system commands with the privileges of the vulnerable application.", "source": "cwe"},
    {"id": "cwe-639", "text": "CWE-639: Authorization Bypass Through User-Controlled Key.It allows attackers to manipulate user-controlled identifiers to access or modify other users' data without proper authorization checks.", "source": "cwe"},
    {"id": "cwe-770", "text": "CWE-770:  Allocation of Resources Without Limits or Throttling. allocating resources without limits allows attackers to exhaust memory, CPU, or connections, causing denial of service and system instability.", "source": "cwe"},
]

#OWASP Top-10
OWASP_DOCS = [
    {"id": "owasp-a01", "text": "OWASP A01:2025 Broken Access Control. Access control enforces policy such that users cannot act outside of their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of data. Common issues: bypassing access control checks, elevation of privilege, metadata manipulation.", "source": "owasp"},
    {"id": "owasp-a02", "text": "OWASP A02:2025 Security Misconfiguration. Missing security hardening, improperly configured permissions, unnecessary features enabled, default accounts unchanged, error handling revealing stack traces, outdated software. Includes XML external entities (XXE).", "source": "owasp"},
    {"id": "owasp-a03", "text": "OWASP A03:2025 Software Supply Chain Failures. Compromised or unverified third-party components can introduce hidden vulnerabilities or malicious code into otherwise trusted systems.", "source": "owasp"},
    {"id": "owasp-a04", "text": "OWASP A04:2025 Cryptographic Failures. Failures related to cryptography which often lead to sensitive data exposure. Issues include: using weak algorithms (MD5, SHA1, DES), hardcoded keys, improper certificate validation, transmitting data in cleartext, using deprecated protocols (SSLv2, TLS 1.0).", "source": "owasp"},
    {"id": "owasp-a05", "text": "OWASP A05:2025 Injection. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. SQL injection, NoSQL injection, OS command injection, LDAP injection. Prevention: use parameterized queries, input validation, escape special characters.", "source": "owasp"},
    {"id": "owasp-a06", "text": "OWASP A06:2025 Insecure Design. Missing or ineffective control design. Threat modeling, secure design patterns, and reference architectures are absent. Differs from implementation bugs — insecure design cannot be fixed by perfect implementation.", "source": "owasp"},
    {"id": "owasp-a07", "text": "OWASP A07:2025 Authentication Failures. Weaknesses in authentication and session management. Permits brute force attacks, uses weak credentials, stores passwords in plaintext or weak hashes, has broken session management, missing MFA.", "source": "owasp"},
    {"id": "owasp-a08", "text": "OWASP A08:2025 Software or Data Integrity Failures. Code and infrastructure that does not protect against integrity violations. Insecure deserialization, unsigned software updates, CI/CD pipeline vulnerabilities, use of untrusted plugins or libraries.", "source": "owasp"},
    {"id": "owasp-a09", "text": "OWASP A09:2025 Security Logging and Alerting Failures. Insufficient logging, detection, monitoring, and active response. Without logging and monitoring, breaches cannot be detected. Log sensitive operations, monitor for anomalies, establish incident response plans.", "source": "owasp"},
    {"id": "owasp-a10", "text": "OWASP A10:2025 Mishandling of Exceptional Conditions. Improper error handling can expose sensitive information, corrupt system state, or allow attackers to bypass normal security controls.", "source": "owasp"},
]

#Bandit Rules Reference
BANDIT_DOCS = [
    {"id": "bandit-B101", "text": "Bandit B101: Use of assert detected. Assert statements are removed with python -O optimization flag, making security checks bypass-able in production. Replace with proper if/raise statements for security-critical checks.", "source": "bandit"},
    {"id": "bandit-B102", "text": "Bandit B102: Use of exec detected. The exec function executes dynamic Python code, which can lead to arbitrary code execution if untrusted input is used. Avoid exec or strictly control and sanitize all inputs.", "source": "bandit"},
    {"id": "bandit-B103", "text": "Bandit B103: Insecure file permissions detected. Setting overly permissive file modes can expose sensitive data to unauthorized users. Apply the principle of least privilege when assigning file permissions.", "source": "bandit"},
    {"id": "bandit-B104", "text": "Bandit B104: Binding to all network interfaces detected. Listening on 0.0.0.0 exposes the service to external networks, increasing attack surface. Bind only to required interfaces.", "source": "bandit"},
    {"id": "bandit-B105", "text": "Bandit B105: Hardcoded password string detected. Storing passwords directly in source code risks credential exposure. Use secure secret management instead.", "source": "bandit"},
    {"id": "bandit-B106", "text": "Bandit B106: Hardcoded password passed as function argument. Embedding credentials in code makes them retrievable from source or logs. Use secure configuration mechanisms.", "source": "bandit"},
    {"id": "bandit-B107", "text": "Bandit B107: Hardcoded password used as default argument. Default credentials in code can be easily discovered and abused. Remove hardcoded secrets and require secure input.", "source": "bandit"},
    {"id": "bandit-B108", "text": "Bandit B108: Hardcoded temporary directory detected. Using fixed temp paths can allow race conditions or symlink attacks. Use secure system-provided temporary directories.", "source": "bandit"},
    {"id": "bandit-B109", "text": "Bandit B109: Password configuration option not marked as secret. Storing sensitive values without secret handling may expose them in logs or interfaces. Mark and protect secrets appropriately.", "source": "bandit"},
    {"id": "bandit-B110", "text": "Bandit B110: try/except/pass detected. Silently ignoring exceptions can hide security failures and unexpected behavior. Handle exceptions explicitly and log appropriately.", "source": "bandit"},
    {"id": "bandit-B111", "text": "Bandit B111: Execution with run_as_root=True detected. Running processes as root increases impact of compromise. Apply least privilege and avoid root execution unless strictly required.", "source": "bandit"},
    {"id": "bandit-B112", "text": "Bandit B112: try/except/continue detected. Suppressing errors with continue may skip critical validation steps. Ensure exceptions are properly handled and reviewed.", "source": "bandit"},
    {"id": "bandit-B113", "text": "Bandit B113: HTTP request without timeout detected. Missing timeouts can cause resource exhaustion or denial of service. Always define reasonable timeouts for network calls.", "source": "bandit"},
    {"id": "bandit-B201", "text": "Bandit B201: Flask debug mode enabled. Debug mode exposes internal details and interactive consoles, which can lead to remote code execution in production.", "source": "bandit"},
    {"id": "bandit-B202", "text": "Bandit B202: Unsafe tarfile extraction detected. Extracting untrusted archives without validation can lead to path traversal and file overwrite attacks.", "source": "bandit"},
    {"id": "bandit-B203", "text": "Bandit B203: Use of flask.app.run with debug=True detected. Never run Flask debug mode in production — exposes interactive debugger allowing RCE.", "source": "bandit"},
    {"id": "bandit-B204", "text": "Bandit B204: Use of subprocess with partial executable path detected. Partial paths are vulnerable to PATH hijacking attacks.", "source": "bandit"},
    {"id": "bandit-B301", "text": "Bandit B301: Use of pickle.loads detected. Deserializing untrusted pickle data allows arbitrary code execution. Use JSON or validate data source strictly.", "source": "bandit"},
    {"id": "bandit-B302", "text": "Bandit B302: Use of marshal.loads detected. Marshal deserialization can execute arbitrary code. Avoid with untrusted data.", "source": "bandit"},
    {"id": "bandit-B303", "text": "Bandit B303: Use of MD5 or SHA1 hash detected. MD5 and SHA1 are cryptographically broken. Use SHA-256 or higher for integrity, bcrypt/argon2 for passwords.", "source": "bandit"},
    {"id": "bandit-B304", "text": "Bandit B304: Use of weak cipher DES, RC2, RC4, or Blowfish detected. These are insecure. Use AES-256-GCM or ChaCha20-Poly1305.", "source": "bandit"},
    {"id": "bandit-B305", "text": "Bandit B305: Use of cipher with ECB mode detected. ECB mode does not provide semantic security. Use CBC, GCM, or CTR mode instead.", "source": "bandit"},
    {"id": "bandit-B306", "text": "Bandit B306: Use of mktemp detected. mktemp is vulnerable to race conditions and symlink attacks. Use tempfile.mkstemp() instead.", "source": "bandit"},
    {"id": "bandit-B307", "text": "Bandit B307: Use of eval detected. eval() executes arbitrary Python expressions. Avoid entirely or use ast.literal_eval() for safe parsing.", "source": "bandit"},
    {"id": "bandit-B308", "text": "Bandit B308: Use of mark_safe detected. Marking content as safe bypasses HTML escaping and enables XSS. Only use with fully trusted content.", "source": "bandit"},
    {"id": "bandit-B310", "text": "Bandit B310: Use of urllib.urlopen with http detected. Unvalidated URLs can lead to SSRF attacks. Validate and allowlist URLs before fetching.", "source": "bandit"},
    {"id": "bandit-B311", "text": "Bandit B311: Use of random module for security purposes. random is not cryptographically secure. Use secrets module or os.urandom() for tokens and keys.", "source": "bandit"},
    {"id": "bandit-B312", "text": "Bandit B312: Use of telnetlib.Telnet detected. Telnet is unencrypted. Use SSH instead.", "source": "bandit"},
    {"id": "bandit-B313", "text": "Bandit B313: Use of xml.etree.ElementTree.parse detected. Vulnerable to XML attacks. Use defusedxml.ElementTree instead.", "source": "bandit"},
    {"id": "bandit-B314", "text": "Bandit B314: Use of xml.etree.ElementTree.fromstring detected. Vulnerable to XML entity expansion. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B315", "text": "Bandit B315: Use of xml.etree.cElementTree detected. Vulnerable to XML attacks. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B316", "text": "Bandit B316: Use of xml.etree.cElementTree.parse detected. Vulnerable to XML attacks. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B317", "text": "Bandit B317: Use of xml.etree.cElementTree.fromstring detected. Vulnerable to XML attacks. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B318", "text": "Bandit B318: Use of xml.dom.minidom.parseString detected. Vulnerable to XML attacks. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B319", "text": "Bandit B319: Use of xml.dom.minidom.parse detected. Vulnerable to XML attacks. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B320", "text": "Bandit B320: Use of xml.sax.parseString detected. Vulnerable to XML attacks. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B321", "text": "Bandit B321: Use of ftplib.FTP detected. FTP transmits credentials in plaintext. Use SFTP instead.", "source": "bandit"},
    {"id": "bandit-B322", "text": "Bandit B322: Use of input() in Python 2 detected. input() evaluates code in Python 2. Use raw_input() instead. Not applicable in Python 3.", "source": "bandit"},
    {"id": "bandit-B323", "text": "Bandit B323: Use of unverified SSL context detected. Disabling certificate verification enables MITM attacks. Always verify SSL certificates.", "source": "bandit"},
    {"id": "bandit-B325", "text": "Bandit B325: Use of tempnam detected. tempnam is vulnerable to race conditions. Use tempfile.mkstemp() instead.", "source": "bandit"},
    {"id": "bandit-B324", "text": "Bandit B324: Insecure or weak hashing algorithm detected. Using outdated hash functions like MD5 or SHA1 can enable collision or brute-force attacks. Use strong algorithms such as SHA-256 or better.", "source": "bandit"},
    {"id": "bandit-B401", "text": "Bandit B401: Import of telnetlib detected. Telnet transmits data including credentials in plaintext. Use SSH via paramiko instead.", "source": "bandit"},
    {"id": "bandit-B402", "text": "Bandit B402: Import of ftplib detected. FTP transmits data including credentials in plaintext. Use SFTP or FTPS instead.", "source": "bandit"},
    {"id": "bandit-B403", "text": "Bandit B403: Import of pickle module detected. Deserializing pickle data from untrusted sources allows arbitrary code execution. Use JSON or other safe formats.", "source": "bandit"},
    {"id": "bandit-B404", "text": "Bandit B404: Import of subprocess module detected. The subprocess module allows execution of system commands. If user-controlled input reaches subprocess calls without proper validation, attackers can execute arbitrary OS commands. Use subprocess.run() with a list of arguments and shell=False. Never pass user input directly to subprocess commands.", "source": "bandit"},
    {"id": "bandit-B405", "text": "Bandit B405: Import of xml.etree detected. Python's built-in XML parsers are vulnerable to XML attacks. Use defusedxml library instead.", "source": "bandit"},
    {"id": "bandit-B406", "text": "Bandit B406: Import of xml.sax detected. Vulnerable to XML attacks including billion laughs. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B407", "text": "Bandit B407: Import of xml.expat detected. Vulnerable to XML denial of service attacks. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B408", "text": "Bandit B408: Import of xml.dom detected. Vulnerable to XML attacks. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B409", "text": "Bandit B409: Import of xml.minidom detected. Vulnerable to XML entity expansion attacks. Use defusedxml instead.", "source": "bandit"},
    {"id": "bandit-B410", "text": "Bandit B410: Import of lxml detected. lxml may be vulnerable to XML attacks depending on configuration. Use defusedxml or configure lxml to disable entity resolution.", "source": "bandit"},
    {"id": "bandit-B411", "text": "Bandit B411: Import of xmlrpclib detected. XML-RPC can be vulnerable to XML attacks and server-side request forgery. Validate and sanitize all inputs.", "source": "bandit"},
    {"id": "bandit-B412", "text": "Bandit B412: Import of httpoxy detected. httpoxy vulnerability allows attackers to proxy HTTP requests via the Proxy header. Unset the HTTP_PROXY environment variable.", "source": "bandit"},
    {"id": "bandit-B413", "text": "Bandit B413: Import of pycrypto detected. PyCrypto is deprecated and unmaintained with known vulnerabilities. Use pycryptodome or cryptography library instead.", "source": "bandit"},
    {"id": "bandit-B414", "text": "Bandit B414: Import of pycryptodome detected. Ensure you are using a current version without known vulnerabilities.", "source": "bandit"},
    {"id": "bandit-B415", "text": "Bandit B415: Import of pyghmi detected. IPMI protocol has known security weaknesses. Ensure proper authentication and network isolation.", "source": "bandit"},
    {"id": "bandit-B501", "text": "Bandit B501: SSL certificate validation disabled. Skipping certificate verification enables man-in-the-middle attacks. Always verify server certificates in HTTPS requests.", "source": "bandit"},
    {"id": "bandit-B502", "text": "Bandit B502: SSL context with insecure protocol version detected. Using deprecated SSL/TLS versions exposes connections to known cryptographic attacks. Enforce modern TLS versions.", "source": "bandit"},
    {"id": "bandit-B503", "text": "Bandit B503: SSL context with insecure default settings detected. Weak ciphers or configurations may compromise transport security. Explicitly configure secure options.", "source": "bandit"},
    {"id": "bandit-B504", "text": "Bandit B504: SSL context created without specifying protocol version. Omitting explicit TLS versions may allow downgrade attacks. Specify secure TLS versions explicitly.", "source": "bandit"},
    {"id": "bandit-B505", "text": "Bandit B505: Weak cryptographic key detected. Insufficient key length reduces resistance to brute-force attacks. Use strong, industry-recommended key sizes.", "source": "bandit"},
    {"id": "bandit-B506", "text": "Bandit B506: Use of unsafe yaml.load detected. Loading YAML without safe loaders can execute arbitrary code. Use safe_load or a secure loader.", "source": "bandit"},
    {"id": "bandit-B507", "text": "Bandit B507: SSH host key verification disabled. Skipping host key checks enables man-in-the-middle attacks. Enforce strict host key verification.", "source": "bandit"},
    {"id": "bandit-B508", "text": "Bandit B508: Insecure SNMP version detected. Using SNMPv1 or v2 exposes communication to interception and spoofing. Use SNMPv3 with authentication and encryption.", "source": "bandit"},
    {"id": "bandit-B509", "text": "Bandit B509: Weak SNMP cryptography detected. Inadequate encryption or authentication reduces protection against interception. Use strong cryptographic configurations.", "source": "bandit"},
    {"id": "bandit-B601", "text": "Bandit B601: Paramiko call detected. Using Paramiko with untrusted input may allow command execution risks. Validate inputs and enforce strict SSH configurations.", "source": "bandit"},
    {"id": "bandit-B602", "text": "Bandit B602: subprocess call with shell=True detected. Using shell=True can allow command injection if inputs are not sanitized. Avoid shell=True or strictly validate inputs.", "source": "bandit"},
    {"id": "bandit-B603", "text": "Bandit B603: subprocess call without shell=True requires careful input validation. Untrusted input passed to subprocess can still introduce command injection risks.", "source": "bandit"},
    {"id": "bandit-B604", "text": "Bandit B604: Function call with shell=True detected. Executing commands via shell increases injection risk. Avoid shell invocation or sanitize all inputs.", "source": "bandit"},
    {"id": "bandit-B605", "text": "Bandit B605: Starting a process with a shell detected. Shell invocation increases command injection risk. Use direct execution without shell where possible.", "source": "bandit"},
    {"id": "bandit-B606", "text": "Bandit B606: Starting a process without a shell still requires validation. Untrusted arguments may affect executed commands. Validate all external inputs.", "source": "bandit"},
    {"id": "bandit-B607", "text": "Bandit B607: Starting process with partial path detected. Using non-absolute paths may allow path hijacking. Always use fully qualified executable paths.", "source": "bandit"},
    {"id": "bandit-B608", "text": "Bandit B608: Hardcoded SQL expression detected. Embedding raw SQL strings can introduce SQL injection vulnerabilities. Use parameterized queries.", "source": "bandit"},
    {"id": "bandit-B609", "text": "Bandit B609: Wildcard injection in Linux commands detected. Non-validated wildcard usage can expand unexpectedly and alter command behavior. Sanitize inputs and avoid shell globbing.", "source": "bandit"},
    {"id": "bandit-B610", "text": "Bandit B610: Django extra() used. The extra() method can introduce SQL injection risks if not carefully controlled. Prefer ORM-safe query construction.", "source": "bandit"},
    {"id": "bandit-B611", "text": "Bandit B611: Django RawSQL used. RawSQL bypasses ORM protections and may allow SQL injection. Use parameterized ORM queries where possible.", "source": "bandit"},
    {"id": "bandit-B612", "text": "Bandit B612: Insecure logging configuration listen detected. Exposing logging configuration over the network can allow remote manipulation. Restrict or disable remote configuration.", "source": "bandit"},
    {"id": "bandit-B613", "text": "Bandit B613: Trojan Source vulnerability pattern detected. Unicode bidirectional control characters may obscure malicious code. Remove hidden control characters from source files.", "source": "bandit"},
    {"id": "bandit-B614", "text": "Bandit B614: Unsafe PyTorch model loading detected. Loading untrusted serialized models may execute arbitrary code. Only load trusted model files.", "source": "bandit"},
    {"id": "bandit-B615", "text": "Bandit B615: Unsafe Hugging Face model download detected. Downloading and loading models without integrity checks may introduce malicious code. Verify source and integrity before use.", "source": "bandit"},
    {"id": "bandit-B701", "text": "Bandit B701: Jinja2 autoescape disabled. Disabling autoescape can allow cross-site scripting (XSS). Keep autoescape enabled for untrusted content.", "source": "bandit"},
    {"id": "bandit-B702", "text": "Bandit B702: Use of Mako templates detected. Mako templates may allow code execution if untrusted input is rendered. Sanitize and restrict template data.", "source": "bandit"},
    {"id": "bandit-B703", "text": "Bandit B703: Django mark_safe used. Marking content as safe bypasses escaping and may introduce XSS if content is untrusted.", "source": "bandit"},
    {"id": "bandit-B704", "text": "Bandit B704: Use of MarkupSafe Markup detected. Marking strings as safe HTML can bypass escaping and enable XSS if input is not trusted.", "source": "bandit"},
]

#Seeding the KB

def seed_kb(force:bool= False)-> int:
    """
    Seed ChromaDB with CWE,OWASP, and Bandit Knowledge.
    Skips if already seeded unless force = true.
    Returns number of documents added.
    """
    collection = get_collection()
    if not force  and collection.count() >0:
        print(f"[rag] Knowledge base already seeded with {collection.count()} documents.")
        return 0
    
    if force:
        # Clear existing documents
        try:
            client = chromadb.PersistentClient(path=CHROMA_DIR)
            client.delete_collection(COLLECTION_NAME)
            collection=get_collection()
        except Exception as e:
            print(f"[rag] Warning: could not clear collection: {e}")

    all_docs = CWE_DOCS + OWASP_DOCS + BANDIT_DOCS
    ids = [doc["id"] for doc in all_docs]
    texts = [doc["text"] for doc in all_docs]
    metadatas = [{"source": doc["source"], "doc_id": doc["id"]} for doc in all_docs]
    print(f"[rag] Seeding {len(all_docs)} documents ({len(CWE_DOCS)} CWE, {len(OWASP_DOCS)} OWASP, {len(BANDIT_DOCS)} Bandit)...")

    #Using Batches for memory
    batch_size = 50
    for i in range(0, len(all_docs), batch_size):
        collection.add(
            ids= ids[i:i+batch_size],
            documents=texts[i:i+batch_size],
            metadatas=metadatas[i:i+batch_size]
        )
    total = collection.count()
    print(f"Seeding complete. Total documents: {total}")
    return total
        
#Retrieval
def retrieve_context(
        finding_id:str,
        find_txt: str,
        severity:str = "",
        source: str="",
        top_k: int = TOP_K
) -> str:
    """
    Retrieve relevant knowledge base documents for a given finding.

    Args:
        finding_id: vulnerability/rule ID (e.g. 'B404', 'CVE-2025-1234')
        find_text: description text of the finding
        severity: severity level for context
        source: scanner source (bandit/trivy/gitleaks)
        top_k: number of documents to retrieve

    Returns:
        Formatted context string ready to inject into LLM prompt
    """
    collection = get_collection()
    if collection.count() == 0:
        print("[rag] KB is empty - Seeding started")
        seed_kb()

    query = f"{finding_id} {find_txt} {severity}".strip()

    try:
        res = collection.query(
            query_texts=[query],
            n_results = min(top_k, collection.count()),
            include= ["documents", "metadatas", "distances"]
        )
        docs = res["documents"][0]
        metadatas = res["metadatas"][0]
        distances = res["distances"][0]

        if not docs:
            return ""
        
        #Formatting the context block for prompt injection
        context_parts = []
        for doc,meta,dist in zip(docs,metadatas,distances):
            relevance= round((1-dist)*100,1)# cosine distance will give similiarity %
            source_label=meta.get("source","").upper()
            doc_id=meta.get("doc_id","")
            context_parts.append(
                f"[{source_label}-{doc_id} | Relevance: {relevance}%]\n{doc}"
            )
        return "\n\n".join(context_parts)
    except Exception as e:
        print(f"[rag] Retrieval error for '{finding_id}': {e}")
        return ""
    
def retrieve_for_finding(node:dict)->str:
    """
    Convenience wrapper — takes a finding node dict (as returned by Neo4j)
    and returns context string.
    """
    finding_id = node.get("id") or node.get("rule") or ""
    find_txt= node.get("text") or ""
    severity = node.get("severity") or ""
    source = node.get("source") or ""
    return retrieve_context(finding_id,find_txt,severity,source)

#Main function
if __name__ == "__main__":
    print("Seeding initiated for KB")
    count= seed_kb(force=True)

    print("\n[rag] Testing retrieval for B404 (subprocess)...")
    ctx = retrieve_context("B404", "import of subprocess module", "LOW", "bandit")
    print(ctx)

    print("\n[rag] Testing retrieval for hardcoded password...")
    ctx = retrieve_context("B105", "Possible hardcoded password", "LOW", "bandit")
    print(ctx)

    print("\n[rag] Testing retrieval for CWE-78 (command injection)...")
    ctx = retrieve_context("CWE-78", "OS command injection via user input", "HIGH", "trivy")
    print(ctx)