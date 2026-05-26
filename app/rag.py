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

from rank_bm25 import BM25Okapi
import numpy as np
load_dotenv()

try:
    import chromadb
    CHROMADB_AVAILABLE = True
except Exception:
    CHROMADB_AVAILABLE = False
    print("[rag] ChromaDB not available — RAG disabled")


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
    {"id": "cwe-798", "text": "CWE-798: Use of Hard-coded Credentials. The software contains hard-coded credentials such as a password or cryptographic key, which it uses for authentication or to protect sensitive data. Hard-coded credentials bypass proper credential management and cannot be rotated without a code change. Common in API tokens, database passwords, and encryption keys stored in source code.", "source": "cwe"},
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
#Query Expansion Map
# Manually curated expansions for common finding IDs.
# Adds domain-specific terms that improve vector search recall.
QUERY_EXPANSIONS = {
    "B404": "subprocess import command injection OS command execution shell",
    "B603": "subprocess Popen shell=False argument injection process execution",
    "B602": "subprocess shell=True command injection shell metacharacters",
    "B605": "os.system shell command injection process execution",
    "B607": "partial path PATH hijacking executable",
    "B110": "try except pass silent exception error handling logging",
    "B105": "hardcoded password credential secret plaintext",
    "B106": "hardcoded password function argument credential",
    "B107": "hardcoded password default argument credential",
    "B104": "binding network interface 0.0.0.0 exposure",
    "B301": "pickle deserialization arbitrary code execution",
    "B303": "MD5 SHA1 weak hash cryptography",
    "B304": "DES RC4 weak cipher encryption",
    "B307": "eval code injection arbitrary execution",
    "B311": "random cryptographic insecure token",
    "B324": "MD5 SHA1 weak hashing algorithm",
    "B501": "SSL certificate validation MITM",
    "B506": "yaml.load deserialization code execution",
    "B608": "SQL injection hardcoded query string",
    "B701": "Jinja2 autoescape XSS template injection",
    "hugging-face-access-token": "HuggingFace API token secret credential exposed",
    "generic-api-token": "API token secret credential hardcoded exposed",
    "aws-access-key": "AWS access key credential secret exposed",
    "B104": "binding 0.0.0.0 network interface exposure attack surface CWE-605",
}

#Source filter Map
# Maps finding ID prefixes to their knowledge base source.
# Prevents cross-source contamination in retrieval.
def get_source_filter(finding_id: str, source:str)-> dict | None:
    """
    Return ChromaDB where filter based on finding type.
    Bandit findings → only search bandit docs
    CVE findings → only search cwe docs
    Secret findings → search bandit + cwe docs
    """
    fid= finding_id.upper()
    if fid.startswith("B") and fid[1:].isdigit():
        return {"source":{"$in":["bandit","owasp"]}}
    if fid.startswith("CVE-") or fid.startswith("CWE-"):
        return {"source":{"$in" :["cwe","owasp"]}}

    return None

#BM25 index

_bm25_index=None
_bm25_docs=None

def get_bm25_index():
    """
    Build BM25 index over all knowledge base documents.
    Cached in module scope — built once per process.
    """
    global _bm25_index,_bm25_docs
    if _bm25_index is not None:
        return _bm25_index,_bm25_docs
    
    all_docs= CWE_DOCS +OWASP_DOCS + BANDIT_DOCS
    _bm25_docs=all_docs

    tokenized=[
        doc["text"].lower().replace(":"," ").replace("-"," ").split()
        for doc in all_docs
    ]
    _bm25_index=BM25Okapi(tokenized)
    return _bm25_index, _bm25_docs

def bm25_search(query:str, top_k: int=5)-> list[dict]:
    """
    BM25 keyword search over knowledge base.
    Returns list of {text, source, id, score} dicts sorted by score.
    """
    bm25,docs=get_bm25_index()
    tokens = query.lower().replace(":", " ").replace("-", " ").split()
    scores = bm25.get_scores(tokens)
    top_indices=np.argsort(scores)[::-1][:top_k]
    res=[]
    for idx in top_indices:
        if scores[idx] >0: 
            res.append({
                "text": docs[idx]["text"],
                "source": docs[idx]["source"],
                "id": docs[idx]["id"],
                "score": float(scores[idx])
            })
    return res

#Hybrid Retrieval
def retrieve_context(
    finding_id: str,
    find_txt: str,
    severity: str = "",
    source: str = "",
    top_k: int = TOP_K
) -> str:
    """
    Hybrid RAG retrieval combining:
    - Query expansion : enriches query with domain terms
    - Metadata filtering : restricts search to relevant source
    - BM25 + vector fusion : combines keyword and semantic search

    Args:
        finding_id: vulnerability/rule ID e.g. 'B404', 'CVE-2025-1234'
        find_txt:   description text of the finding
        severity:   severity level for context
        source:     scanner source (bandit/trivy/gitleaks)
        top_k:      number of documents to return

    Returns:
        Formatted context string ready to inject into LLM prompt
    """
    collection= get_collection()
    if collection.count() ==0:
        print("[rag] KB is empty - seeding...")
        seed_kb()
    
    #Query Expansion
    expansion = QUERY_EXPANSIONS.get(finding_id, "")
    query = f"{finding_id} {find_txt} {severity} {expansion}".strip()

    #Metadata filtering
    where_filter = get_source_filter(finding_id, source)

    #Vector Search
    try:
        vector_kwargs={
            "query_texts":[query],
            "n_results":min(top_k*2,collection.count()),
            "include":["documents","metadatas","distances"]
        }
        if where_filter:
            vector_kwargs["where"]=where_filter

        vector_res= collection.query(**vector_kwargs)
        vector_docs= vector_res["documents"][0]
        vector_metas=vector_res["metadatas"][0]
        vector_distances=vector_res["distances"][0]

        #Build scored candidates from vector search
        #Convert cosine distance to similiarity score(0-1)
        candidates={}
        for doc, meta, dist in zip(vector_docs, vector_metas, vector_distances):
            doc_id = meta.get("doc_id", "")
            vector_score = 1 - dist  # cosine similarity
            candidates[doc_id] = {
                "text": doc,
                "meta": meta,
                "vector_score": vector_score,
                "bm25_score": 0.0
            }
    except Exception as e:
        print(f"[rag] Vector search error for '{finding_id}': {e}")
        candidates = {}
    #BM-25  Search
    try:
        bm25_results= bm25_search(query,top_k=top_k*2)

        #Normalize
        max_bm25 = max((r["score"] for r in bm25_results), default=1.0)
        if max_bm25 ==0:
            max_bm25=1.0

        for res in bm25_results:
            doc_id = res["id"]
            normalized_bm25= res["score"]/max_bm25

            if doc_id in candidates:
                candidates[doc_id]["bm25_score"]=normalized_bm25
            else:
                candidates[doc_id] = {
                    "text": res["text"],
                    "meta": {"source": res["source"], "doc_id": doc_id},
                    "vector_score": 0.0,
                    "bm25_score": normalized_bm25
                }
    except Exception as e:
        print(f"[rag] BM25 search error: {e}")


    #Fusion Scoring
    # Weighted combination: vector (60%) + BM25 (40%)
    # BM25 is weighted lower because vector search handles semantic meaning better
    # BM25 is better at exact term matching (finding IDs, rule numbers)

    VECTOR_WEIGHT=0.6
    BM25_WEIGHT=0.4

    scored=[]
    for doc_id, data in candidates.items():
        fusion_score=(
            VECTOR_WEIGHT*data["vector_score"]+ BM25_WEIGHT*data["bm25_score"]
        )
        scored.append({
            "doc_id":       doc_id,
            "text":         data["text"],
            "meta":         data["meta"],
            "vector_score": data["vector_score"],
            "bm25_score":   data["bm25_score"],
            "fusion_score": fusion_score
        })

    scored.sort(key=lambda x: x["fusion_score"],reverse=True)
    top_results= scored[:top_k]

    if not top_results:
        return ""
    
    # Format context for LLM prompt
    context_parts = []
    for item in top_results:
        relevance    = round(item["fusion_score"] * 100, 1)
        source_label = item["meta"].get("source", "").upper()
        doc_id       = item["meta"].get("doc_id", "")
        context_parts.append(
            f"[{source_label}-{doc_id} | Relevance: {relevance}%]\n{item['text']}"
        )

    return "\n\n".join(context_parts)

def retrieve_for_finding(node: dict) -> str:
    """
    Convenience wrapper — takes a finding node dict (as returned by Neo4j)
    and returns context string.
    """
    finding_id = node.get("id") or node.get("rule") or ""
    find_txt   = node.get("text") or ""
    severity   = node.get("severity") or ""
    source     = node.get("source") or ""
    return retrieve_context(finding_id, find_txt, severity, source)

#Main function
if __name__ == "__main__":
    print("Seeding initiated for KB")
    count= seed_kb(force=True)

    print("\n[rag] Testing hybrid retrieval for B404 (subprocess)...")
    ctx = retrieve_context("B404", "import of subprocess module", "LOW", "bandit")
    print(ctx)

    print("\n[rag] Testing hybrid retrieval for hardcoded password...")
    ctx = retrieve_context("B105", "Possible hardcoded password", "LOW", "bandit")
    print(ctx)

    print("\n[rag] Testing retrieval for CVE (command injection)...")
    ctx = retrieve_context("CVE-2017-18342", "PyYAML arbitrary code execution", "CRITICAL", "trivy")
    print(ctx)