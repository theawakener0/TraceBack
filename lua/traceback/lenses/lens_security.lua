local U = require('traceback.lenses.utils')

local M = {}

-- improved helpers: Shannon entropy and stronger secret heuristics

local function shannon_entropy(s)
  if #s == 0 then return 0 end
  local counts = {}
  for i = 1, #s do
    local c = s:sub(i,i)
    counts[c] = (counts[c] or 0) + 1
  end
  local H = 0
  for _, v in pairs(counts) do
    local p = v / #s
    H = H - p * (math.log(p) / math.log(2))
  end
  return H
end

-- small helper to strip common wrappers/quotes/prefixes
local function normalize_token(s)
  if not s then return '' end
  s = s:gsub('^%s+', ''):gsub('%s+$', '')
  -- remove surrounding quotes/brackets
  s = s:gsub('^["\']', ''):gsub('["\']$', '')
  s = s:gsub('^%(', ''):gsub('%)$', '')
  -- strip common prefixes like "Bearer " or "token="
  s = s:gsub('^[Bb]earer%s+', '')
  s = s:gsub('^[Tt]oken%s*[:=]%s*', '')
  return s
end

-- heuristics to filter obvious false-positives (urls, paths, emails, small ids)
local function likely_false_positive(s)
  if s:match('^[%w]+://') then return true end -- URLs
  if s:match('[@%w%.%-]+%.[A-Za-z][A-Za-z]+') and s:match('@') then return true end -- emails
  if s:match('^/[%w%._%-/]+') or s:match('^[A-Za-z]:\\\\') then return true end -- file paths (unix/windows)
  if s:match('^%d+$') then return true end -- pure numbers
  if s:match('^[%w_]+%-%w+%-%w+%-%w+%-%w+$') then return false end -- keep UUID-like as possible secret? treat specially below
  return false
end

-- improved secret detector: checks base64-like, hex-like, known prefixes and entropy
local function looks_like_secret(matched, cfg)
  matched = matched or ''
  local cleaned = normalize_token(matched)
  -- drop common surrounding punctuation used in code
  cleaned = cleaned:gsub('[%s%p]+$', ''):gsub('^[%s%p]+', '')
  if #cleaned == 0 then return false end

  -- config-driven thresholds with sane defaults
  local min_entropy = (cfg and cfg.min_secret_entropy) or 4.0
  local min_len = (cfg and cfg.min_secret_len) or 20
  local min_len_hex = (cfg and cfg.min_secret_hex_len) or 32
  local min_len_short_token = (cfg and cfg.min_short_token_len) or 16

  -- quick false-positive filters
  if likely_false_positive(cleaned) then return false end

  -- private key blocks are definitely secrets
  if cleaned:match('^-----BEGIN% .+KEY-----') then return true end

  -- known token prefixes (AWS, Slack, JWT starting 'eyJ' etc.)
  if cleaned:match('^AKIA[%w]+') then return true end
  if cleaned:match('^xox[baprs]%-[%w%-]+') then return true end
  if cleaned:match('^eyJ') and #cleaned >= 20 then return true end -- common JWT base64 header start

  -- hex-like: long hex blobs are suspicious
  if cleaned:match('^[0-9a-fA-F]+$') then
    if #cleaned >= min_len_hex then return true end
    -- allow slightly shorter hex if entropy is high
    local H = shannon_entropy(cleaned)
    if #cleaned >= min_len and H >= (min_entropy - 0.5) then return true end
    return false
  end

  -- base64-like (standard and URL-safe): letters, digits, +/=- or -_=
  if cleaned:match('^[A-Za-z0-9%+%/%=]+$') or cleaned:match('^[A-Za-z0-9%-%_%=]+$') then
    if #cleaned >= min_len_short_token then
      local H = shannon_entropy(cleaned)
      -- normalized: base64 alphabet entropy ~6 bits/char, so require a fraction of that
      if H >= min_entropy then return true end
    end
    return false
  end

  -- fallback: require both length and entropy for generic tokens
  if #cleaned >= min_len then
    local H = shannon_entropy(cleaned)
    if H >= min_entropy then return true end
  end

  return false
end

local insecure_by_ft = {
  c = {
    -- Command injection and execution
    { pat = 'system%(', msg = 'system call (CVE prone command injection)', hl = 'DiagnosticError' },
    { pat = 'popen%(', msg = 'popen call (command injection risk)', hl = 'DiagnosticError' },
    { pat = 'execl?%w*%(', msg = 'exec family (process spawn security risk)', hl = 'DiagnosticWarn' },
    
    -- Buffer overflow vulnerabilities (CWE-119, CWE-120, CWE-125)
    { pat = 'gets%s*%(', msg = 'gets (CWE-120: buffer overflow)', hl = 'DiagnosticError' },
    { pat = 'strcpy%s*%(', msg = 'strcpy (CWE-120: buffer overflow)', hl = 'DiagnosticError' },
    { pat = 'strcat%s*%(', msg = 'strcat (CWE-120: buffer overflow)', hl = 'DiagnosticError' },
    { pat = 'sprintf%s*%(', msg = 'sprintf (CWE-120: buffer overflow)', hl = 'DiagnosticError' },
    { pat = 'vsprintf%s*%(', msg = 'vsprintf (CWE-120: buffer overflow)', hl = 'DiagnosticError' },
    
    -- Memory management issues
    { pat = 'memcpy%s*%(', msg = 'memcpy (CWE-119: verify bounds/overlap)', hl = 'DiagnosticWarn' },
    { pat = 'memmove%s*%(', msg = 'memmove (verify bounds/overlap)', hl = 'DiagnosticWarn' },
    { pat = 'strncpy%s*%(', msg = 'strncpy (CWE-170: ensure null-termination)', hl = 'DiagnosticWarn' },
    { pat = 'strncat%s*%(', msg = 'strncat (CWE-193: off-by-one error risk)', hl = 'DiagnosticWarn' },
    { pat = 'snprintf%s*%(', msg = 'snprintf (verify buffer bounds)', hl = 'DiagnosticWarn' },
    
    -- Format string vulnerabilities (CWE-134)
    { pat = 'printf%s*%([^,%)]*["\']?[^,%)]*%?[^,%)]*["\']?[^,%)]*%)', msg = 'printf (CWE-134: format string vulnerability)', hl = 'DiagnosticWarn' },
    { pat = 'fprintf%s*%(', msg = 'fprintf (CWE-134: format string risk)', hl = 'DiagnosticWarn' },
    { pat = 'syslog%s*%(', msg = 'syslog (format string vulnerability)', hl = 'DiagnosticWarn' },
    
    -- Input validation issues (CWE-20)
    { pat = 'scanf%s*%(', msg = 'scanf (CWE-20: input validation)', hl = 'DiagnosticWarn' },
    { pat = 'sscanf%s*%(', msg = 'sscanf (input validation required)', hl = 'DiagnosticWarn' },
    { pat = 'atoi%s*%(', msg = 'atoi (no error checking)', hl = 'DiagnosticWarn' },
    { pat = 'atol%s*%(', msg = 'atol (no error checking)', hl = 'DiagnosticWarn' },
    
    -- File and I/O operations
    { pat = 'fopen%s*%(', msg = 'fopen (verify mode and path)', hl = 'DiagnosticWarn' },
    { pat = 'open%s*%(', msg = 'open (verify flags/permissions)', hl = 'DiagnosticWarn' },
    { pat = 'tmpnam%s*%(', msg = 'tmpnam (race condition risk)', hl = 'DiagnosticWarn' },
    { pat = 'mktemp%s*%(', msg = 'mktemp (race condition risk)', hl = 'DiagnosticWarn' },
    
    -- Memory allocation issues (CWE-401, CWE-415, CWE-416)
    { pat = 'malloc%s*%(', msg = 'malloc (check for leaks/double-free)', hl = 'DiagnosticInfo' },
    { pat = 'calloc%s*%(', msg = 'calloc (check for leaks)', hl = 'DiagnosticInfo' },
    { pat = 'realloc%s*%(', msg = 'realloc (check return value)', hl = 'DiagnosticInfo' },
    { pat = 'free%s*%(', msg = 'free (CWE-415: double-free risk)', hl = 'DiagnosticInfo' },
    
    -- Integer overflow risks (CWE-190)
    { pat = 'size_t.*%+', msg = 'size_t arithmetic (integer overflow risk)', hl = 'DiagnosticWarn' },
    { pat = 'unsigned.*%*', msg = 'unsigned multiplication (overflow risk)', hl = 'DiagnosticWarn' },
    
    -- Environment and system access
    { pat = 'getenv%s*%(', msg = 'getenv (sensitive environment variables)', hl = 'DiagnosticWarn' },
    { pat = 'setuid%s*%(', msg = 'setuid (privilege escalation risk)', hl = 'DiagnosticWarn' },
    { pat = 'setgid%s*%(', msg = 'setgid (privilege escalation risk)', hl = 'DiagnosticWarn' },
    
    -- Network security
    { pat = 'http://', msg = 'insecure HTTP (use HTTPS)', hl = 'DiagnosticWarn' },
    { pat = 'socket%s*%(', msg = 'socket creation (verify security)', hl = 'DiagnosticInfo' },
  },
  cpp = {
    -- Command injection and process execution
    { pat = 'std::system%(', msg = 'std::system (CWE-78: command injection)', hl = 'DiagnosticError' },
    { pat = 'system%(', msg = 'system call (command injection)', hl = 'DiagnosticError' },
    { pat = 'std::popen%(', msg = 'std::popen (command injection)', hl = 'DiagnosticError' },
    { pat = 'popen%(', msg = 'popen call (command injection)', hl = 'DiagnosticError' },
    { pat = 'execv[%w_]*%(', msg = 'exec family (process spawn)', hl = 'DiagnosticWarn' },
    { pat = 'fork%(', msg = 'fork (careful with exec/state)', hl = 'DiagnosticWarn' },

    -- Buffer overflow vulnerabilities (CWE-119, CWE-120)
    { pat = 'gets%s*%(', msg = 'gets (CWE-120: buffer overflow)', hl = 'DiagnosticError' },
    { pat = 'strcpy%s*%(', msg = 'strcpy (CWE-120: buffer overflow)', hl = 'DiagnosticError' },
    { pat = 'strcat%s*%(', msg = 'strcat (CWE-120: buffer overflow)', hl = 'DiagnosticError' },
    { pat = 'sprintf%s*%(', msg = 'sprintf (CWE-120: buffer overflow)', hl = 'DiagnosticError' },
    { pat = 'vsprintf%s*%(', msg = 'vsprintf (CWE-120: buffer overflow)', hl = 'DiagnosticError' },

    -- Memory management (CWE-119, CWE-401, CWE-415, CWE-416)
    { pat = 'memcpy%s*%(', msg = 'memcpy (CWE-119: verify bounds)', hl = 'DiagnosticWarn' },
    { pat = 'memmove%s*%(', msg = 'memmove (verify bounds)', hl = 'DiagnosticWarn' },
    { pat = 'strncpy%s*%(', msg = 'strncpy (CWE-170: null-termination)', hl = 'DiagnosticWarn' },
    { pat = 'std::memcpy%s*%(', msg = 'std::memcpy (verify bounds)', hl = 'DiagnosticWarn' },
    
    -- C++ specific memory issues
    { pat = 'delete%s+%w+;.*delete%s+%w+', msg = 'potential double delete (CWE-415)', hl = 'DiagnosticError' },
    { pat = 'new%s+[%w_]+%[', msg = 'new[] allocation (ensure delete[])', hl = 'DiagnosticInfo' },
    { pat = 'std::unique_ptr.*%.reset%(', msg = 'unique_ptr reset (check usage)', hl = 'DiagnosticInfo' },
    
    -- Format string and input validation
    { pat = 'printf%s*%(', msg = 'printf (CWE-134: format string)', hl = 'DiagnosticWarn' },
    { pat = 'scanf%s*%(', msg = 'scanf (CWE-20: input validation)', hl = 'DiagnosticWarn' },
    { pat = 'std::cin%s*>>', msg = 'std::cin (validate input bounds)', hl = 'DiagnosticWarn' },

    -- File operations
    { pat = 'fopen%s*%(', msg = 'fopen (verify mode and path)', hl = 'DiagnosticWarn' },
    { pat = 'open%s*%(', msg = 'open (verify flags/permissions)', hl = 'DiagnosticWarn' },
    { pat = 'std::fstream', msg = 'fstream (check file permissions)', hl = 'DiagnosticWarn' },
    { pat = 'std::ifstream', msg = 'ifstream (validate file source)', hl = 'DiagnosticInfo' },
    { pat = 'std::ofstream', msg = 'ofstream (check write permissions)', hl = 'DiagnosticInfo' },

    -- Environment access
    { pat = 'getenv%s*%(', msg = 'getenv (sensitive environment access)', hl = 'DiagnosticWarn' },
    { pat = 'std::getenv%s*%(', msg = 'std::getenv (environment access)', hl = 'DiagnosticWarn' },

    -- Regex and DoS vulnerabilities
    { pat = 'std::regex', msg = 'std::regex (CWE-1333: ReDoS risk)', hl = 'DiagnosticWarn' },
    { pat = 'std::regex_match', msg = 'regex_match (ReDoS with untrusted input)', hl = 'DiagnosticWarn' },
    { pat = 'std::regex_search', msg = 'regex_search (ReDoS risk)', hl = 'DiagnosticWarn' },

    -- Network security
    { pat = 'http://', msg = 'insecure HTTP (use HTTPS)', hl = 'DiagnosticWarn' },

    -- Unsafe casting (CWE-704)
    { pat = 'reinterpret_cast%<', msg = 'reinterpret_cast (CWE-704: unsafe cast)', hl = 'DiagnosticWarn' },
    { pat = 'const_cast%<', msg = 'const_cast (review const-correctness)', hl = 'DiagnosticInfo' },
    { pat = 'static_cast%<.*%(.*%-', msg = 'static_cast with negative (sign issues)', hl = 'DiagnosticWarn' },
    
    -- Integer overflow (CWE-190)
    { pat = 'size_t.*%+', msg = 'size_t arithmetic (CWE-190: overflow)', hl = 'DiagnosticWarn' },
    { pat = 'unsigned.*%*', msg = 'unsigned multiplication (overflow)', hl = 'DiagnosticWarn' },
    
    -- Concurrency issues
    { pat = 'volatile', msg = 'volatile use (review concurrency)', hl = 'DiagnosticInfo' },
    { pat = 'std::thread', msg = 'std::thread (check synchronization)', hl = 'DiagnosticInfo' },
    { pat = 'std::mutex.*%.lock%(', msg = 'mutex lock (ensure unlock)', hl = 'DiagnosticInfo' },
  },
  lua = {
    { pat = '%f[%w]os%.execute%f[^%w]%(', msg = 'shell exec', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]io%.popen%f[^%w]%(', msg = 'shell popen', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]os%.getenv%f[^%w]%(', msg = 'os.getenv (sensitive env)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]loadstring%f[^%w]%(', msg = 'loadstring (exec arbitrary code)', hl = 'DiagnosticError' },
    { pat = '%f[%w]load%f[^%w]%(', msg = 'load (exec arbitrary code)', hl = 'DiagnosticError' },
    { pat = '%f[%w]loadfile%f[^%w]%(', msg = 'loadfile (exec file contents)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]dofile%f[^%w]%(', msg = 'dofile (exec file contents)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]io%.open%f[^%w]%(', msg = 'io.open (file access)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]os%.remove%f[^%w]%(', msg = 'os.remove (file delete)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]os%.rename%f[^%w]%(', msg = 'os.rename (file rename)', hl = 'DiagnosticWarn' },
    { pat = 'http://', msg = 'insecure http', hl = 'DiagnosticWarn' },
    { pat = 'socket%.http', msg = 'socket.http (HTTP request library)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]package%.loadlib%f[^%w]%(', msg = 'package.loadlib (dynamic native module)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]debug%.[%w_]+', msg = 'debug library use (exposes internals)', hl = 'DiagnosticInfo' },
    { pat = '%f[%w]require%s*%b()', msg = 'require call (watch dynamic module names)', hl = 'DiagnosticInfo' },
  },
  python = {
    -- Code execution vulnerabilities (CWE-94)
    { pat = '%f[%w]eval%f[^%w]%(', msg = 'eval (CWE-94: code injection)', hl = 'DiagnosticError' },
    { pat = '%f[%w]exec%f[^%w]%(', msg = 'exec (CWE-94: code injection)', hl = 'DiagnosticError' },
    { pat = '%f[%w]execfile%f[^%w]%(', msg = 'execfile (py2, code execution)', hl = 'DiagnosticError' },
    { pat = '%f[%w]compile%f[^%w]%(', msg = 'compile (code generation/execution)', hl = 'DiagnosticWarn' },
    { pat = '__import__%s*%(', msg = '__import__ (dynamic import risk)', hl = 'DiagnosticWarn' },

    -- Command injection (CWE-78)
    { pat = '%f[%w]subprocess%.Popen%f[^%w]%(', msg = 'subprocess.Popen (CWE-78: command injection)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]subprocess%.run%f[^%w]%(', msg = 'subprocess.run (command injection)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]subprocess%.call%f[^%w]%(', msg = 'subprocess.call (command injection)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]subprocess%.check_call%f[^%w]%(', msg = 'subprocess.check_call (command injection)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]subprocess%.check_output%f[^%w]%(', msg = 'subprocess.check_output (command injection)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]Popen%f[^%w]%(', msg = 'Popen (imported from subprocess)', hl = 'DiagnosticWarn' },
    { pat = 'shell%s*=%s*True', msg = 'shell=True (CWE-78: shell injection)', hl = 'DiagnosticError' },
    { pat = '%f[%w]os%.system%f[^%w]%(', msg = 'os.system (command injection)', hl = 'DiagnosticError' },
    { pat = '%f[%w]os%.popen%f[^%w]%(', msg = 'os.popen (command injection)', hl = 'DiagnosticWarn' },

    -- Deserialization vulnerabilities (CWE-502)
    { pat = 'pickle%.loads%(', msg = 'pickle.loads (CWE-502: deserialization)', hl = 'DiagnosticError' },
    { pat = 'pickle%.load%(', msg = 'pickle.load (CWE-502: deserialization)', hl = 'DiagnosticError' },
    { pat = 'cPickle%.loads%(', msg = 'cPickle.loads (deserialization)', hl = 'DiagnosticError' },
    { pat = 'cPickle%.load%(', msg = 'cPickle.load (deserialization)', hl = 'DiagnosticError' },
    { pat = 'marshal%.loads%(', msg = 'marshal.loads (deserialization)', hl = 'DiagnosticError' },
    { pat = 'shelve%.open%(', msg = 'shelve.open (deserialization risk)', hl = 'DiagnosticWarn' },
    { pat = 'yaml%.load%(', msg = 'yaml.load (CWE-502: use yaml.safe_load)', hl = 'DiagnosticError' },
    { pat = 'yaml%.unsafe_load%(', msg = 'yaml.unsafe_load (deserialization)', hl = 'DiagnosticError' },

    -- Network and TLS vulnerabilities
    { pat = 'http://', msg = 'insecure HTTP (use HTTPS)', hl = 'DiagnosticWarn' },
    { pat = 'verify%s*=%s*False', msg = 'TLS verification disabled (CWE-295)', hl = 'DiagnosticError' },
    { pat = 'ssl_verify%s*=%s*False', msg = 'SSL verification disabled', hl = 'DiagnosticError' },
    { pat = 'check_hostname%s*=%s*False', msg = 'hostname verification disabled', hl = 'DiagnosticWarn' },
    { pat = 'requests%.[%w_]+%b()', msg = 'requests call (check verify/timeout)', hl = 'DiagnosticWarn' },
    { pat = 'urllib%.request%.urlopen%(', msg = 'urlopen (verify SSL context)', hl = 'DiagnosticWarn' },

    -- File and path operations (CWE-22)
    { pat = '%f[%w]open%f[^%w]%(', msg = 'open (CWE-22: path traversal)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]os%.remove%f[^%w]%(', msg = 'os.remove (verify path)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]os%.rename%f[^%w]%(', msg = 'os.rename (verify paths)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]os%.path%.join%f[^%w]%(', msg = 'os.path.join (check for ../ traversal)', hl = 'DiagnosticInfo' },
    { pat = 'shutil%.rmtree%(', msg = 'shutil.rmtree (verify path)', hl = 'DiagnosticWarn' },

    -- Cryptographic issues (CWE-327, CWE-328)
    { pat = 'hashlib%.md5%(', msg = 'MD5 (CWE-328: weak hash)', hl = 'DiagnosticWarn' },
    { pat = 'hashlib%.sha1%(', msg = 'SHA1 (CWE-328: weak hash)', hl = 'DiagnosticWarn' },
    { pat = 'random%.random%(', msg = 'random.random (not cryptographically secure)', hl = 'DiagnosticWarn' },
    { pat = 'random%.randint%(', msg = 'random.randint (not cryptographically secure)', hl = 'DiagnosticWarn' },

    -- Native code extensions (potential memory issues)
    { pat = '%f[%w]ctypes%.CDLL%f[^%w]%(', msg = 'ctypes.CDLL (native code risk)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]ctypes%.PyDLL%f[^%w]%(', msg = 'ctypes.PyDLL (native code risk)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]ctypes%.windll', msg = 'ctypes.windll (Windows DLL access)', hl = 'DiagnosticWarn' },

    -- XML vulnerabilities (CWE-611)
    { pat = 'ElementTree%.parse%(', msg = 'XML parsing (CWE-611: XXE risk)', hl = 'DiagnosticWarn' },
    { pat = 'ElementTree%.fromstring%(', msg = 'XML fromstring (XXE risk)', hl = 'DiagnosticWarn' },
    { pat = 'xml%.etree%.', msg = 'XML parsing (check for XXE)', hl = 'DiagnosticWarn' },
    { pat = 'xml%.sax', msg = 'SAX parser (XXE risk)', hl = 'DiagnosticWarn' },
    { pat = 'xml%.dom%.minidom', msg = 'minidom (XXE risk)', hl = 'DiagnosticWarn' },

    -- SQL injection (CWE-89)
    { pat = 'cursor%.execute%(', msg = 'SQL execute (CWE-89: injection risk)', hl = 'DiagnosticWarn' },
    { pat = '%.execute%s*%(%s*["\'].*%+', msg = 'SQL execute with concatenation (injection)', hl = 'DiagnosticError' },
    { pat = '%.execute%s*%(%s*f["\']', msg = 'SQL execute with f-string (injection)', hl = 'DiagnosticError' },
    { pat = '%.execute%s*%(%s*["\'].*%{', msg = 'SQL execute with format (injection)', hl = 'DiagnosticError' },

    -- Path traversal and input validation (CWE-20)
    { pat = '%.%./%.%./', msg = 'path traversal pattern (CWE-22)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]input%f[^%w]%(', msg = 'input (CWE-20: validate user input)', hl = 'DiagnosticInfo' },
    { pat = '%f[%w]raw_input%f[^%w]%(', msg = 'raw_input (py2, validate input)', hl = 'DiagnosticInfo' },

    -- Template injection (CWE-94)
    { pat = 'Template%.render%(', msg = 'template render (injection risk)', hl = 'DiagnosticWarn' },
    { pat = 'jinja2%.Template', msg = 'Jinja2 template (SSTI risk)', hl = 'DiagnosticWarn' },
    
    -- Regular expression DoS (CWE-1333)
    { pat = 're%.compile%s*%(["\'].*%*.*%*', msg = 'regex (CWE-1333: ReDoS risk)', hl = 'DiagnosticWarn' },
    { pat = 're%.match%s*%(["\'].*%*.*%*', msg = 'regex match (ReDoS risk)', hl = 'DiagnosticWarn' },
    
    -- Django specific vulnerabilities
    { pat = 'mark_safe%(', msg = 'mark_safe (XSS risk)', hl = 'DiagnosticWarn' },
    { pat = 'django%.utils%.safestring', msg = 'safestring (XSS risk)', hl = 'DiagnosticWarn' },
    { pat = 'extra%s*=%s*%{', msg = 'Django extra (SQL injection risk)', hl = 'DiagnosticWarn' },
  },
  javascript = {
    -- Code execution vulnerabilities (CWE-94)
    { pat = '%f[%w]eval%f[^%w]%(', msg = 'eval (CWE-94: code injection)', hl = 'DiagnosticError' },
    { pat = 'Function%s*%(', msg = 'Function constructor (code execution)', hl = 'DiagnosticError' },
    { pat = 'new%s+Function%(', msg = 'Function constructor (code execution)', hl = 'DiagnosticError' },
    { pat = 'setTimeout%s*%(%s*["\']', msg = 'setTimeout with string (code execution)', hl = 'DiagnosticError' },
    { pat = 'setInterval%s*%(%s*["\']', msg = 'setInterval with string (code execution)', hl = 'DiagnosticError' },

    -- XSS vulnerabilities (CWE-79)
    { pat = '%f[%w]document%.write%f[^%w]%(', msg = 'document.write (CWE-79: XSS risk)', hl = 'DiagnosticError' },
    { pat = '%f[%w]document%.writeln%f[^%w]%(', msg = 'document.writeln (XSS risk)', hl = 'DiagnosticError' },
    { pat = 'innerHTML%s*=', msg = 'innerHTML assignment (CWE-79: XSS)', hl = 'DiagnosticWarn' },
    { pat = 'outerHTML%s*=', msg = 'outerHTML assignment (XSS risk)', hl = 'DiagnosticWarn' },
    { pat = 'insertAdjacentHTML%s*%(', msg = 'insertAdjacentHTML (XSS risk)', hl = 'DiagnosticWarn' },
    { pat = 'dangerouslySetInnerHTML', msg = 'dangerouslySetInnerHTML (React XSS)', hl = 'DiagnosticError' },
    { pat = 'v%-html', msg = 'v-html directive (Vue.js XSS risk)', hl = 'DiagnosticWarn' },

    -- Command injection (Node.js) (CWE-78)
    { pat = 'child_process%.[%w_]+%(', msg = 'child_process (CWE-78: command injection)', hl = 'DiagnosticWarn' },
    { pat = 'require%(%s*[\'"]child_process[\'"]%s*%)', msg = 'require("child_process") (command injection)', hl = 'DiagnosticWarn' },
    { pat = 'execSync%(', msg = 'execSync (command injection)', hl = 'DiagnosticWarn' },
    { pat = 'exec%(', msg = 'exec (command injection risk)', hl = 'DiagnosticWarn' },
    { pat = 'spawn%(', msg = 'spawn (verify command arguments)', hl = 'DiagnosticWarn' },

    -- Network security
    { pat = 'fetch%(%s*["\']http://', msg = 'fetch over HTTP (use HTTPS)', hl = 'DiagnosticWarn' },
    { pat = 'XMLHttpRequest%.open%(%s*["\'].*["\']%s*,%s*["\']http://', msg = 'XHR over HTTP (use HTTPS)', hl = 'DiagnosticWarn' },
    { pat = 'http://', msg = 'insecure HTTP (use HTTPS)', hl = 'DiagnosticWarn' },
    { pat = 'fetch%([^)]*verify%s*:%s*false', msg = 'fetch with disabled verification', hl = 'DiagnosticWarn' },

    -- Cookie security (CWE-1004)
    { pat = 'document%.cookie%s*=', msg = 'document.cookie (CWE-1004: check flags)', hl = 'DiagnosticWarn' },
    { pat = 'Set%-Cookie:[^;]*;[^;]*httponly', msg = 'Set-Cookie without HttpOnly', hl = 'DiagnosticWarn' },
    { pat = 'Set%-Cookie:[^;]*;[^;]*secure', msg = 'Set-Cookie without Secure flag', hl = 'DiagnosticWarn' },

    -- Environment variable exposure (Node.js)
    { pat = 'process%.env%.[%w_]+', msg = 'process.env access (secret exposure)', hl = 'DiagnosticWarn' },
    { pat = 'process%.env%[', msg = 'process.env access (secret exposure)', hl = 'DiagnosticWarn' },

    -- Cryptographic issues (CWE-327, CWE-328)
    { pat = 'crypto%.createHash%(%s*[\'\"]md5', msg = 'MD5 hash (CWE-328: weak)', hl = 'DiagnosticWarn' },
    { pat = 'crypto%.createHash%(%s*[\'\"]sha1', msg = 'SHA1 hash (CWE-328: weak)', hl = 'DiagnosticWarn' },
    { pat = 'Math%.random%(', msg = 'Math.random (not cryptographically secure)', hl = 'DiagnosticWarn' },

    -- Regular expression DoS (CWE-1333)
    { pat = 'new%s+RegExp%(', msg = 'RegExp (CWE-1333: ReDoS risk)', hl = 'DiagnosticWarn' },
    { pat = 'RegExp%s*%(', msg = 'RegExp (ReDoS with untrusted input)', hl = 'DiagnosticWarn' },
    { pat = '%.match%s*%(/.*%*.*%*/', msg = 'regex match (ReDoS risk)', hl = 'DiagnosticWarn' },

    -- Prototype pollution (CWE-1321)
    { pat = '__proto__', msg = '__proto__ (CWE-1321: prototype pollution)', hl = 'DiagnosticError' },
    { pat = 'constructor%.prototype', msg = 'constructor.prototype (pollution risk)', hl = 'DiagnosticWarn' },
    { pat = 'Object%.setPrototypeOf', msg = 'Object.setPrototypeOf (prototype pollution)', hl = 'DiagnosticWarn' },

    -- URL parsing and validation (CWE-20)
    { pat = 'new%s+URL%(', msg = 'URL constructor (validate input)', hl = 'DiagnosticWarn' },
    { pat = 'location%.href%s*=', msg = 'location.href assignment (open redirect)', hl = 'DiagnosticWarn' },
    { pat = 'window%.location%s*=', msg = 'window.location (open redirect risk)', hl = 'DiagnosticWarn' },

    -- File system access (Node.js) (CWE-22)
    { pat = 'fs%.readFile%(', msg = 'fs.readFile (CWE-22: path traversal)', hl = 'DiagnosticWarn' },
    { pat = 'fs%.writeFile%(', msg = 'fs.writeFile (path traversal)', hl = 'DiagnosticWarn' },
    { pat = 'fs%.readFileSync%(', msg = 'fs.readFileSync (path traversal)', hl = 'DiagnosticWarn' },
    { pat = 'fs%.writeFileSync%(', msg = 'fs.writeFileSync (path traversal)', hl = 'DiagnosticWarn' },
    { pat = 'path%.join%([^)]*%.%./%.%./', msg = 'path.join with traversal (CWE-22)', hl = 'DiagnosticWarn' },

    -- SQL injection (when using template literals)
    { pat = '%.query%s*%(`.*%${', msg = 'SQL query with template literal (injection)', hl = 'DiagnosticError' },
    { pat = '%.execute%s*%(`.*%${', msg = 'SQL execute with template literal (injection)', hl = 'DiagnosticError' },

    -- Deserialization (CWE-502)
    { pat = 'JSON%.parse%(', msg = 'JSON.parse (validate input source)', hl = 'DiagnosticWarn' },
    { pat = 'eval%s*%(%s*JSON', msg = 'eval with JSON (use JSON.parse)', hl = 'DiagnosticError' },

    -- React/JSX specific
    { pat = 'dangerouslySetInnerHTML', msg = 'dangerouslySetInnerHTML (XSS risk)', hl = 'DiagnosticError' },
    { pat = 'React%.createElement%s*%([^,]*,%s*{[^}]*dangerously', msg = 'React.createElement with dangerous props', hl = 'DiagnosticWarn' },

    -- Vue.js specific
    { pat = 'v%-html%s*=', msg = 'v-html directive (XSS risk)', hl = 'DiagnosticWarn' },

    -- General execution context
    { pat = 'eval%.call', msg = 'eval.call (code execution)', hl = 'DiagnosticError' },
    { pat = 'eval%.apply', msg = 'eval.apply (code execution)', hl = 'DiagnosticError' },
  },
  go = {
    -- Command injection and process execution (CWE-78)
    { pat = 'exec%.Command%(', msg = 'exec.Command (CWE-78: command injection)', hl = 'DiagnosticWarn' },
    { pat = 'exec%.CommandContext%(', msg = 'exec.CommandContext (command injection)', hl = 'DiagnosticWarn' },
    { pat = 'syscall%.Exec%(', msg = 'syscall.Exec (process replacement)', hl = 'DiagnosticWarn' },
    { pat = 'syscall%.ForkExec%(', msg = 'syscall.ForkExec (process spawn)', hl = 'DiagnosticWarn' },
    { pat = 'exec%.LookPath%(', msg = 'exec.LookPath (executable lookup)', hl = 'DiagnosticInfo' },
    { pat = '%.CombinedOutput%(', msg = 'Command.CombinedOutput (process exec)', hl = 'DiagnosticWarn' },
    { pat = '%.Output%(', msg = 'Command.Output (process exec)', hl = 'DiagnosticWarn' },
    { pat = '%.Run%(', msg = 'Command.Run (process execution)', hl = 'DiagnosticWarn' },
    { pat = '%.Start%(', msg = 'Command.Start (async process execution)', hl = 'DiagnosticWarn' },

    -- Network security
    { pat = 'http://', msg = 'insecure HTTP (use HTTPS)', hl = 'DiagnosticWarn' },
    { pat = 'http%.Get%(%s*[\'"]http://', msg = 'http.Get over HTTP (insecure)', hl = 'DiagnosticWarn' },
    { pat = 'http%.Post%(%s*[\'"]http://', msg = 'http.Post over HTTP (insecure)', hl = 'DiagnosticWarn' },
    { pat = 'http%.NewRequest%(.*[\'"]http://', msg = 'http.NewRequest over HTTP (insecure)', hl = 'DiagnosticWarn' },

    -- TLS/SSL security (CWE-295)
    { pat = 'InsecureSkipVerify%s*[:=]%s*true', msg = 'TLS InsecureSkipVerify (CWE-295)', hl = 'DiagnosticError' },
    { pat = 'SkipVerify%s*:%s*true', msg = 'TLS SkipVerify enabled', hl = 'DiagnosticError' },
    { pat = 'tls%.Config.*InsecureSkipVerify', msg = 'TLS config with skip verify', hl = 'DiagnosticWarn' },

    -- Cryptographic issues (CWE-327, CWE-328)
    { pat = 'md5%.New', msg = 'MD5 hash (CWE-328: weak hash)', hl = 'DiagnosticWarn' },
    { pat = 'sha1%.New', msg = 'SHA1 hash (CWE-328: weak hash)', hl = 'DiagnosticWarn' },
    { pat = 'crypto/md5', msg = 'importing crypto/md5 (weak hash)', hl = 'DiagnosticWarn' },
    { pat = 'crypto/sha1', msg = 'importing crypto/sha1 (weak hash)', hl = 'DiagnosticWarn' },
    { pat = 'crypto/des', msg = 'importing crypto/des (weak cipher)', hl = 'DiagnosticWarn' },
    { pat = 'math/rand', msg = 'math/rand (not cryptographically secure)', hl = 'DiagnosticWarn' },

    -- SQL injection (CWE-89)
    { pat = 'db%.Exec%(', msg = 'db.Exec (CWE-89: SQL injection risk)', hl = 'DiagnosticWarn' },
    { pat = 'DB%.Exec%(', msg = 'DB.Exec (SQL injection risk)', hl = 'DiagnosticWarn' },
    { pat = 'db%.Query%(', msg = 'db.Query (SQL injection risk)', hl = 'DiagnosticWarn' },
    { pat = 'db%.QueryRow%(', msg = 'db.QueryRow (SQL injection risk)', hl = 'DiagnosticWarn' },
    { pat = 'sql%.Open%(', msg = 'sql.Open (verify credentials/connection)', hl = 'DiagnosticWarn' },
    { pat = 'fmt%.Sprintf%(.*SELECT', msg = 'fmt.Sprintf with SQL (injection)', hl = 'DiagnosticError' },
    { pat = 'fmt%.Sprintf%(.*INSERT', msg = 'fmt.Sprintf with SQL (injection)', hl = 'DiagnosticError' },
    { pat = 'fmt%.Sprintf%(.*UPDATE', msg = 'fmt.Sprintf with SQL (injection)', hl = 'DiagnosticError' },
    { pat = 'fmt%.Sprintf%(.*DELETE', msg = 'fmt.Sprintf with SQL (injection)', hl = 'DiagnosticError' },

    -- Path traversal and file operations (CWE-22)
    { pat = 'os%.Open%(', msg = 'os.Open (CWE-22: path traversal)', hl = 'DiagnosticWarn' },
    { pat = 'os%.Create%(', msg = 'os.Create (verify file path)', hl = 'DiagnosticWarn' },
    { pat = 'os%.Remove%(', msg = 'os.Remove (verify file path)', hl = 'DiagnosticWarn' },
    { pat = 'os%.RemoveAll%(', msg = 'os.RemoveAll (verify directory path)', hl = 'DiagnosticWarn' },
    { pat = 'ioutil%.ReadFile%(', msg = 'ioutil.ReadFile (path traversal)', hl = 'DiagnosticWarn' },
    { pat = 'ioutil%.WriteFile%(', msg = 'ioutil.WriteFile (verify path)', hl = 'DiagnosticWarn' },
    { pat = 'filepath%.Join%([^)]*%.%./%.%./', msg = 'filepath.Join with traversal (CWE-22)', hl = 'DiagnosticWarn' },

    -- Environment variable access
    { pat = 'os%.Getenv%(', msg = 'os.Getenv (sensitive environment access)', hl = 'DiagnosticWarn' },
    { pat = 'os%.Setenv%(', msg = 'os.Setenv (environment modification)', hl = 'DiagnosticWarn' },

    -- Memory safety with unsafe package (CWE-119)
    { pat = 'import%s+[\'"]C[\'"]', msg = 'cgo usage (CWE-119: memory safety)', hl = 'DiagnosticWarn' },
    { pat = 'unsafe%.', msg = 'unsafe package (CWE-119: memory safety)', hl = 'DiagnosticWarn' },
    { pat = 'unsafe%.Pointer', msg = 'unsafe.Pointer (memory safety risk)', hl = 'DiagnosticWarn' },

    -- Template injection (CWE-94)
    { pat = 'text/template', msg = 'text/template (CWE-94: no auto HTML escaping)', hl = 'DiagnosticWarn' },
    { pat = 'template%.Execute%(', msg = 'template Execute (injection risk)', hl = 'DiagnosticWarn' },
    { pat = 'template%.New%(.*%.Parse%(', msg = 'template parsing (validate source)', hl = 'DiagnosticWarn' },

    -- Regular expression DoS (CWE-1333)
    { pat = 'regexp%.Compile%s*%(["\'].*%*.*%*', msg = 'regexp.Compile (CWE-1333: ReDoS)', hl = 'DiagnosticWarn' },
    { pat = 'regexp%.MustCompile%s*%(["\'].*%*.*%*', msg = 'regexp.MustCompile (ReDoS risk)', hl = 'DiagnosticWarn' },

    -- XML parsing vulnerabilities (CWE-611)
    { pat = 'xml%.Unmarshal%(', msg = 'xml.Unmarshal (CWE-611: XXE risk)', hl = 'DiagnosticWarn' },
    { pat = 'xml%.Decoder%.Decode%(', msg = 'xml.Decoder.Decode (XXE risk)', hl = 'DiagnosticWarn' },

    -- Deserialization (CWE-502)
    { pat = 'json%.Unmarshal%(', msg = 'json.Unmarshal (validate input source)', hl = 'DiagnosticWarn' },
    { pat = 'gob%.Decode%(', msg = 'gob.Decode (CWE-502: deserialization)', hl = 'DiagnosticWarn' },

    -- HTTP security headers
    { pat = 'http%.Header%.Set%(.*[\'"]X%-Frame%-Options', msg = 'X-Frame-Options header (good practice)', hl = 'DiagnosticInfo' },
    { pat = 'http%.Header%.Set%(.*[\'"]Content%-Security%-Policy', msg = 'CSP header (good practice)', hl = 'DiagnosticInfo' },

    -- Authentication and session management
    { pat = 'crypto/rand%.Read%(', msg = 'crypto/rand.Read (secure random)', hl = 'DiagnosticInfo' },
    { pat = 'session%.Values%[', msg = 'session value access (validate data)', hl = 'DiagnosticWarn' },

    -- Input validation and string handling
    { pat = 'fmt%.Sprintf%(', msg = 'fmt.Sprintf (CWE-134: format string safety)', hl = 'DiagnosticWarn' },
    { pat = 'strconv%.Atoi%(', msg = 'strconv.Atoi (check error return)', hl = 'DiagnosticInfo' },
    { pat = 'strconv%.ParseInt%(', msg = 'strconv.ParseInt (validate input)', hl = 'DiagnosticInfo' },

    -- Network listeners and servers
    { pat = 'net%.Listen%(%s*[\'"]tcp[\'"]%s*,%s*[\'"]:', msg = 'net.Listen (verify bind address)', hl = 'DiagnosticWarn' },
    { pat = 'http%.ListenAndServe%(', msg = 'http.ListenAndServe (consider TLS)', hl = 'DiagnosticInfo' },
    { pat = 'http%.ListenAndServeTLS%(', msg = 'http.ListenAndServeTLS (verify certs)', hl = 'DiagnosticInfo' },
  },
  default = {
    -- CVE-specific patterns and common security issues
    
    -- AWS and Cloud credentials (CVE-2019-5418 style exposure)
    { pat = 'AWS[_%-]?SECRET[_%-]?ACCESS[_%-]?KEY', msg = 'AWS secret access key (CVE-prone exposure)', hl = 'DiagnosticError' },
    { pat = 'AWS[_%-]?ACCESS[_%-]?KEY[_%-]?ID', msg = 'AWS access key ID', hl = 'DiagnosticWarn' },
    { pat = 'AKIA[%w]+', msg = 'AWS Access Key (AKIA...) (credential exposure)', hl = 'DiagnosticError' },
    { pat = 'ASIA[%w]+', msg = 'AWS Session Token (ASIA...) (credential exposure)', hl = 'DiagnosticError' },
    
    -- API keys and tokens
    { pat = '[Aa][Pp][Ii][_%-]?[Kk]EY[_%-]?[=:]', msg = 'API key pattern (credential exposure)', hl = 'DiagnosticWarn' },
    { pat = '[Tt][Oo][Kk][Ee][Nn]%s*[:=]', msg = 'token assignment (credential exposure)', hl = 'DiagnosticWarn' },
    { pat = '[Cc]lient[_%-]?[Ss]ecret', msg = 'client secret (credential exposure)', hl = 'DiagnosticError' },
    { pat = '[Ss]ecret[_%-]?[Kk]ey', msg = 'secret key (credential exposure)', hl = 'DiagnosticError' },
    { pat = '[Aa]ccess[_%-]?[Tt]oken', msg = 'access token (credential exposure)', hl = 'DiagnosticWarn' },
    { pat = '[Rr]efresh[_%-]?[Tt]oken', msg = 'refresh token (credential exposure)', hl = 'DiagnosticWarn' },

    -- Database and service credentials
    { pat = 'DATABASE[_%-]?URL', msg = 'database URL (credential exposure)', hl = 'DiagnosticWarn' },
    { pat = 'DB[_%-]?PASSWORD', msg = 'database password (credential exposure)', hl = 'DiagnosticError' },
    { pat = 'REDIS[_%-]?PASSWORD', msg = 'Redis password (credential exposure)', hl = 'DiagnosticError' },
    
    -- Generic password patterns (CWE-256, CWE-798)
    { pat = '%f[%w]password%s*=%s*["\']?%w+', msg = 'hardcoded password (CWE-798)', hl = 'DiagnosticError' },
    { pat = '%f[%w]passwd%s*=%s*["\']?%w+', msg = 'hardcoded passwd (CWE-798)', hl = 'DiagnosticError' },
    { pat = '%f[%w]pwd%s*=%s*["\']?%w+', msg = 'hardcoded pwd (CWE-798)', hl = 'DiagnosticError' },
    { pat = '[Uu]sername%s*=%s*["\']?%w+', msg = 'hardcoded username', hl = 'DiagnosticWarn' },
    { pat = '[Ll]ogin%s*=%s*["\']?%w+', msg = 'hardcoded login', hl = 'DiagnosticWarn' },

    -- Private key material (CWE-200)
    { pat = '-----BEGIN RSA PRIVATE KEY-----', msg = 'RSA private key (CWE-200: exposure)', hl = 'DiagnosticError' },
    { pat = '-----BEGIN PRIVATE KEY-----', msg = 'private key material (credential exposure)', hl = 'DiagnosticError' },
    { pat = '-----BEGIN EC PRIVATE KEY-----', msg = 'EC private key (credential exposure)', hl = 'DiagnosticError' },
    { pat = '-----BEGIN DSA PRIVATE KEY-----', msg = 'DSA private key (credential exposure)', hl = 'DiagnosticError' },
    { pat = '-----BEGIN OPENSSH PRIVATE KEY-----', msg = 'OpenSSH private key (credential exposure)', hl = 'DiagnosticError' },
    
    -- Public key hints (check for nearby private keys)
    { pat = 'ssh%-rsa%s+', msg = 'SSH public key (check for private keys)', hl = 'DiagnosticWarn' },
    { pat = 'ssh%-ed25519%s+', msg = 'SSH Ed25519 public key (check for private keys)', hl = 'DiagnosticWarn' },
    { pat = 'ssh%-dss%s+', msg = 'SSH DSS public key (check for private keys)', hl = 'DiagnosticWarn' },

    -- JWT and bearer tokens
    { pat = '[Aa]uthorization%s*:%s*[Bb]earer%s+%S+', msg = 'Authorization Bearer token', hl = 'DiagnosticWarn' },
    { pat = 'eyJ[%w+/]+=*%.eyJ[%w+/]+=*%.[%w+/%-_]*', msg = 'JWT token (CWE-200: exposure)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]JWT%s*=%s*%S+', msg = 'JWT assignment', hl = 'DiagnosticWarn' },

    -- Service-specific tokens
    { pat = 'xox[baprs]%-[%w%-]+', msg = 'Slack token (xox...) (credential exposure)', hl = 'DiagnosticError' },
    { pat = 'ghp_[%w]+', msg = 'GitHub personal access token', hl = 'DiagnosticError' },
    { pat = 'gho_[%w]+', msg = 'GitHub OAuth token', hl = 'DiagnosticError' },
    { pat = 'ghs_[%w]+', msg = 'GitHub server token', hl = 'DiagnosticError' },
    { pat = 'sk_live_[%w]+', msg = 'Stripe live secret key', hl = 'DiagnosticError' },
    { pat = 'sk_test_[%w]+', msg = 'Stripe test secret key', hl = 'DiagnosticWarn' },
    { pat = 'pk_live_[%w]+', msg = 'Stripe live publishable key', hl = 'DiagnosticWarn' },

    -- Database connection strings with credentials (CWE-200)
    { pat = 'postgres://%S+:%S+@', msg = 'PostgreSQL connection with credentials (CWE-200)', hl = 'DiagnosticError' },
    { pat = 'mysql://%S+:%S+@', msg = 'MySQL connection with credentials (CWE-200)', hl = 'DiagnosticError' },
    { pat = 'mongodb://%S+:%S+@', msg = 'MongoDB connection with credentials (CWE-200)', hl = 'DiagnosticError' },
    { pat = 'redis://%S+:%S+@', msg = 'Redis connection with credentials (CWE-200)', hl = 'DiagnosticError' },

    -- Private key filenames (CWE-200)
    { pat = '%f[%w]id_rsa%f[%W]', msg = 'private key filename (id_rsa)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]id_dsa%f[%W]', msg = 'private key filename (id_dsa)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]id_ed25519%f[%W]', msg = 'private key filename (id_ed25519)', hl = 'DiagnosticWarn' },
    { pat = '%f[%w]id_ecdsa%f[%W]', msg = 'private key filename (id_ecdsa)', hl = 'DiagnosticWarn' },

    -- Network security (CWE-319, CWE-295)
    { pat = 'http://', msg = 'insecure HTTP (CWE-319: use HTTPS)', hl = 'DiagnosticWarn' },
    { pat = '[Ii]nsecureSkipVerify%s*[:=]%s*[Tt]rue', msg = 'TLS InsecureSkipVerify (CWE-295)', hl = 'DiagnosticError' },
    { pat = '[Vv]erify%s*=%s*[Ff]alse', msg = 'TLS verification disabled (CWE-295)', hl = 'DiagnosticError' },
    { pat = 'ssl_verify%s*=%s*false', msg = 'SSL verification disabled (CWE-295)', hl = 'DiagnosticError' },

    -- Certificate and cryptographic material
    { pat = 'BEGIN% [Cc]ertificate', msg = 'certificate block (check storage)', hl = 'DiagnosticWarn' },
    { pat = 'BEGIN% [Pp]kcs7', msg = 'PKCS7 certificate/secret block', hl = 'DiagnosticWarn' },
    { pat = '[Ss]ervice[_%-]account[_%-]key', msg = 'service account key (GCP/cloud)', hl = 'DiagnosticError' },

    -- Generic sensitive patterns
    { pat = '[Pp]assphrase', msg = 'passphrase (credential exposure)', hl = 'DiagnosticWarn' },
    { pat = '[Pp]rivate[_%-]key', msg = 'private_key reference (credential exposure)', hl = 'DiagnosticWarn' },
    { pat = '[Mm]aster[_%-]key', msg = 'master_key (credential exposure)', hl = 'DiagnosticError' },
    { pat = '[Ee]ncryption[_%-]key', msg = 'encryption_key (credential exposure)', hl = 'DiagnosticWarn' },

    -- Configuration and environment variable patterns
    { pat = 'SECRET_KEY%s*=', msg = 'SECRET_KEY environment variable', hl = 'DiagnosticWarn' },
    { pat = 'PRIVATE_KEY%s*=', msg = 'PRIVATE_KEY environment variable', hl = 'DiagnosticWarn' },
    { pat = 'API_SECRET%s*=', msg = 'API_SECRET environment variable', hl = 'DiagnosticWarn' },
    
    -- Base64 encoded potential secrets (high entropy)
    { pat = '[A-Za-z0-9+/]{40,}={0,2}', msg = 'base64-like string (potential secret)', hl = 'DiagnosticInfo' },
    
    -- Hex encoded potential secrets
    { pat = '[0-9a-fA-F]{64,}', msg = 'long hex string (potential secret)', hl = 'DiagnosticInfo' },

    -- Lower-severity review patterns
    { pat = '[Tt]oken%:?', msg = 'token-like word (review context)', hl = 'DiagnosticInfo' },
    { pat = '[Aa]pi[_%-]?[Kk]ey', msg = 'api_key-like word (review context)', hl = 'DiagnosticInfo' },
    { pat = '[Cc]redential', msg = 'credential reference (review context)', hl = 'DiagnosticInfo' },
    
    -- OWASP Top 10 related patterns
    { pat = 'admin:admin', msg = 'default credentials (admin:admin)', hl = 'DiagnosticError' },
    { pat = 'root:root', msg = 'default credentials (root:root)', hl = 'DiagnosticError' },
    { pat = 'admin:password', msg = 'default credentials (admin:password)', hl = 'DiagnosticError' },
    { pat = 'guest:guest', msg = 'default credentials (guest:guest)', hl = 'DiagnosticError' },
  },
}

-- per-language Treesitter taint queries for better accuracy
local taint_queries = {
  c = [[
    ;; common call/arg shapes (string/char/identifier/concatenation/binary expr)
    (call_expression function: (_) arguments: (argument_list (string) @arg) ) @call
    (call_expression function: (_) arguments: (argument_list (char) @arg) ) @call
    (call_expression function: (_) arguments: (argument_list (identifier) @arg) ) @call
    (call_expression function: (_) arguments: (argument_list (binary_expression) @arg) ) @call
    ;; assignments and returns
    (assignment_expression left: (identifier) @lhs right: (_) @rhs)
    (assignment_statement left: (identifier) right: (_) @rhs)
    (return_statement (identifier) @rhs)
  ]],
  cpp = [[
    ;; C++ call forms including scoped/namespace function names and literals
    (call_expression function: (_) arguments: (argument_list (string) @arg) ) @call
    (call_expression function: (_) arguments: (argument_list (char) @arg) ) @call
    (call_expression function: (_) arguments: (argument_list (identifier) @arg) ) @call
    (call_expression function: (scoped_identifier) arguments: (argument_list (string) @arg)) @call
    (call_expression function: (field_expression) arguments: (argument_list (identifier) @arg)) @call
    ;; assignments / returns
    (assignment_expression left: (identifier) @lhs right: (_) @rhs)
    (assignment_statement left: (identifier) right: (_) @rhs)
    (return_statement (identifier) @rhs)
  ]],
  lua = [[
    ;; function calls via modern and older tree-sitter node names
    (call_expression arguments: (arguments (string) @arg) ) @call
    (call_expression arguments: (arguments (identifier) @arg) ) @call
    (function_call name: (identifier) arguments: (arguments (string) @arg) ) @call
    (function_call name: (identifier) arguments: (arguments (identifier) @arg) ) @call
    ;; assignments (local/global) and table index assignments
    (assignment_statement (variable_list (identifier) @lhs) (expression_list (_) @rhs))
    (assignment_statement (variable_list (index_expression (identifier) @lhs) ) (expression_list (_) @rhs))
    (return_statement (expression_list (_) @rhs))
  ]],
  python = [[
    ;; calls with string/name/attribute arguments and formatted strings
    (call function: (_) arguments: (argument_list (string) @arg)) @call
    (call function: (_) arguments: (argument_list (name) @arg)) @call
    (call function: (attribute) arguments: (argument_list (string) @arg)) @call
    (call function: (_) arguments: (argument_list (formatted_value) @arg)) @call
    ;; assignments, targets and returns
    (assignment left: (identifier) @lhs right: (_) @rhs)
    (assignment left: (attribute) right: (_) @rhs)
    (return_statement (atom) @rhs)
  ]],
  javascript = [[
    ;; call shapes including member expressions and constructor calls
    (call_expression arguments: (arguments (string) @arg) ) @call
    (call_expression arguments: (arguments (identifier) @arg) ) @call
    (call_expression function: (member_expression) arguments: (arguments (string) @arg)) @call
    (new_expression arguments: (arguments (string) @arg)) @call
    ;; assignment and return forms
    (assignment_expression left: (identifier) @lhs right: (_) @rhs)
    (assignment_expression left: (member_expression) right: (_) @rhs)
    (return_statement (identifier) @rhs)
  ]],
  go = [[
    ;; go call expressions, includes selector expressions and literal args
    (call_expression function: (_) arguments: (argument_list (string) @arg) ) @call
    (call_expression function: (_) arguments: (argument_list (identifier) @arg) ) @call
    (call_expression function: (selector_expression) arguments: (argument_list (string) @arg)) @call
    (call_expression function: (selector_expression) arguments: (argument_list (identifier) @arg)) @call
    ;; assignments, short assignments and returns
    (assignment_statement left: (identifier) @lhs right: (_) @rhs)
    (short_var_declaration left: (identifier) @lhs right: (_) @rhs)
    (return_statement (expression_list (_) ) @rhs)
  ]],
}

-- per-project allowlist loader
local function load_project_allowlist()
  local cwd = vim.fn.getcwd()
  local path = cwd .. '/.traceback_security.lua'
  if vim.fn.filereadable(path) == 1 then
    local ok, tbl = pcall(dofile, path)
    if ok and type(tbl) == 'table' then return tbl end
  end
  return {}
end

-- in-memory allowlist (can be extended by UI command)
local project_allowlist = load_project_allowlist()

function M.get_project_allowlist()
  return project_allowlist
end

function M.add_allow(pattern)
  if not pattern or pattern == '' then return end
  table.insert(project_allowlist, pattern)
end


function M.render(bufnr, ns, cfg, from, to)
  local max_anno = cfg.max_annotations
  local lines = vim.api.nvim_buf_get_lines(bufnr, from-1, to, false)
  local ft = vim.bo[bufnr].filetype
  local rules = insecure_by_ft[ft] or insecure_by_ft.default
  local sc_ranges = (cfg.treesitter and U.ts_available(bufnr, cfg)) and U.ts_sc_ranges(bufnr, ft, from, to) or {}
  local anno = 0
  local severity_score = { DiagnosticError = 3, DiagnosticWarn = 2, DiagnosticInfo = 1 }
  local min_score = (cfg and cfg.min_issue_score) or 2
  -- taint helpers: lightweight Treesitter-based check for flow to sinks
  local function taint_boost(line_nr, col_s, col_e)
    if not (cfg and cfg.taint_enabled and U.ts_available(bufnr, cfg)) then return 0 end
    -- simple heuristic: get parser and search for function call nodes that include this range
    local ok, parser = pcall(vim.treesitter.get_parser, bufnr, ft)
    if not ok then return 0 end
    local tree = parser:parse()[1]
    if not tree then return 0 end
    local root = tree:root()
    local q_text = [[
      (call_expression function: (_) @fn args: (argument_list (identifier) @arg) )
      (call_expression function: (_) @fn args: (argument_list (string) @arg) )
      (assignment left: (identifier) @lhs right: (_) @rhs)
    ]]
    -- parse query best-effort; this is generic and may return nil for unsupported fts
    local okq, q = pcall(vim.treesitter.query.parse, ft, q_text)
    if not okq or not q then return 0 end
    for id, node in q:iter_captures(root, bufnr, from-1, to) do
      local name = q.captures[id]
      if name == 'arg' or name == 'lhs' then
        local sr, sc, er, ec = node:range()
        if line_nr-1 >= sr and line_nr-1 <= er then
          -- if ranges overlap with matched span, consider it tainted flow to a sink
          if not (col_e < sc or col_s > ec) then
            return (cfg.taint_boost or 2)
          end
        end
      end
    end
    return 0
  end
  for i, line in ipairs(lines) do
    for _, r in ipairs(rules) do
      local s, e = line:find(r.pat)
      if s and not U.col_in_ranges((from+i-2), s-1, sc_ranges) then
        local matched = line:sub(s, e)
        -- base score from severity
        local base = severity_score[r.hl] or 1
        -- secret heuristic bonus for token-like findings
        local secret_ok = false
        if r.msg:lower():match('key') or r.msg:lower():match('secret') or r.msg:lower():match('token') or r.pat:match('AKIA') or r.pat:match('xox') or r.pat:match('JWT') then
          secret_ok = looks_like_secret(matched, cfg)
        end
        local secret_bonus = secret_ok and (cfg.secret_bonus or 2) or 0
        local taint_bonus = taint_boost(from+i-1, s-1, e) or 0
        local score = base + secret_bonus + taint_bonus
        -- consult project allowlist (string patterns)
        local skip = false
        for _, p in ipairs(project_allowlist) do
          if matched:match(p) then skip = true; break end
        end
        if skip then goto continue end

        if score >= min_score then
          vim.api.nvim_buf_set_extmark(bufnr, ns, (from+i-2), s-1, { end_col = e, hl_group = r.hl })
          vim.api.nvim_buf_set_extmark(bufnr, ns, (from+i-2), 0, {
            virt_text = {{'󰌾 '..r.msg, r.hl}}, virt_text_pos = 'eol'
          })
          anno = anno + 1
          if anno >= max_anno then break end
        end
        ::continue::
      end
    end
    if anno >= max_anno then break end
  end
  return anno
end

return M
