/**
 * Windows System Survey Script (Stealth & Portable)
 * Compatible with Windows 7 and above.
 * Runs via: cscript /nologo win-survey.js
 */

var RESULTS_FILE = ""; // Empty = auto-generate with hostname
var ENCODE_OUTPUT = false; // Set to true to Base64 encode the output file
var EVENT_LOG_LIMIT = 100;
var ENABLE_PROCESS_HASHING = false; // Default: off. Use --hash to enable

var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var logBuffer = ""; // Store logs if encoding is needed
var _collectedProcesses = []; // Global cache for anomaly detection

function Log(msg) {
    WScript.Echo(msg);
    logBuffer += msg + "\r\n";
}

function EscapeBatch(str) {
    return str.replace(/([&|^<>"])/g, "^$1");
}

function SafeEnvValue(key, value) {
    var sensitivePattern = /key|secret|password|passwd|token|credential|private|auth/i;
    if (sensitivePattern.test(key)) {
        return value.length > 4 ? value.substring(0, 4) + "********" : "****";
    }
    return value;
}



function RandomSuffix() {
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    var result = "";
    for (var i = 0; i < 8; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// --- Base64 Implementation ---
var Base64 = (function() {
    var keys = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    return {
        encode: function(input) {
            var output = "";
            var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
            var i = 0;
            while (i < input.length) {
                chr1 = input.charCodeAt(i++);
                chr2 = input.charCodeAt(i++);
                chr3 = input.charCodeAt(i++);
                enc1 = chr1 >> 2;
                enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                enc4 = chr3 & 63;
                if (isNaN(chr2)) enc3 = enc4 = 64;
                else if (isNaN(chr3)) enc4 = 64;
                output += keys.charAt(enc1) + keys.charAt(enc2) + keys.charAt(enc3) + keys.charAt(enc4);
            }
            return output;
        }
    };
})();

function FormatWMIDate(wmiDate) {
    if (!wmiDate) return "N/A";
    return wmiDate.substring(0, 4) + "-" + wmiDate.substring(4, 6) + "-" + wmiDate.substring(6, 8) + " " +
           wmiDate.substring(8, 10) + ":" + wmiDate.substring(10, 12) + ":" + wmiDate.substring(12, 14);
}

function Pad(str, len) {
    str = String(str);
    while (str.length < len) str += " ";
    return str;
}

function Section(title) {
    var border = "################################################################################";
    Log("\n" + border);
    Log("#  " + title.toUpperCase());
    Log(border + "\n");
}

// MD5 engine removed. Using certutil mapping instead.

// GetFileHash removed; hashing is now optimally batched within SurveyProcesses.

// --- WMI Helpers (Obfuscated Strings) ---
var _w = "win" + "mgmts" + ":" + "\\\\" + ".\\" + "root" + "\\" + "cim" + "v2";
var wmi = GetObject(_w);

function QueryWMI(query, callback) {
    try {
        var items = wmi.ExecQuery(query);
        var enumItems = new Enumerator(items);
        for (; !enumItems.atEnd(); enumItems.moveNext()) {
            callback(enumItems.item());
        }
    } catch (e) {
        Log("WMI Error [" + query + "]: " + e.message);
    }
}

// ... survey modules below ...

// --- Survey Modules ---

function SurveySystemInfo() {
    Section("System Information");
    QueryWMI("SELECT * FROM Win32_OperatingSystem", function(item) {
        Log("Host Name: " + item.CSName);
        Log("OS: " + item.Caption + " (" + item.Version + ")");
        Log("Architecture: " + item.OSArchitecture);
        Log("Install Date: " + FormatWMIDate(item.InstallDate));
        Log("Registered User: " + item.RegisteredUser);
        Log("Last Boot: " + FormatWMIDate(item.LastBootUpTime));
    });
    QueryWMI("SELECT * FROM Win32_ComputerSystem", function(item) {
        Log("Model: " + item.Manufacturer + " " + item.Model);
        Log("Domain: " + item.Domain);
        Log("Total Memory: " + Math.round(item.TotalPhysicalMemory / 1024 / 1024) + " MB");
    });
}

function SafeArray(arr) {
    // Safely convert WMI SafeArray to JScript array
    // WMI returns SafeArrays that sometimes fail .toArray() on Win11/WSH
    try {
        if (!arr || arr === null) return [];
        if (typeof arr === 'unknown') {
            // Try VBArray conversion as fallback
            try { return new VBArray(arr).toArray(); } catch(e2) { return []; }
        }
        if (typeof arr.toArray === 'function') return arr.toArray();
        if (typeof arr === 'string') return [arr];
        return [arr];
    } catch (e) {
        return [];
    }
}

function RunCommand(cmd, timeoutMs) {
    // Run a command via shell.Run (hidden window) with temp file output + timeout
    // Default timeout: 30 seconds
    if (!timeoutMs) timeoutMs = 30000;
    var tmpFile = "";
    try {
        var tempDir = shell.ExpandEnvironmentStrings("%TEMP%");
        tmpFile = tempDir + "\\sys_cmd_" + RandomSuffix() + ".out";
        // Run hidden (0), don't wait (false) — we poll with our own timeout
        shell.Run('cmd.exe /c ' + cmd + ' > "' + tmpFile + '" 2>&1', 0, false);
        // Wait for output file to appear
        var waited = 0;
        while (!fso.FileExists(tmpFile) && waited < timeoutMs) {
            WScript.Sleep(100);
            waited += 100;
        }
        if (!fso.FileExists(tmpFile)) return ""; // Timeout
        // Wait for file size to stabilize (process still writing)
        var lastSize = -1;
        var stableCount = 0;
        waited = 0;
        while (waited < timeoutMs && stableCount < 3) {
            WScript.Sleep(200);
            waited += 200;
            try {
                var curSize = fso.GetFile(tmpFile).Size;
                if (curSize === lastSize) { stableCount++; } else { stableCount = 0; lastSize = curSize; }
            } catch(e) { stableCount = 0; }
        }
        if (fso.FileExists(tmpFile)) {
            var f = fso.OpenTextFile(tmpFile, 1);
            var output = f.AtEndOfStream ? "" : f.ReadAll();
            f.Close();
            return output;
        }
    } catch(e) {
    } finally {
        try { if (tmpFile && fso.FileExists(tmpFile)) fso.DeleteFile(tmpFile); } catch(e2) {}
    }
    return "";
}

function SurveyNetwork() {
    // Primary: ipconfig /all — most reliable for IP/DNS/DHCP on all Windows
    Section("Network Configuration (ipconfig /all)");
    try {
        var ipconfigOut = RunCommand('ipconfig /all', 15000);
        if (ipconfigOut.length > 0) {
            var lines = ipconfigOut.split('\n');
            for (var i = 0; i < lines.length; i++) {
                Log(lines[i].replace(/\r/g, ""));
            }
        } else {
            Log("  ipconfig not available");
        }
    } catch(e) {
        Log("  ipconfig error: " + e.message);
    }

    Section("Network Connections (netstat -anob)");
    try {
        var netstatOut = RunCommand('netstat -anob', 60000);
        if (netstatOut.length > 0) {
            var lines = netstatOut.split('\n');
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].replace(/\r/g, "");
                Log(line);
            }
        } else {
            Log("  netstat not available (requires elevated privileges for -b flag)");
            // Try without -b (no process names)
            try {
                var netstatAn = RunCommand('netstat -an', 30000);
                if (netstatAn.length > 0) {
                    Log("  (showing netstat -an without process names)");
                    var anLines = netstatAn.split('\n');
                    for (var j = 0; j < anLines.length; j++) {
                        Log(anLines[j].replace(/\r/g, ""));
                    }
                }
            } catch(e2) {}
        }
    } catch(e) {
        Log("  netstat error: " + e.message);
    }

    Section("Network Shares");
    QueryWMI("SELECT * FROM Win32_Share", function(item) {
        Log(item.Name + " => " + item.Path + " [" + item.Description + "]");
    });
}

function SurveyUsers() {
    Section("Local Users");
    QueryWMI("SELECT * FROM Win32_UserAccount", function(item) {
        Log(item.Name + " (Disabled: " + item.Disabled + ", Locked: " + item.Lockout + ", SID: " + item.SID + ")");
    });

    Section("Administrators Group Members");
    // SID S-1-5-32-544 is the built-in Administrators group
    QueryWMI("SELECT * FROM Win32_Group WHERE SID = 'S-1-5-32-544'", function(group) {
        // Find members via association
        var query = "SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='" + group.Domain + "',Name='" + group.Name + "'\"";
        QueryWMI(query, function(assoc) {
            // PartComponent is the user/group reference
            var memberPath = assoc.PartComponent; 
            var nameMatch = memberPath.match(/Name="([^"]+)"/);
            if (nameMatch) {
                Log("  Admin Member: " + nameMatch[1]);
            } else {
                Log("  Admin Member: " + memberPath); // Fallback: log raw path
            }
        });
    });

    Section("Logged-on Sessions");
    QueryWMI("SELECT * FROM Win32_LogonSession", function(item) {
        var startTime = FormatWMIDate(item.StartTime);
        var logonType = (typeof item.LogonType === 'number' && item.LogonType > 0) ? item.LogonType : 0;
        var typeMap = {
            2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
            6: "Proxy", 7: "Unlock", 8: "NetworkCleartext",
            9: "NewCredentials", 10: "RemoteInteractive", 11: "CachedInteractive"
        };
        var type = typeMap[logonType] || (logonType > 0 ? "Type" + logonType : "Unknown");
        var sessionId = item.LogonId || item.Id || "N/A";
        Log("Session: ID=" + sessionId + " | Type=" + type + " | Start=" + startTime);
    });
}

var shellCompanyIndex = -1;
var globalShellApp = null;
var namespaceCache = {};
function GetFileCompany(path) {
    try {
        if (!fso.FileExists(path)) return "";
        if (!globalShellApp) globalShellApp = new ActiveXObject("Shell.Application");
        var folderPath = fso.GetParentFolderName(path);
        var folderObj = namespaceCache[folderPath];
        if (!folderObj) {
            folderObj = globalShellApp.NameSpace(folderPath);
            if (!folderObj) return "";
            namespaceCache[folderPath] = folderObj;
        }
        var itemObj = folderObj.ParseName(fso.GetFileName(path));
        
        if (shellCompanyIndex === -1) {
            for (var i = 0; i < 50; i++) {
                var header = folderObj.GetDetailsOf(null, i);
                if (header && (header.toLowerCase() === "company" || header.toLowerCase() === "compañía")) {
                    shellCompanyIndex = i;
                    break;
                }
            }
            if (shellCompanyIndex === -1) shellCompanyIndex = 33;
        }
        return folderObj.GetDetailsOf(itemObj, shellCompanyIndex) || "";
    } catch(e) {
        return "";
    }
}

function SurveyProcesses() {
    if (ENABLE_PROCESS_HASHING) {
        Section("Running Processes (with MD5)");
    } else {
        Section("Running Processes");
    }
    var processes = [];
    var uniquePaths = {};
    
    // 1. Collect all running processes
    QueryWMI("SELECT * FROM Win32_Process", function(item) {
        var path = item.ExecutablePath || "N/A";
        if (path !== "N/A" && !uniquePaths[path]) {
            uniquePaths[path] = true;
        }
        processes.push({
            PID: item.ProcessId,
            PPID: item.ParentProcessId || "N/A",
            Name: item.Name,
            Path: path
        });
    });
    
    // 2. Batch hash all unique paths via single certutil call (silent, no visible windows)
    var hashMap = {};
    if (ENABLE_PROCESS_HASHING) {
        try {
            var tempDir = shell.ExpandEnvironmentStrings("%TEMP%");
            var batPath = tempDir + "\\sys_" + RandomSuffix() + ".bat";
            var outPath = tempDir + "\\sys_" + RandomSuffix() + ".out";
            
            var batFile = fso.CreateTextFile(batPath, true);
            batFile.WriteLine("@echo off");
            for (var p in uniquePaths) {
                if (fso.FileExists(p)) {
                    batFile.WriteLine('certutil -hashfile "' + EscapeBatch(p) + '" MD5');
                }
            }
            batFile.Close();
            
            // Run hidden (0 = no window), wait for completion (true)
            shell.Run('cmd.exe /c "' + batPath + '" > "' + outPath + '" 2>&1', 0, true);
            
            if (fso.FileExists(outPath)) {
                var outFile = fso.OpenTextFile(outPath, 1);
                var output = outFile.AtEndOfStream ? "" : outFile.ReadAll();
                outFile.Close();
                
                // Parse: MD5 certutil output is simple:
                // MD5 hash of C:\path\file.exe:
                // a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
                // CertUtil: -hashfile command completed successfully.
                var lines = output.split('\n');
                var currentPath = null;
                for (var i = 0; i < lines.length; i++) {
                    var line = lines[i].replace(/\r/g, "");
                    if (line.indexOf("hash of ") !== -1) {
                        // "MD5 hash of C:\path\file.exe:"
                        var start = line.indexOf("hash of ") + 8;
                        var pathPart = line.substring(start);
                        if (pathPart.charAt(pathPart.length - 1) === ':') pathPart = pathPart.substring(0, pathPart.length - 1);
                        currentPath = pathPart;
                    } else if (currentPath && line.length === 32 && /^[0-9a-fA-F]{32}$/.test(line)) {
                        hashMap[currentPath.toLowerCase()] = line.toLowerCase();
                        currentPath = null;
                    }
                }
            }
        } catch(e) {
            Log("  [Hashing failed: " + e.message + "]");
        } finally {
            try { if (typeof outPath !== 'undefined' && fso.FileExists(outPath)) fso.DeleteFile(outPath); } catch(e2) {}
            try { if (typeof batPath !== 'undefined' && fso.FileExists(batPath)) fso.DeleteFile(batPath); } catch(e2) {}
        }
    }
    
    // 3. Output results
    if (ENABLE_PROCESS_HASHING) {
        Log(Pad("PID", 8) + Pad("PPID", 8) + Pad("Name", 35) + Pad("MD5", 34) + "Path");
        Log(Pad("---", 8) + Pad("----", 8) + Pad("----", 35) + Pad("---", 34) + "----");
    } else {
        Log(Pad("PID", 8) + Pad("PPID", 8) + Pad("Name", 35) + "Path");
        Log(Pad("---", 8) + Pad("----", 8) + Pad("----", 35) + "----");
    }
    
    for (var j = 0; j < processes.length; j++) {
        var p = processes[j];
        var dispName = p.Name;
        
        if (p.Path !== "N/A") {
            var company = GetFileCompany(p.Path);
            if (company.indexOf("Microsoft") !== -1) {
                dispName += " [MS]";
            }
        }
        
        if (ENABLE_PROCESS_HASHING) {
            var hash = "N/A";
            if (p.Path !== "N/A") {
                hash = hashMap[p.Path.toLowerCase()] || "N/A";
            }
            Log(Pad(p.PID, 8) + Pad(p.PPID, 8) + Pad(dispName, 35) + Pad(hash, 34) + p.Path);
        } else {
            Log(Pad(p.PID, 8) + Pad(p.PPID, 8) + Pad(dispName, 35) + p.Path);
        }
    }
    
    // Store globally for anomaly detection
    _collectedProcesses = processes;
}

function SurveyServices() {
    Section("Services");
    Log(Pad("Name", 30) + Pad("Status", 10) + Pad("State", 12) + Pad("StartMode", 12) + "DisplayName");
    Log(Pad("----", 30) + Pad("------", 10) + Pad("-----", 12) + Pad("---------", 12) + "-----------");
    QueryWMI("SELECT * FROM Win32_Service", function(item) {
        var startMode = (item.StartMode || "Unknown").substring(0, 12);
        Log(Pad(item.Name, 30) + Pad(item.Status || "N/A", 10) + Pad(item.State || "N/A", 12) + Pad(startMode, 12) + (item.DisplayName || ""));
    });
}

function SurveyStartup() {
    Section("Startup Keys");
    var keys = [
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    ];
    var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
    var locator = new ActiveXObject(_loc);
    var _rd = "root" + "\\" + "default";
    var reg = locator.ConnectServer(".", _rd).Get("StdRegProv");

    for (var i = 0; i < keys.length; i++) {
        Log("\nChecking: " + keys[i]);
        try {
            var hDefKey = (keys[i].indexOf("HKLM") === 0) ? 0x80000002 : 0x80000001;
            var subKey = keys[i].substr(5);
            
            var method = reg.Methods_.Item("EnumValues");
            var inParams = method.InParameters.SpawnInstance_();
            inParams.hDefKey = hDefKey;
            inParams.sSubKeyName = subKey;
            
            var outParams = reg.ExecMethod_(method.Name, inParams);
            if (outParams.sNames !== null) {
                var names = outParams.sNames.toArray();
                for (var j = 0; j < names.length; j++) {
                    var valMethod = reg.Methods_.Item("GetStringValue");
                    var valIn = valMethod.InParameters.SpawnInstance_();
                    valIn.hDefKey = hDefKey;
                    valIn.sSubKeyName = subKey;
                    valIn.sValueName = names[j];
                    var valOut = reg.ExecMethod_(valMethod.Name, valIn);
                    Log("  " + names[j] + " => " + valOut.sValue);
                }
            } else {
                Log("  (No values found)");
            }
        } catch (e) {
            Log("  Error reading " + keys[i] + ": " + e.message);
        }
    }
}

function SurveyScheduledTasks() {
    Section("Scheduled Tasks");
    try {
        var service = new ActiveXObject("Schedule.Service");
        service.Connect();
        var rootFolder = service.GetFolder("\\");
        
        function EnumTasks(folder) {
            var tasks = folder.GetTasks(0);
            for (var i = 1; i <= tasks.Count; i++) {
                var t = tasks.Item(i);
                Log(t.Path + " [Enabled: " + t.Enabled + ", State: " + t.State + "]");
            }
            var subfolders = folder.GetFolders(0);
            for (var j = 1; j <= subfolders.Count; j++) {
                EnumTasks(subfolders.Item(j));
            }
        }
        EnumTasks(rootFolder);
    } catch (e) {
        Log("Error querying Scheduled Tasks: " + e.message);
    }
}

function SurveyFirewall() {
    Section("Firewall Settings & Rules");
    try {
        // NetFwPolicy2 is available on Win7+
        var fwPolicy2 = new ActiveXObject("HNetCfg.FwPolicy2");
        Log("Domain Profile Enabled: " + fwPolicy2.FirewallEnabled(1));
        Log("Private Profile Enabled: " + fwPolicy2.FirewallEnabled(2));
        Log("Public Profile Enabled: " + fwPolicy2.FirewallEnabled(4));
        
        Log("\nEnabled Firewall Rules:");
        var rules = fwPolicy2.Rules;
        var enumRules = new Enumerator(rules);
        var enabledRules = [];
        for (; !enumRules.atEnd(); enumRules.moveNext()) {
            var rule = enumRules.item();
            if (rule.Enabled) {
                enabledRules.push(rule);
            }
        }
        
        // Sort by name for consistent output
        enabledRules.sort(function(a, b) { return a.Name < b.Name ? -1 : 1; });
        
        if (enabledRules.length > 0) {
            Log("  " + Pad("Name", 40) + Pad("Direction", 12) + Pad("Action", 10) + Pad("Protocol", 10) + Pad("Ports", 20));
            Log("  " + Pad("----", 40) + Pad("---------", 12) + Pad("------", 10) + Pad("--------", 10) + Pad("-----", 20));
            for (var i = 0; i < enabledRules.length; i++) {
                var r = enabledRules[i];
                var dir = (r.Direction === 1) ? "In" : "Out";
                var act = (r.Action === 1) ? "Block" : "Allow";
                var proto = r.Protocol;
                // Protocol numbers to names
                if (proto === 1) proto = "ICMP";
                else if (proto === 6) proto = "TCP";
                else if (proto === 17) proto = "UDP";
                else if (proto === 47) proto = "GRE";
                else if (proto === 58) proto = "ICMPv6";
                var ports = r.LocalPorts || "Any";
                var name = r.Name ? r.Name.substring(0, 39) : "Unknown";
                Log("  " + Pad(name, 40) + Pad(dir, 12) + Pad(act, 10) + Pad(proto, 10) + Pad(String(ports).substring(0, 19), 20));
            }
            Log("\n  Total enabled rules: " + enabledRules.length);
        } else {
            Log("  No enabled firewall rules found.");
        }
    } catch (e) {
        Log("Error querying Firewall: " + e.message);
    }
}

function SurveyWMIPersistence() {
    Section("WMI Event Subscriptions (Persistence)");
    try {
        var _sub = "win" + "mgmts" + ":" + "\\\\" + ".\\" + "root" + "\\" + "sub" + "scription";
        var subWmi = GetObject(_sub);
        var classes = ["__EventFilter", "__EventConsumer", "__FilterToConsumerBinding"];
        for (var i = 0; i < classes.length; i++) {
            Log("\nClass: " + classes[i]);
            var items = subWmi.ExecQuery("SELECT * FROM " + classes[i]);
            var enumItems = new Enumerator(items);
            var count = 0;
            for (; !enumItems.atEnd(); enumItems.moveNext()) {
                var item = enumItems.item();
                Log("  Name: " + (item.Name || "Unnamed") + " | Path: " + item.Path_);
                count++;
            }
            if (count === 0) Log("  (None found)");
        }
    } catch (e) {
        Log("Error querying WMI persistence: " + e.message);
    }
}

function SurveyPSHistory() {
    Section("PowerShell History (Last 50 Lines per User)");
    try {
        var userDir = "C:\\Users";
        if (fso.FolderExists(userDir)) {
            var folders = fso.GetFolder(userDir).SubFolders;
            var enumFolders = new Enumerator(folders);
            for (; !enumFolders.atEnd(); enumFolders.moveNext()) {
                var folder = enumFolders.item();
                var histPath = folder.Path + "\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt";
                if (fso.FileExists(histPath)) {
                    var lastMod = fso.GetFile(histPath).DateLastModified;
                    Log("  User: " + folder.Name + " | Last Modified: " + lastMod);
                    try {
                        var f = fso.OpenTextFile(histPath, 1);
                        var content = f.AtEndOfStream ? "" : f.ReadAll();
                        f.Close();
                        var lines = content.split('\n');
                        var startIdx = Math.max(0, lines.length - 50);
                        Log("  (" + lines.length + " total lines, showing last 50):");
                        for (var k = startIdx; k < lines.length; k++) {
                            var histLine = lines[k].replace(/\r/g, "").replace(/^\s+|\s+$/g, "");
                            if (histLine.length > 0) {
                                Log("    " + histLine);
                            }
                        }
                    } catch (readErr) {
                        Log("    (could not read: " + readErr.message + ")");
                    }
                }
            }
        }
    } catch (e) {
        Log("Error checking PS History: " + e.message);
    }
}

function SurveySecurityProducts() {
    Section("Security Product Status (AV/EDR)");

    // Check if this is a server OS (SecurityCenter2 is client-only)
    var isServerOS = false;
    QueryWMI("SELECT * FROM Win32_OperatingSystem", function(item) {
        if (item.ProductType && item.ProductType !== "1") {
            isServerOS = true;
        }
    });

    try {
        // SecurityCenter2 is client-only (Vista+)
        var _sc = "win" + "mgmts" + ":" + "\\\\" + ".\\" + "root" + "\\" + "Security" + "Center2";
        var scWmi = GetObject(_sc);
        var products = ["AntivirusProduct", "AntiSpywareProduct", "FirewallProduct"];
        for (var i = 0; i < products.length; i++) {
            var items = scWmi.ExecQuery("SELECT * FROM " + products[i]);
            var enumItems = new Enumerator(items);
            for (; !enumItems.atEnd(); enumItems.moveNext()) {
                var item = enumItems.item();
                Log(products[i] + ": " + item.displayName + " [State: " + item.productState + "]");
            }
        }
    } catch (e) {
        if (isServerOS) {
            Log("SecurityCenter2 is not available on Server OS (client-only namespace).");
        } else {
            Log("Error querying SecurityCenter2: " + e.message);
        }
    }
}

function SurveyHotfixes() {
    Section("Installed Hotfixes (Patches)");
    QueryWMI("SELECT * FROM Win32_QuickFixEngineering", function(item) {
        Log(item.HotFixID + " | InstalledOn: " + item.InstalledOn + " | Description: " + item.Description);
    });
}

function SurveyEnvVars() {
    Section("Environment Variables (Process level)");
    var vars = shell.Environment("PROCESS");
    var enumVars = new Enumerator(vars);
    for (; !enumVars.atEnd(); enumVars.moveNext()) {
        var item = enumVars.item();
        var eqPos = item.indexOf('=');
        if (eqPos !== -1) {
            var key = item.substring(0, eqPos);
            var value = item.substring(eqPos + 1);
            Log("  " + key + "=" + SafeEnvValue(key, value));
        } else {
            Log("  " + item);
        }
    }
}

function SurveyRemoteAccess() {
    Section("Remote Access Configuration");
    try {
        var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
        var locator = new ActiveXObject(_loc);
        var _rd = "root" + "\\" + "default";
        var reg = locator.ConnectServer(".", _rd).Get("StdRegProv");
        
        function GetRegVal(hDefKey, subKey, valName) {
            var vMethod = reg.Methods_.Item("GetDWORDValue");
            var vIn = vMethod.InParameters.SpawnInstance_();
            vIn.hDefKey = hDefKey;
            vIn.sSubKeyName = subKey;
            vIn.sValueName = valName;
            var vOut = reg.ExecMethod_(vMethod.Name, vIn);
            return (vOut.uValue === null) ? "N/A" : vOut.uValue;
        }

        var tsKey = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
        var fDeny = GetRegVal(0x80000002, tsKey, "fDenyTSConnections");
        Log("Remote Desktop (fDenyTSConnections): " + (fDeny === 0 ? "ENABLED" : (fDeny === 1 ? "DISABLED" : "N/A")));

        var winRMKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service";
        var winRMEnc = GetRegVal(0x80000002, winRMKey, "allow_unencrypted");
        Log("WinRM Allow Unencrypted: " + winRMEnc);
    } catch (e) {
        Log("Error querying Remote Access registry: " + e.message);
    }
}

function SurveyDrivers() {
    Section("Kernel Drivers (Signed)");
    Log(Pad("Name", 30) + Pad("DeviceID", 40) + "Manufacturer");
    Log(Pad("----", 30) + Pad("--------", 40) + "------------");
    QueryWMI("SELECT * FROM Win32_PnPSignedDriver", function(item) {
        if (item.Manufacturer && item.Manufacturer.indexOf("Microsoft") === -1) {
            var devName = item.FriendlyName || item.DeviceName || "Unknown";
            var devID = item.DeviceID ? item.DeviceID.substring(0, 38) : "N/A";
            Log(Pad(devName, 30) + Pad(devID, 40) + item.Manufacturer);
        }
    });
}

function SurveyNeighbors() {
    Section("Network Neighbors (ARP / Neighbor Cache)");
    try {
        var _wsm = "win" + "mgmts" + ":" + "\\\\" + ".\\" + "root" + "\\" + "standard" + "cim" + "v2";
        var wmiStd = GetObject(_wsm);
        var items = wmiStd.ExecQuery("SELECT * FROM MSFT_NetNeighbor");
        var enumItems = new Enumerator(items);
        Log(Pad("IP Address", 25) + "State");
        Log(Pad("----------", 25) + "-----");
        for (; !enumItems.atEnd(); enumItems.moveNext()) {
            var item = enumItems.item();
            Log(Pad(item.IPAddress, 25) + item.State);
        }
    } catch (e) {
        Log("MSFT_NetNeighbor not available (Old Windows or OS not supporting CIM v2)");
    }
}

function SurveyInstalledPrograms() {
    Section("Installed Programs (Fast Registry Query)");
    Log(Pad("Name", 60) + Pad("Version", 20) + "Publisher");
    Log(Pad("----", 60) + Pad("-------", 20) + "---------");

    var keys = [
        ["HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"],
        ["HKEY_LOCAL_MACHINE", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"],
        ["HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"]
    ];

    var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
    var locator = new ActiveXObject(_loc);
    var reg = locator.ConnectServer(".", "root\\default").Get("StdRegProv");

    for (var i = 0; i < keys.length; i++) {
        try {
            var hDefKey = (keys[i][0] === "HKEY_LOCAL_MACHINE") ? 0x80000002 : 0x80000001;
            var subKey = keys[i][1];
            
            var method = reg.Methods_.Item("EnumKey");
            var inParams = method.InParameters.SpawnInstance_();
            inParams.hDefKey = hDefKey;
            inParams.sSubKeyName = subKey;
            
            var outParams = reg.ExecMethod_(method.Name, inParams);
            if (outParams.sNames !== null) {
                var names = outParams.sNames.toArray();
                for (var j = 0; j < names.length; j++) {
                    var fullSubKey = subKey + "\\" + names[j];
                    
                    function GetRegVal(valName) {
                        var vMethod = reg.Methods_.Item("GetStringValue");
                        var vIn = vMethod.InParameters.SpawnInstance_();
                        vIn.hDefKey = hDefKey;
                        vIn.sSubKeyName = fullSubKey;
                        vIn.sValueName = valName;
                        var vOut = reg.ExecMethod_(vMethod.Name, vIn);
                        return vOut.sValue || "N/A";
                    }

                    var pName = GetRegVal("DisplayName");
                    if (pName !== "N/A") {
                        var pVer = GetRegVal("DisplayVersion");
                        var pPub = GetRegVal("Publisher");
                        Log(Pad(pName.substring(0, 58), 60) + Pad(pVer.substring(0, 18), 20) + pPub);
                    }
                }
            }
        } catch (e) {
            // Path might not exist on all architectures/users
        }
    }
}

function SurveyHostsFile() {
    Section("Hosts File");
    var hostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    try {
        if (fso.FileExists(hostsPath)) {
            var f = fso.OpenTextFile(hostsPath, 1);
            var content = f.AtEndOfStream ? "" : f.ReadAll();
            f.Close();
            var lines = content.split('\n');
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].replace(/\r/g, "").replace(/^\s+|\s+$/g, "");
                if (line.length > 0) {
                    Log("  " + line);
                }
            }
        } else {
            Log("  hosts file not found at " + hostsPath);
        }
    } catch (e) {
        Log("  Error reading hosts file: " + e.message);
    }
}

function SurveyDNSCache() {
    Section("DNS Cache (ipconfig /displaydns)");
    try {
        var dnsOut = RunCommand('ipconfig /displaydns', 15000);
        if (dnsOut.length > 0) {
            var lines = dnsOut.split('\n');
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].replace(/\r/g, "").replace(/^\s+|\s+$/g, "");
                if (line.length > 0 && line.indexOf("---") === -1) {
                    Log("  " + line);
                }
            }
        } else {
            Log("  (no DNS cache data or ipconfig not available)");
        }
    } catch (e) {
        Log("  Error querying DNS cache: " + e.message);
    }
}

function SurveyListeningPorts() {
    Section("Listening Ports (TCP)");
    try {
        var netstatOut = RunCommand('netstat -an', 30000);
        if (netstatOut.length > 0) {
            var lines = netstatOut.split('\n');
            var headerPrinted = false;
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].replace(/\r/g, "").replace(/^\s+|\s+$/g, "");
                if (line.indexOf("LISTENING") !== -1) {
                    if (!headerPrinted) {
                        Log(Pad("Proto", 8) + Pad("Local Address", 30) + "State");
                        Log(Pad("-----", 8) + Pad("-------------", 30) + "-----");
                        headerPrinted = true;
                    }
                    // Parse: "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING"
                    var parts = line.split(/\s+/);
                    if (parts.length >= 3) {
                        Log(Pad(parts[0], 8) + Pad(parts[1], 30) + parts[parts.length - 1]);
                    }
                }
            }
            if (!headerPrinted) {
                Log("  No listening TCP ports found.");
            }
        } else {
            Log("  (netstat not available)");
        }
    } catch (e) {
        Log("  Error querying listening ports: " + e.message);
    }
}

function SurveyAuditPolicy() {
    Section("Audit Policy (auditpol)");
    try {
        var auditOut = RunCommand('auditpol /get /category:*', 15000);
        if (auditOut.length > 0) {
            var lines = auditOut.split('\n');
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].replace(/\r/g, "").replace(/^\s+|\s+$/g, "");
                if (line.length > 0) {
                    Log("  " + line);
                }
            }
        } else {
            Log("  (auditpol not available or requires elevated privileges)");
        }
    } catch (e) {
        Log("  Error querying audit policy: " + e.message);
    }
}

function SurveyDefenderExclusions() {
    Section("Windows Defender Exclusions");
    try {
        var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
        var locator = new ActiveXObject(_loc);
        var reg = locator.ConnectServer(".", "root\\default").Get("StdRegProv");
        var HKLM = 0x80000002;
        var baseKey = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions";
        var subKeys = ["Paths", "Extensions", "Processes"];
        
        for (var i = 0; i < subKeys.length; i++) {
            var fullKey = baseKey + "\\" + subKeys[i];
            Log("\n  " + subKeys[i] + " Exclusions:");
            try {
                var method = reg.Methods_.Item("EnumValues");
                var inParams = method.InParameters.SpawnInstance_();
                inParams.hDefKey = HKLM;
                inParams.sSubKeyName = fullKey;
                var outParams = reg.ExecMethod_(method.Name, inParams);
                if (outParams.sNames !== null) {
                    var names = outParams.sNames.toArray();
                    if (names.length > 0) {
                        for (var j = 0; j < names.length; j++) {
                            Log("    [!] " + names[j]);
                        }
                    } else {
                        Log("    (none)");
                    }
                } else {
                    Log("    (none)");
                }
            } catch (e2) {
                Log("    (not readable or key does not exist)");
            }
        }
    } catch (e) {
        Log("  Error querying Defender exclusions: " + e.message);
    }
}

function SurveyPSExecutionPolicy() {
    Section("PowerShell Execution Policy");
    try {
        var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
        var locator = new ActiveXObject(_loc);
        var reg = locator.ConnectServer(".", "root\\default").Get("StdRegProv");
        var HKLM = 0x80000002;
        var HKCU = 0x80000001;
        
        var policies = [
            [HKLM, "SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", "Machine"],
            [HKCU, "SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", "User"]
        ];
        
        for (var i = 0; i < policies.length; i++) {
            try {
                var vMethod = reg.Methods_.Item("GetStringValue");
                var vIn = vMethod.InParameters.SpawnInstance_();
                vIn.hDefKey = policies[i][0];
                vIn.sSubKeyName = policies[i][1];
                vIn.sValueName = "ExecutionPolicy";
                var vOut = reg.ExecMethod_(vMethod.Name, vIn);
                var policy = vOut.sValue || "Not Set";
                Log("  " + policies[i][2] + " Policy: " + policy);
            } catch (e2) {
                Log("  " + policies[i][2] + " Policy: Not Set");
            }
        }
    } catch (e) {
        Log("  Error querying execution policy: " + e.message);
    }
}

function SurveyNamedPipes() {
    Section("Named Pipes");
    try {
        var pipesOut = RunCommand('dir \\\\.\\pipe\\', 15000);
        if (pipesOut.length > 0) {
            var lines = pipesOut.split('\n');
            var pipeNames = [];
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].replace(/\r/g, "").replace(/^\s+|\s+$/g, "");
                // Lines with pipe names typically don't start with Volume, Directory, or blank
                if (line.length > 0 && line.indexOf("Volume") === -1 && line.indexOf("Directory") === -1 && line.indexOf(" File(s)") === -1 && line.indexOf(" Dir(s)") === -1) {
                    pipeNames.push(line);
                }
            }
            // Flag suspicious pipes
            var suspicious = ["msagent_", "MSSE-", "postex_", "status_", "mojo.", "interprocess.", "lsadump", "cachedump", "wceaux"];
            for (var j = 0; j < pipeNames.length; j++) {
                var flag = "";
                for (var s = 0; s < suspicious.length; s++) {
                    if (pipeNames[j].toLowerCase().indexOf(suspicious[s].toLowerCase()) !== -1) {
                        flag = " [!!! SUSPICIOUS]";
                        break;
                    }
                }
                Log("  " + pipeNames[j] + flag);
            }
            Log("\n  Total pipes: " + pipeNames.length);
        } else {
            Log("  (could not enumerate named pipes)");
        }
    } catch (e) {
        Log("  Error enumerating named pipes: " + e.message);
    }
}

function SurveyLSAProtection() {
    Section("LSA Protection & Credential Guard");
    try {
        var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
        var locator = new ActiveXObject(_loc);
        var reg = locator.ConnectServer(".", "root\\default").Get("StdRegProv");
        var HKLM = 0x80000002;
        
        // LSA Protection (RunAsPPL)
        try {
            var vMethod = reg.Methods_.Item("GetDWORDValue");
            var vIn = vMethod.InParameters.SpawnInstance_();
            vIn.hDefKey = HKLM;
            vIn.sSubKeyName = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
            vIn.sValueName = "RunAsPPL";
            var vOut = reg.ExecMethod_(vMethod.Name, vIn);
            if (vOut.uValue !== null && vOut.uValue > 0) {
                Log("  LSA Protection (RunAsPPL): ENABLED (credential dumping blocked)");
            } else {
                Log("  [!] LSA Protection (RunAsPPL): DISABLED or NOT SET (vulnerable to Mimikatz)");
            }
        } catch (e2) {
            Log("  LSA Protection (RunAsPPL): Could not read (" + e2.message + ")");
        }
        
        // Credential Guard
        try {
            var cgMethod = reg.Methods_.Item("GetDWORDValue");
            var cgIn = cgMethod.InParameters.SpawnInstance_();
            cgIn.hDefKey = HKLM;
            cgIn.sSubKeyName = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
            cgIn.sValueName = "EnableVirtualizationBasedSecurity";
            var cgOut = reg.ExecMethod_(cgMethod.Name, cgIn);
            if (cgOut.uValue !== null && cgOut.uValue > 0) {
                Log("  Credential Guard (VBS): ENABLED");
            } else {
                Log("  Credential Guard (VBS): DISABLED or NOT SET");
            }
        } catch (e3) {
            Log("  Credential Guard: Could not read");
        }
    } catch (e) {
        Log("  Error querying LSA/Credential Guard: " + e.message);
    }
}

function SurveySMBv1() {
    Section("SMBv1 Status");
    try {
        var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
        var locator = new ActiveXObject(_loc);
        var reg = locator.ConnectServer(".", "root\\default").Get("StdRegProv");
        var HKLM = 0x80000002;
        
        // SMB1 server
        try {
            var vMethod = reg.Methods_.Item("GetDWORDValue");
            var vIn = vMethod.InParameters.SpawnInstance_();
            vIn.hDefKey = HKLM;
            vIn.sSubKeyName = "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters";
            vIn.sValueName = "SMB1";
            var vOut = reg.ExecMethod_(vMethod.Name, vIn);
            if (vOut.uValue !== null && vOut.uValue === 0) {
                Log("  SMBv1 Server: DISABLED (secure)");
            } else {
                Log("  [!] SMBv1 Server: ENABLED or NOT SET (vulnerable to EternalBlue/WannaCry)");
            }
        } catch (e2) {
            Log("  SMBv1 Server: Could not determine status");
        }
        
        // SMB1 client (mrxsmb10 driver)
        try {
            var cMethod = reg.Methods_.Item("GetDWORDValue");
            var cIn = cMethod.InParameters.SpawnInstance_();
            cIn.hDefKey = HKLM;
            cIn.sSubKeyName = "SYSTEM\\CurrentControlSet\\Services\\mrxsmb10";
            cIn.sValueName = "Start";
            var cOut = reg.ExecMethod_(cMethod.Name, cIn);
            if (cOut.uValue !== null && cOut.uValue === 4) {
                Log("  SMBv1 Client: DISABLED (secure)");
            } else {
                Log("  [!] SMBv1 Client: ENABLED (Start=" + (cOut.uValue !== null ? cOut.uValue : "N/A") + ")");
            }
        } catch (e3) {
            Log("  SMBv1 Client: Could not determine status");
        }
    } catch (e) {
        Log("  Error querying SMBv1 status: " + e.message);
    }
}

function SurveyRecentlyModifiedFiles() {
    Section("Recently Modified Files (Last Hour)");
    Log("  Scanning C:\\ drive (may take a minute)...");

    var MAX_RESULTS = 100;
    var TIMEOUT_MS = 90000; // 90 seconds
    var SKIP_DIRS = {
        "$recycle.bin": true, "system volume information": true,
        "windows\\servicing": true, "windows\\winsxs": true,
        "windows\\installer": true, "windows\\assembly": true,
        "config.msi": true
    };

    var results = [];
    var dirsScanned = 0;
    var startTime = new Date().getTime();
    var timedOut = false;

    // Cutoff: 1 hour ago
    var cutoff = new Date();
    cutoff.setTime(cutoff.getTime() - 3600000);

    // Stack-based traversal to avoid call-stack overflow on deep trees
    var stack = [];
    try { stack.push(fso.GetFolder("C:\\")); } catch(e) {
        Log("  Error: Cannot access C:\\ drive.");
        return;
    }

    while (stack.length > 0 && results.length < MAX_RESULTS) {
        // Timeout check
        if (new Date().getTime() - startTime > TIMEOUT_MS) {
            timedOut = true;
            break;
        }

        var folder = stack.pop();
        dirsScanned++;

        // Check files in this folder
        try {
            var files = new Enumerator(folder.Files);
            for (; !files.atEnd(); files.moveNext()) {
                if (results.length >= MAX_RESULTS) break;
                try {
                    var f = files.item();
                    if (f.DateLastModified >= cutoff) {
                        results.push({
                            path: f.Path,
                            modified: f.DateLastModified,
                            size: f.Size
                        });
                    }
                } catch(ef) { /* access denied on individual file */ }
            }
        } catch(eFiles) { /* access denied on file enumeration */ }

        // Queue subdirectories
        try {
            var subs = new Enumerator(folder.SubFolders);
            for (; !subs.atEnd(); subs.moveNext()) {
                try {
                    var sub = subs.item();
                    // Skip known problematic/noisy directories
                    var relPath = sub.Path.substring(3).toLowerCase(); // strip "C:\"
                    if (!SKIP_DIRS[relPath] && !SKIP_DIRS[sub.Name.toLowerCase()]) {
                        stack.push(sub);
                    }
                } catch(es) { /* access denied on subfolder */ }
            }
        } catch(eSubs) { /* access denied on subfolder enumeration */ }
    }

    // Output results
    if (results.length > 0) {
        Log(Pad("  Modified", 24) + Pad("Size", 14) + "Path");
        Log(Pad("  --------", 24) + Pad("----", 14) + "----");
        for (var i = 0; i < results.length; i++) {
            var r = results[i];
            var sizeStr = r.size < 1024 ? r.size + " B" :
                          r.size < 1048576 ? Math.round(r.size / 1024) + " KB" :
                          Math.round(r.size / 1048576) + " MB";
            Log(Pad("  " + r.modified, 24) + Pad(sizeStr, 14) + r.path);
        }
    } else {
        Log("  No recently modified files found.");
    }

    Log("\n  Directories scanned: " + dirsScanned);
    if (results.length >= MAX_RESULTS) {
        Log("  [!] Output capped at " + MAX_RESULTS + " files.");
    }
    if (timedOut) {
        Log("  [!] Scan timed out after " + Math.round(TIMEOUT_MS / 1000) + "s (partial results shown).");
    }
}

function SurveyAnomalyDetection() {
    Section("Anomaly Detection (Threat Hunting)");
    var findings = [];
    
    // --- 1. Critical Windows processes running from wrong paths ---
    var EXPECTED_PATHS = {
        "svchost.exe":    "c:\\windows\\system32\\svchost.exe",
        "lsass.exe":      "c:\\windows\\system32\\lsass.exe",
        "services.exe":   "c:\\windows\\system32\\services.exe",
        "csrss.exe":      "c:\\windows\\system32\\csrss.exe",
        "wininit.exe":    "c:\\windows\\system32\\wininit.exe",
        "winlogon.exe":   "c:\\windows\\system32\\winlogon.exe",
        "smss.exe":       "c:\\windows\\system32\\smss.exe",
        "explorer.exe":   "c:\\windows\\explorer.exe",
        "spoolsv.exe":    "c:\\windows\\system32\\spoolsv.exe",
        "taskhostw.exe":  "c:\\windows\\system32\\taskhostw.exe",
        "taskhost.exe":   "c:\\windows\\system32\\taskhost.exe",
        "conhost.exe":    "c:\\windows\\system32\\conhost.exe",
        "dwm.exe":        "c:\\windows\\system32\\dwm.exe",
        "dllhost.exe":    "c:\\windows\\system32\\dllhost.exe",
        "wuauclt.exe":    "c:\\windows\\system32\\wuauclt.exe",
        "searchindexer.exe": "c:\\windows\\system32\\searchindexer.exe"
    };
    
    // --- 2. Suspicious execution locations ---
    var SUSPICIOUS_LOCATIONS = [
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
        "\\users\\public\\", "\\$recycle.bin\\", "\\programdata\\",
        "\\downloads\\", "\\desktop\\", "\\perflogs\\"
    ];
    
    // --- 3. LOLBins (Living Off the Land Binaries) ---
    var LOLBINS = [
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
        "bitsadmin.exe", "wmic.exe", "cmstp.exe", "msiexec.exe",
        "installutil.exe", "regasm.exe", "regsvcs.exe",
        "msbuild.exe", "csc.exe", "wscript.exe", "cscript.exe",
        "pcalua.exe", "infdefaultinstall.exe", "odbcconf.exe"
    ];
    
    // Build PID-to-process lookup for parent checking
    var pidMap = {};
    for (var i = 0; i < _collectedProcesses.length; i++) {
        pidMap[_collectedProcesses[i].PID] = _collectedProcesses[i];
    }
    
    for (var j = 0; j < _collectedProcesses.length; j++) {
        var proc = _collectedProcesses[j];
        var nameLower = proc.Name.toLowerCase();
        var pathLower = (proc.Path || "N/A").toLowerCase();
        
        // Check 1: System process running from wrong path
        if (EXPECTED_PATHS[nameLower] && pathLower !== "n/a") {
            if (pathLower !== EXPECTED_PATHS[nameLower]) {
                findings.push("[!!!] CRITICAL: " + proc.Name + " (PID " + proc.PID + ") running from UNEXPECTED path: " + proc.Path + " (expected: " + EXPECTED_PATHS[nameLower] + ")");
            }
        }
        
        // Check 2: Executables running from suspicious locations
        if (pathLower !== "n/a") {
            for (var s = 0; s < SUSPICIOUS_LOCATIONS.length; s++) {
                if (pathLower.indexOf(SUSPICIOUS_LOCATIONS[s]) !== -1) {
                    findings.push("[!!] SUSPICIOUS LOCATION: " + proc.Name + " (PID " + proc.PID + ") running from: " + proc.Path);
                    break;
                }
            }
        }
        
        // Check 3: LOLBin usage
        for (var l = 0; l < LOLBINS.length; l++) {
            if (nameLower === LOLBINS[l]) {
                var parentInfo = "";
                if (pidMap[proc.PPID]) {
                    parentInfo = " (parent: " + pidMap[proc.PPID].Name + " PID " + proc.PPID + ")";
                }
                findings.push("[!] LOLBIN: " + proc.Name + " (PID " + proc.PID + ") is running" + parentInfo);
                break;
            }
        }
        
        // Check 4: Double extension (e.g., document.pdf.exe)
        if (pathLower !== "n/a") {
            var exts = [".doc.", ".pdf.", ".jpg.", ".png.", ".txt.", ".xlsx.", ".pptx."];
            for (var d = 0; d < exts.length; d++) {
                if (pathLower.indexOf(exts[d]) !== -1) {
                    findings.push("[!!!] DOUBLE EXTENSION: " + proc.Name + " (PID " + proc.PID + ") has suspicious double extension: " + proc.Path);
                    break;
                }
            }
        }
    }
    
    // Output findings
    if (findings.length > 0) {
        Log("  *** " + findings.length + " anomalies detected ***\n");
        for (var f = 0; f < findings.length; f++) {
            Log("  " + findings[f]);
        }
    } else {
        Log("  No anomalies detected. All processes appear to be running from expected locations.");
    }
}

function SurveyEventLogs() {
    Section("Event Logs (Last " + EVENT_LOG_LIMIT + " entries each)");
    var logs = ["System", "Security", "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"];
    
    for (var i = 0; i < logs.length; i++) {
        Log("\n--- Log: " + logs[i] + " ---");
        try {
            // WMI Win32_NTLogEvent
            // Note: Security log requires SeSecurityPrivilege
            var query = "SELECT * FROM Win32_NTLogEvent WHERE Logfile = '" + logs[i].replace(/'/g, "\\'") + "'";
            var items = wmi.ExecQuery(query);
            var enumItems = new Enumerator(items);
            var count = 0;
            
            // WMI doesn't easily support ORDER BY or LIMIT in standard SELECT * for event logs
            // So we iterate and stop. To get the 'latest', we'd need to manually sort or use a better query.
            // But standard WMI enumeration is usually sequential.
            for (; !enumItems.atEnd() && count < EVENT_LOG_LIMIT; enumItems.moveNext()) {
                var log = enumItems.item();
                Log("[" + FormatWMIDate(log.TimeGenerated) + "] ID: " + log.EventCode + " | Type: " + log.Type + " | Category: " + (log.CategoryString || log.Category || "N/A") + " | Source: " + log.SourceName);
                // Log("Message: " + log.Message.substr(0, 100) + "...");
                count++;
            }
            if (count === 0) Log("No logs found or access denied.");
        } catch (e) {
            Log("Error querying " + logs[i] + ": " + e.message);
        }
    }
}

// --- Main ---
try {
    // WSH deprecation warning
    if (typeof WScript !== "undefined") {
        WScript.Echo("NOTE: Windows Script Host (WSH) is deprecated by Microsoft.");
        WScript.Echo("Consider migrating to PowerShell for long-term compatibility.");
        WScript.Echo("");
    }

    // Parse command-line arguments
    var args = WScript.Arguments;
    var outputFileName = RESULTS_FILE;
    if (!outputFileName) {
        var hostName = ".";
        try { hostName = shell.ExpandEnvironmentStrings("%COMPUTERNAME%"); } catch(e) { hostName = "unknown"; }
        // Default to script's own directory
        var scriptDir = fso.GetParentFolderName(WScript.ScriptFullName);
        outputFileName = scriptDir + "\\survey_" + hostName + ".txt";
    }
    var encodeOutput = ENCODE_OUTPUT;
    var skipHashing = !ENABLE_PROCESS_HASHING;

    for (var a = 0; a < args.length; a++) {
        if (args(a) === "--output" && a + 1 < args.length) {
            outputFileName = args(a + 1); a++;
        } else if (args(a) === "--encode") {
            encodeOutput = true;
        } else if (args(a) === "--no-hash") {
            skipHashing = true;
        } else if (args(a) === "--hash") {
            skipHashing = false;
        } else if (args(a) === "--help") {
            WScript.Echo("Usage: cscript /nologo win-survey.js [options]");
            WScript.Echo("  --output <file>   Output file path (default: survey_results.txt)");
            WScript.Echo("  --encode          Base64 encode the output");
            WScript.Echo("  --no-hash         Skip process hashing (default: off)");
            WScript.Echo("  --hash            Enable process hashing (MD5 via certutil)");
            WScript.Echo("  --help            Show this help");
            WScript.Quit(0);
        }
    }

    // Apply CLI overrides
    if (!skipHashing) {
        ENABLE_PROCESS_HASHING = true;
    }

    Log("Starting System Survey at " + new Date());
    SurveySystemInfo();
    SurveyNetwork();
    SurveyUsers();
    SurveyProcesses();
    SurveyServices();
    SurveyStartup();
    SurveyScheduledTasks();
    SurveyWMIPersistence();
    SurveyPSHistory();
    SurveySecurityProducts();
    SurveyHotfixes();
    SurveyInstalledPrograms();
    SurveyEnvVars();
    SurveyRemoteAccess();
    SurveyDrivers();
    SurveyNeighbors();
    SurveyFirewall();
    SurveyHostsFile();
    SurveyDNSCache();
    SurveyListeningPorts();
    SurveyAuditPolicy();
    SurveyDefenderExclusions();
    SurveyPSExecutionPolicy();
    SurveyNamedPipes();
    SurveyLSAProtection();
    SurveySMBv1();
    SurveyAnomalyDetection();
    SurveyEventLogs();
    SurveyRecentlyModifiedFiles();
    Log("\nSurvey completed at " + new Date());
    
    // Validate output path
    var outputLower = outputFileName.toLowerCase();
    var prohibited = ["\\windows\\system32", "\\windows\\syswow64", "\\windows\\system"];
    for (var pi = 0; pi < prohibited.length; pi++) {
        if (outputLower.indexOf(prohibited[pi]) !== -1) {
            WScript.Echo("ERROR: Refusing to write to " + outputFileName);
            WScript.Quit(1);
        }
    }

    // Final Write
    var finalOutput = encodeOutput ? Base64.encode(logBuffer) : logBuffer;
    var logFile = fso.CreateTextFile(outputFileName, true);
    logFile.Write(finalOutput);
    logFile.Close();
} catch (e) {
    WScript.Echo("FATAL ERROR: " + e.message);
} finally {
    WScript.Echo("\nResults saved to " + outputFileName);
}
