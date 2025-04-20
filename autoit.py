import re, math, sys, argparse, os
from collections import Counter

# Bypass Limit to do the math stuff.
sys.set_int_max_str_digits(1000000)

def save_logs(txt):
    with open("Log.txt", 'a') as f:
        f.write(txt + "\n")

def create_parser():
    parser = argparse.ArgumentParser(description="AutoIT3 Unpacker 3.x")
    parser.add_argument('-f', '--file', type=str, help='Dateipfad zum Eingabe-Datei')
    parser.add_argument('-v', '--verbose', action='store_true', help='Aktiviert den ausführlichen Modus')
    return parser

def logger(step, mode, far=False):
    save_logs(step)
    modes = {
        "+": ("\x1b[92m", "+"),
        "-": ("\x1b[91m", "-"),
        "!": ("\x1b[1;91m", "!"),
        "?": ("\x1b[94m", "?"),
        ">": ("\x1b[93m", ">"),
    }
    color, symbol = modes.get(mode, ("\x1b[0m", "?"))
    output = f"\x1b[0m[{color}{symbol}\x1b[0m]{color} {step}\x1b[0m"
    save_logs(step)
    if far:
        print(f"\t{output}")
    else:
        print(f"\x1b[0m[\x1b[96mAUTOIT UNPACKER\x1b[0m] {output}")
    

def extract_key(raw_code):
    key_pattern = r'Local\s+\$([A-Za-z0-9_]+)\s*=\s*0x([0-9a-fA-F]+)'
    match = re.search(key_pattern, raw_code)
    if match:
        return int(match.group(2), 16)
    return None

def extract_globals(raw_code):
    global_pattern = r'Global\s+\$([A-Za-z0-9_]+)\s*=\s*(.*)'
    matches = re.findall(global_pattern, raw_code)
    return dict(matches)

def convert_number(arg):
    if arg.startswith('0x'):
        return int(arg, 16)
    try:
        return float(arg) if '.' in arg else int(arg)
    except ValueError:
        return arg

def concat_big_string(raw_code):
    globals_dict = extract_globals(raw_code)
    first_key = next(iter(globals_dict.keys()), None)
    bigstring_pattern = re.compile(r'\$' + first_key + r'\s*\&=\s*"(.*)"')
    matches = re.findall(bigstring_pattern, raw_code)
    if matches:
        value = globals_dict[first_key]
        for match in matches:
            value += match
        return {'key': first_key, 'value': value}
    return None

def remove_concats(raw_code, var_key, value):
    concat_pattern = re.compile(r'\$' + re.escape(var_key) + r'\s*&=\s*".*?"\s*\n?', re.DOTALL)
    global_pattern = re.compile(r'Global \$' + re.escape(var_key) + r'\s*=\s*".*?"', re.DOTALL)
    match = global_pattern.search(raw_code)
    raw_code = re.sub(concat_pattern, "", raw_code)
    if match:
        value = value.replace('"', '')
        raw_code = raw_code.replace(match.group(0), f'Global ${var_key} = "{value}"')
    return raw_code

def decrypt_string(key, string):
    decrypt_string = ""
    for char in string:
        decrypted_char = chr(ord(char) ^ key)
        decrypt_string += decrypted_char
    return decrypt_string

def extract_call_obj(raw_code):
    first_line = raw_code.splitlines()[0]
    match = re.match(r'^\$(.*?) =', first_line)
    if match:
        return match.group(1)
    return ''

def extract_calls(raw_code, call_var):
    pattern = rf'\${re.escape(call_var).upper()}\((.*?)\)'
    return [call + ")" for call in re.findall(pattern, raw_code)]

def extract_func_names(raw_code):
    return re.findall(r"^\s*Func\s+([a-zA-Z0-9_]+)\s*\(", raw_code, flags=re.MULTILINE)

def extract_func_string(raw_code, function):
    pattern = rf"{re.escape(function)}\(\s*(\".*?(?:\"\s*&\s*\".*?)*\")\s*\)"
    matches = re.findall(pattern, raw_code)
    return [match.replace('"', '') for match in matches]

def extract_func_calls(raw_code):
    calls = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', raw_code)
    calls_counter = Counter(calls)
    return list(set(calls)), calls_counter

def check_calls(calls):
    all_funcs = ['ACos', 'ASin', 'ATan', 'Abs', 'AdlibRegister', 'AdlibUnRegister', 'Asc', 'AscW', 'Assign', 'AutoItSetOption', 'AutoItWinGetTitle', 'AutoItWinSetTitle', 'Beep', 'Binary', 'BinaryLen', 'BinaryMid', 'BinaryToString', 'BitAND', 'BitNOT', 'BitOR', 'BitRotate', 'BitShift', 'BitXOR', 'BlockInput', 'Break', 'CDTray', 'Call', 'Ceiling', 'Chr', 'ChrW', 'ClipGet', 'ClipPut', 'ConsoleRead', 'ConsoleWrite', 'ConsoleWriteError', 'ControlClick', 'ControlCommand', 'ControlDisable', 'ControlEnable', 'ControlFocus', 'ControlGetFocus', 'ControlGetHandle', 'ControlGetPos', 'ControlGetText', 'ControlHide', 'ControlListView', 'ControlMove', 'ControlSend', 'ControlSetText', 'ControlShow', 'ControlTreeView', 'Cos', 'Dec', 'DirCopy', 'DirCreate', 'DirGetSize', 'DirMove', 'DirRemove', 'DllCall', 'DllCallAddress', 'DllCallbackFree', 'DllCallbackGetPtr', 'DllCallbackRegister', 'DllClose', 'DllOpen', 'DllStructCreate', 'DllStructGetData', 'DllStructGetPtr', 'DllStructGetSize', 'DllStructSetData', 'DriveGetDrive', 'DriveGetFileSystem', 'DriveGetLabel', 'DriveGetSerial', 'DriveGetType', 'DriveMapAdd', 'DriveMapDel', 'DriveMapGet', 'DriveSetLabel', 'DriveSpaceFree', 'DriveSpaceTotal', 'DriveStatus', 'EnvGet', 'EnvSet', 'EnvUpdate', 'Eval', 'Execute', 'Exp', 'FileChangeDir', 'FileClose', 'FileCopy', 'FileCreateNTFSLink', 'FileCreateShortcut', 'FileDelete', 'FileExists', 'FileFindFirstFile', 'FileFindNextFile', 'FileFlush', 'FileGetAttrib', 'FileGetEncoding', 'FileGetLongName', 'FileGetPos', 'FileGetShortName', 'FileGetShortcut', 'FileGetSize', 'FileGetTime', 'FileGetVersion', 'FileInstall', 'FileMove', 'FileOpen', 'FileOpenDialog', 'FileRead', 'FileReadLine', 'FileReadToArray', 'FileRecycle', 'FileRecycleEmpty', 'FileSaveDialog', 'FileSelectFolder', 'FileSetAttrib', 'FileSetEnd', 'FileSetPos', 'FileSetTime', 'FileWrite', 'FileWriteLine', 'Floor', 'FtpSetProxy', 'FuncName', 'GUICreate', 'GUICtrlCreateAvi', 'GUICtrlCreateButton', 'GUICtrlCreateCheckbox', 'GUICtrlCreateCombo', 'GUICtrlCreateContextMenu', 'GUICtrlCreateDate', 'GUICtrlCreateDummy', 'GUICtrlCreateEdit', 'GUICtrlCreateGraphic', 'GUICtrlCreateGroup', 'GUICtrlCreateIcon', 'GUICtrlCreateInput', 'GUICtrlCreateLabel', 'GUICtrlCreateList', 'GUICtrlCreateListView', 'GUICtrlCreateListViewItem', 'GUICtrlCreateMenu', 'GUICtrlCreateMenuItem', 'GUICtrlCreateMonthCal', 'GUICtrlCreateObj', 'GUICtrlCreatePic', 'GUICtrlCreateProgress', 'GUICtrlCreateRadio', 'GUICtrlCreateSlider', 'GUICtrlCreateTab', 'GUICtrlCreateTabItem', 'GUICtrlCreateTreeView', 'GUICtrlCreateTreeViewItem', 'GUICtrlCreateUpdown', 'GUICtrlDelete', 'GUICtrlGetHandle', 'GUICtrlGetState', 'GUICtrlRead', 'GUICtrlRecvMsg', 'GUICtrlRegisterListViewSort', 'GUICtrlSendMsg', 'GUICtrlSendToDummy', 'GUICtrlSetBkColor', 'GUICtrlSetColor', 'GUICtrlSetCursor', 'GUICtrlSetData', 'GUICtrlSetDefBkColor', 'GUICtrlSetDefColor', 'GUICtrlSetFont', 'GUICtrlSetGraphic', 'GUICtrlSetImage', 'GUICtrlSetLimit', 'GUICtrlSetOnEvent', 'GUICtrlSetPos', 'GUICtrlSetResizing', 'GUICtrlSetState', 'GUICtrlSetStyle', 'GUICtrlSetTip', 'GUIDelete', 'GUIGetCursorInfo', 'GUIGetMsg', 'GUIGetStyle', 'GUIRegisterMsg', 'GUISetAccelerators', 'GUISetBkColor', 'GUISetCoord', 'GUISetCursor', 'GUISetFont', 'GUISetHelp', 'GUISetIcon', 'GUISetOnEvent', 'GUISetState', 'GUISetStyle', 'GUIStartGroup', 'GUISwitch', 'HWnd', 'Hex', 'HotKeySet', 'HttpSetProxy', 'HttpSetUserAgent', 'InetClose', 'InetGet', 'InetGetInfo', 'InetGetSize', 'InetRead', 'IniDelete', 'IniRead', 'IniReadSection', 'IniReadSectionNames', 'IniRenameSection', 'IniWrite', 'IniWriteSection', 'InputBox', 'Int', 'IsAdmin', 'IsArray', 'IsBinary', 'IsBool', 'IsDeclared', 'IsDllStruct', 'IsFloat', 'IsFunc', 'IsHWnd', 'IsInt', 'IsKeyword', 'IsMap', 'IsNumber', 'IsObj', 'IsPtr', 'IsString', 'Log', 'MapAppend', 'MapExists', 'MapKeys', 'MapRemove', 'MemGetStats', 'Mod', 'MouseClick', 'MouseClickDrag', 'MouseDown', 'MouseGetCursor', 'MouseGetPos', 'MouseMove', 'MouseUp', 'MouseWheel', 'MsgBox', 'Number', 'ObjCreate', 'ObjCreateInterface', 'ObjEvent', 'ObjGet', 'ObjName', 'OnAutoItExitRegister', 'OnAutoItExitUnRegister', 'Ping', 'PixelChecksum', 'PixelGetColor', 'PixelSearch', 'ProcessClose', 'ProcessExists', 'ProcessGetStats', 'ProcessList', 'ProcessSetPriority', 'ProcessWait', 'ProcessWaitClose', 'ProgressOff', 'ProgressOn', 'ProgressSet', 'Ptr', 'Random', 'RegDelete', 'RegEnumKey', 'RegEnumVal', 'RegRead', 'RegWrite', 'Round', 'Run', 'RunAs', 'RunAsWait', 'RunWait', 'SRandom', 'Send', 'SendKeepActive', 'SetError', 'SetExtended', 'ShellExecute', 'ShellExecuteWait', 'Shutdown', 'Sin', 'Sleep', 'SoundPlay', 'SoundSetWaveVolume', 'SplashImageOn', 'SplashOff', 'SplashTextOn', 'Sqrt', 'StatusbarGetText', 'StderrRead', 'StdinWrite', 'StdioClose', 'StdoutRead', 'String', 'StringAddCR', 'StringCompare', 'StringFormat', 'StringFromASCIIArray', 'StringInStr', 'StringIsASCII', 'StringIsAlNum', 'StringIsAlpha', 'StringIsDigit', 'StringIsFloat', 'StringIsInt', 'StringIsLower', 'StringIsSpace', 'StringIsUpper', 'StringIsXDigit', 'StringLeft', 'StringLen', 'StringLower', 'StringMid', 'StringRegExp', 'StringRegExpReplace', 'StringReplace', 'StringReverse', 'StringRight', 'StringSplit', 'StringStripCR', 'StringStripWS', 'StringToASCIIArray', 'StringToBinary', 'StringTrimLeft', 'StringTrimRight', 'StringUpper', 'TCPAccept', 'TCPCloseSocket', 'TCPConnect', 'TCPListen', 'TCPNameToIP', 'TCPRecv', 'TCPSend', 'TCPShutdown', 'TCPStartup', 'Tan', 'TimerDiff', 'TimerInit', 'ToolTip', 'TrayCreateItem', 'TrayCreateMenu', 'TrayGetMsg', 'TrayItemDelete', 'TrayItemGetHandle', 'TrayItemGetState', 'TrayItemGetText', 'TrayItemSetOnEvent', 'TrayItemSetState', 'TrayItemSetText', 'TraySetClick', 'TraySetIcon', 'TraySetOnEvent', 'TraySetPauseIcon', 'TraySetState', 'TraySetToolTip', 'TrayTip', 'UBound', 'UDPBind', 'UDPCloseSocket', 'UDPOpen', 'UDPRecv', 'UDPSend', 'UDPShutdown', 'UDPStartup', 'VarGetType', 'WinActivate', 'WinActive', 'WinClose', 'WinExists', 'WinFlash', 'WinGetCaretPos', 'WinGetClassList', 'WinGetClientSize', 'WinGetHandle', 'WinGetPos', 'WinGetProcess', 'WinGetState', 'WinGetText', 'WinGetTitle', 'WinKill', 'WinList', 'WinMenuSelectItem', 'WinMinimizeAll', 'WinMinimizeAllUndo', 'WinMove', 'WinSetOnTop', 'WinSetState', 'WinSetTitle', 'WinSetTrans', 'WinWait', 'WinWaitActive', 'WinWaitClose', 'WinWaitNotActive']
    good_funcs = [
        "MsgBox", "ConsoleWrite", "ConsoleWriteError", "Sleep", "ToolTip", "TraySetToolTip", "TrayTip",
        "InputBox", "StringTrimLeft", "StringTrimRight", "StringLen", "StringLower", "StringUpper", 
        "StringMid", "StringReplace", "StringInStr", "StringCompare", "StringRegExp", "StringRegExpReplace",
        "UBound", "IsString", "IsInt", "IsArray", "IsBool", "IsFloat", "IsNumber", "IsBinary", "IsPtr",
        "Round", "Ceiling", "Floor", "Random", "Abs", "Sin", "Cos", "Tan", "Sqrt", "Log", "Exp", "Mod",
        "ACos", "ASin", "ATan", "BitAND", "BitOR", "BitXOR", "BitNOT", "BitShift", "BitRotate",
        "TimerInit", "TimerDiff", "Hex", "Chr", "Asc", "Int", "Number", "ClipGet", "ClipPut",
        "ConsoleRead", "GUI*","GUICtrl*", "GUIDelete", "WinGet*", "WinExists", "WinList", 
        "WinWait", "WinWaitActive", "WinWaitNotActive", "WinWaitClose", "WinActive", "WinGetHandle"
    ]
    bad_funcs = [
        "RegDelete", "RegWrite", "RegEnumKey", "RegEnumVal", "FileDelete", "DirRemove", "FileMove",
        "DirMove", "ProcessClose", "WinKill", "Shutdown", "RunAs", "RunAsWait", "Send", "SendKeepActive",
        "MouseClick", "MouseClickDrag", "MouseMove", "MouseDown", "MouseUp", "FileRecycle", "FileRecycleEmpty",
        "BlockInput", "DriveMapDel", "DriveSetLabel", "TraySetPauseIcon", "SetError", "SetExtended"
    ]
    suspicious_funcs = [
        "Run", "RunWait", "Execute", "Eval", "Call", "DllCall", "DllCallAddress", "DllOpen", "DllClose",
        "DllStructCreate", "DllStructSetData", "DllStructGetData", "InetRead", "InetGet", "InetGetSize",
        "HttpSetProxy", "HttpSetUserAgent", "FtpSetProxy", "Ping", "FileInstall", "FileOpen", "FileRead", 
        "FileWrite", "FileCreateShortcut", "FileCreateNTFSLink", "TCPConnect", "TCPSend", "TCPRecv", 
        "TCPAccept", "UDPRecv", "UDPSend", "UDPOpen", "OnAutoItExitRegister", "AdlibRegister", 
        "HotKeySet", "AutoItSetOption", "Send", "ControlSend", "ControlClick", "ControlSetText",
        "ControlCommand", "ProcessWait", "ProcessWaitClose", "ProcessList", "ProcessSetPriority"
    ]
    FUNC_CATEGORIES = {
        "good": good_funcs,
        "bad": bad_funcs,
        "suspicious": suspicious_funcs
    }
    result = {
        "good": [],
        "suspicious": [],
        "bad": []
    }
    for func in calls:
        found = False
        for category, functions in FUNC_CATEGORIES.items():
            if func in functions:
                result[category].append(func)
                found = True
                break
        if not found:
            result.setdefault("unknown", []).append(func)
    return result

def fix_strings(key, raw_code, strings, function):
    for string in strings:
        decoded = decrypt_string(key, string)
        raw_code = re.sub(rf'{function}\("{string}"\)', decoded, raw_code)
    return raw_code

def unwrap_call_wrappers(code, wrapper_name):
    pattern = rf'(?i)\${re.escape(wrapper_name)}\(([^,]+?),\s*(.*?)\)'
    def repl(match):
        func_name = match.group(1).strip()
        args = match.group(2).strip()
        return f'{func_name}({args})'
    return re.sub(pattern, repl, code)

def clean_and_sign(raw_code):
    if '" & "' in raw_code:
        raw_code = re.sub('" & "', '', raw_code)
    
    # For future replacements, but some obfuscation methods have " and ' in addition of the strings, means we have to replace the same line with " equal to " and not '.
    
    #if '" & \'' in raw_code:
    #    raw_code = re.sub('" & \'', '', raw_code)
    #if '\' & "' in raw_code:
    #    raw_code = re.sub('\' & "', '', raw_code)
    #if "' & '" in raw_code:
    #    raw_code = re.sub("' & '", '', raw_code)
    #if ' & "' in raw_code:
    #    raw_code = re.sub(' & "', ' & \\"', raw_code)
    return raw_code

def apply_match_function(func_name, argument):
    try:
        argument = convert_number(argument)
        if func_name == 'Ceiling':
            return math.ceil(argument)
        elif func_name == 'ATan':
            return math.atan(argument)
        elif func_name == 'Tan':
            return math.tan(argument)
        elif func_name == 'Sin':
            return math.sin(argument)
        elif func_name == 'Sqrt':
            return math.sqrt(argument)
        elif func_name == 'Floor':
            return math.floor(argument)
        elif func_name == 'Log':
            return math.log(argument)
        elif func_name == 'Abs':
            return abs(argument)
    except Exception as e:
        return None

def clean_math(raw_code):
    def is_good_line(line):
        if re.search(r"\bIf\b|\bThen\b|[><=!]", line):
            return True
        return False
    func_pattern = re.compile(r"(\w+)\(([-+]?\d*\.\d+|\d+|0x[0-9a-fA-F]+)\)")
    replacements = {}
    lines = raw_code.splitlines()
    for line in lines:
        matches = func_pattern.findall(line)
        for match in matches:
            func_name, argument_str = match
            if is_good_line(line):
                result = apply_match_function(func_name, argument_str)
                if result is not None:
                    raw_code = raw_code.replace(f"{func_name}({argument_str})", str(result))
                else:
                    raw_code = raw_code.replace(f"{func_name}({argument_str})", "")
            else:
                raw_code = raw_code.replace(f"{func_name}({argument_str})", "")
    for line in raw_code.splitlines():
        binary_numbers = re.findall(r"0x[0-9a-fA-F]+", line)
        new_line = line
        if binary_numbers:
            for binary_number in binary_numbers:
                real_number = convert_number(binary_number)
                new_line = new_line.replace(binary_number, str(real_number))
            raw_code = raw_code.replace(line, new_line)
    return raw_code

def print_calls_with_length(calls, counter_calls, mode):
    for call in calls:
        if call in counter_calls:
            logger(f"{call} : {counter_calls[call]}", mode, True)

def replace_smart(raw_code):
    lines = raw_code.splitlines()
    for line in lines:
        if " & ":
            try:
                templine = line.replace("\" & '", "")
                templine = templine.replace("' & \"", "")
                start_char = re.findall(r'\((\'|")', templine)[0]
                end_char = re.findall(r'(\'|")\)$', templine)[0]
                if start_char != end_char:
                    if start_char == '"':
                        new_line = templine.replace("'", "\"")
                    else:
                        new_line = templine.replace("\"", "'")
                raw_code = raw_code.replace(line, new_line)
            except:
                pass
    return raw_code
        

def unpack_autoit_code(code):
    code = re.sub(r'\$\w+ = \d+', '', code)
    code = re.sub(r"\n\s*\n", "\n", code)
    code = re.sub(r"If\s+\d+\s*>\s*\d+\s*Then", "", code)
    code = re.sub(r'ElseIf \$\w+ <> \$\w+ Then\n.+', '', code)
    code = re.sub(r'Else\n.+\nEndIf', '', code)
    code = re.sub(r'If .+ Then\n.+\nElseIf .+ Then\n.+\nEndIf', '', code)
    code = re.sub(r"ElseIf\s+[-+]?\d+\.\d+\s*(>=|<|==)\s*\d+", "", code)
    code = re.sub(r"Else\s*EndIf", "", code)
    code = re.sub(r'ElseIf .+ Then', '', code)
    code = re.sub(r"\$[a-zA-Z]+\d+", "", code)
    code = re.sub(r'If .+ Then\n.+\nElse\n.+\nEndIf', '', code)
    code = re.sub(r"For\s+\$[a-zA-Z]+\d+\s*=\s*\d+\s*To\s*\d+\s*Next", "", code)
    code = re.sub(r'For \$\w+ = \d+ To \d+ \nNext', '', code)
    code = re.sub(r"\b(FileRecycleEmpty|TimerInit|EnvUpdate|FileFindFirstFile|FileSetTime|ProcessClose|ProcessSetPriority|FileCreateNTFSLink)\([^\)]*\)", "", code)
    code = re.sub(r"\$[a-zA-Z]+\d+\s*=\s*\d+", "", code)
    code = re.sub(r"Then\s*[\n\s]*EndIf", "", code)
    return code

def replace_dummies(raw_code):
    if_statements_dummy = re.sub(r'If[\s\S]*?"default"[\s\S]*?EndIf', '', raw_code)
    if_statements = re.sub(r'If\s+[^\s]+(\s+<=\s+[^\s]+|>=\s+[^\s]+|=\s+[^\s]+)\s+Then', '', if_statements_dummy)
    for_loops = re.sub(r"For\s+\$[a-zA-Z0-9_]+\s+=\s+[0-9]+\s+To\s+[0-9]+\s*$(?:\s+.*\s*)+Next", '', if_statements)

    # nested

    nested_v0 = re.sub(r"For\s+\$[a-zA-Z0-9_]+\s*=\s*[^ ]+\s*To\s*[^ ]+[\s\S]*?Next|If\s+[^ ]+[\s\S]*?EndIf", '', for_loops)
    nested_v1 = re.sub(r"For\s+\$[a-zA-Z0-9_]+\s*=\s*[^ ]+\s*To\s*[^ ]+[\s\S]*?Next(?!\s*Next)|If\s+[^ ]+[\s\S]*?EndIf", '', nested_v0)
    nested_v2 = re.sub(r'(?i)(\s*Next\s*|Else\s*(?=\s*Next))\s*', '', nested_v1)
    
    # clean unused keywords, tabs, etc.

    clean_v0 = re.sub(r'(?i)(Else|End|Next|EndIf|If)', '', nested_v2)
    return clean_v0

def normalize_variables(func_code):
    arg_map = {}
    local_map = {}
    counter = {"arg": 1, "local": 1}

    func_def = re.search(r'Func\s+\w+\((.*?)\)', func_code)
    if func_def:
        args = [a.strip() for a in func_def.group(1).split(",") if a.strip()]
        for arg in args:
            if re.match(r'^\$\w+$', arg):
                arg_map[arg] = f"$arg{counter['arg']}"
                counter["arg"] += 1

    for local_decl in re.findall(r'Local\s+(.*)', func_code):
        variables = [v.strip().split('=')[0].strip() for v in local_decl.split(',')]
        for var in variables:
            if re.match(r'^\$\w+$', var) and var not in local_map:
                local_map[var] = f"$local{counter['local']}"
                counter["local"] += 1

    for loop_var in re.findall(r'For\s+(\$\w+)', func_code):
        if loop_var not in local_map:
            local_map[loop_var] = f"$loopvar{counter['local']}"
            counter["local"] += 1

    all_vars = {**arg_map, **local_map}

    sorted_vars = sorted(all_vars.items(), key=lambda x: -len(x[0]))

    def replace_vars_safe(line):
        in_string = False
        result = ""
        i = 0
        while i < len(line):
            if line[i] == '"':
                in_string = not in_string
                result += line[i]
                i += 1
                continue

            if not in_string:
                matched = False
                for original, replacement in sorted_vars:
                    if line[i:].startswith(original):
                        result += replacement
                        i += len(original)
                        matched = True
                        break
                if matched:
                    continue

            result += line[i]
            i += 1
        return result

    cleaned_lines = [replace_vars_safe(line) for line in func_code.splitlines()]
    return "\n".join(cleaned_lines)

def finish_up(raw_code):
    try:
        match = re.match(r'^(.*?)\n\n', raw_code, flags=re.DOTALL)
        source = match.group(1)
        functions = extract_func_names(source)
        def extract_function_code(raw_code, func_name):
            pattern = rf"Func\s+{re.escape(func_name)}\(.*?\)(.*?)EndFunc"
            match = re.search(pattern, raw_code, re.DOTALL)
            if match:
                return match.group(0)
            return None
        func_codes = [extract_function_code(source, func) for func in functions]
        for func_code in func_codes:
            deobfuscated = normalize_variables(func_code)
            source = source.replace(func_code, deobfuscated)
        return source
    except:
        return raw_code

def save_as_dll(byte_string, filename='output.dll'):
    with open(filename, 'wb') as f:
        f.write(byte_string)


def main():
    parser = create_parser()
    args = parser.parse_args()
    file = args.file 
    if file is None:
        print("Error: No file speficied!")
        return
    if os.path.exists(file):
        with open(file, mode='r', errors='ignore', encoding='utf-8') as f:
            raw_code = f.read()
        if args.verbose:
            logger("Opened Document", "?")

        key = extract_key(raw_code)
        if args.verbose:
            logger(f"Extracted key : {key}", "+")

        global_vars = extract_globals(raw_code)
        logger(f"Global Variables : {len(global_vars)}", ">")
        try:
            big_string = concat_big_string(raw_code)
            if args.verbose:
                logger(f"Binary String Length : {len(big_string.get('value'))}", ">")

            global_vars[big_string.get('key')] = big_string.get('value')
        except:
            big_string = False
        raw_code = clean_and_sign(raw_code)
        raw_code = replace_smart(raw_code)
        logger(f"Cleaned up string obfuscation", "+")

        call_var = extract_call_obj(raw_code)
        
        if args.verbose:
            logger(f"Call Variable : {call_var}", ">")

        script_calls = extract_calls(raw_code, call_var)
        logger(f"Script Calls : {len(script_calls)}", ">")

        func_names = extract_func_names(raw_code)
        logger(f"Function Names : {len(func_names)}", ">")

        func_calls, counter_calls = extract_func_calls(raw_code)
        logger(f"Function Calls : {len(func_calls)}", ">")

        calls_cat = check_calls(func_calls)
        if args.verbose:
            print('')
            print_calls_with_length(calls_cat.get('unknown'), counter_calls, "?")
            print_calls_with_length(calls_cat.get('good'), counter_calls, "+")
            print_calls_with_length(calls_cat.get('bad'), counter_calls, "-")
            print_calls_with_length(calls_cat.get('suspicious'), counter_calls, "!")
            print('')
        strings = extract_func_string(raw_code, func_names[0])
        logger(f"Strings : {len(strings)}", ">")

        raw_code = fix_strings(key, raw_code, strings, func_names[0])
        logger(f"Deobfuscated Strings", "+")

        raw_code = unwrap_call_wrappers(raw_code, call_var)
        logger(f"Unwrapped Function Calls", "+")

        if big_string:
            raw_code = remove_concats(raw_code, big_string.get('key'), big_string.get('value'))
            logger(f"Cleaned up binary string", "+")

        raw_code = clean_math(raw_code)
        logger(f"Cleaned up math obfuscation", "+")

        raw_code_temp = finish_up(raw_code)
        raw_code = replace_dummies(raw_code_temp)
        #raw_code = unpack_autoit_code(raw_code)
        new_file = os.path.splitext(file)
        with open(new_file[0] + '_unpacked' + new_file[1], 'w') as f: f.write(raw_code)
        logger(f"Successfull source code to '{new_file}'", "+")
        if big_string:
            byte_string = decrypt_string(key, big_string.get('value').replace('"', '')).encode()
            save_as_dll(byte_string, 'exported_dll.dll')
            logger("Successfull exported DLL to 'exported_dll.dll'", "+")
        
    
    else:
        print(f"Error: File {args.file} not found.")
    return

if __name__ == '__main__':
    main()
