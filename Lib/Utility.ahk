#Include %A_LineFile%\..\JSON.ahk

; @RequireAdmin() {
	; FULL_COMMAND_LINE := DllCall("GetCommandLine", "str")
	; if not (A_IsAdmin or RegExMatch(FULL_COMMAND_LINE, " /restart(?!\S)")) {
		; try {
			; if A_IsCompiled
				; Run *RunAs "%A_ScriptFullPath%" /restart	
			; else
				; Run *RunAs "%A_AhkPath%" /restart "%A_ScriptFullPath%"
		; }
		; ExitApp
	; }
; }

@RequireAdmin() {
	if not (A_IsAdmin or RegExMatch(DllCall("GetCommandLine", "Str"), " /restart(?!\S)")) {
		try {
			FilePath := (A_IsCompiled ? A_ScriptFullPath : Format("{} /restart \\\""{}\\\""", A_AhkPath, A_ScriptFullPath))

			psScript =
			(
				param($param1)
				Start-Process powershell -WindowStyle Hidden -Verb RunAs -ArgumentList \"-Command $param1\"
			)
			
			psScript := Format("powershell -Command &{{1}} '{2}'", psScript, FilePath)
								
			RunWait, % psScript,, Hide
		}
		ExitApp
	}
}

GetProcessID(name) {
	return ProcessExist(name)
}

ProcessExist(name) {
	PID := ProcessListExist(name).1
	if (PID)
		return PID
	return 0
}

ProcessListExist(name) {
	static wmi := ComObjGet("winmgmts:\\.\root\cimv2")
		
	if (name == "")
		return

	PIDs := []
	for Process in wmi.ExecQuery("SELECT * FROM Win32_Process WHERE Name LIKE '" StrReplace(name, "*", "%") "%'")
		PIDs.Push(Process.processId)
	return PIDs
}

Bin_BytesView(nAdrBuf, nSzBuf, nCols:=16, nRows:=20, sFormat:="u", nSpaces:=3) {
    Static IMAGE_ICON       := 1
         , SB_VERT          := 1
         , SB_THUMBPOSITION := 4
         , CRYPT_STRING_HEX := 0x0004
         , WM_SETICON       := 0x0080
         , WM_KEYUP         := 0x0101
         , WM_COMMAND       := 0x0111
         , WM_VSCROLL       := 0x0115
         , WM_LBUTTONUP     := 0x0202
         , EM_GETSEL        := 0x00B0
         , EM_LINELENGTH    := 0x00C1
         , EM_SETLIMITTEXT  := 0x00C5
         , EN_VSCROLL       := 0x0602
         , hEdit1, hEdit2, sOfftFormat, nByteLen, nHdrCols, nRowLen
         , cbSubclassProc := RegisterCallback("Bin_BytesView",, 6)
         
    If ( sFormat == hEdit2 )
    {   ; Subclass call to catch scrollbar thumb scrolling and calculate offset.
        If ( nSzBuf == WM_VSCROLL )
            DllCall( "PostMessage", Ptr,hEdit1, UInt,WM_VSCROLL, Ptr,nCols, Ptr,nRows )
        If ( nSzBuf == WM_LBUTTONUP || nSzBuf == WM_KEYUP )
        {
            DllCall( "SendMessage", Ptr,hEdit2, UInt,EM_GETSEL, UIntP,nStart, UIntP,nEnd )
            nOfft := ((nStart // nRowLen) * nHdrCols) + (Mod(nStart, nRowLen) // nByteLen)
            GuiControl, _BV:, Static1, % "Offset: " Format("{1:02" sOfftFormat "}" , nOfft)
        }
        Return DllCall( "DefSubclassProc", Ptr,nAdrBuf, UInt,nSzBuf, Ptr,nCols, Ptr,nRows )
    }
    
    If ( nCols == WM_COMMAND )
    {   ; OnMessage call to catch scrolling. It doesn't notify of thumb scrolling.
        If ( nAdrBuf >> 16 == EN_VSCROLL )
            nPos := DllCall( "GetScrollPos", Ptr,hEdit2, Int,SB_VERT )
          , DllCall( "PostMessage", Ptr,hEdit1, UInt,WM_VSCROLL, Ptr,(nPos<<16)+SB_THUMBPOSITION, Ptr,0 )
        Return
    }
    
    Else
    {   ; Normal function call.
        If ( !nSzBuf || nSzBuf + 0 != nSzBuf || Mod(nCols, 8) != 0 || nSpaces < 1 )
        {   ; Ensures parameters integrity and a column size no less than 8.
            MsgBox, 0x10, BytesView, Wrong parameter(s)?
            Return
        } ( nSzBuf <= 8 ) ? nCols := 8
        
        ; Strings population (offset column, offset header and bytes dump view).
        sSpaces := Format("{1:" nSpaces "s}", A_Space)
        Loop % Ceil(nSzBuf / nCols)
            sOffsetCol .= Format("{1:0" StrLen(nSzBuf) sFormat "}", (A_Index-1)*nCols) "`n"
        Loop %nCols%
            sOffsetHdr .= Format("{1:02" sFormat "}" , A_Index-1) (( A_Index != nCols ) ? sSpaces : "")
        Loop %nSzBuf%
            sDump .= Format("{1:02X}", NumGet(nAdrBuf+0, A_Index-1, "UChar"))
                  .  (( Mod(A_Index, nCols) != 0 ) ? sSpaces : "`n")
        sDump := RTrim(sDump)
        
        Gui, _BV: +HwndhWnd
        Gui, _BV: Color, 909090
        Gui, _BV: Font, 8, Consolas
        Gui, _BV: Margin, 5, 5
        Gui, _BV: Add, Edit, ym+21 r%nRows% HwndhEdit1 -E0x200 ReadOnly -VScroll, %sOffsetCol%
        Gui, _BV: Add, Edit, x+5 ym+21 r%nRows% HwndhEdit2 -E0x200 +WantTab Section, %sOffsetHdr%
        GuiControlGet, nE1Pos, _BV: Pos, Edit1
        GuiControlGet, nE2Pos, _BV: Pos, Edit2
        Gui, _BV: Add, Text, % "w" nE2PosW - 95 " xs y+5 HwndhText1", Offset: 00
        Gui, _BV: Add, Button, w90 x+5 -Theme +0x8000, &Close
        Gui, _BV: Add, Edit, % "w" nE2PosW " xm+" nE1PosW + 5 " ym -E0x200 ReadOnly -VScroll", %sOffsetHdr%
  
        GuiControl, _BV:, Edit2, %sDump% ; Workaround edit control memory allocation limit.
        GuiControl, _BV: Focus, Edit2    ; Set focus on the bytes view.
        DllCall( "PostMessage", Ptr,hEdit2, UInt,EM_SETLIMITTEXT, Ptr,1, Ptr,0 ) ; Disable text editing.
        
        ; Set window and taskbar/alt-tab icon.
        hIcon := DllCall( "LoadImage", Ptr,DllCall("GetModuleHandle",Str,"Shell32.dll")
                                     , Ptr,13, UInt,IMAGE_ICON, Int,32, Int,32, UInt,0 )
        d := A_DetectHiddenWindows
        DetectHiddenWindows, On
        SendMessage, WM_SETICON, 0, hIcon,, ahk_id %hWnd%
        SendMessage, WM_SETICON, 1, hIcon,, ahk_id %hWnd%
        DetectHiddenWindows, %d%
        
        ; The EN_VSCROLL notification code is sent through the WM_COMMAND message, so we monitor it to get 
        ; notification about scrolling with mousewheel, keyboard and scrollbar arrows. This notification 
        ; is not sent when scrolling through the scrollbar thumb, so we need to subclass the edit control 
        ; to make it work. We use subclassing also for offset calculation so we set the required static
        ; variables to be used when receiving the subclass call.
        sOfftFormat := sFormat, nByteLen := nSpaces + 2, nHdrCols := nCols, nRowLen := (nByteLen * (nCols-1)) + 4
        DllCall( "SetWindowSubclass", Ptr,hEdit2, Ptr,cbSubclassProc, Ptr,hEdit2, Ptr,0 )
        OnMessage(WM_COMMAND, A_ThisFunc)
        
        Gui, _BV: Show,, BytesView
        WinWaitClose ; Prevent early return.
        Return
        
        _BVBUTTONCLOSE:
            DllCall( "RemoveWindowSubclass", Ptr,hEdit2, Ptr,cbSubclassProc, Ptr,hEdit2 )
            Gui, _BV: Destroy
            Return
        ;_BVBUTTONCLOSE
    }
}

HexToDec(hexDigit) {
	if (hexDigit >= "0" && hexDigit <= "9") {
		return hexDigit
	} else if (hexDigit >= "A" && hexDigit <= "F") {
		return Ord(hexDigit) - 55
	} else if (hexDigit >= "a" && hexDigit <= "f") {
		return Ord(hexDigit) - 87
	} else {
		return -1  ; Invalid hex digit
	}
}

BigEndianToLittleEndian(hexValue) {
	length := StrLen(hexValue)
	if (Mod(length, 2) != 0) {
		hexValue .= "0"  ; Ensure even number of digits
		length++
	}
	
	littleEndian := ""
	Loop, % length / 2 {
		startIndex := (A_Index - 1) * 2 + 1
		hexPair := SubStr(hexValue, startIndex, 2)
		littleEndian := hexPair . littleEndian
	}
	
	return littleEndian
}

EndianHexToDecimal(hexValue) {
	decimalValue := 0
	length := StrLen(hexValue)
	
	Loop, % length {
		hexDigit := SubStr(hexValue, A_Index, 1)
		decimalValue += (HexToDec(hexDigit) * (16 ** (length - A_Index)))
	}
	
	return decimalValue
}

EndianToBitmask(hexValue) {
	return EndianHexToDecimal(BigEndianToLittleEndian(hexValue))
}

BitmaskToProcessorNumbers(bitmask) {
	VarSetCapacity(sysInfo, 64)
	DllCall("kernel32\GetSystemInfo", "Ptr", &sysInfo)
	CORE_COUNT := NumGet(sysInfo, 32, "UInt")

	processorNumbers := []
	
	Loop, % CORE_COUNT {
		if (bitmask & (1 << A_Index - 1)) {
			processorNumbers.Push(A_Index - 1)
		}
	}
	
	return processorNumbers
}

MaxDictStringLength(dict, key) {
	maxLength := 0
	for k, obj in dict {
		len := StrLen(obj[key])
		if (len > maxLength)
			maxLength := len
	}
	return maxLength
}

StrRepeat(string, times) {
	output := ""
	loop % times
		output .= string
	return output
}