ReloadApp() {
    Reload
}

BindReload(keyCombo, actionHandler, activationRequirement := "") {
    if (activationRequirement)
        Hotkey, IfWinActive, % activationRequirement
    Hotkey, % keyCombo, % actionHandler
}

InitDebugging() {
    BindReload("^R", Func("ReloadApp"), "ahk_exe notepad++.exe")
}

InitDebugging()