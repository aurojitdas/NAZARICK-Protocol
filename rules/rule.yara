rule PEFile {
    meta:
        description = "Detects PE executable files"
    condition:
        uint16(0) == 0x5A4D // Checks for MZ header
}

rule ContainsNotepad {
    meta:
        description = "Detects notepad-related strings"
    strings:
        $notepad1 = "notepad" nocase
        $notepad2 = "Notepad"
        $edit = "edit" nocase
    condition:
        any of them
}