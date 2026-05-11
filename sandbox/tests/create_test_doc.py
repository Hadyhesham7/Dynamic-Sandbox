"""Create a test Word document with a VBA macro for sandbox testing."""
import os
import sys

try:
    import win32com.client
except ImportError:
    print("ERROR: pywin32 not installed. Run: pip install pywin32")
    sys.exit(1)

doc_path = os.path.abspath(os.path.join("sandbox", "tests", "test_macro_doc.doc"))

print("[TEST] Creating Word document with VBA macro...")
word = win32com.client.Dispatch("Word.Application")
word.Visible = False
word.DisplayAlerts = False

try:
    doc = word.Documents.Add()
    doc.Content.Text = "This is a test document for sandbox analysis.\nIt contains a harmless VBA macro."

    # Add a VBA macro
    vb_module = doc.VBProject.VBComponents.Add(1)
    vb_module.Name = "TestMacro"
    macro_code = (
        'Sub Auto_Open()\n'
        '    MsgBox "Test macro executed"\n'
        '    Shell "cmd.exe /c echo sandbox_test"\n'
        'End Sub\n'
        '\n'
        'Sub Document_Open()\n'
        '    Auto_Open\n'
        'End Sub\n'
    )
    vb_module.CodeModule.AddFromString(macro_code)

    # Save as .doc (OLE format with macros)
    doc.SaveAs(doc_path, 0)  # 0 = wdFormatDocument
    doc.Close()
    print(f"[TEST] Created: {doc_path} ({os.path.getsize(doc_path)} bytes)")

except Exception as e:
    print(f"[TEST] ERROR: {e}")
    print("[TEST] Note: You may need to enable 'Trust access to the VBA project object model'")
    print("[TEST]   Word > File > Options > Trust Center > Trust Center Settings")
    print("[TEST]   > Macro Settings > Check 'Trust access to the VBA project object model'")
finally:
    word.Quit()
