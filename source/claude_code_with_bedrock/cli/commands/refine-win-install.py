#!/usr/bin/env python3
"""
Refine Windows installer .bat files to fix cmd.exe and PowerShell compatibility issues.

Transformations applied:
1. Flatten nested if-exist blocks for claude-settings into goto-based control flow,
   eliminating SKIP_SETTINGS variable and cmd.exe delayed expansion issues.
2. Rewrite multi-line PowerShell settings command to single-line format using
   $env:USERPROFILE instead of %USERPROFILE%, with -Raw for Get-Content.
3. Collapse multi-line for-loop PowerShell commands (^ continuations) into single lines.
4. Replace piped Get-Content|ConvertFrom-Json with -InputObject pattern to avoid
   cmd.exe pipe parsing conflicts inside for /f loops.

Usage:
    python refine-install.py <input.bat> [output.bat]

If output path is omitted, the input file is modified in-place.
"""

import re
import sys
from pathlib import Path


# Replacement for the settings section: flat goto-based structure instead of nested if blocks.
# Raw string so backslashes are literal (matching .bat file content).
NEW_SETTINGS_SECTION = r"""REM Copy Claude Code settings if they exist
if not exist "claude-settings" goto :skip_settings
echo Copying Claude Code telemetry settings...
if not exist "%USERPROFILE%\.claude" mkdir "%USERPROFILE%\.claude"

if not exist "claude-settings\settings.json" goto :skip_settings

set OVERWRITE=y
if exist "%USERPROFILE%\.claude\settings.json" (
    echo Existing Claude Code settings found
    set /p OVERWRITE="Overwrite with new settings? (y/n): "
)
if /i not "%OVERWRITE%"=="y" (
    echo Skipping Claude Code settings...
    goto :skip_settings
)

REM Use PowerShell to replace placeholders (use semicolons not pipes to avoid cmd.exe pipe parsing)
powershell -Command "$dest = $env:USERPROFILE + '\.claude\settings.json'; $otelPath = ($env:USERPROFILE + '\claude-code-with-bedrock\otel-helper.exe') -replace '\\', '\\'; $credPath = ($env:USERPROFILE + '\claude-code-with-bedrock\credential-process.exe') -replace '\\', '\\'; $content = (Get-Content 'claude-settings\settings.json' -Raw) -replace '__OTEL_HELPER_PATH__', $otelPath -replace '__CREDENTIAL_PROCESS_PATH__', $credPath; Set-Content -Path $dest -Value $content"
echo OK Claude Code settings configured

:skip_settings

"""


def replace_settings_section(content: str) -> str:
    """Replace nested if-exist settings section with flat goto-based structure."""
    start_marker = "REM Copy Claude Code settings if they exist\n"
    end_marker = "REM Configure AWS profiles"

    start_idx = content.find(start_marker)
    end_idx = content.find(end_marker)

    if start_idx == -1 or end_idx == -1:
        return content

    return content[:start_idx] + NEW_SETTINGS_SECTION + content[end_idx:]


def join_multiline_ps_commands(content: str) -> str:
    """Collapse multi-line PowerShell commands in for /f loops into single lines.

    Matches lines ending with 'powershell -Command ^' followed by a continuation
    line containing the quoted PowerShell command, and joins them.
    """
    return re.sub(
        r"'powershell -Command \^\n\s*\"([^\"]*)\"\'\)",
        lambda m: f"'powershell -Command \"{m.group(1)}\"')",
        content,
    )


def fix_powershell_json_patterns(content: str) -> str:
    """Replace piped Get-Content|ConvertFrom-Json with -InputObject pattern.

    Handles two styles:
    A) & {$var=Get-Content file|ConvertFrom-Json;$var.accessor}
    B) $var = Get-Content file | ConvertFrom-Json; $var.accessor
    """
    # Pattern A: compact scriptblock style (no spaces around pipe)
    content = re.sub(
        r'"& \{\$(\w+)=Get-Content (\S+)\|ConvertFrom-Json;\$\1\.([^}]+)\}"',
        r'"(ConvertFrom-Json -InputObject (Get-Content \2 -Raw)).\3"',
        content,
    )

    # Pattern B: verbose variable style (spaces around pipe)
    content = re.sub(
        r'"\$(\w+) = Get-Content (\S+) \| ConvertFrom-Json; \$\1\.([^"]+)"',
        r'"(ConvertFrom-Json -InputObject (Get-Content \2 -Raw)).\3"',
        content,
    )

    return content


def refine_installer(content: str) -> str:
    """Apply all transformations to installer bat file content."""
    content = replace_settings_section(content)
    content = join_multiline_ps_commands(content)
    content = fix_powershell_json_patterns(content)
    return content


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.bat> [output.bat]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else input_path

    content = input_path.read_text()

    # Detect and normalize line endings
    crlf = "\r\n" in content
    if crlf:
        content = content.replace("\r\n", "\n")

    content = refine_installer(content)

    # Restore original line endings
    if crlf:
        content = content.replace("\n", "\r\n")

    output_path.write_text(content)
    print(f"Refined installer written to: {output_path}")


if __name__ == "__main__":
    main()
