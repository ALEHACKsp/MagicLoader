# MagicLoader
Auto launch specified PE loaders (debuggers or decompilers) with specified PE file, depending on the given PE file is whether 32 or 64 bits

## Usage:
`MagicLoader.exe <32 Bits Loader> <64 Bits Loader> <Loader Parameters> <Executable Image File> <Admin Rights> <Minimized>`

## Example:
```javascript
C:\MagicLoader.exe "C:\Debuggers\dnSpy-net472\dnSpy-x86.exe" "C:\Debuggers\dnSpy-net472\dnSpy.exe" "--no-load-files" "%1" 1 0

// "C:\Debuggers\dnSpy-net472\dnSpy-x86.exe": x32 Loader (Debugger)
// "C:\Debuggers\dnSpy-net472\dnSpy.exe": x64 Loader (Debugger)
// "--no-load-files": Tell dnSpy do not keep previously opened files (Debugger Parameters)
// "%1": Full path of target binary passed from context menu (Image File)
// 1: Run debugger with Elevated rights
// 0: Run debugger in Normal window (don't run debugger in minimized window)
```
