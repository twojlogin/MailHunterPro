<?xml version="1.0" encoding="utf-8"?>
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>

  <MappedFolders>
    <MappedFolder>
      <HostFolder>D:\MailSandbox</HostFolder>
      <SandboxFolder>D:\MailSandbox</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>

  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File D:\MailSandbox\MailHunter\scripts\init_sandbox.ps1</Command>
  </LogonCommand>

  <MemoryInMB>4096</MemoryInMB>
</Configuration>
