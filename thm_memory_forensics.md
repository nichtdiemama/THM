# Memory Forensics with volatility3

## Preparation
install volitily3:
```
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3/
python3 -m venv venv && . venv/bin/activate
pip install -e ".[dev]"
```
Download Memory Dumps

## Task 2 Login
**What is John's password?**

```
./vol.py -f ../Snapshot6_1609157562389.vmem  windows.registry.hashdump > ../hashes.txt

cat ../hashes.txt
Volatility 3 Framework 2.27.0

User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
John    1001    aad3b435b51404eeaad3b435b51404ee        47fbd6536d7868c873d5ea455f2fc0c9
HomeGroupUser$  1002    aad3b435b51404eeaad3b435b51404ee        91c34c06b7988e216c3bfeb9530cabfb
```
put NTLM-Hash in [Crackstation](https://crackstation.net/)
->	47fbd6536d7868c873d5ea455f2fc0c9	NTLM	**charmander999**

## Task 3 Analysis
**When was the machine last shutdown?**
```
./vol.py -f ../Snapshot19_1609159453792.vmem windows.registry.printkey --key "ControlSet001\\Control\\Windows"
...
2020-12-27 22:50:12.000000 UTC  0xf8a000024010  REG_BINARY      \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Windows  ShutdownTime
```

**What did John write?**
no idea to do this with volatility3, so hint: __It's written between curly brackets: THM{XXXX}__
```
strings ../Snapshot19_1609159453792.vmem | grep -i thm\{
THM{You_found_me}
```

## Task 4 TrueCrypt
**What is the TrueCrypt passphrase?**
First try:
```
./vol.py -f ../Snapshot14_1609164553061.vmem windows.truecrypt.Passphrase
Volatility 3 Framework 2.27.0
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. Snapshot14_1609164553061.vmem and Snapshot14_1609164553061.vmss.
Progress:  100.00               PDB scanning finished
Offset  Length  Password
Traceback (most recent call last):
  File "/home/unicorn/thm/memory_forensics/volatility3/./vol.py", line 11, in <module>
    volatility3.cli.main()
  File "/home/unicorn/thm/memory_forensics/volatility3/volatility3/cli/__init__.py", line 932, in main
    CommandLine().run()
  File "/home/unicorn/thm/memory_forensics/volatility3/volatility3/cli/__init__.py", line 520, in run
    renderer.render(grid)
  File "/home/unicorn/thm/memory_forensics/volatility3/volatility3/cli/text_renderer.py", line 330, in render
    grid.populate(visitor, outfd)
  File "/home/unicorn/thm/memory_forensics/volatility3/volatility3/framework/renderers/__init__.py", line 317, in populate
    for level, item in self._generator:
  File "/home/unicorn/thm/memory_forensics/volatility3/volatility3/framework/plugins/windows/truecrypt.py", line 137, in _generator
    for offset, password in self.scan_module(
  File "/home/unicorn/thm/memory_forensics/volatility3/volatility3/framework/plugins/windows/truecrypt.py", line 82, in scan_module
    raise ValueError("PE data section not DWORD-aligned!")
        pe_table_name = intermed.IntermediateSymbolTable.create(
ValueError: PE data section not DWORD-aligned!
```

the solution in [TrueCrypt Windows - PE data section not DWORD-aligned! #1159](https://github.com/volatilityfoundation/volatility3/issues/1159) helped a lot
```
./vol.py -f ../Snapshot14_1609164553061.vmem windows.truecrypt.Passphrase
Volatility 3 Framework 2.27.0
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. Snapshot14_1609164553061.vmem and Snapshot14_1609164553061.vmss.
Progress:  100.00               PDB scanning finished
Offset  Length  Password

0xf8800512bee4  11      forgetmenot

Volatility was unable to read a requested page:
Page error 0xf8800512e000 in layer layer_name (Page Fault at entry 0x0 in page entry)

        * Memory smear during acquisition (try re-acquiring if possible)
        * An intentionally invalid page lookup (operating system protection)
        * A bug in the plugin/volatility3 (re-run with -vvv and file a bug)

No further results will be produced
```
