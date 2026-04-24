<p align="center">
  <img src="media/quake-readme.gif" alt="Quake running on Galileo">
</p>

# Galileo MS-DOS boot speed run

I used codex to rebuild something I did a long time ago - setting up the quark firmware package with CSM support so a galileo could boot MS-DOS (as long as it had a PCIe to PCI VGA adapter, or PCIe VGA adapter).
What works: dos boots, games run.
What doesn't work: keyboard support provided by BIOS works, but just like 10 years ago, I'll need to try to kerjigger something together with SMM to support keyboard i/o & irq.
This means that quake launches and runs fine but you can't use the keyboard, for example...
