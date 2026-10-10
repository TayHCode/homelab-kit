# Document any device

`add-host NAME` creates a docs-only host with the same template as SSH and local
hosts. Repeat it for a NAS, TrueNAS appliance, router, switch, Windows or Mac
machine. Write hardware, OS/firmware, network settings, restore steps and links
to services and backups. `--config-export-location` records only a pointer to a
securely stored export. Non-SSH devices stay docs-only. Linux, Mac and Windows hosts with configured
SSH can collect read-only inventories; appliance exports remain pointers.
