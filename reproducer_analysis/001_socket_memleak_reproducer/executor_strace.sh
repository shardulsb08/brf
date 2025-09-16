sudo strace -f -o 20250915_224617_repro_execprog.log ./bin/linux_amd64/syz-execprog -executor=bin/linux_amd64/syz-executor -repeat=1 -procs=1 repro.txt
