kexec_load-objs := \
	kexec.o \
	machine_kexec.o \
	relocate_kernel.o \
	sys.o \
	../../../../arch/arm/mm/idmap.o \
	../../../../arch/arm/mm/proc-v7.o \
	../../../../arch/arm/mm/tlb-v7.o \
	../../../../arch/arm/mm/cache-v7.o \
	../../../../arch/arm/mm/proc-macros.o \
	../../../../arch/arm/mm/abort-ev7.o \
	../../../../arch/arm/mm/pabort-v7.o \
	../../../../arch/arm/kernel/sleep.o \
	../../../../arch/arm/mm/copypage-v6.o

obj-$(CONFIG_KEXEC_LOAD) += kexec_load.o
