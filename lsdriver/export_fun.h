#ifndef _EXPORT_FUN_H_
#define _EXPORT_FUN_H_

#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/types.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

// 必须使用 unsigned long，与内核原生定义保持一致
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

/*
Android 5.15+ GKI 开启了 CFI
即使拿到了函数地址，直接强转调用也会触发 CFI Panic。
必须使用 no_sanitize("cfi") 禁止编译器对该 wrapper 函数进行检查。
*/
#ifdef __clang__
__attribute__((no_sanitize("cfi")))  // 屏蔽cfi
__attribute__((no_sanitize("kcfi"))) // 屏蔽kcfi
#endif
static unsigned long _bypass_cfi_call(unsigned long addr, const char *name)
{
        kallsyms_lookup_name_t fn = (kallsyms_lookup_name_t)addr;
        return fn(name);
}

static unsigned long generic_kallsyms_lookup_name(const char *name)
{
        static unsigned long kallsyms_addr = 0;
        struct kprobe kp = {0};
        int ret;

        if (!kallsyms_addr)
        {
                kp.symbol_name = "kallsyms_lookup_name";

                ret = register_kprobe(&kp);
                if (ret < 0)
                        return 0;

                kallsyms_addr = (unsigned long)kp.addr;
                unregister_kprobe(&kp);

                if (!kallsyms_addr)
                        return 0;
        }

        return _bypass_cfi_call(kallsyms_addr, name);
}

#else

// < 5.7.0
static unsigned long generic_kallsyms_lookup_name(const char *name)
{
        return kallsyms_lookup_name(name);
}

#endif
#endif