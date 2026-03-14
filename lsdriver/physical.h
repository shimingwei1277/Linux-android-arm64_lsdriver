
/*
使用了两种方案进行读写
    1.pte直接映射任意物理地址进行读写，设置页任意属性，任意写入，不区分设备内存和系统内存

(建议使用，因为都是都是通过页表建立虚拟地址→物理地址的映射。)
底层原理都是映射
    2.是用内核线性地址读写，只能操作系统内存

*/

#ifndef PHYSICAL_H
#define PHYSICAL_H
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/pgtable.h>
#include <asm/pgtable-prot.h>
#include <asm/memory.h>
#include <asm/barrier.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/sort.h>
#include "export_fun.h"
#include "io_struct.h"

//============方案1:(不建议使用：顶部有说原因)PTE读写+MMU硬件翻译地址============

struct pte_physical_page_info
{
    void *base_address;
    size_t size;
    pte_t *pte_address;
};
static struct pte_physical_page_info pte_info;

// 直接从硬件寄存器获取内核页表基地址
static inline pgd_t *get_kernel_pgd_base(void)
{
    // TTBR0_EL1：对应 "低地址段虚拟地址"（如用户进程的虚拟地址，由内核管理）；
    // TTBR1_EL1：对应 "高地址段虚拟地址"（如内核自身的虚拟地址，仅内核可访问）；
    uint64_t ttbr1;

    // 读取 TTBR1_EL1 寄存器 (存放内核页表物理地址)
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

    // TTBR1 包含 ASID 或其他控制位，通常低 48 位是物理地址
    // 这里做一个简单的掩码处理 (64位用48位物理寻址)
    // 将物理地址转为内核虚拟地址
    return (pgd_t *)phys_to_virt(ttbr1 & 0x0000FFFFFFFFF000ULL);
}

// 初始化
static inline int allocate_physical_page_info(void)
{
    uint64_t vaddr;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    if (in_atomic())
    {
        pr_debug("原子上下文禁止调用 vmalloc\n");
        return -EPERM;
    }

    memset(&pte_info, 0, sizeof(pte_info));

    // 分配内存
    vaddr = (uint64_t)vmalloc(PAGE_SIZE);
    if (!vaddr)
    {
        pr_debug("vmalloc 失败\n");
        return -ENOMEM;
    }

    // 必须 memset 触发缺页，让内核填充 TTBR1 指向的页表
    memset((void *)vaddr, 0xAA, PAGE_SIZE);

    // --- 页表 Walk: PGD → P4D → PUD → PMD → PTE ---

    // 计算 PGD 索引 (pgd_offset_raw)
    pgd = get_kernel_pgd_base() + pgd_index(vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
    {
        pr_debug("PGD 无效\n");
        goto err_out;
    }

    // P4D
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
    {
        pr_debug("P4D 无效\n");
        goto err_out;
    }

    // PUD
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud))
    {
        pr_debug("PUD 无效\n");
        goto err_out;
    }

    // PMD
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
    {
        pr_debug("PMD 无效\n");
        goto err_out;
    }

    // 大页检查
    if (pmd_leaf(*pmd))
    {
        pr_debug("遇到大页 (Block Mapping)，无法获取 PTE\n");
        goto err_out;
    }

    // PTE
    ptep = pte_offset_kernel(pmd, vaddr);
    if (!ptep)
    {
        pr_debug("PTE 指针为空\n");
        goto err_out;
    }

    pte_info.base_address = (void *)vaddr;
    pte_info.size = PAGE_SIZE;
    pte_info.pte_address = ptep;
    return 0;

err_out:
    vfree((void *)vaddr);
    return -EFAULT;
}

// 释放
static inline void free_physical_page_info(void)
{
    if (pte_info.base_address)
    {
        // 释放之前通过 vmalloc 分配的虚拟内存
        vfree(pte_info.base_address);
        pte_info.base_address = NULL;
    }
}

// 验证参数并直接操作PTE建立物理页映射
static inline void *pte_map_page(phys_addr_t paddr, size_t size, const void *buffer)
{
    static const uint64_t FLAGS = PTE_TYPE_PAGE | PTE_VALID | PTE_AF |
                                  PTE_SHARED | PTE_PXN | PTE_UXN |
                                  PTE_ATTRINDX(MT_NORMAL);
    uint64_t pfn = __phys_to_pfn(paddr);

    // 参数检查
    if (unlikely(!size || !buffer))
        return ERR_PTR(-EINVAL);
    // PFN 有效性检查：确保物理页帧在系统内存管理范围内
    if (unlikely(!pfn_valid(pfn)))
        return ERR_PTR(-EFAULT);
    // 跨页检查：读写可能跨越页边界，访问到未映射的下一页
    if (unlikely(((paddr & ~PAGE_MASK) + size) > PAGE_SIZE))
        return ERR_PTR(-EINVAL);

    // 修改 PTE 指向目标物理页
    set_pte(pte_info.pte_address, pfn_pte(pfn, __pgprot(FLAGS)));

    // dsb(ishst);  // 内存全序屏障
    // 刷新该页的 TLB
    flush_tlb_kernel_range((uint64_t)pte_info.base_address, (uint64_t)pte_info.base_address + PAGE_SIZE);
    // flush_tlb_all();//刷新全部cpu核心TLB
    // isb(); // 刷新流水线，确保后续读取使用新的映射

    return (uint8_t *)pte_info.base_address + (paddr & ~PAGE_MASK);
}

// 读取
static inline int pte_read_physical(phys_addr_t paddr, void *buffer, size_t size)
{
    void *mapped = pte_map_page(paddr, size, buffer);
    if (IS_ERR(mapped))
    {
        return PTR_ERR(mapped);
    }

    // 极限性能且安全的内存拷贝 (防未对齐崩溃)
    switch (size)
    {
    case 1:
        __builtin_memcpy(buffer, mapped, 1);
        break;
    case 2:
        __builtin_memcpy(buffer, mapped, 2);
        break;
    case 4:
        __builtin_memcpy(buffer, mapped, 4);
        break;
    case 8:
        __builtin_memcpy(buffer, mapped, 8);
        break;
    default:
        __builtin_memcpy(buffer, mapped, size);
        break;
    }

    return 0;
}

// 写入
static inline int pte_write_physical(phys_addr_t paddr, const void *buffer, size_t size)
{
    void *mapped = pte_map_page(paddr, size, (void *)buffer);
    if (IS_ERR(mapped))
    {
        return PTR_ERR(mapped);
    }

    switch (size)
    {
    case 1:
        __builtin_memcpy(mapped, buffer, 1);
        break;
    case 2:
        __builtin_memcpy(mapped, buffer, 2);
        break;
    case 4:
        __builtin_memcpy(mapped, buffer, 4);
        break;
    case 8:
        __builtin_memcpy(mapped, buffer, 8);
        break;
    default:
        __builtin_memcpy(mapped, buffer, size);
        break;
    }

    return 0;
}

// 硬件mmu翻译
static inline int mmu_translate_va_to_pa(struct mm_struct *mm, u64 va, phys_addr_t *pa)
{
    u64 pgd_phys;
    int ret;
    u64 phys_out;
    u64 tmp_daif, tmp_ttbr, tmp_par, tmp_offset;

    if (unlikely(!mm || !mm->pgd || !pa))
        return -EINVAL;

    pgd_phys = virt_to_phys(mm->pgd);

    asm volatile(
        // 关中断，防止抢占和中断嵌套
        "mrs    %[tmp_daif], daif\n"
        "msr    daifset, #0xf\n" /* 关闭所有中断(D/A/I/F) */
        "isb\n"

        // 切换 TTBR0，ASID 域清零 (bits[63:48]=0)
        "mrs    %[tmp_ttbr], ttbr0_el1\n"
        "msr    ttbr0_el1, %[pgd_phys]\n"
        "isb\n"

        // 硬件地址翻译
        "at     s1e0r, %[va]\n"
        "isb\n"
        "mrs    %[tmp_par], par_el1\n"

        // 清除 ASID=0 的 TLB 污染
        //  vaae1is: VA+所有ASID, EL1, Inner Shareable (广播所有核)
        "lsr    %[tmp_offset], %[va], #12\n"
        "tlbi   vaae1is, %[tmp_offset]\n" // 广播所有CPU，所有ASID
        "dsb    ish\n"
        "isb\n"

        // 恢复 TTBR0
        "msr    ttbr0_el1, %[tmp_ttbr]\n"
        "isb\n"

        // 恢复中断（最后恢复，缩小窗口）
        "msr    daif, %[tmp_daif]\n"
        "isb\n"

        // 检查 PAR_EL1.F (bit 0)，1 表示翻译失败
        "tbnz   %[tmp_par], #0, .L_efault%=\n"

        // 提取物理地址
        // PAR_EL1[47:12] = PA[47:12]，保留低12位页内偏移
        "ubfx   %[tmp_par], %[tmp_par], #12, #36\n"
        "lsl    %[tmp_par], %[tmp_par], #12\n"
        "and    %[tmp_offset], %[va], #0xFFF\n"
        "orr    %[phys_out], %[tmp_par], %[tmp_offset]\n"
        "mov    %w[ret], #0\n"
        "b      .L_end%=\n"

        ".L_efault%=:\n"
        "mov    %w[ret], %w[efault_val]\n"
        "mov    %[phys_out], #0\n"

        ".L_end%=:\n"

        : [ret] "=&r"(ret),
          [phys_out] "=&r"(phys_out),
          [tmp_daif] "=&r"(tmp_daif),
          [tmp_ttbr] "=&r"(tmp_ttbr),
          [tmp_par] "=&r"(tmp_par),
          [tmp_offset] "=&r"(tmp_offset)
        : [pgd_phys] "r"(pgd_phys),
          [va] "r"(va),
          [efault_val] "r"(-EFAULT)
        : "cc", "memory");

    if (ret == 0)
        *pa = phys_out;

    return ret;
}

//============方案2:(建议使用,顶部有说原因)内核已经映射的线性地址读写+手动走页表翻译地址============
// 读取
static inline int linear_read_physical(phys_addr_t paddr, void *buffer, size_t size)
{
    void *kernel_vaddr = phys_to_virt(paddr);

    // 下面这个先暂时不使用，靠翻译阶段得出绝对有效物理地址，死机请加上
    //  // 最后的安全底线：防算错物理地址/内存空洞导致死机
    //  if (unlikely(!virt_addr_valid(kernel_vaddr)))
    //  {
    //      return -EFAULT;
    //  }

    // 极限性能且安全的内存拷贝 (防未对齐崩溃)
    switch (size)
    {
    case 1:
        __builtin_memcpy(buffer, kernel_vaddr, 1);
        break;
    case 2:
        __builtin_memcpy(buffer, kernel_vaddr, 2);
        break;
    case 4:
        __builtin_memcpy(buffer, kernel_vaddr, 4);
        break;
    case 8:
        __builtin_memcpy(buffer, kernel_vaddr, 8);
        break;
    default:
        __builtin_memcpy(buffer, kernel_vaddr, size);
        break;
    }

    return 0;
}

// 写入
static inline int linear_write_physical(phys_addr_t paddr, void *buffer, size_t size)
{
    void *kernel_vaddr = phys_to_virt(paddr);

    // if (unlikely(!virt_addr_valid(kernel_vaddr)))
    // {
    //     return -EFAULT;
    // }

    // 极限性能且安全的内存拷贝 (防未对齐崩溃)
    switch (size)
    {
    case 1:
        __builtin_memcpy(kernel_vaddr, buffer, 1);
        break;
    case 2:
        __builtin_memcpy(kernel_vaddr, buffer, 2);
        break;
    case 4:
        __builtin_memcpy(kernel_vaddr, buffer, 4);
        break;
    case 8:
        __builtin_memcpy(kernel_vaddr, buffer, 8);
        break;
    default:
        __builtin_memcpy(kernel_vaddr, buffer, size);
        break;
    }

    return 0;
}

// 手动走页表翻译（不再禁止中断，靠每级安全检查防护）
static inline int walk_translate_va_to_pa(struct mm_struct *mm, uint64_t vaddr, phys_addr_t *paddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep, pte;
    unsigned long pfn;

    if (unlikely(!mm || !paddr))
        return -1;

    // PGD Level
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return -1;

    // P4D Level
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return -1;

    // PUD Level (可能遇到 1GB 大页)
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud))
        return -1;

    // 检查是否是 1G 大页
    if (pud_leaf(*pud))
    {
        // 检查pfn
        pfn = pud_pfn(*pud);
        if (unlikely(!pfn_valid(pfn)))
            return -1;

        *paddr = (pud_pfn(*pud) << PAGE_SHIFT) + (vaddr & ~PUD_MASK);
        return 0;
    }
    if (pud_bad(*pud))
        return -1;

    //  PMD Level (可能遇到 2MB 大页)
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd))
        return -1;

    // 检查是否是 2M 大页
    if (pmd_leaf(*pmd))
    {
        // 检查pfn
        pfn = pmd_pfn(*pmd);
        if (unlikely(!pfn_valid(pfn)))
            return -1;

        *paddr = (pmd_pfn(*pmd) << PAGE_SHIFT) + (vaddr & ~PMD_MASK);
        return 0;
    }
    if (pmd_bad(*pmd))
        return -1;

    //  PTE Level (普通的 4KB 页)
    ptep = pte_offset_map(pmd, vaddr);
    if (unlikely(!ptep))
        return -1;

    pte = *ptep;     // 原子读取 PTE 内容到栈上
    pte_unmap(ptep); // 立即释放映射

    // 必须检查 pte_present，因为页可能被换出到 Swap 分区
    // 如果 present 为 false，pfn 字段是无效的（存的是 swap offset）
    if (pte_present(pte))
    {
        // 检查pfn
        pfn = pte_pfn(pte);
        if (unlikely(!pfn_valid(pfn)))
            return -1;

        *paddr = (pte_pfn(pte) << PAGE_SHIFT) + (vaddr & ~PAGE_MASK);
        return 0;
    }

    return -1;
}

// 进程读写
static inline int _process_memory_rw(enum sm_req_op op, pid_t pid, uint64_t vaddr, void *buffer, size_t size)
{
    static pid_t s_last_pid = 0;
    static struct mm_struct *s_last_mm = NULL;
    static uint64_t s_last_vpage_base = -1ULL;
    static phys_addr_t s_last_ppage_base = 0;

    phys_addr_t paddr_of_page = 0;
    uint64_t current_vaddr = vaddr;
    size_t bytes_remaining = size;
    size_t bytes_copied = 0;
    size_t bytes_done = 0;
    int status = 0;

    if (unlikely(!buffer || size == 0))
        return -EINVAL;

    /* ---------- mm_struct 缓存 ---------- */
    if (unlikely(pid != s_last_pid || s_last_mm == NULL))
    {
        struct pid *pid_struct;
        struct task_struct *task;

        if (s_last_mm)
        {
            mmput(s_last_mm); // 引用计数-1
            s_last_mm = 0;
        }

        pid_struct = find_get_pid(pid);
        if (!pid_struct)
            return -ESRCH;

        task = get_pid_task(pid_struct, PIDTYPE_PID);
        put_pid(pid_struct);
        if (!task)
            return -ESRCH;

        s_last_mm = get_task_mm(task); // 引用计数+1
        put_task_struct(task);

        if (!s_last_mm)
            return -EINVAL;

        s_last_pid = pid;
        s_last_vpage_base = -1ULL;
    }

    /* ---------- 逐页循环 ---------- */
    while (bytes_remaining > 0)
    {
        size_t page_offset = current_vaddr & (PAGE_SIZE - 1);
        size_t bytes_this_page = PAGE_SIZE - page_offset;
        uint64_t current_vpn = current_vaddr & PAGE_MASK;

        if (bytes_this_page > bytes_remaining)
            bytes_this_page = bytes_remaining;

        /* 软件 TLB 缓存 */
        if (current_vpn == s_last_vpage_base)
        {
            paddr_of_page = s_last_ppage_base;
        }
        else
        {
            // 翻译地址
            // status = mmu_translate_va_to_pa(s_last_mm, current_vpn, &paddr_of_page);
            status = walk_translate_va_to_pa(s_last_mm, current_vpn, &paddr_of_page);

            if (unlikely(status != 0))
            {
                s_last_vpage_base = -1ULL;
                if (op == op_r)
                    memset((uint8_t *)buffer + bytes_copied, 0, bytes_this_page);
                goto next_chunk;
            }
            s_last_vpage_base = current_vpn;
            s_last_ppage_base = paddr_of_page;
        }

        /* 执行读/写 */
        if (op == op_r)
        {

            // status = pte_read_physical(paddr_of_page + page_offset, (uint8_t *)buffer + bytes_copied, bytes_this_page);
            status = linear_read_physical(paddr_of_page + page_offset, (uint8_t *)buffer + bytes_copied, bytes_this_page);
        }
        else
        {

            // status = pte_write_physical(paddr_of_page + page_offset, (const uint8_t *)buffer + bytes_copied, bytes_this_page);
            status = linear_write_physical(paddr_of_page + page_offset, (uint8_t *)buffer + bytes_copied, bytes_this_page);
        }

        if (unlikely(status != 0))
        {
            s_last_vpage_base = -1ULL;
            if (op == op_r)
                memset((uint8_t *)buffer + bytes_copied, 0, bytes_this_page);
            goto next_chunk;
        }

        bytes_done += bytes_this_page;

    next_chunk:
        bytes_remaining -= bytes_this_page;
        bytes_copied += bytes_this_page;
        current_vaddr += bytes_this_page;
    }

    return (bytes_done == 0) ? -EFAULT : (int)bytes_done;
}

/* ---------- 对外接口 ---------- */
static inline int read_process_memory(pid_t pid, uint64_t vaddr, void *buffer, size_t size)
{
    return _process_memory_rw(op_r, pid, vaddr, buffer, size);
}
static inline int write_process_memory(pid_t pid, uint64_t vaddr, void *buffer, size_t size)
{
    return _process_memory_rw(op_w, pid, vaddr, buffer, size);
}

/*
 maps 文件
r--p (只读) 段:
7583e30000
7600a50000
r-xp (可执行) 段:
7600ef1000
760277c000
rw-p (读写) 段:
76025d4000
760264a000
7602780000
7602784000
Modifier's View :
[0] -> 7600ef1000 (第一个 r-xp)
[1] -> 760277c000 (第二个 r-xp)
[2] -> 7583e30000 (第一个 r--p)
[3] -> 7600a50000 (第二个 r--p)
[4] -> 76025d4000 (第一个 rw-p)
[5] -> 760264a000 (第二个 rw-p)
[6] -> 7602780000 (第三个 rw-p)
[7] -> 7602784000 (第四个 rw-p)
规则如下：
优先级分组: 将所有内存段按权限分为三组，并按固定的优先级顺序排列它们。
最高优先级: r-xp (可执行)
中等优先级: r--p (只读)
最低优先级: rw-p (可读写)
组内排序 : 在每一个权限组内部，所有的段都严格按照内存地址从低到高进行排序。
展平为最终列表 : 将这三个排好序的组按优先级顺序拼接成一个大的虚拟列表，然后呈现。
先放所有排好序的 r-xp 段。
然后紧接着放所有排好序的 r--p 段。
最后放所有排好序的 rw-p 段。

*/

// 版本兼容
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
// 内核 >= 6.1 使用 VMA 迭代器
#define DECLARE_VMA_ITER() struct vma_iterator vmi
#define INIT_VMA_ITER(mm) vma_iter_init(&vmi, mm, 0)
#define FOR_EACH_VMA_UNIFIED(vma) for_each_vma(vmi, vma)
#else
// 内核 < 6.1 使用传统链表
#define DECLARE_VMA_ITER()
#define INIT_VMA_ITER(mm) \
    do                    \
    {                     \
    } while (0)
#define FOR_EACH_VMA_UNIFIED(vma) for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif

// VMA 权限检查宏
#define VMA_PERM_MASK (VM_READ | VM_WRITE | VM_EXEC)
#define VMA_IS_RX(vma) (((vma)->vm_flags & VMA_PERM_MASK) == (VM_READ | VM_EXEC))  // r-x
#define VMA_IS_RO(vma) (((vma)->vm_flags & VMA_PERM_MASK) == VM_READ)              // r--
#define VMA_IS_RW(vma) (((vma)->vm_flags & VMA_PERM_MASK) == (VM_READ | VM_WRITE)) // rw-

#define VMA_IS_RWP(vma) (VMA_IS_RW(vma) && !((vma)->vm_flags & VM_SHARED)) // rw-p (私有)

static inline int find_or_add_module(struct module_info *modules, int *module_count, const uint8_t *name)
{
    int i;
    for (i = 0; i < *module_count; i++)
        if (strcmp(modules[i].name, name) == 0)
            return i;
    if (*module_count >= MAX_MODULES)
        return -1;
    i = (*module_count)++;
    strscpy(modules[i].name, name, MOD_NAME_LEN);
    modules[i].seg_count = 0;
    return i;
}

static inline void add_seg(struct module_info *m, short type_tag, uint8_t prot, uint64_t start, uint64_t end)
{
    if (m->seg_count >= MAX_SEGS_PER_MODULE)
        return;
    m->segs[m->seg_count].index = type_tag;
    m->segs[m->seg_count].prot = prot;
    m->segs[m->seg_count].start = start;
    m->segs[m->seg_count].end = end;
    m->seg_count++;
}

static inline int enum_process_memory(pid_t pid, struct memory_info *info)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct vm_area_struct *vma, *prev = NULL;
    char *path_buf, *path;
    int last_mod_idx = -1;
    int i, j;
    short seq;
    bool excluded, mod_accepted;

    static const char *const mod_include_prefixes[] = {
        "/data/", NULL};

    static const char *const excl_prefixes[] = {
        "/dev/", "/system/", "/vendor/", "/apex/", NULL};
    static const char *const excl_keywords[] = {
        ".oat", ".art", ".odex", ".vdex", ".dex", ".ttf",
        "dalvik", "gralloc", "ashmem", NULL};

    DECLARE_VMA_ITER();

    if (!info)
        return -EINVAL;

    path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buf)
        return -ENOMEM;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    if (!task)
    {
        kfree(path_buf);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm)
    {
        put_task_struct(task);
        kfree(path_buf);
        return -EINVAL;
    }

    info->module_count = 0;
    info->region_count = 0;

    mmap_read_lock(mm);
    INIT_VMA_ITER(mm);

    FOR_EACH_VMA_UNIFIED(vma)
    {
        uint8_t current_prot = 0;
        if (vma->vm_flags & VM_READ)
            current_prot |= 1;
        if (vma->vm_flags & VM_WRITE)
            current_prot |= 2;
        if (vma->vm_flags & VM_EXEC)
            current_prot |= 4;

        /* ========== 模块收集 ========== */

        /*
         * BSS 检测条件：
         *   - 无文件映射（匿名页）
         *   - 含写权限（VM_WRITE）即可，不强求可读。
         *     ACE 反作弊会将 BSS 权限故意设为 -w-p（只写无读），
         *     原先的 VMA_IS_RW 宏要求同时具备读写，导致此类 BSS 被漏掉。
         *   - 与上一个 VMA 首尾严格相连（vm_start == prev->vm_end）
         *   - 上一个 VMA 属于我们正在追踪的模块（last_mod_idx >= 0）
         */
        if (prev && !vma->vm_file && vma->vm_start == prev->vm_end &&
            (vma->vm_flags & VM_WRITE) && last_mod_idx >= 0)
        {
            add_seg(&info->modules[last_mod_idx], -1, current_prot, vma->vm_start, vma->vm_end);
            /*
             * BSS 收集后继续保持 last_mod_idx 有效。
             * 这样如果 BSS 后面紧跟着更多匿名 RW 碎片（极少见但存在），
             * 也能被一并归入同一模块。
             */
        }
        else if (vma->vm_file)
        {
            last_mod_idx = -1;

            path = d_path(&vma->vm_file->f_path, path_buf, PATH_MAX);
            if (!IS_ERR(path))
            {
                mod_accepted = false;
                for (i = 0; mod_include_prefixes[i]; i++)
                {
                    if (strncmp(path, mod_include_prefixes[i], strlen(mod_include_prefixes[i])) == 0)
                    {
                        mod_accepted = true;
                        break;
                    }
                }
                if (mod_accepted)
                {
                    last_mod_idx = find_or_add_module(info->modules, &info->module_count, path);
                    if (last_mod_idx >= 0)
                    {
                        add_seg(&info->modules[last_mod_idx], 0, current_prot, vma->vm_start, vma->vm_end);
                    }
                }
            }
        }
        else
        {
            last_mod_idx = -1;
        }

        /* ========== 扫描区域收集 ========== */

        if (VMA_IS_RWP(vma) && info->region_count < MAX_SCAN_REGIONS)
        {
            excluded = false;

            if (vma->vm_file)
            {
                path = d_path(&vma->vm_file->f_path, path_buf, PATH_MAX);
                if (!IS_ERR(path))
                {
                    for (i = 0; excl_prefixes[i]; i++)
                        if (strncmp(path, excl_prefixes[i],
                                    strlen(excl_prefixes[i])) == 0)
                        {
                            excluded = true;
                            break;
                        }
                    if (!excluded)
                        for (i = 0; excl_keywords[i]; i++)
                            if (strstr(path, excl_keywords[i]))
                            {
                                excluded = true;
                                break;
                            }
                }
            }
            else
            {
                if (mm->start_stack >= vma->vm_start &&
                    mm->start_stack < vma->vm_end)
                    excluded = true;

                if (!excluded && vma->vm_ops && vma->vm_ops->name)
                {
                    const char *vma_name = vma->vm_ops->name(vma);
                    if (vma_name &&
                        (strcmp(vma_name, "[vvar]") == 0 ||
                         strcmp(vma_name, "[vdso]") == 0 ||
                         strcmp(vma_name, "[vsyscall]") == 0))
                        excluded = true;
                }
            }

            if (!excluded)
            {
                info->regions[info->region_count].start = vma->vm_start;
                info->regions[info->region_count].end = vma->vm_end;
                info->region_count++;
            }
        }

        prev = vma;
    }

    mmap_read_unlock(mm);

    /*
     * =========================================================================================
     * 反作弊 VMA 碎裂与诱饵对抗机制 (七步完全体)
     * =========================================================================================
     *
     * 【第一阶段：理想状态下的纯净内存布局 (原生 ELF 加载)】
     *
     * 当 Android 原生加载一个 libil2cpp.so 时，内存布局连续且规律。
     * 现代 64 位 Android（LLVM/Clang 编译）出于安全考虑，至少产生以下几个连续段：
     *
     *   PT_LOAD[0] (r--)  : ELF Header + 只读数据（.rodata、.eh_frame 等），真实基址起点。
     *   PT_LOAD[1] (r-x)  : .text 代码段，核心逻辑所在。
     *   PT_LOAD[2] (rw-)  : .data.rel.ro + RELRO 安全页，写完重定位后锁为只读的数据。
     *   PT_LOAD[3] (rw-)  : .data 全局变量段。
     *   BSS        (-w-/rw-) : 尾部额外分配的匿名读写内存（零初始化全局变量）。
     *
     * 即便没有反作弊，最纯净的环境也自然产生 [RO -> RX -> RW -> RW -> RW(anon)] 的天然区段。
     *
     * 【第二阶段：顶级反作弊的四重攻击手段】
     *
     *   攻击一：VMA 碎裂
     *   反作弊高频调用 mprotect() Hook 游戏函数，内核被迫将原本一整块 RX 代码段
     *   "劈碎"成几十甚至上百个细碎 VMA，部分页被改为 RWX 混合权限，
     *   彻底打乱原本连贯的天然区段。
     *
     *   攻击二：远端假诱饵
     *   反作弊在距离真实模块上百 MB 远的极低地址（如 0x6e32250000）凭空 mmap()
     *   一块假内存，命名为 libil2cpp.so，权限设为 RO。
     *   常规合并算法会误把假地址当成模块基址，导致读取指针全部失效。
     *
     *   攻击三：prot 权限污染
     *   代码段内部散布着少量 RWX 碎片（反作弊自身的 trampoline hook 页）。
     *   若在缝合阶段对权限做 OR 合并，RWX 碎片的 W 位会"传染"整个代码段，
     *   使本该是 RX 的代码段最终呈现为 RWX，干扰上层对段类型的判断。
     *
     *   攻击四：BSS 权限异化
     *   ACE 反作弊将 BSS 段的权限故意设为 -w-p（只写，无读权限）。
     *   若 BSS 检测逻辑要求 VM_READ|VM_WRITE，则此类 BSS 完全不可见，
     *   导致上层计算出的模块尾部地址偏短，BSS 内的全局变量无法定位。
     *
     * 【第三阶段：七步对抗算法 (完全体)】
     *
     *   步骤 1：纯物理排序
     *   无视所有权限和假象，按物理起始地址绝对升序排列所有碎片。
     *   应对极端的反作弊内核级乱序映射干扰。
     *
     *   步骤 2：改进版体积聚类 (寻找生命主干)
     *   ARM64 寻址限制要求真实 .so 内存紧凑相连。遍历碎片，相邻块缝隙超过
     *   16MB (0x1000000) 即视为"内存断层"，划分不同群落。
     *   累加每个群落的真实映射体积（严防重叠映射导致体积虚高），
     *   体积最大、最丰满的群落即为真实的 .so 本体。
     *
     *   步骤 3：物理抹杀假诱饵 + BSS 豁免保留
     *   锁定真实本体的 [best_base, best_end] 范围，剔除范围外的假诱饵碎片。
     *   豁免：index==-1 的匿名 BSS 段即便 end 超出 best_end，
     *   只要 start 在 best_end 附近（≤ 0x3000，一个 guard 页的余量），
     *   就视为合法的本体尾部延伸，保留并动态扩展 best_end。
     *   这直接解决了 ACE 将 BSS 权限设为 -w-p 后尾部被误杀的问题。
     *
     *   步骤 4：严谨拓扑标记 (核心：破解权限篡改)
     *   寻找天然的"防波堤"：向后扫描找到第一个"纯原生数据段 (有W无X)"。
     *   在 Header 和第一个数据段之间的所有碎片，无论现在权限是 RO 还是 RWX，
     *   物理拓扑上必定属于"核心代码段"，强制内部标签重置为 0(RX)。
     *   跨过数据段后恢复原生判定，绝不越界吞噬。
     *   内部临时标签约定：1=RO(头部), 0=RX(代码), 2=RW(数据), -1=BSS(保持不变)
     *
     *   步骤 4.5：强制规范化 prot (消除权限污染)
     *   反作弊的 RWX hook 页在步骤 4 中已被正确归入代码段（index=0），
     *   但其 W 位仍残留在 prot 字段中。
     *   此步骤根据步骤 4 确立的权威拓扑标签，强制覆写每个碎片的 prot：
     *     index=1(Header/RELRO) → prot=1(R)
     *     index=0(Code)         → prot=5(RX)
     *     index=2(Data)         → prot=3(RW)
     *     index=-1(BSS)         → prot=3(RW)  (同时修正 -w- 的异常权限)
     *   彻底断绝 prot 污染，使对外输出的 prot 与原生 ELF 加载完全一致。
     *
     *   步骤 5：拉链式精准缝合 (还原原生边界)
     *   遍历洗白后的碎片，仅当相邻碎片【首尾绝对相连】且【拓扑标签一致】时，
     *   进行无缝拉链式融合。天然的段边界（如 RX→RO、RO→RW）自然断开保留。
     *   缝合时不再合并 prot（步骤 4.5 已完成规范化，此处无需再动）。
     *
     *   步骤 6：最终 Index 序列化
     *   给缝合后的完美区段重新发放 0, 1, 2, 3... 的连续 Index，BSS 保留 -1。
     *
     * 【最终战果】：
     * 无论反作弊怎么切分、放诱饵、异化权限，跑完此算法后，
     * 产出结果与干净手机上的原生 ELF 映射 1:1 完全一致。
     *
     * 典型输出（libil2cpp.so，ACE 保护环境）：
     *   seg[0] index=0  prot=1(R)  → PT_LOAD[0] ELF Header
     *   seg[1] index=1  prot=5(RX) → PT_LOAD[1] .text 代码段
     *   seg[2] index=2  prot=3(RW) → PT_LOAD[2] .data.rel.ro
     *   seg[3] index=3  prot=1(R)  → RELRO 只读页
     *   seg[4] index=4  prot=3(RW) → PT_LOAD[3] .data
     *   seg[5] index=-1 prot=3(RW) → BSS (原始权限 -w-p，已被规范化)
     *   seg[6] index=5  prot=5(RX) → PT_LOAD[4]
     *   seg[7] index=6  prot=3(RW) → PT_LOAD[5]
     *   seg[8] index=7  prot=3(RW) → PT_LOAD[6]
     *
     * 外部调用：Base = info->modules[X].segs[0].start，即可获取绝对真实基址。
     * =========================================================================================
     */

    for (i = 0; i < info->module_count; i++)
    {
        struct module_info *m = &info->modules[i];

        if (m->seg_count > 0)
        {
            /* --- 步骤 1：纯物理地址排序 --- */
            for (int x = 1; x < m->seg_count; x++)
            {
                struct segment_info key = m->segs[x];
                int y = x - 1;
                while (y >= 0 && m->segs[y].start > key.start)
                {
                    m->segs[y + 1] = m->segs[y];
                    y--;
                }
                m->segs[y + 1] = key;
            }

            /* --- 步骤 2：改进版体积聚类 (寻找生命主干) --- */
            uint64_t current_base = m->segs[0].start;
            uint64_t current_end = m->segs[0].end;
            uint64_t current_volume = m->segs[0].end - m->segs[0].start;

            uint64_t max_volume = 0;
            uint64_t best_base = current_base;
            uint64_t best_end = current_end;

            for (j = 1; j < m->seg_count; j++)
            {
                if (m->segs[j].start >= current_end &&
                    (m->segs[j].start - current_end > 0x1000000))
                {
                    if (current_volume > max_volume)
                    {
                        max_volume = current_volume;
                        best_base = current_base;
                        best_end = current_end;
                    }
                    current_base = m->segs[j].start;
                    current_end = m->segs[j].end;
                    current_volume = m->segs[j].end - m->segs[j].start;
                }
                else
                {
                    if (m->segs[j].end > current_end)
                    {
                        uint64_t increment_start = (m->segs[j].start > current_end)
                                                       ? m->segs[j].start
                                                       : current_end;
                        current_volume += (m->segs[j].end - increment_start);
                        current_end = m->segs[j].end;
                    }
                }
            }
            if (current_volume > max_volume)
            {
                best_base = current_base;
                best_end = current_end;
            }

            /* --- 步骤 3：物理抹杀假诱饵 + BSS 豁免保留 --- */
            /*
             * 常规判定：碎片必须完整落在 [best_base, best_end] 内。
             * BSS 豁免：index==-1 的匿名段，start 在 best_end 附近（≤0x3000）
             * 即视为本体尾部延伸，保留并动态扩展 best_end，
             * 防止后续 BSS 碎片因 end 超界而被误杀。
             */
            int valid_count = 0;
            for (j = 0; j < m->seg_count; j++)
            {
                if (m->segs[j].start >= best_base && m->segs[j].end <= best_end)
                {
                    m->segs[valid_count++] = m->segs[j];
                }
                else if (m->segs[j].index == -1 &&
                         m->segs[j].start >= best_base &&
                         m->segs[j].start <= best_end + 0x3000)
                {
                    m->segs[valid_count++] = m->segs[j];
                    if (m->segs[j].end > best_end)
                        best_end = m->segs[j].end;
                }
            }
            m->seg_count = valid_count;

            if (m->seg_count == 0)
                continue;

            /* --- 步骤 4：严谨拓扑标记 --- */
            int first_data_idx = -1;

            for (j = 0; j < m->seg_count; j++)
            {
                if (m->segs[j].index == -1)
                    continue;

                if ((m->segs[j].prot & 2) && !(m->segs[j].prot & 4))
                {
                    first_data_idx = j;
                    break;
                }
            }

            for (j = 0; j < m->seg_count; j++)
            {
                if (m->segs[j].index == -1)
                    continue;

                if (j == 0)
                {
                    if (!(m->segs[j].prot & 4) && !(m->segs[j].prot & 2))
                        m->segs[j].index = 1;
                    else if (m->segs[j].prot & 4)
                        m->segs[j].index = 0;
                    else
                        m->segs[j].index = 2;
                }
                else if (first_data_idx != -1 && j < first_data_idx)
                {
                    m->segs[j].index = 0;
                }
                else
                {
                    if (m->segs[j].prot & 4)
                        m->segs[j].index = 0;
                    else if (m->segs[j].prot & 2)
                        m->segs[j].index = 2;
                    else
                        m->segs[j].index = 1;
                }
            }

            /* --- 步骤 4.5：强制规范化 prot (消除反作弊权限污染) --- */
            /*
             * 步骤 4 已建立权威拓扑标签，此处根据标签反推标准 prot，
             * 同时修正 BSS 的 -w-p 异常权限为标准 RW。
             * 缝合阶段（步骤 5）不再需要合并 prot。
             */
            for (j = 0; j < m->seg_count; j++)
            {
                switch (m->segs[j].index)
                {
                case 1:
                    m->segs[j].prot = 1;
                    break; /* RO  : Header / RELRO     */
                case 0:
                    m->segs[j].prot = 5;
                    break; /* RX  : 代码段              */
                case 2:
                    m->segs[j].prot = 3;
                    break; /* RW  : 数据段              */
                case -1:
                    m->segs[j].prot = 3;
                    break; /* RW  : BSS（修正 -w- 异常）*/
                }
            }

            /* --- 步骤 5：拉链式精准缝合 --- */
            int out_idx = 0;
            for (j = 1; j < m->seg_count; j++)
            {
                struct segment_info *prev_seg = &m->segs[out_idx];
                struct segment_info *curr_seg = &m->segs[j];

                if (prev_seg->end == curr_seg->start &&
                    prev_seg->index == curr_seg->index)
                {
                    /* 首尾相连且拓扑标签一致，直接延伸尾部，prot 无需合并 */
                    prev_seg->end = curr_seg->end;
                }
                else
                {
                    out_idx++;
                    if (out_idx != j)
                        m->segs[out_idx] = *curr_seg;
                }
            }
            m->seg_count = out_idx + 1;

            /* --- 步骤 6：最终 Index 序列化 --- */
            seq = 0;
            for (j = 0; j < m->seg_count; j++)
            {
                if (m->segs[j].index != -1)
                    m->segs[j].index = seq++;
            }
        }
    }

    mmput(mm);
    put_task_struct(task);
    kfree(path_buf);
    return 0;
}
#endif // PHYSICAL_H
