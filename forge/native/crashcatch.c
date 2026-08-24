/* crashcatch.c - a fault reporter you inject into a binary you cannot rebuild.
   Referenced by Part 14 (14.1, 14.2, 14.8).

   The problem it solves. A black box has no AddressSanitizer in it, so the only
   fault report you get is whatever the operating system decides to say. On macOS
   that means the crash reporter, which SUSPENDS the dying process while it
   collects a report. Under a fuzzer that produces crashes at speed the machine
   fills with suspended processes that cannot be killed, and the campaign stops.
   The same trick that fixes that also gives you the two facts triage needs.

   The trick: DYLD_INSERT_LIBRARIES puts this library into the target's address
   space before main runs. A constructor installs signal handlers. When the target
   faults, OUR handler runs instead of the default one, prints what it knows, and
   calls _exit(), so no signal is ever delivered to the parent and the crash
   reporter never engages.

   What it prints, and why each field is worth having with no symbols:
       sig     which fault: SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGTRAP
       addr    the address the faulting instruction touched (siginfo si_addr)
       pc      the faulting instruction, as it was in memory this run
       module  WHICH loaded image that pc falls in, and the offset into it. This
               is the field that stops you wasting an afternoon: a fault inside
               libsystem_malloc is the allocator noticing corruption somebody
               else caused, and disassembling your own binary at that address
               tells you nothing.
       static_pc  pc minus the MAIN EXECUTABLE's ASLR slide. Meaningful only when
               module is the main executable; the triage tool checks that.

   This is the black-box equivalent of a sanitizer report, and it is much weaker:
   it fires only when the hardware or the allocator notices. Part 14.10 is the
   list of what it is blind to.

   Build:
       cc -dynamiclib -O1 -o libcrashcatch.dylib demos/crashcatch.c
   Use:
       DYLD_INSERT_LIBRARIES=./libcrashcatch.dylib ./bb-tga poc.tga
*/
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

static unsigned long g_slide;          /* captured before any fault */
static char          g_altstack[SIGSTKSZ * 4];

/* The loaded-image table, snapshotted in the constructor. Walking dyld's list
   from inside a signal handler is not async-signal-safe; walking a plain array
   we filled earlier is. */
#define MAXIMG 600
static unsigned long g_base[MAXIMG];
static const char   *g_name[MAXIMG];
static unsigned      g_nimg;

/* Everything below runs in a signal handler, so it may only use
   async-signal-safe calls. No printf, no malloc. write() and nothing else. */
static void wr(const char *s) { (void)!write(2, s, strlen(s)); }

static void wrhex(unsigned long v) {
    char b[19]; int i = 18;
    b[i--] = 0;
    if (!v) b[i--] = '0';
    while (v) { b[i--] = "0123456789abcdef"[v & 0xf]; v >>= 4; }
    b[i--] = 'x'; b[i] = '0';
    wr(&b[i]);
}

static const char *signame(int s) {
    switch (s) {
        case SIGSEGV: return "SIGSEGV";
        case SIGBUS:  return "SIGBUS";
        case SIGILL:  return "SIGILL";
        case SIGABRT: return "SIGABRT";
        case SIGTRAP: return "SIGTRAP";
        case SIGFPE:  return "SIGFPE";
        default:      return "SIG?";
    }
}

/* dyld calls this for every image already loaded and for every image loaded
   later, including anything the target dlopen()s. Snapshotting once in the
   constructor is NOT enough: a harness that dlopen()s the library under test
   loads it AFTER we run, and the fault then gets blamed on whichever image
   happens to sit below it in memory. That misattribution is silent and
   convincing, which is the worst combination a triage tool can have. */
static void image_added(const struct mach_header *mh, intptr_t slide) {
    (void)slide;
    if (g_nimg >= MAXIMG || !mh) return;
    unsigned idx = g_nimg;
    g_base[idx] = (unsigned long)mh;
    g_name[idx] = "?";
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++)
        if (_dyld_get_image_header(i) == mh) { g_name[idx] = _dyld_get_image_name(i); break; }
    g_nimg = idx + 1;                  /* published last: the handler may read it */
}

/* The last image whose load address is at or below pc. Linear, tiny, and safe. */
static unsigned which_image(unsigned long pc) {
    unsigned best = (unsigned)-1;
    unsigned long bestbase = 0;
    for (unsigned i = 0; i < g_nimg; i++)
        if (g_base[i] <= pc && g_base[i] >= bestbase) { bestbase = g_base[i]; best = i; }
    return best;
}

static const char *basename_of(const char *p) {
    const char *b = p;
    for (const char *q = p; *q; q++) if (*q == '/') b = q + 1;
    return b;
}

static void handler(int sig, siginfo_t *si, void *uc) {
    unsigned long pc = 0;
#if defined(__arm64__) || defined(__aarch64__)
    /* Apple does not let you read __pc directly under pointer authentication.
       On arm64e the program counter is a SIGNED pointer, so the raw field is not
       a usable address and the header hides it behind an accessor that strips the
       signature. Reaching for ->__ss.__pc compiles on some SDKs and fails on this
       one with "no member named __pc", which is the compiler telling you that the
       representation is not what you assumed. Use the accessor. */
    if (uc) pc = (unsigned long)arm_thread_state64_get_pc(
                     ((ucontext_t *)uc)->uc_mcontext->__ss);
#elif defined(__x86_64__)
    if (uc) pc = (unsigned long)((ucontext_t *)uc)->uc_mcontext->__ss.__rip;
#endif
    wr("== CRASHCATCH sig=");
    wr(signame(sig));
    wr(" addr=");
    wrhex(si ? (unsigned long)si->si_addr : 0);
    wr(" pc=");
    wrhex(pc);
    unsigned img = which_image(pc);
    wr(" module=");
    if (img != (unsigned)-1 && g_name[img]) {
        wr(basename_of(g_name[img]));
        wr("+");
        wrhex(pc - g_base[img]);
    } else {
        wr("unknown");
    }
    wr(" static_pc=");
    /* pc minus the ASLR slide is the address the linker gave this instruction,
       which is what you can look up in the file on disk with otool. */
    wrhex(pc > g_slide ? pc - g_slide : 0);
    wr("\n");
    _exit(128 + sig);              /* shell convention: 139 = SEGV, 134 = ABRT */
}

/* The ASLR slide of the MAIN EXECUTABLE, not of image 0. With
   DYLD_INSERT_LIBRARIES set, image 0 is not necessarily the program: it can be
   this library. Getting that wrong silently prints static_pc=0, which looks like
   a missing feature rather than a wrong one. */
static void find_main_slide(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) {
            g_slide = (unsigned long)_dyld_get_image_vmaddr_slide(i);
            return;
        }
    }
    g_slide = (unsigned long)_dyld_get_image_vmaddr_slide(0);
}

__attribute__((constructor))
static void crashcatch_init(void) {
    find_main_slide();

    _dyld_register_func_for_add_image(image_added);

    /* A stack overflow faults with the stack unusable, so the handler needs a
       stack of its own or it faults again and the process dies silently. */
    stack_t ss;
    ss.ss_sp = g_altstack;
    ss.ss_size = sizeof(g_altstack);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);

    /* Set CRASHCATCH_VERBOSE=1 to see how much code is actually in the process.
       This number is the argument for instrumenting selected modules only. */
    if (getenv("CRASHCATCH_VERBOSE")) {
        wr("== CRASHCATCH armed, images loaded=");
        wrhex(g_nimg);
        wr(" main_slide=");
        wrhex(g_slide);
        wr("\n");
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGTRAP, SIGFPE };
    for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
        sigaction(sigs[i], &sa, NULL);
}
