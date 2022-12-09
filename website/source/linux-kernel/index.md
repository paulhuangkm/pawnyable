---
title: Linux Kernel Exploitation
---

<div class="balloon_l">
  <div class="faceicon"><img src="img/wolf_normal.png" alt="オオカミくん" ></div>
  <p class="says">
  In this chapter, you will learn about Exploit techniques in the kernel space, so-called privilege escalation.
  Since common hardware security mechanisms and privilege escalation methods also appear in Windows Kernel Exploit, the knowledge in this chapter is useful not only for Linux.
  </p>
</div>

- Execution environment and debugging methods
  - [Introduction to kernel exploit](introduction/introduction.html)
  - [Debugging the kernel with gdb](introduction/debugging.html)
  - [Security mechanisms](introduction/security.html)
  - [Compilation and exploit transfers](introduction/compile-and-transfer.html)
- Basics of kernel exploits (LK01: Holstein)
  - [Analyzing the Holstein module and triggering vulnerabilities](LK01/welcome-to-holstein.html)
  - [Holstein v1: Stack Overflow exploit](LK01/stack_overflow.html)
  - [Holstein v2: Heap Overflow exploit](LK01/heap_overflow.html)
  - [Holstein v3: Use-after-Free exploit](LK01/use_after_free.html)
  - [Holstein v4: Race Condition exploit](LK01/race_condition.html)
- Kernel Space Specific Attacks
  - [NULL Pointer Dereference (LK02: Angus)](LK02/null_ptr_deref.html)
  - [Double Fetch (LK03: Dexter)](LK03/double_fetch.html)
  - [Use of userfaultfd (LK04: Fleckvieh)](LK04/uffd.html)
  - [Using FUSE (LK04: Fleckvieh)](LK04/fuse.html)
  - [Exploitation of a weak mmap implementation (LK05: Highland) (under construction)](#)
- eBPF and the JIT compiler (LK06: Brahman)
  - [Introduction to BPF](LK06/ebpf.html)
  - [Verifier and JIT compiler](LK06/verifier.html)
  - [Exploitation of a bug in eBPF](LK06/exploit.html)
<!--
- UEFIアプリケーション（LK07: ???）
- TrustZoneとTEE（LK08: ???）
- 付録
  - [buildrootによるカーネルのビルド (工事中)](appendix/buildroot.html)
-->

<div class="column" title="講師プロフィール">
  <div style="overflow: hidden">
    <div style="float: left; margin-right: 1em;" class="faceicon">
      <img src="img/wolf_suyasuya.png" alt="オオカミくん" >
    </div>
    <div style="float: left;">
      <b>オオカミくん</b><br>
      オオカミの群れで権限昇格してリーダーになったという伝説がある。<br>
      動物界ではOS開発の第一人者。基本寝ている。<br>
      好きなもの：牛 / Linux<br>
      苦手なもの：ハイエナ / Windows
    </div>
  </div>
</div>
