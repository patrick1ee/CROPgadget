
vuln3-32:     file format elf32-i386

SYMBOL TABLE:
080480f4 l    d  .note.ABI-tag	00000000 .note.ABI-tag
08048114 l    d  .note.gnu.build-id	00000000 .note.gnu.build-id
08048138 l    d  .rel.plt	00000000 .rel.plt
080481a8 l    d  .init	00000000 .init
080481d0 l    d  .plt	00000000 .plt
08048240 l    d  .text	00000000 .text
080ab550 l    d  __libc_freeres_fn	00000000 __libc_freeres_fn
080ac100 l    d  __libc_thread_freeres_fn	00000000 __libc_thread_freeres_fn
080ac228 l    d  .fini	00000000 .fini
080ac240 l    d  .rodata	00000000 .rodata
080c4918 l    d  .eh_frame	00000000 .eh_frame
080d6764 l    d  .gcc_except_table	00000000 .gcc_except_table
080d86e0 l    d  .tdata	00000000 .tdata
080d86f0 l    d  .tbss	00000000 .tbss
080d86f0 l    d  .init_array	00000000 .init_array
080d86f8 l    d  .fini_array	00000000 .fini_array
080d8700 l    d  .data.rel.ro	00000000 .data.rel.ro
080d9fd4 l    d  .got	00000000 .got
080da000 l    d  .got.plt	00000000 .got.plt
080da060 l    d  .data	00000000 .data
080daf80 l    d  __libc_subfreeres	00000000 __libc_subfreeres
080dafc0 l    d  __libc_IO_vtables	00000000 __libc_IO_vtables
080db314 l    d  __libc_atexit	00000000 __libc_atexit
080db318 l    d  __libc_thread_subfreeres	00000000 __libc_thread_subfreeres
080db320 l    d  .bss	00000000 .bss
080dbffc l    d  __libc_freeres_ptrs	00000000 __libc_freeres_ptrs
00000000 l    d  .comment	00000000 .comment
00000000 l    d  .debug_aranges	00000000 .debug_aranges
00000000 l    d  .debug_info	00000000 .debug_info
00000000 l    d  .debug_abbrev	00000000 .debug_abbrev
00000000 l    d  .debug_line	00000000 .debug_line
00000000 l    d  .debug_str	00000000 .debug_str
00000000 l    df *ABS*	00000000 libc_fatal.o
08048240 l     F .text	00000001 backtrace_and_maps.constprop.0
00000000 l    df *ABS*	00000000 dl-tls.o
0809d1b0 l     F .text	00000044 allocate_dtv
08048241 l     F .text	00000029 oom
080bf378 l     O .rodata	00000013 __PRETTY_FUNCTION__.9242
080bf360 l     O .rodata	00000016 __PRETTY_FUNCTION__.9304
080bf34c l     O .rodata	00000014 __PRETTY_FUNCTION__.9343
00000000 l    df *ABS*	00000000 sdlerror.o
080a0cc0 l     F .text	00000047 init
080a0fa0 l     F .text	0000004b free_key_mem
080dbaa4 l     O .bss	00000004 key
080dbaac l     O .bss	00000014 last_result
080dbaa8 l     O .bss	00000004 static_buf
080dbaa0 l     O .bss	00000004 once
080a0f50 l     F .text	00000050 check_free.isra.0
08048270 l     F .text	00000015 fini
080daf40 l     O .data	00000034 _dlfcn_hooks
00000000 l    df *ABS*	00000000 cacheinfo.o
0806aad0 l     F .text	00000202 handle_amd
080ae3e0 l     O .rodata	0000000b __PRETTY_FUNCTION__.9233
0806ace0 l     F .text	0000028f intel_check_word.isra.0
080ae1c0 l     O .rodata	00000220 intel_02_known
080ae3ec l     O .rodata	00000011 __PRETTY_FUNCTION__.9163
0806af70 l     F .text	00000153 handle_intel.constprop.1
08048290 l     F .text	000004a0 init_cacheinfo
0806ab30 l       .text	00000000 .L39
0806ac20 l       .text	00000000 .L6
0806abf0 l       .text	00000000 .L8
0806ac18 l       .text	00000000 .L9
0806ab80 l       .text	00000000 .L10
0806aba0 l       .text	00000000 .L11
0806abb8 l       .text	00000000 .L12
0806abd0 l       .text	00000000 .L13
0806ab50 l       .text	00000000 .L14
0806ab68 l       .text	00000000 .L15
0806ac75 l       .text	00000000 .L28
0806ac39 l       .text	00000000 .L41
0806ac6b l       .text	00000000 .L31
0806ac61 l       .text	00000000 .L32
0806ac4d l       .text	00000000 .L33
0806ac43 l       .text	00000000 .L34
0806ac57 l       .text	00000000 .L35
0806ac2f l       .text	00000000 .L44
0806ac7d l       .text	00000000 .L36
0806aca7 l       .text	00000000 .L18
0806ac91 l       .text	00000000 .L26
00000000 l    df *ABS*	00000000 crtstuff.c
080c4944 l     O .eh_frame	00000000 __EH_FRAME_BEGIN__
08048790 l     F .text	00000000 deregister_tm_clones
080487d0 l     F .text	00000000 register_tm_clones
08048810 l     F .text	00000000 __do_global_dtors_aux
080db320 l     O .bss	00000001 completed.6767
080d86f8 l     O .fini_array	00000000 __do_global_dtors_aux_fini_array_entry
08048860 l     F .text	00000000 frame_dummy
080db324 l     O .bss	00000018 object.6772
080d86f0 l     O .init_array	00000000 __frame_dummy_init_array_entry
00000000 l    df *ABS*	00000000 vuln3.c
00000000 l    df *ABS*	00000000 libc-start.o
080489f0 l     F .text	0000026b get_common_indeces.constprop.1
080ac358 l     O .rodata	00000012 __PRETTY_FUNCTION__.10495
00000000 l    df *ABS*	00000000 check_fds.o
08049360 l     F .text	000000ba check_one_fd
00000000 l    df *ABS*	00000000 libc-tls.o
080db340 l     O .bss	00000208 static_slotinfo
00000000 l    df *ABS*	00000000 assert.o
080ac3b0 l     O .rodata	00000013 errstr.10882
00000000 l    df *ABS*	00000000 dcigettext.o
08049990 l     F .text	00000183 plural_eval
080ab550 l     F __libc_freeres_fn	000000ca free_mem
080db598 l     O .bss	00000004 root
080db594 l     O .bss	00000004 transmem_list
08049b20 l     F .text	0000007d transcmp
08049ba0 l     F .text	0000005b plural_lookup.isra.2
080db590 l     O .bss	00000004 lock.10450
080db584 l     O .bss	00000004 output_charset_cached.10502
080db580 l     O .bss	00000004 output_charset_cache.10501
080db58c l     O .bss	00000004 freemem.10458
080db588 l     O .bss	00000004 freemem_size.10459
080db5a0 l     O .bss	00000020 tree_lock
080daf80 l     O __libc_subfreeres	00000004 __elf_set___libc_subfreeres_element_free_mem__
08049afe l       .text	00000000 .L14
08049af1 l       .text	00000000 .L16
08049ae4 l       .text	00000000 .L17
08049add l       .text	00000000 .L18
08049ad6 l       .text	00000000 .L19
08049ac9 l       .text	00000000 .L20
08049abc l       .text	00000000 .L21
08049aaf l       .text	00000000 .L22
08049aa2 l       .text	00000000 .L23
08049a95 l       .text	00000000 .L24
08049b06 l       .text	00000000 .L25
00000000 l    df *ABS*	00000000 finddomain.o
080db5c0 l     O .bss	00000020 lock.10110
080db5e0 l     O .bss	00000004 _nl_loaded_domains
00000000 l    df *ABS*	00000000 loadmsgcat.o
080db5e4 l     O .bss	0000000c lock.9720
00000000 l    df *ABS*	00000000 localealias.o
0804c660 l     F .text	0000002c alias_compare
0804c690 l     F .text	00000558 read_alias_file
080db5f8 l     O .bss	00000004 nmap
080db5f4 l     O .bss	00000004 maxmap
080db600 l     O .bss	00000004 string_space_act
080db5fc l     O .bss	00000004 string_space_max
080dc000 l     O __libc_freeres_ptrs	00000004 string_space
080dbffc l     O __libc_freeres_ptrs	00000004 map
080db604 l     O .bss	00000004 lock
080db5f0 l     O .bss	00000004 locale_alias_path.9126
00000000 l    df *ABS*	00000000 plural.o
0804d750 l     F .text	000000dc new_exp
080ac79c l     O .rodata	0000001b yypact
080ac7c0 l     O .rodata	00000107 yytranslate
080ac700 l     O .rodata	00000037 yycheck
080ac780 l     O .rodata	0000001b yydefact
080ac6cc l     O .rodata	0000000e yyr2
080ac740 l     O .rodata	00000037 yytable
080ac777 l     O .rodata	00000003 yydefgoto
080ac6dc l     O .rodata	0000000e yyr1
080ac77a l     O .rodata	00000003 yypgoto
0804dfee l       .text	00000000 .L86
0804dd9c l       .text	00000000 .L58
0804de2d l       .text	00000000 .L75
0804dc45 l       .text	00000000 .L87
0804dc6f l       .text	00000000 .L89
0804dd0a l       .text	00000000 .L90
0804dd5c l       .text	00000000 .L91
0804d9f0 l       .text	00000000 .L95
0804dcd6 l       .text	00000000 .L96
0804dcb1 l       .text	00000000 .L97
0804dd26 l       .text	00000000 .L98
0804dd78 l       .text	00000000 .L99
0804df34 l       .text	00000000 .L60
0804df10 l       .text	00000000 .L61
0804dee6 l       .text	00000000 .L62
0804df01 l       .text	00000000 .L63
0804dfa6 l       .text	00000000 .L64
0804df82 l       .text	00000000 .L65
0804dfca l       .text	00000000 .L66
0804df5e l       .text	00000000 .L67
0804de7b l       .text	00000000 .L68
0804de49 l       .text	00000000 .L69
0804de1f l       .text	00000000 .L70
0804dded l       .text	00000000 .L71
00000000 l    df *ABS*	00000000 plural-exp.o
080ac8f0 l     O .rodata	00000014 plvar
080ac8dc l     O .rodata	00000014 plone
00000000 l    df *ABS*	00000000 abort.o
080db60c l     O .bss	0000000c lock
080db618 l     O .bss	00000004 stage
00000000 l    df *ABS*	00000000 msort.o
0804e480 l     F .text	0000037c msort_with_tmp.part.0
080db620 l     O .bss	00000004 pagesize.7804
080db61c l     O .bss	00000004 phys_pages.7803
00000000 l    df *ABS*	00000000 cxa_atexit.o
080ac91c l     O .rodata	0000000d __PRETTY_FUNCTION__.7213
080db640 l     O .bss	00000208 initial
00000000 l    df *ABS*	00000000 fxprintf.o
0804f940 l     F .text	00000187 locked_vfxprintf
00000000 l    df *ABS*	00000000 wfileops.o
080503d0 l     F .text	000000ca adjust_wide_data
080ac950 l     O .rodata	00000014 __PRETTY_FUNCTION__.10675
08051550 l     F .text	0000004b _IO_wfile_underflow_maybe_mmap
080515a0 l     F .text	0000015f _IO_wfile_underflow_mmap
00000000 l    df *ABS*	00000000 fileops.o
08052410 l     F .text	0000007c _IO_file_seekoff_maybe_mmap
08052590 l     F .text	00000168 new_do_write
08052a10 l     F .text	00000324 mmap_remap_check
08052d50 l     F .text	0000005a _IO_file_sync_mmap
08052db0 l     F .text	00000201 decide_maybe_mmap
08053020 l     F .text	0000006f _IO_file_xsgetn_maybe_mmap
08053960 l     F .text	00000150 _IO_file_xsgetn_mmap
080ac9e8 l     O .rodata	00000013 __PRETTY_FUNCTION__.11820
00000000 l    df *ABS*	00000000 genops.o
080ab7a0 l     F __libc_freeres_fn	00000049 buffer_free
080db848 l     O .bss	00000004 freeres_list
080db84c l     O .bss	00000001 dealloc_buffers
08054e60 l     F .text	00000219 save_for_backup
08055080 l     F .text	00000081 flush_cleanup
080db854 l     O .bss	00000004 run_fp
080db858 l     O .bss	0000000c list_all_lock
08055110 l     F .text	0000024a _IO_un_link.part.2
080db850 l     O .bss	00000004 stdio_needs_locking
080db314 l     O __libc_atexit	00000004 __elf_set___libc_atexit_element__IO_cleanup__
080daf84 l     O __libc_subfreeres	00000004 __elf_set___libc_subfreeres_element_buffer_free__
00000000 l    df *ABS*	00000000 stdfiles.o
080db864 l     O .bss	0000000c _IO_stdfile_2_lock
080da120 l     O .data	000000b4 _IO_wide_data_2
080db870 l     O .bss	0000000c _IO_stdfile_1_lock
080da280 l     O .data	000000b4 _IO_wide_data_1
080db87c l     O .bss	0000000c _IO_stdfile_0_lock
080da3e0 l     O .data	000000b4 _IO_wide_data_0
00000000 l    df *ABS*	00000000 strops.o
080571a0 l     F .text	000001ec enlarge_userbuf
080aca18 l     O .rodata	00000010 __PRETTY_FUNCTION__.10098
00000000 l    df *ABS*	00000000 malloc.o
080da4c0 l     O .data	00000040 mp_
080db8b0 l     O .bss	00000004 perturb_byte
08057a10 l     F .text	00000092 mem2mem_check
08057ab0 l     F .text	000001e5 mem2chunk_check
080da520 l     O .data	0000045c main_arena
08057ca0 l     F .text	00000111 int_mallinfo
08057dc0 l     F .text	00000065 __malloc_assert
08057e30 l     F .text	00000050 detach_arena
080ad8f0 l     O .rodata	0000000d __PRETTY_FUNCTION__.11251
08057e80 l     F .text	000000f0 get_free_list
080db8a8 l     O .bss	00000004 free_list
0000001c l       .tbss	00000004 thread_arena
080db8ac l     O .bss	00000004 free_list_lock
080ad900 l     O .rodata	0000000e __PRETTY_FUNCTION__.11285
08057f70 l     F .text	0000001d malloc_printerr
08057f90 l     F .text	00000065 top_check
08058000 l     F .text	000002be malloc_consolidate
080582c0 l     F .text	000001b8 new_heap
080db8a0 l     O .bss	00000004 aligned_heap_area
08058480 l     F .text	0000008b munmap_chunk
080ad940 l     O .rodata	0000000d __PRETTY_FUNCTION__.11570
08058510 l     F .text	00000157 mremap_chunk
080ad930 l     O .rodata	0000000d __PRETTY_FUNCTION__.11610
08058670 l     F .text	0000015e ptmalloc_init.part.0
080db8b4 l     O .bss	00000004 global_max_fast
080587d0 l     F .text	000003f5 arena_get2.part.4
080db894 l     O .bss	00000004 narenas_limit.11327
080da4a8 l     O .data	00000004 narenas
080db890 l     O .bss	00000004 next_to_use.11305
080ad8d8 l     O .rodata	00000016 __PRETTY_FUNCTION__.11297
080db8a4 l     O .bss	00000004 list_lock
08058bd0 l     F .text	00000096 arena_get_retry
080db898 l     O .bss	00000004 disallow_malloc_check
0805b530 l     F .text	0000009d malloc_check
080db89c l     O .bss	00000004 using_malloc_checking
0805bab0 l     F .text	00000012 free_check
0805be30 l     F .text	0000023e realloc_check
0805b8e0 l     F .text	0000010a memalign_check
08058ce0 l     F .text	000004c6 __malloc_info.part.12
080591b0 l     F .text	000000c4 systrim.isra.1.constprop.13
08059280 l     F .text	00000acd _int_free
00000014 l       .tbss	00000004 tcache
080ad95c l     O .rodata	0000000a __PRETTY_FUNCTION__.11958
080da4a0 l     O .data	00000004 may_shrink_heap.10278
080ad980 l     O .rodata	0000000b __PRETTY_FUNCTION__.11632
080ad950 l     O .rodata	0000000a __PRETTY_FUNCTION__.11244
08059d50 l     F .text	00000841 sysmalloc
080ad968 l     O .rodata	0000000a __PRETTY_FUNCTION__.11526
0805a5a0 l     F .text	00000f88 _int_malloc
080ad98c l     O .rodata	0000000c __PRETTY_FUNCTION__.11879
080ad974 l     O .rodata	0000000b __PRETTY_FUNCTION__.11637
0805b5d0 l     F .text	000000ff tcache_init.part.6
0805b6d0 l     F .text	0000020c _int_memalign
080ad998 l     O .rodata	0000000e __PRETTY_FUNCTION__.12015
0805b9f0 l     F .text	000000be free_check.part.3
0805bad0 l     F .text	00000354 _int_realloc
080ad920 l     O .rodata	0000000d __PRETTY_FUNCTION__.11998
080ad910 l     O .rodata	0000000e __PRETTY_FUNCTION__.11678
00000018 l       .tbss	00000001 tcache_shutting_down
0805c540 l     F .text	0000004a malloc_hook_ini
0805c590 l     F .text	0000026a _mid_memalign
080ad8b8 l     O .rodata	0000000e __PRETTY_FUNCTION__.11749
0805c800 l     F .text	00000061 memalign_hook_ini
080ac100 l     F __libc_thread_freeres_fn	00000127 arena_thread_freeres
080ad9a8 l     O .rodata	00000015 __PRETTY_FUNCTION__.11370
080ad8c8 l     O .rodata	0000000f __PRETTY_FUNCTION__.11716
0805ccc0 l     F .text	00000057 realloc_hook_ini
080ad8a8 l     O .rodata	0000000e __PRETTY_FUNCTION__.11797
080ad8a0 l     O .rodata	00000006 __PRETTY_FUNCTION__.12029
080db318 l     O __libc_thread_subfreeres	00000004 __elf_set___libc_thread_subfreeres_element_arena_thread_freeres__
0805d9a0 l       .text	00000000 .L1467
0805d8d0 l       .text	00000000 .L1457
0805d8e8 l       .text	00000000 .L1459
0805d900 l       .text	00000000 .L1460
0805d938 l       .text	00000000 .L1461
0805d958 l       .text	00000000 .L1462
0805d980 l       .text	00000000 .L1463
0805d890 l       .text	00000000 .L1464
0805d910 l       .text	00000000 .L1465
00000000 l    df *ABS*	00000000 strchr.o
0805daa0 l     F .text	00000032 strchr_ifunc
00000000 l    df *ABS*	00000000 strcmp.o
0805dae0 l     F .text	00000036 strcmp_ifunc
00000000 l    df *ABS*	00000000 strcpy.o
0805db20 l     F .text	00000038 strcpy_ifunc
00000000 l    df *ABS*	00000000 strcspn.o
0805db60 l     F .text	00000027 strcspn_ifunc
00000000 l    df *ABS*	00000000 strerror.o
080dc004 l     O __libc_freeres_ptrs	00000004 buf
00000000 l    df *ABS*	00000000 strstr.o
0805de20 l     F .text	000004c1 two_way_long_needle
00000000 l    df *ABS*	00000000 memcmp.o
0805e600 l     F .text	00000036 memcmp_ifunc
00000000 l    df *ABS*	00000000 memset.o
0805e640 l     F .text	00000032 memset_ifunc
00000000 l    df *ABS*	00000000 stpcpy.o
0805e680 l     F .text	00000038 __stpcpy_ifunc
00000000 l    df *ABS*	00000000 strcasecmp_l.o
0805e6c0 l     F .text	00000036 __strcasecmp_l_ifunc
00000000 l    df *ABS*	00000000 rawmemchr.o
0805e700 l     F .text	00000032 __rawmemchr_ifunc
00000000 l    df *ABS*	00000000 mbsrtowcs.o
080db8b8 l     O .bss	00000008 state
00000000 l    df *ABS*	00000000 wcsmbsload.o
080d9940 l     O .data.rel.ro	0000003c to_wc
080d9900 l     O .data.rel.ro	0000003c to_mb
00000000 l    df *ABS*	00000000 mbsrtowcs_l.o
080ae518 l     O .rodata	0000000e __PRETTY_FUNCTION__.9334
00000000 l    df *ABS*	00000000 sysconf.o
0806b930 l     F .text	00000125 __sysconf_check_spec
0806bdf0 l       .text	00000000 .L29
0806bc15 l       .text	00000000 .L98
0806bde6 l       .text	00000000 .L31
0806bddc l       .text	00000000 .L32
0806be26 l       .text	00000000 .L33
0806bdd2 l       .text	00000000 .L34
0806bcec l       .text	00000000 .L69
0806bc80 l       .text	00000000 .L78
0806bc60 l       .text	00000000 .L81
0806bcf6 l       .text	00000000 .L70
0806bc90 l       .text	00000000 .L77
0806bd3c l       .text	00000000 .L40
0806bd28 l       .text	00000000 .L41
0806bc9a l       .text	00000000 .L68
0806bd0a l       .text	00000000 .L43
0806bca4 l       .text	00000000 .L76
0806bd82 l       .text	00000000 .L45
0806bce2 l       .text	00000000 .L73
0806bcb8 l       .text	00000000 .L71
0806bcae l       .text	00000000 .L49
0806bd46 l       .text	00000000 .L50
0806bd00 l       .text	00000000 .L61
0806bd64 l       .text	00000000 .L53
0806bd96 l       .text	00000000 .L54
0806bda0 l       .text	00000000 .L55
0806bdaa l       .text	00000000 .L56
0806bd50 l       .text	00000000 .L57
0806bdb4 l       .text	00000000 .L59
0806bd78 l       .text	00000000 .L60
0806bd6e l       .text	00000000 .L63
0806bd1e l       .text	00000000 .L64
0806bd14 l       .text	00000000 .L65
0806bd8c l       .text	00000000 .L67
0806bd5a l       .text	00000000 .L72
0806bdbe l       .text	00000000 .L74
0806bdc8 l       .text	00000000 .L75
0806bcc2 l       .text	00000000 .L79
0806bcd2 l       .text	00000000 .L80
0806bd32 l       .text	00000000 .L82
00000000 l    df *ABS*	00000000 fcntl.o
0806c240 l     F .text	00000064 fcntl_common.part.0
00000000 l    df *ABS*	00000000 getcwd.o
080ae9c4 l     O .rodata	00000009 __PRETTY_FUNCTION__.7759
00000000 l    df *ABS*	00000000 getpagesize.o
080ae9fc l     O .rodata	0000000e __PRETTY_FUNCTION__.9102
00000000 l    df *ABS*	00000000 tsearch.o
0806cf80 l     F .text	0000008c trecurse
0806d010 l     F .text	00000057 tdestroy_recurse
0806d070 l     F .text	0000015b maybe_split_for_insert.isra.0
00000000 l    df *ABS*	00000000 getsysstats.o
0806d970 l     F .text	000001bd next_line
080aea70 l     O .rodata	0000000a __PRETTY_FUNCTION__.10277
0806db30 l     F .text	0000004d sysinfo_mempages
080db8c4 l     O .bss	00000004 timestamp.10282
080da9a0 l     O .data	00000004 cached_result.10281
00000000 l    df *ABS*	00000000 dl-tunables.o
0806e3f0 l     F .text	00000061 do_tunable_update_val
0806e460 l     F .text	00000046 tunable_initialize
080d9980 l     O .data.rel.ro	000003c8 tunable_list
00000000 l    df *ABS*	00000000 dl-support.o
0806ea70 l     F .text	00000003 .hidden _dl_sysinfo_int80
080daaa0 l     O .data	0000025c _dl_main_map
080d9d60 l     O .data.rel.ro	00000040 dyn_temp.9608
080aef20 l     O .rodata	00000138 unsecure_envvars.9651
080af36c l     O .rodata	0000000b __PRETTY_FUNCTION__.9611
080af354 l     O .rodata	00000015 __PRETTY_FUNCTION__.9602
080daa30 l     O .data	00000004 __compound_literal.3
080dad00 l     O .data	0000000c __compound_literal.0
080dacfc l     O .data	00000004 __compound_literal.1
080db958 l     O .bss	00000004 __compound_literal.2
0806ec0b l       .text	00000000 .L4
0806ef20 l       .text	00000000 .L5
0806ef00 l       .text	00000000 .L7
0806ebe8 l       .text	00000000 .L8
0806eee0 l       .text	00000000 .L9
0806eec0 l       .text	00000000 .L10
0806eea0 l       .text	00000000 .L11
0806ee80 l       .text	00000000 .L12
0806ee58 l       .text	00000000 .L13
0806ee30 l       .text	00000000 .L14
0806ee10 l       .text	00000000 .L15
0806edf0 l       .text	00000000 .L16
0806edc0 l       .text	00000000 .L17
0806ed98 l       .text	00000000 .L18
0806ed70 l       .text	00000000 .L19
0806ed50 l       .text	00000000 .L20
0806ed28 l       .text	00000000 .L21
00000000 l    df *ABS*	00000000 dl-sysdep.o
0806f920 l       .text	00000000 .L2
0806fdf3 l       .text	00000000 .L113
0806fdc4 l       .text	00000000 .L110
0806fd95 l       .text	00000000 .L109
0806fbe5 l       .text	00000000 .L83
0806fbab l       .text	00000000 .L84
0806fb71 l       .text	00000000 .L85
0806fd18 l       .text	00000000 .L86
0806fcb1 l       .text	00000000 .L88
0806fc69 l       .text	00000000 .L89
0806fa94 l       .text	00000000 .L90
0806fa5d l       .text	00000000 .L91
0806fa0d l       .text	00000000 .L92
0806f9b9 l       .text	00000000 .L93
0806fb1d l       .text	00000000 .L94
0806face l       .text	00000000 .L95
0806f964 l       .text	00000000 .L96
0806fc1c l       .text	00000000 .L97
0806f8d4 l       .text	00000000 .L87
0806fd4b l       .text	00000000 .L82
0806fe6d l       .text	00000000 .L7
0806fe41 l       .text	00000000 .L77
0806fbf0 l       .text	00000000 .L106
0806fbb6 l       .text	00000000 .L107
0806fb7c l       .text	00000000 .L108
0806fe9c l       .text	00000000 .L39
0806fc74 l       .text	00000000 .L111
0806fa9f l       .text	00000000 .L112
0806fa0f l       .text	00000000 .L51
0806f9bb l       .text	00000000 .L53
0806fb1f l       .text	00000000 .L55
0806fad0 l       .text	00000000 .L59
0806f966 l       .text	00000000 .L61
0806fc1e l       .text	00000000 .L63
0806f8d6 l       .text	00000000 .L65
0806fd4d l       .text	00000000 .L67
00000000 l    df *ABS*	00000000 gconv.o
080af668 l     O .rodata	00000008 __PRETTY_FUNCTION__.8652
00000000 l    df *ABS*	00000000 gconv_db.o
080ab7f0 l     F __libc_freeres_fn	000000c7 free_derivation
080ab8c0 l     F __libc_freeres_fn	00000063 free_modules_db
080ab930 l     F __libc_freeres_fn	00000066 free_mem
080db960 l     O .bss	00000004 known_derivations
08070c80 l     F .text	0000003e derivation_compare
080af698 l     O .rodata	00000015 __PRETTY_FUNCTION__.8812
08070d90 l     F .text	00000adb find_derivation
080db95c l     O .bss	00000004 once
080daf88 l     O __libc_subfreeres	00000004 __elf_set___libc_subfreeres_element_free_mem__
00000000 l    df *ABS*	00000000 gconv_conf.o
080ab9a0 l     F __libc_freeres_fn	00000034 free_mem
080afc08 l     O .rodata	00000008 empty_path_elem
08071cf0 l     F .text	00000108 insert_module
08071e00 l     F .text	00000059 detect_conflict
08071e60 l     F .text	0000032c add_module.isra.0
08072190 l     F .text	0000007f add_alias2.isra.1.part.2
080db968 l     O .bss	00000004 lock.11270
080af80c l     O .rodata	00000011 __PRETTY_FUNCTION__.11288
080dad20 l     O .data	00000180 builtin_modules
080af820 l     O .rodata	000003e7 builtin_aliases
080db964 l     O .bss	00000004 modcounter.11250
080daf8c l     O __libc_subfreeres	00000004 __elf_set___libc_subfreeres_element_free_mem__
00000000 l    df *ABS*	00000000 gconv_builtin.o
080d9dc0 l     O .data.rel.ro	000000c0 map
080afc48 l     O .rodata	0000001a __PRETTY_FUNCTION__.8221
00000000 l    df *ABS*	00000000 gconv_simple.o
080b0100 l     O .rodata	00000020 __PRETTY_FUNCTION__.9459
080b00e0 l     O .rodata	00000020 __PRETTY_FUNCTION__.9546
080b00a0 l     O .rodata	00000022 __PRETTY_FUNCTION__.9627
080b0060 l     O .rodata	00000022 __PRETTY_FUNCTION__.9715
080b0020 l     O .rodata	00000021 __PRETTY_FUNCTION__.9801
080afe38 l     O .rodata	0000001b __PRETTY_FUNCTION__.9864
080affe0 l     O .rodata	00000021 __PRETTY_FUNCTION__.9917
080affc0 l     O .rodata	00000020 __PRETTY_FUNCTION__.10049
080afe1c l     O .rodata	0000001a __PRETTY_FUNCTION__.9988
080b0120 l     O .rodata	00000005 inmask.10126
080affa0 l     O .rodata	00000020 __PRETTY_FUNCTION__.10203
080afe00 l     O .rodata	0000001a __PRETTY_FUNCTION__.10137
080aff80 l     O .rodata	00000020 __PRETTY_FUNCTION__.10325
080afde4 l     O .rodata	0000001a __PRETTY_FUNCTION__.10271
080afdc8 l     O .rodata	0000001a __PRETTY_FUNCTION__.10389
080aff60 l     O .rodata	00000020 __PRETTY_FUNCTION__.10443
080aff20 l     O .rodata	00000027 __PRETTY_FUNCTION__.10567
080afee0 l     O .rodata	00000021 __PRETTY_FUNCTION__.10510
080afe60 l     O .rodata	00000021 __PRETTY_FUNCTION__.10634
080afea0 l     O .rodata	00000027 __PRETTY_FUNCTION__.10691
00000000 l    df *ABS*	00000000 gconv_cache.o
080784a0 l     F .text	000000f2 find_module_idx
080db974 l     O .bss	00000004 gconv_cache
080db970 l     O .bss	00000004 cache_size
080785a0 l     F .text	000000fd find_module
080ab9e0 l     F __libc_freeres_fn	00000051 free_mem
080db96c l     O .bss	00000004 cache_malloced
080daf90 l     O __libc_subfreeres	00000004 __elf_set___libc_subfreeres_element_free_mem__
00000000 l    df *ABS*	00000000 gconv_dl.o
08078e00 l     F .text	00000025 known_compare
080aba40 l     F __libc_freeres_fn	00000036 do_release_all
080aba80 l     F __libc_freeres_fn	00000030 free_mem
080db97c l     O .bss	00000004 loaded
08078e30 l     F .text	0000009f do_release_shlib
080db978 l     O .bss	00000004 release_handle
080b01a4 l     O .rodata	00000011 __PRETTY_FUNCTION__.8833
080b01b8 l     O .rodata	00000013 __PRETTY_FUNCTION__.8825
080daf94 l     O __libc_subfreeres	00000004 __elf_set___libc_subfreeres_element_free_mem__
00000000 l    df *ABS*	00000000 gconv_charset.o
080790f0 l     F .text	00000193 gconv_parse_code
00000000 l    df *ABS*	00000000 setlocale.o
08079610 l     F .text	00000204 new_composite_name
080abab0 l     F __libc_freeres_fn	000000bd free_category
080d9ec0 l     O .data.rel.ro	00000034 _nl_current_used
080d9e80 l     O .data.rel.ro	00000034 _nl_category_postload
00000000 l    df *ABS*	00000000 findlocale.o
080b02dc l     O .rodata	00000004 slashdot.9318
080b0300 l     O .rodata	00000034 codeset_idx.9343
080b02e0 l     O .rodata	00000010 __PRETTY_FUNCTION__.9348
00000000 l    df *ABS*	00000000 loadlocale.o
080b09a0 l     O .rodata	00000034 _nl_category_num_items
080d8740 l     O .data.rel.ro	00000034 _nl_value_types
080b09d4 l     O .rodata	00000017 __PRETTY_FUNCTION__.8759
080b07e0 l     O .rodata	00000158 _nl_value_type_LC_CTYPE
080b06fc l     O .rodata	00000018 _nl_value_type_LC_NUMERIC
080b0480 l     O .rodata	0000027c _nl_value_type_LC_TIME
080b0940 l     O .rodata	0000004c _nl_value_type_LC_COLLATE
080b0720 l     O .rodata	000000b8 _nl_value_type_LC_MONETARY
080b045c l     O .rodata	00000014 _nl_value_type_LC_MESSAGES
080b0450 l     O .rodata	0000000c _nl_value_type_LC_PAPER
080b0434 l     O .rodata	0000001c _nl_value_type_LC_NAME
080b0400 l     O .rodata	00000034 _nl_value_type_LC_ADDRESS
080b045c l     O .rodata	00000014 _nl_value_type_LC_TELEPHONE
080b03e0 l     O .rodata	00000008 _nl_value_type_LC_MEASUREMENT
080b03a0 l     O .rodata	00000040 _nl_value_type_LC_IDENTIFICATION
0807a9b0 l       .text	00000000 .L8
0807a9a0 l       .text	00000000 .L9
0807a8e8 l       .text	00000000 .L11
0807a990 l       .text	00000000 .L12
0807a980 l       .text	00000000 .L13
0807a8b8 l       .text	00000000 .L14
0807a960 l       .text	00000000 .L15
0807a950 l       .text	00000000 .L16
0807a940 l       .text	00000000 .L17
0807a930 l       .text	00000000 .L18
0807a970 l       .text	00000000 .L19
00000000 l    df *ABS*	00000000 loadarchive.o
0807ae00 l     F .text	0000000d rangecmp
080db9a0 l     O .bss	00000004 archloaded
080dba30 l     O .bss	00000004 archmapped
080dba20 l     O .bss	00000010 headmap
080db9c0 l     O .bss	00000060 archive_stat
080b0a84 l     O .rodata	0000001f archfname
080b0a64 l     O .rodata	0000001d __PRETTY_FUNCTION__.8835
080b0a4c l     O .rodata	00000017 __PRETTY_FUNCTION__.8875
00000000 l    df *ABS*	00000000 C-ctype.o
080baf20 l     O .rodata	00001524 translit_from_idx
080b84c0 l     O .rodata	00002a48 translit_from_tbl
080b6f80 l     O .rodata	00001524 translit_to_idx
080b2480 l     O .rodata	00004af4 translit_to_tbl
00000000 l    df *ABS*	00000000 sigaction.o
0807bc50 l       .text	00000000 __restore_rt
0807bc58 l       .text	00000000 __restore
00000000 l    df *ABS*	00000000 setenv.o
080dba3c l     O .bss	00000004 envlock
080dba34 l     O .bss	00000004 last_environ
080dba38 l     O .bss	00000004 known_values
080abe90 l     F __libc_freeres_fn	00000037 free_mem
080daf98 l     O __libc_subfreeres	00000004 __elf_set___libc_subfreeres_element_free_mem__
00000000 l    df *ABS*	00000000 vfprintf.o
0807d370 l     F .text	0000005f read_int
0807d3d0 l     F .text	00000145 group_number
0807d520 l     F .text	00000285 _i18n_number_rewrite
0807d7b0 l     F .text	000000d7 _IO_helper_overflow
0807d890 l     F .text	0000272b printf_positional
080bc980 l     O .rodata	0000005b jump_table
080d8900 l     O .data.rel.ro	00000078 step4_jumps.12073
080bc93c l     O .rodata	00000012 __PRETTY_FUNCTION__.12069
080bc968 l     O .rodata	00000007 null
08082960 l     F .text	00000207 buffered_vfprintf
080d8c00 l     O .data.rel.ro	00000078 step0_jumps.11858
080d8a00 l     O .data.rel.ro	00000078 step4_jumps.11894
080d8a80 l     O .data.rel.ro	00000078 step3a_jumps.11891
080d8980 l     O .data.rel.ro	00000078 step3b_jumps.11893
080d8b80 l     O .data.rel.ro	00000078 step1_jumps.11889
080d8b00 l     O .data.rel.ro	00000078 step2_jumps.11890
080bc950 l     O .rodata	00000016 __PRETTY_FUNCTION__.11854
080db260 l     O __libc_IO_vtables	00000054 _IO_helper_jumps
00000000 l    df *ABS*	00000000 printf_fp.o
08082b70 l     F .text	00000110 hack_digit
08082c80 l     F .text	00000285 _i18n_number_rewrite
08082f10 l     F .text	00000046 __guess_grouping.part.0
00000000 l    df *ABS*	00000000 reg-printf.o
080dba40 l     O .bss	00000004 lock
00000000 l    df *ABS*	00000000 printf_fphex.o
080bcab8 l     O .rodata	0000000f __PRETTY_FUNCTION__.13612
00000000 l    df *ABS*	00000000 reg-modifier.o
080abed0 l     F __libc_freeres_fn	00000065 free_mem
080dba44 l     O .bss	00000004 next_bit
080dba48 l     O .bss	00000004 lock
080daf9c l     O __libc_subfreeres	00000004 __elf_set___libc_subfreeres_element_free_mem__
00000000 l    df *ABS*	00000000 reg-type.o
080dba4c l     O .bss	00000004 lock
080daf18 l     O .data	00000004 pa_next_type
00000000 l    df *ABS*	00000000 vfwprintf.o
08087960 l     F .text	00000096 read_int
08087a00 l     F .text	00000109 group_number
08087b10 l     F .text	00000137 _i18n_number_rewrite
08087c50 l     F .text	000000f7 _IO_helper_overflow
08087d50 l     F .text	00002835 printf_positional
080bcb20 l     O .rodata	0000005b jump_table
080d8c80 l     O .data.rel.ro	00000078 step4_jumps.12097
080bc93c l     O .rodata	00000012 __PRETTY_FUNCTION__.12093
080bcae0 l     O .rodata	0000001c null
0808cf40 l     F .text	0000021e buffered_vfprintf
080d8f80 l     O .data.rel.ro	00000078 step0_jumps.11884
080d8d80 l     O .data.rel.ro	00000078 step4_jumps.11920
080d8d00 l     O .data.rel.ro	00000078 step3b_jumps.11919
080d8e00 l     O .data.rel.ro	00000078 step3a_jumps.11917
080d8e80 l     O .data.rel.ro	00000078 step2_jumps.11916
080d8f00 l     O .data.rel.ro	00000078 step1_jumps.11915
080bcafc l     O .rodata	0000000e __PRETTY_FUNCTION__.11880
080db2c0 l     O __libc_IO_vtables	00000054 _IO_helper_jumps
00000000 l    df *ABS*	00000000 printf-parsemb.o
0808d190 l     F .text	0000005f read_int
0808d26f l       .text	00000000 .L16
0808d5e8 l       .text	00000000 .L78
0808d5f8 l       .text	00000000 .L55
0808d350 l       .text	00000000 .L17
0808d340 l       .text	00000000 .L19
0808d330 l       .text	00000000 .L20
0808d320 l       .text	00000000 .L21
0808d310 l       .text	00000000 .L22
0808d300 l       .text	00000000 .L23
0808d258 l       .text	00000000 .L24
0808d499 l       .text	00000000 .L45
0808d360 l       .text	00000000 .L47
0808d4a8 l       .text	00000000 .L48
0808d4c0 l       .text	00000000 .L49
0808d488 l       .text	00000000 .L50
0808d588 l       .text	00000000 .L56
0808d5a0 l       .text	00000000 .L58
0808d578 l       .text	00000000 .L59
0808d540 l       .text	00000000 .L60
0808d530 l       .text	00000000 .L61
0808d520 l       .text	00000000 .L62
0808d500 l       .text	00000000 .L63
0808d4d0 l       .text	00000000 .L64
00000000 l    df *ABS*	00000000 printf-parsewc.o
0808d7c0 l     F .text	00000096 read_int
0808d950 l       .text	00000000 .L23
0808d9f8 l       .text	00000000 .L54
0808dca0 l       .text	00000000 .L65
0808d940 l       .text	00000000 .L24
0808d930 l       .text	00000000 .L26
0808d920 l       .text	00000000 .L27
0808d910 l       .text	00000000 .L28
0808d900 l       .text	00000000 .L29
0808d8f0 l       .text	00000000 .L30
0808d8d0 l       .text	00000000 .L31
0808db43 l       .text	00000000 .L55
0808da40 l       .text	00000000 .L57
0808d9e0 l       .text	00000000 .L58
0808db58 l       .text	00000000 .L59
0808db30 l       .text	00000000 .L60
0808db70 l       .text	00000000 .L66
0808dc48 l       .text	00000000 .L68
0808dc70 l       .text	00000000 .L69
0808dbb0 l       .text	00000000 .L70
0808dbd0 l       .text	00000000 .L71
0808dc00 l       .text	00000000 .L72
0808dc28 l       .text	00000000 .L73
0808dc38 l       .text	00000000 .L74
00000000 l    df *ABS*	00000000 iopadn.o
080bdc64 l     O .rodata	00000010 blanks
080bdc54 l     O .rodata	00000010 zeroes
00000000 l    df *ABS*	00000000 iowpadn.o
080bdcc0 l     O .rodata	00000040 blanks
080bdc80 l     O .rodata	00000040 zeroes
00000000 l    df *ABS*	00000000 wgenops.o
0808eab0 l     F .text	00000224 save_for_wbackup.isra.0
00000000 l    df *ABS*	00000000 iofwide.o
0808f9a0 l     F .text	00000026 do_encoding
0808f9d0 l     F .text	00000003 do_always_noconv
0808f9e0 l     F .text	0000000b do_max_length
0808f9f0 l     F .text	000000ed do_in
0808fae0 l     F .text	000000cd do_unshift
0808fbb0 l     F .text	000000ed do_out
0808fca0 l     F .text	000000b1 do_length
080bdd0c l     O .rodata	0000000a __PRETTY_FUNCTION__.12152
00000000 l    df *ABS*	00000000 strnlen.o
08090120 l     F .text	00000027 __strnlen_ifunc
00000000 l    df *ABS*	00000000 strrchr.o
08090150 l     F .text	00000032 strrchr_ifunc
00000000 l    df *ABS*	00000000 memchr.o
08090210 l     F .text	00000032 __memchr_ifunc
00000000 l    df *ABS*	00000000 memmem.o
08090250 l     F .text	0000044d two_way_long_needle
00000000 l    df *ABS*	00000000 wcslen.o
08092720 l     F .text	00000027 __wcslen_ifunc
00000000 l    df *ABS*	00000000 wcrtomb.o
080dba50 l     O .bss	00000008 state
080bdd44 l     O .rodata	0000000a __PRETTY_FUNCTION__.9328
00000000 l    df *ABS*	00000000 wcsrtombs.o
080dba58 l     O .bss	00000008 state
080bdd9c l     O .rodata	0000000c __PRETTY_FUNCTION__.9334
00000000 l    df *ABS*	00000000 opendir.o
080932d0 l     F .text	00000099 opendir_tail
00000000 l    df *ABS*	00000000 dl-load.o
08094020 l     F .text	000000a3 is_dst
080940d0 l     F .text	0000017e is_trusted_path_normalize
080be54c l     O .rodata	00000010 system_dirs_len
080be560 l     O .rodata	00000024 system_dirs
08094250 l     F .text	000000eb add_name_to_object.isra.5
080be4c0 l     O .rodata	00000013 __PRETTY_FUNCTION__.9817
08094340 l     F .text	00000081 lose.isra.6
080943d0 l     F .text	000005de open_verify.constprop.8
080be53c l     O .rodata	00000010 expected.9999
080be530 l     O .rodata	00000009 expected2.9998
080be520 l     O .rodata	00000010 expected_note.10005
080949b0 l     F .text	000005fd open_path
080d9fbc l     O .data.rel.ro	00000004 max_capstrlen
080dba64 l     O .bss	00000004 max_dirnamelen
080d9fc0 l     O .data.rel.ro	00000004 ncapstr
080d9fc4 l     O .data.rel.ro	00000004 capstr
080d9fc8 l     O .data.rel.ro	00000008 env_path_list
080d9fb4 l     O .data.rel.ro	00000008 rtld_search_dirs
08094fb0 l     F .text	00000f80 _dl_map_object_from_fd.constprop.9
080af354 l     O .rodata	00000015 __PRETTY_FUNCTION__.9665
080be4a8 l     O .rodata	00000017 __PRETTY_FUNCTION__.9950
08095f30 l     F .text	000000b1 add_path.isra.4.constprop.10
08096240 l     F .text	000000f6 expand_dynamic_string_token
080be4e4 l     O .rodata	0000001c __PRETTY_FUNCTION__.9804
08096340 l     F .text	000002e9 fillin_rpath
08096630 l     F .text	00000218 cache_rpath.part.7
080be500 l     O .rodata	0000000f __PRETTY_FUNCTION__.9896
080be584 l     O .rodata	00000004 dummy_bucket.10101
080be4d4 l     O .rodata	0000000f __PRETTY_FUNCTION__.10083
00000000 l    df *ABS*	00000000 dl-lookup.o
08097670 l     F .text	00000184 check_match
080be7e4 l     O .rodata	0000000c __PRETTY_FUNCTION__.9916
08097800 l     F .text	00000aa6 do_lookup_x
080be7f0 l     O .rodata	00000014 __PRETTY_FUNCTION__.10117
080be7d4 l     O .rodata	0000000f __PRETTY_FUNCTION__.10145
00000000 l    df *ABS*	00000000 dl-reloc.o
080bef80 l     O .rodata	0000003b errstring.9813
080bef40 l     O .rodata	00000040 msg.9819
080be96c l     O .rodata	00000019 __PRETTY_FUNCTION__.9660
08099a00 l       .text	00000000 .L89
0809b10f l       .text	00000000 .L110
0809b0fe l       .text	00000000 .L254
08099cb0 l       .text	00000000 .L419
0809a930 l       .text	00000000 .L138
0809a9b0 l       .text	00000000 .L420
08099d30 l       .text	00000000 .L353
08099d00 l       .text	00000000 .L354
08099cd8 l       .text	00000000 .L355
08099c90 l       .text	00000000 .L123
08099c60 l       .text	00000000 .L122
08099d61 l       .text	00000000 .L218
08099ef0 l       .text	00000000 .L220
08099ea8 l       .text	00000000 .L221
08099e70 l       .text	00000000 .L222
08099e50 l       .text	00000000 .L223
08099e30 l       .text	00000000 .L224
08099e00 l       .text	00000000 .L225
08099d58 l       .text	00000000 .L226
08099dc0 l       .text	00000000 .L227
08099da8 l       .text	00000000 .L228
08099d37 l       .text	00000000 .L111
08099d07 l       .text	00000000 .L113
080999c8 l       .text	00000000 .L132
08099cdf l       .text	00000000 .L115
0809a020 l       .text	00000000 .L130
08099ff0 l       .text	00000000 .L117
0809a060 l       .text	00000000 .L124
08099fb0 l       .text	00000000 .L128
08099f60 l       .text	00000000 .L125
080999bc l       .text	00000000 .L114
0809a018 l       .text	00000000 .L116
0809a059 l       .text	00000000 .L118
08099fa8 l       .text	00000000 .L119
08099c83 l       .text	00000000 .L120
08099f5a l       .text	00000000 .L121
0809a521 l       .text	00000000 .L255
0809a670 l       .text	00000000 .L257
0809a630 l       .text	00000000 .L258
0809a5f8 l       .text	00000000 .L259
0809a5d8 l       .text	00000000 .L260
0809a5b8 l       .text	00000000 .L261
0809a588 l       .text	00000000 .L262
0809a518 l       .text	00000000 .L263
0809a548 l       .text	00000000 .L264
0809a688 l       .text	00000000 .L265
0809a9ea l       .text	00000000 .L356
0809a9c3 l       .text	00000000 .L357
0809a989 l       .text	00000000 .L358
0809a970 l       .text	00000000 .L171
0809a948 l       .text	00000000 .L170
0809a9f1 l       .text	00000000 .L159
0809a9ca l       .text	00000000 .L161
0809a8f8 l       .text	00000000 .L180
0809a990 l       .text	00000000 .L163
0809ab38 l       .text	00000000 .L178
0809aa50 l       .text	00000000 .L165
0809ab10 l       .text	00000000 .L172
0809aad0 l       .text	00000000 .L176
0809aa80 l       .text	00000000 .L173
0809a8ed l       .text	00000000 .L162
0809ab31 l       .text	00000000 .L164
0809ab08 l       .text	00000000 .L166
0809aac7 l       .text	00000000 .L167
0809a967 l       .text	00000000 .L168
0809aa77 l       .text	00000000 .L169
00000000 l    df *ABS*	00000000 dl-hwcaps.o
080bf00c l     O .rodata	00000015 __PRETTY_FUNCTION__.9539
00000000 l    df *ABS*	00000000 dl-misc.o
0809bf00 l     F .text	00000453 _dl_debug_vdprintf
080bf078 l     O .rodata	00000013 __PRETTY_FUNCTION__.9354
080bf0a0 l     O .rodata	00000078 primes.9404
00000000 l    df *ABS*	00000000 dl-profile.o
080dba8c l     O .bss	00000004 running
080dba68 l     O .bss	00000004 log_hashfraction
080dba70 l     O .bss	00000004 lowpc
080dba6c l     O .bss	00000004 textsize
080dba78 l     O .bss	00000004 fromlimit
080dba84 l     O .bss	00000004 narcsp
080dba90 l     O .bss	00000004 data
080dba80 l     O .bss	00000004 tos
080dba74 l     O .bss	00000004 fromidx
080dba7c l     O .bss	00000004 froms
080dba88 l     O .bss	00000004 narcs
00000000 l    df *ABS*	00000000 dl-origin.o
080bf3fc l     O .rodata	0000000f __PRETTY_FUNCTION__.9107
00000000 l    df *ABS*	00000000 dl-exception.o
0809dde0 l     F .text	00000029 length_mismatch
080bf480 l     O .rodata	0000000e _dl_out_of_memory
00000000 l    df *ABS*	00000000 dl-cache.o
080dba9c l     O .bss	00000004 cache
080dba94 l     O .bss	00000004 cachesize
080dba98 l     O .bss	00000004 cache_new
00000000 l    df *ABS*	00000000 dl-libc.o
0809ea80 l     F .text	0000003d do_dlopen
0809eac0 l     F .text	0000008d dlerror_run
0809ed60 l     F .text	00000035 do_dlsym
0809eda0 l     F .text	00000037 do_dlvsym
0809ede0 l     F .text	00000005 do_dlclose
080abf40 l     F __libc_freeres_fn	00000084 free_slotinfo
0809ecd0 l     F .text	00000085 do_dlsym_private
080abfd0 l     F __libc_freeres_fn	00000127 free_mem
080daf1c l     O .data	00000010 _dl_open_hook
080dafa0 l     O __libc_subfreeres	00000004 __elf_set___libc_subfreeres_element_free_mem__
00000000 l    df *ABS*	00000000 dl-error.o
0809ef50 l     F .text	000000cb fatal_error
0000002c l       .tbss	00000004 catch_hook
00000000 l    df *ABS*	00000000 C-monetary.o
080bf559 l     O .rodata	00000002 not_available
080bf55c l     O .rodata	00000008 conversion_rate
00000000 l    df *ABS*	00000000 C-collate.o
080c0120 l     O .rodata	00000100 collseqmb
080bfd00 l     O .rodata	0000041c collseqwc
00000000 l    df *ABS*	00000000 sdlinfo.o
080a1260 l     F .text	00000111 dlinfo_doit
080a1347 l       .text	00000000 .L2
080a12b0 l       .text	00000000 .L3
080a12c0 l       .text	00000000 .L5
080a12d0 l       .text	00000000 .L6
080a12f0 l       .text	00000000 .L7
080a1310 l       .text	00000000 .L8
080a1330 l       .text	00000000 .L9
080a1290 l       .text	00000000 .L10
00000000 l    df *ABS*	00000000 sdlmopen.o
080a13f0 l     F .text	00000070 dlmopen_doit
00000000 l    df *ABS*	00000000 strspn.o
080a14f0 l     F .text	00000027 strspn_ifunc
00000000 l    df *ABS*	00000000 profil.o
080a1790 l     F .text	00000040 __profil_counter
080dbb60 l     O .bss	00000004 pc_offset
080dbb5c l     O .bss	00000004 pc_scale
080dbb64 l     O .bss	00000004 nsamples
080dbb68 l     O .bss	00000004 samples
080dbb4c l     O .bss	00000010 otimer.7758
080dbac0 l     O .bss	0000008c oact.7757
00000000 l    df *ABS*	00000000 dl-runtime.o
080c3ae4 l     O .rodata	0000000a __PRETTY_FUNCTION__.10682
080c3ad0 l     O .rodata	00000012 __PRETTY_FUNCTION__.10733
00000000 l    df *ABS*	00000000 dl-open.o
080a1d70 l     F .text	0000027d add_to_global
080c3d24 l     O .rodata	00000018 __PRETTY_FUNCTION__.10551
080a2410 l     F .text	00000767 dl_open_worker
080c3d18 l     O .rodata	00000009 __PRETTY_FUNCTION__.10629
080c3d08 l     O .rodata	0000000f __PRETTY_FUNCTION__.10569
00000000 l    df *ABS*	00000000 dl-close.o
080a2b80 l     F .text	00000138 remove_slotinfo
080c3f90 l     O .rodata	00000010 __PRETTY_FUNCTION__.10502
080dbb6c l     O .bss	00000004 dl_close_state.10515
080c3fa0 l     O .rodata	00000011 __PRETTY_FUNCTION__.10529
00000000 l    df *ABS*	00000000 tlsdesc.o
080a3e00 l     F .text	0000006e _dl_tlsdesc_resolve_early_return_p
00000000 l    df *ABS*	00000000 sdlopen.o
080a46c0 l     F .text	0000007d dlopen_doit
00000000 l    df *ABS*	00000000 sdlclose.o
080a47d0 l     F .text	00000005 dlclose_doit
00000000 l    df *ABS*	00000000 sdlsym.o
080a4810 l     F .text	0000002a dlsym_doit
00000000 l    df *ABS*	00000000 sdlvsym.o
080a48f0 l     F .text	0000002d dlvsym_doit
00000000 l    df *ABS*	00000000 dl-deps.o
080a4a00 l     F .text	0000005c _dl_build_local_scope
080a4a60 l     F .text	0000003c openaux
080c416c l     O .rodata	00000014 __PRETTY_FUNCTION__.9296
00000000 l    df *ABS*	00000000 dl-init.o
080a57d0 l     F .text	00000127 call_init.part.0
00000000 l    df *ABS*	00000000 dl-version.o
080c434c l     O .rodata	00000017 __PRETTY_FUNCTION__.8333
080c433c l     O .rodata	0000000d __PRETTY_FUNCTION__.8311
00000000 l    df *ABS*	00000000 dl-sym.o
080a61b0 l     F .text	0000002d call_dl_lookup
080a61e0 l     F .text	00000230 do_sym
00000000 l    df *ABS*	00000000 unwind-dw2.o
080a6bc0 l     F .text	00000150 read_encoded_value_with_base
080a6d10 l     F .text	0000005d base_of_encoded_value
080a6d70 l     F .text	00000862 execute_cfa_program
080a75e0 l     F .text	0000007b init_dwarf_reg_size_table
080dbb74 l     O .bss	00000012 dwarf_reg_size_table
080a7660 l     F .text	0000057a uw_frame_state_for
080a7be0 l     F .text	000006cb execute_stack_op
080a82b0 l     F .text	0000039e uw_update_context_1
080a8650 l     F .text	0000015a uw_init_context_1
080dbb70 l     O .bss	00000004 once_regsizes.9388
080a87b0 l     F .text	00000068 uw_update_context
080a8820 l     F .text	0000009d _Unwind_RaiseException_Phase2
080a88c0 l     F .text	000000c3 _Unwind_ForcedUnwind_Phase2
080a8990 l     F .text	000001a5 uw_install_context_1
080a8db0 l     F .text	00000001 _Unwind_DebugHook
080a6d0b l       .text	00000000 .L4
080a75b1 l       .text	00000000 .L58
080a6eb0 l       .text	00000000 .L131
080a7d2b l       .text	00000000 .L266
080a83c8 l       .text	00000000 .L414
080a6c00 l       .text	00000000 .L13
080a6cc8 l       .text	00000000 .L18
080a6d00 l       .text	00000000 .L8
080a6c50 l       .text	00000000 .L14
080a6c70 l       .text	00000000 .L19
080a6c60 l       .text	00000000 .L12
080a6ef0 l       .text	00000000 .L60
080a6f30 l       .text	00000000 .L61
080a6f50 l       .text	00000000 .L62
080a6f70 l       .text	00000000 .L63
080a6f90 l       .text	00000000 .L106
080a6ff8 l       .text	00000000 .L107
080a7038 l       .text	00000000 .L108
080a7078 l       .text	00000000 .L109
080a70a0 l       .text	00000000 .L110
080a7100 l       .text	00000000 .L69
080a7138 l       .text	00000000 .L70
080a7160 l       .text	00000000 .L111
080a71c8 l       .text	00000000 .L112
080a7208 l       .text	00000000 .L113
080a7240 l       .text	00000000 .L74
080a7280 l       .text	00000000 .L114
080a72e0 l       .text	00000000 .L115
080a7348 l       .text	00000000 .L116
080a73c8 l       .text	00000000 .L117
080a7418 l       .text	00000000 .L118
080a7550 l       .text	00000000 .L119
080a7480 l       .text	00000000 .L120
080a6ec0 l       .text	00000000 .L122
080a74e0 l       .text	00000000 .L121
080a7c50 l       .text	00000000 .L275
080a7cf0 l       .text	00000000 .L269
080a7ce0 l       .text	00000000 .L270
080a7cd0 l       .text	00000000 .L271
080a7cc0 l       .text	00000000 .L272
080a7cb0 l       .text	00000000 .L273
080a7c98 l       .text	00000000 .L277
080a7f60 l       .text	00000000 .L340
080a7f18 l       .text	00000000 .L341
080a8050 l       .text	00000000 .L280
080a8018 l       .text	00000000 .L281
080a8038 l       .text	00000000 .L282
080a7e88 l       .text	00000000 .L283
080a80c8 l       .text	00000000 .L284
080a8090 l       .text	00000000 .L285
080a7ee0 l       .text	00000000 .L286
080a7eb0 l       .text	00000000 .L287
080a8080 l       .text	00000000 .L288
080a8070 l       .text	00000000 .L289
080a7e40 l       .text	00000000 .L290
080a7dc8 l       .text	00000000 .L342
080a7d70 l       .text	00000000 .L343
080a7f90 l       .text	00000000 .L344
080a7ca8 l       .text	00000000 .L345
080a7d38 l       .text	00000000 .L295
080a81c0 l       .text	00000000 .L320
080a81c9 l       .text	00000000 .L322
080a81d7 l       .text	00000000 .L323
080a81e0 l       .text	00000000 .L324
080a81ef l       .text	00000000 .L325
080a81f9 l       .text	00000000 .L326
080a8202 l       .text	00000000 .L327
080a820b l       .text	00000000 .L328
080a8214 l       .text	00000000 .L329
080a821d l       .text	00000000 .L330
080a8226 l       .text	00000000 .L331
080a822f l       .text	00000000 .L332
080a823f l       .text	00000000 .L333
080a824f l       .text	00000000 .L334
080a825f l       .text	00000000 .L335
080a826f l       .text	00000000 .L336
080a827f l       .text	00000000 .L337
080a8500 l       .text	00000000 .L415
080a84c8 l       .text	00000000 .L417
080a8408 l       .text	00000000 .L418
080a83a0 l       .text	00000000 .L419
080a8460 l       .text	00000000 .L420
00000000 l    df *ABS*	00000000 unwind-dw2-fde-dip.o
080a91b0 l     F .text	00000019 fde_unencoded_compare
080a91d0 l     F .text	000000b7 frame_downheap
080a9290 l     F .text	0000008f frame_heapsort
080a9320 l     F .text	00000150 read_encoded_value_with_base
080a9470 l     F .text	00000110 get_cie_encoding
080a9580 l     F .text	0000004f size_of_encoded_value.part.3
080a95d0 l     F .text	00000059 base_from_object.part.4
080a9630 l     F .text	00000078 fde_single_encoding_compare
080a96b0 l     F .text	000001d5 linear_search_fdes
080a9890 l     F .text	00000096 fde_mixed_encoding_compare
080a9930 l     F .text	0000017e classify_object_over_fdes
080a9ab0 l     F .text	000001ad add_fdes
080a9c60 l     F .text	00000748 search_object
080dbba4 l     O .bss	00000008 terminator.9151
080dbba0 l     O .bss	00000004 marker.9045
080aa3b0 l     F .text	00000059 base_from_cb_data.part.5
080aa410 l     F .text	00000553 _Unwind_IteratePhdrCallback
080dbbb8 l     O .bss	00000004 frame_hdr_cache_head
080daf78 l     O .data	00000008 adds.9307
080dbbb0 l     O .bss	00000008 subs.9308
080dbbc0 l     O .bss	000000c0 frame_hdr_cache
080aa970 l     F .text	000000a5 __register_frame_info_bases.part.6
080dbc80 l     O .bss	00000018 object_mutex
080dbc98 l     O .bss	00000004 any_objects_registered
080dbca0 l     O .bss	00000004 unseen_objects
080dbc9c l     O .bss	00000004 seen_objects
080a946b l       .text	00000000 .L28
080a9360 l       .text	00000000 .L37
080a9428 l       .text	00000000 .L42
080a9460 l       .text	00000000 .L32
080a93b0 l       .text	00000000 .L38
080a93d0 l       .text	00000000 .L43
080a93c0 l       .text	00000000 .L36
00000000 l    df *ABS*	00000000 unwind-c.o
080aaf80 l     F .text	0000007e base_of_encoded_value
080ab000 l     F .text	00000150 read_encoded_value_with_base
080ab14b l       .text	00000000 .L25
080ab040 l       .text	00000000 .L34
080ab108 l       .text	00000000 .L39
080ab140 l       .text	00000000 .L29
080ab090 l       .text	00000000 .L35
080ab0b0 l       .text	00000000 .L40
080ab0a0 l       .text	00000000 .L33
00000000 l    df *ABS*	00000000 crtstuff.c
080d6760 l     O .eh_frame	00000000 __FRAME_END__
00000000 l    df *ABS*	00000000 
08048000 l       .note.ABI-tag	00000000 __ehdr_start
080d8700 l       .fini_array	00000000 __fini_array_end
08048138 l       .rel.plt	00000000 __rel_iplt_start
080481a8 l       .rel.plt	00000000 __rel_iplt_end
080d86f8 l       .fini_array	00000000 __fini_array_start
080d86f8 l       .init_array	00000000 __init_array_end
080d86f0 l       .tbss	00000000 __preinit_array_end
080da000 l     O .got.plt	00000000 _GLOBAL_OFFSET_TABLE_
080d86f0 l       .init_array	00000000 __init_array_start
080d86f0 l       .tbss	00000000 __preinit_array_start
08054e5a g     F .text	00000000 .hidden __x86.get_pc_thunk.cx
080d8780 g     O .data.rel.ro	0000017c .hidden _nl_C_LC_CTYPE
0806e2c0 g     F .text	0000001b .hidden __stack_chk_fail_local
080a6b40 g     F .text	00000076 .hidden __sfp_handle_exceptions
0805e680  w  i   .text	00000038 stpcpy
080b0ee0 g     O .rodata	0000004c .hidden _nl_C_LC_CTYPE_class_print
0806d1d0  w    F .text	00000152 tsearch
080dbf08 g     O .bss	00000004 .hidden __x86_shared_non_temporal_threshold
080da97c g     O .data	00000004 __morecore
0806cdb0 g     F .text	0000004d .hidden __getdtablesize
08056ba0 g     F .text	00000038 _IO_remove_marker
0807c950  w    F .text	00000037 secure_getenv
0806aa40 g     F .text	0000008b .hidden __stpcpy_ia32
0807bc60 g     F .text	0000015c __libc_sigaction
0805db20 g   i   .text	00000038 strcpy
0808f620 g     F .text	000000b8 _IO_wdefault_xsgetn
080a6410 g     F .text	000000bd _dl_vsym
08098e90 g     F .text	000000b5 .hidden _dl_setup_hash
08055380 g     F .text	000001eb _IO_link_in
080aad50 g     F .text	0000022f .hidden _Unwind_Find_FDE
0807c790  w    F .text	00000114 unsetenv
080da508  w    O .data	00000004 __malloc_hook
0809c3f0 g     F .text	0000002f .hidden _dl_debug_printf
0807bb60  w    F .text	000000ee gsignal
08056250 g     F .text	0000007f _IO_sputbackc
080b1120 g     O .rodata	00000048 .hidden _nl_C_LC_CTYPE_class_upper
080561a0 g     F .text	00000094 _IO_default_finish
0806a810 g     F .text	00000087 .hidden __strcpy_ia32
080a3f00 g     F .text	0000013b .hidden _dl_tlsdesc_resolve_rel_fixup
0805e600  w  i   .text	00000036 bcmp
080a5a60 g     F .text	000006e8 .hidden _dl_check_map_versions
080a8c20 g     F .text	00000014 .hidden _Unwind_GetIPInfo
08075300 g     F .text	00000ee2 __gconv_transform_utf8_internal
0805da70 g     F .text	00000028 __default_morecore
080dbf94 g     O .bss	00000004 .hidden __libc_argc
0809f2e0 g     F .text	00000031 .hidden __longjmp
08054aa0  w    F .text	000000a7 _IO_file_finish
080b0b20 g     O .rodata	0000005c .hidden _nl_C_LC_CTYPE_width
0804fb80 g     F .text	000000bd .hidden __fxprintf_nocancel
0806cca0  w    F .text	00000026 getrlimit
0804f8e0 g     F .text	0000002d __printf
080ab680 g     F __libc_freeres_fn	00000112 .hidden _nl_unload_domain
080a1380 g     F .text	0000006e .hidden __dlinfo
080a8c10 g     F .text	00000008 .hidden _Unwind_GetIP
08090190  w    F .text	0000007e strtok_r
0809fbb0 g     F .text	00000108 .hidden __mpn_impn_mul_n_basecase
0808f1f0 g     F .text	0000005a _IO_wdoallocbuf
08093840  w    F .text	0000000d getgid
080a1780 g     F .text	0000000d __getpid
08050110 g     F .text	0000011a _IO_fread
08087500 g     F .text	0000017b __register_printf_modifier
08056ee0 g     F .text	00000050 _IO_list_lock
0806ba60  w    F .text	000003d0 sysconf
0804f8e0 g     F .text	0000002d printf
080da498 g     O .data	00000004 stdout
08092360 g     F .text	00000058 __strcasecmp_ia32
0804b0b0 g     F .text	000015aa .hidden _nl_load_domain
08055f00 g     F .text	0000007c _IO_default_doallocate
080dad10 g     O .data	00000004 .hidden __libc_multiple_libcs
080496a9 g     F .text	00000000 .hidden __x86.get_pc_thunk.si
0806cca0 g     F .text	00000026 __new_getrlimit
0806cdb0  w    F .text	0000004d getdtablesize
08093740  w    F .text	000000be fdopendir
0809b720 g     F .text	000007da .hidden _dl_important_hwcaps
08060900 g     F .text	0000028b .hidden __strcmp_sse4_2
0806beb0 g     F .text	00000026 ___xstat64
08053f90 g     F .text	000001e2 _IO_new_file_xsputn
08099510 g     F .text	00000061 .hidden _dl_reloc_bad_type
08091840 g     F .text	00000354 .hidden __memchr_sse2_bsf
0808ece0 g     F .text	00000030 _IO_least_wmarker
08056190 g     F .text	00000003 _IO_default_sync
080aaa80 g     F .text	00000042 .hidden __register_frame
08054d60  w    F .text	000000fa _IO_file_sync
080a0070 g     F .text	0000011b .hidden __mpn_impn_sqr_n_basecase
0808f8e0 g     F .text	00000087 _IO_seekwmark
0804fe70 g     F .text	00000123 _IO_fflush
080a0780 g     F .text	00000117 .hidden __mpn_extract_long_double
08091ba0 g     F .text	000006eb .hidden __strnlen_sse2
080db080 g     O __libc_IO_vtables	00000054 _IO_wfile_jumps
080b0fa0 g     O .rodata	0000004c .hidden _nl_C_LC_CTYPE_class_xdigit
080538b0  w    F .text	000000a4 _IO_file_write
080a1ff0 g     F .text	0000009c _dl_find_dso_for_object
0805dbe0 g     F .text	00000099 strerror
08066b40 g     F .text	000003d4 .hidden __strchr_sse2
0806e020 g     F .text	00000044 .hidden __init_misc
08073c10 g     F .text	0000034c __gconv_transform_ascii_internal
080a0590 g     F .text	00000098 .hidden __mpn_sub_n
0806b4a0 g     F .text	00000083 .hidden __wcsmbs_clone_conv
08093830  w    F .text	0000000d geteuid
080900d0  w    F .text	00000049 strndup
080935b0 g     F .text	000000b3 .hidden __getdents
080dbf20 g     O .bss	00000004 _dl_profile_output
0809f320 g     F .text	00000045 .hidden __mpn_cmp
080909f0  w    F .text	000000bf argz_add_sep
080a4680 g     F .text	0000003c .hidden __mpn_addmul_1
08090120 g   i   .text	00000027 __strnlen
080709f0 g     F .text	000001ed .hidden __gconv
0806a560 g     F .text	00000058 memmove
080761f0 g     F .text	00000624 __gconv_transform_ucs2_internal
080dbff8 g     O .bss	00000004 .hidden __printf_modifier_table
08093c20 g     F .text	000000d7 __tcgetattr
08099000 g     F .text	0000032b .hidden _dl_new_object
080da980 g     O .data	00000004 .hidden __x86_raw_shared_cache_size
080a9040 g     F .text	000000c6 .hidden _Unwind_Resume_or_Rethrow
0805ce00 g     F .text	00000381 __calloc
0809dc70 g     F .text	0000007b _dl_make_stack_executable
08055cd0 g     F .text	000000a9 _IO_default_xsgetn
080910e0 g     F .text	000001e6 .hidden __strrchr_sse2_bsf
08090190 g     F .text	0000007e __strtok_r
0809de10 g     F .text	000000d4 _dl_exception_create
0806cef0  w    F .text	00000024 munmap
0804cd93 g     F .text	00000000 .hidden __x86.get_pc_thunk.di
080d9da8 g     O .data.rel.ro	00000004 __libc_stack_end
08055f80 g     F .text	00000040 _IO_enable_locks
080b02f0 g     O .rodata	00000010 .hidden _nl_default_locale_path
08072210 g     F .text	00000384 .hidden __gconv_get_path
08085910 g     F .text	000000d4 __register_printf_specifier
080da9ec g     O .data	00000004 _dl_debug_fd
080d96e0 g     O .data.rel.ro	00000040 .hidden _nl_C_LC_NAME
0806d1d0 g     F .text	00000152 __tsearch
08051ea0 g     F .text	000001cf _IO_vasprintf
0807ca00 g     F .text	00000525 ____strtol_l_internal
08053d30 g     F .text	0000017d _IO_file_seekoff_mmap
0806c2b0 g     F .text	000000ab .hidden __libc_fcntl
0804d6e0 g     F .text	0000006c .hidden __gettext_free_exp
080da99c g     O .data	00000004 .hidden __x86_data_cache_size_half
0809e2a0 g     F .text	000006f1 .hidden _dl_load_cache_lookup
080da984 g     O .data	00000004 .hidden __x86_raw_shared_cache_size_half
00000002 g       *ABS*	00000000 _nl_current_LC_NUMERIC_used
0806c100  w    F .text	00000091 __write
0804e0e0 g     F .text	0000010e .hidden __gettext_extract_plural
0805d620  w    F .text	000001e7 malloc_stats
08055c70 g     F .text	0000005f _IO_sgetn
0806ce00 g     F .text	0000004e __mmap
0806cf20 g     F .text	00000026 __mprotect
080daa04 g     O .data	00000004 _dl_use_load_bias
080da990 g     O .data	00000004 .hidden __x86_raw_data_cache_size
080dbef0 g     O .bss	00000004 _nl_domain_bindings
0809f0f0 g     F .text	000000fc _dl_catch_exception
080dbfa8 g     O .bss	00000004 .hidden __gconv_path_envvar
080a8c60 g     F .text	00000008 .hidden _Unwind_GetRegionStart
0807c380 g     F .text	00000393 .hidden __add_to_environ
080daa28 g     O .data	00000008 _dl_initial_searchlist
0804eb50 g     F .text	000000ec getenv
08052d40 g     F .text	00000010 _IO_file_seek
08092720  w  i   .text	00000027 wcslen
0808d860 g     F .text	00000608 .hidden __parse_one_specwc
0807cf50 g     F .text	000000eb .hidden _itoa_word
00000010 g       .tbss	00000004 errno
08093850  w    F .text	0000000d getegid
0806d950 g     F .text	0000001a __tdestroy
0805e700 g   i   .text	00000032 __rawmemchr
080a1b40 g     F .text	00000212 _dl_profile_fixup
0806c460 g     F .text	0000083e .hidden __getcwd
080a9130 g     F .text	00000072 .hidden _Unwind_Backtrace
0806b5b0 g     F .text	0000035c .hidden __mbsrtowcs_l
08056b40 g     F .text	00000060 _IO_init_marker
080906a0  w    F .text	00000254 memmem
0807c990 g     F .text	00000032 __strtol_internal
080912d0 g     F .text	00000564 .hidden __memchr_sse2
080b0210 g     O .rodata	0000000d .hidden _nl_category_name_idxs
080929d0  w    F .text	000001b8 c32rtomb
0806b110  w    F .text	00000029 wmempcpy
0808f080 g     F .text	00000077 __woverflow
080da1e0 g     O .data	00000098 _IO_2_1_stdout_
080859f0 g     F .text	00000005 __register_printf_function
080a04e0 g     F .text	000000ae __mpn_mul_n
080541c0 g     F .text	0000003b _IO_new_file_init
080a1780  w    F .text	0000000d getpid
0806cd70  w    F .text	0000003c getpagesize
080938e0 g     F .text	000000b6 __libc_openat
08078970 g     F .text	0000045e .hidden __gconv_lookup_cache
0809c4e0 g     F .text	00000074 .hidden _dl_higher_prime_number
08093a00 g     F .text	000000b6 __openat64
080b0dc0 g     O .rodata	0000004c .hidden _nl_C_LC_CTYPE_class_cntrl
0804eb30 g     F .text	0000001e qsort
0805d9b0 g     F .text	0000005f __posix_memalign
08056900 g     F .text	00000237 _IO_flush_all_linebuffered
0804fc40  w    F .text	0000022e _IO_fclose
080dbf9c g     O .bss	00000004 .hidden __gconv_modules_db
0804cbf0 g     F .text	000001a3 _nl_expand_alias
08051700 g     F .text	000001cb _IO_wdo_write
080ac240 g     O .rodata	00000004 _fp_hw
0808e340  w    F .text	000002f8 __getdelim
0806c030  w    F .text	00000091 __read
08092f20 g     F .text	0000001f __wcschrnul
0809c560 g     F .text	000001d2 .hidden _dl_strtoul
08055ad0 g     F .text	00000006 _IO_default_underflow
0808d160 g     F .text	0000002d _IO_funlockfile
080a5900 g     F .text	00000152 .hidden _dl_init
080786c0 g     F .text	00000204 .hidden __gconv_load_cache
0805d510 g     F .text	0000010f __mallinfo
08073750 g     F .text	000004b9 __gconv_transform_ucs4le_internal
080dbf24 g     O .bss	00000004 _dl_platformlen
080dbcc0 g     O .bss	00000004 _dl_tls_static_used
0808f2a0 g     F .text	00000068 _IO_switch_to_wget_mode
080da504  w    O .data	00000004 __realloc_hook
080a8ba0 g     F .text	00000008 .hidden _Unwind_GetCFA
080da070 g     O .data	00000004 .hidden __exit_funcs
0804d830 g     F .text	000008a6 .hidden __gettextparse
0806a4e0 g     F .text	00000065 memcpy
080a49d0  w    F .text	00000026 setitimer
08055b40 g     F .text	0000012a _IO_default_xsputn
0809f770 g     F .text	00000057 .hidden __mpn_lshift
080daf80 g     O __libc_subfreeres	00000000 .hidden __TMC_END__
0807aa10 g     F .text	00000356 .hidden _nl_load_locale
080858b0 g     F .text	0000002b ___printf_fp
0808e1b0 g     F .text	00000187 _IO_fwrite
08055d80 g     F .text	00000114 _IO_default_setbuf
080562d0 g     F .text	0000006f _IO_sungetc
08099330 g     F .text	000000cf .hidden _dl_try_allocate_static_tls
080a4840 g     F .text	000000a7 .hidden __dlsym
080786a0 g     F .text	00000011 __gconv_get_cache
080a4570 g     F .text	00000056 .hidden _dl_addr_inside_object
0808fd60 g     F .text	000001b7 _IO_fwide
08078ed0 g     F .text	000001e9 .hidden __gconv_find_shlib
0807ad70 g     F .text	00000083 .hidden _nl_unload_locale
080543f0 g     F .text	0000019a _IO_new_file_close_it
080dbf28 g     O .bss	00000004 _dl_debug_mask
080518d0 g     F .text	000002b1 _IO_wfile_overflow
0805cd20 g     F .text	00000010 __libc_memalign
0808fff0 g     F .text	000000d1 __libc_scratch_buffer_set_array_size
08067570 g     F .text	00000048 __strcasecmp_l_nonascii
08050230  w    F .text	0000019b puts
0809edf0 g     F .text	00000069 .hidden __libc_dlsym_private
08055700 g     F .text	00000065 __overflow
08092830 g     F .text	0000019e .hidden __btowc
0809f830 g     F .text	0000033f .hidden __mpn_mul
080bc580 g     O .rodata	0000008c .hidden __strtol_ul_max_tab
0806ef50 g     F .text	0000080d .hidden _dl_non_dynamic_init
08093820  w    F .text	0000000d getuid
0804efb0 g     F .text	000000a3 .hidden __internal_atexit
08093530  w    F .text	0000007a rewinddir
0805cd20 g     F .text	00000010 __memalign
080a0630 g     F .text	0000003c .hidden __mpn_submul_1
08052490 g     F .text	00000020 _IO_file_close
0805d190 g     F .text	0000029c __malloc_trim
080a11c0 g     F .text	00000025 .hidden __dladdr
080da06c g     O .data	00000004 .hidden _nl_current_default_domain
080dbef4 g     O .bss	00000004 _nl_msg_cat_cntr
0805c270 g     F .text	000002c1 malloc
080a6620 g     F .text	00000311 .hidden __letf2
0806bf10  w    F .text	000000be __open
08056ca0 g     F .text	0000002a _IO_unsave_markers
080b2180 g     O .rodata	00000300 .hidden _nl_C_LC_CTYPE_class
08093bd0  w    F .text	0000004b isatty
080da9f8 g     O .data	00000008 _dl_load_adds
080923c0 g     F .text	0000019b .hidden __memchr_ia32
080d8700 g     O .data.rel.ro	00000014 .hidden __gettext_germanic_plural
0806b1e0 g     F .text	00000079 .hidden __wcsmbs_getfct
080da340 g     O .data	00000098 _IO_2_1_stdin_
08072b00 g     F .text	000003ae __gconv_transform_internal_ucs4
0806be50 g     F .text	00000054 .hidden __get_child_max
080994a0 g     F .text	0000006b .hidden _dl_protect_relro
08093a00  w    F .text	000000b6 openat64
0805dc80 g     F .text	00000191 __strerror_r
0804f910 g     F .text	00000029 __asprintf
08092830  w    F .text	0000019e btowc
0806b260 g     F .text	0000023d .hidden __wcsmbs_load_conv
0806e0b0  w    F .text	00000020 sysinfo
080db314 g       __libc_IO_vtables	00000000 .protected __stop___libc_IO_vtables
080a0190 g     F .text	00000349 .hidden __mpn_impn_sqr_n
080bd7c8  w    O .rodata	00000004 sys_nerr
08087500  w    F .text	0000017b register_printf_modifier
080d9720 g     O .data.rel.ro	00000058 .hidden _nl_C_LC_ADDRESS
080dbf2c g     O .bss	00000004 _dl_wait_lookup_done
080489e7 g     F .text	00000000 .hidden __x86.get_pc_thunk.ax
0806f7f0 g     F .text	00000021 _dl_mcount_wrapper
0809d7f0 g     F .text	00000086 _dl_deallocate_tls
080b0e80 g     O .rodata	0000004c .hidden _nl_C_LC_CTYPE_class_graph
0809fcc0 g     F .text	000003a6 .hidden __mpn_impn_mul_n
0807b9f0 g     F .text	0000001c .hidden __current_locale_name
080dbf30 g     O .bss	00000004 _dl_profile
080b1180 g     O .rodata	00000600 .hidden _nl_C_LC_CTYPE_tolower
0804f0d0  w    F .text	00000030 strtoul
080da064 g     O .data	00000000 .hidden __dso_handle
080a1520 g     F .text	0000004e __strsep
0804ee80 g     F .text	00000122 .hidden __new_exitfn
0806e0d0 g     F .text	00000036 __libc_alloca_cutoff
0808ed10 g     F .text	00000028 _IO_switch_to_main_wget_area
08057920 g     F .text	00000021 _dl_tunable_set_trim_threshold
08049970 g     F .text	0000001e __dcgettext
08049750 g     F .text	0000004a __libc_csu_fini
00000002 g       *ABS*	00000000 _nl_current_LC_CTYPE_used
08057820 g     F .text	0000002b _IO_str_init_readonly
08053090  w    F .text	000007e5 _IO_file_seekoff
080704a0 g     F .text	00000102 .hidden _dl_discover_osversion
0809f020 g     F .text	0000005b _dl_signal_exception
0806f780 g     F .text	00000065 __libc_init_secure
0809d310 g     F .text	0000005c .hidden _dl_count_modids
080dbef8 g     O .bss	00000004 __exit_funcs_lock
08099450 g     F .text	0000004e .hidden _dl_nothread_init_static_tls
080a8cd0 g     F .text	000000dc .hidden __frame_state_for
08093460  w    F .text	000000cc readdir
0806ea00 g     F .text	0000006b __tunable_get_val
0808f7d0 g     F .text	00000055 _IO_adjust_wcolumn
0806e4d0 g     F .text	00000526 __tunables_init
0804f090 g     F .text	00000032 __strtoul_internal
0805cd80  w    F .text	00000077 pvalloc
08057390 g     F .text	0000034a _IO_str_seekoff
0807ba70 g     F .text	0000004d __ctype_init
08093840 g     F .text	0000000d .hidden __getgid
0809ea20 g     F .text	00000015 .hidden _dl_tlsdesc_resolve_rel
080dba60  w    O .bss	00000004 ___brk_addr
0806c1d0 g     F .text	0000006c .hidden __lseek64
080524b0  w    F .text	00000046 _IO_file_setbuf
08054590 g     F .text	00000510 _IO_new_file_fopen
0806a5d0  w    F .text	00000022 mempcpy
0804f8e0 g     F .text	0000002d _IO_printf
0805d510 g     F .text	0000010f __libc_mallinfo
0804fe70  w    F .text	00000123 fflush
080500f0 g     F .text	00000016 _IO_new_fopen
080db8c0  w    O .bss	00000004 _environ
080dbf38 g     O .bss	00000008 _dl_cpuclock_offset
08072ae0 g     F .text	00000012 __gconv_btwoc_ascii
08092720 g   i   .text	00000027 __wcslen
08056e60 g     F .text	00000003 _IO_default_write
0806c030 g     F .text	00000091 __libc_read
0804fad0 g     F .text	000000ad .hidden __fxprintf
0806e1e0 g     F .text	000000b3 .hidden __libc_disable_asynccancel
08071990 g     F .text	000002bd .hidden __gconv_find_transform
080ab150 g     F .text	00000284 .hidden __gcc_personality_v0
0806beb0 g     F .text	00000026 __xstat64
080529d0 g     F .text	00000040 _IO_file_close_mmap
0809d3a0 g     F .text	000000ba .hidden _dl_allocate_tls_storage
08093b20  w    F .text	000000a9 lseek
0805c950 g     F .text	0000036d __libc_realloc
08092750  w    F .text	00000029 wmemcpy
08057870 g     F .text	0000002a _dl_tunable_set_mmap_threshold
00000020 g       .tbss	00000004 __libc_tsd_CTYPE_TOLOWER
08077120 g     F .text	0000061d __gconv_transform_ucs2reverse_internal
0807c8b0  w    F .text	00000098 clearenv
080dbcc4 g     O .bss	00000004 _dl_tls_static_align
0809db80 g     F .text	000000e8 .hidden _dl_scope_free
080db8c0 g     O .bss	00000004 __environ
0806ce00  w    F .text	0000004e mmap
0806b90c  w    F .text	00000018 _Exit
0807cf30  w    F .text	0000001e strtol_l
0807a7b0 g     F .text	00000259 .hidden _nl_intern_locale_data
080982b0 g     F .text	00000bd7 .hidden _dl_lookup_symbol_x
080a6500 g     F .text	00000116 .hidden __udivdi3
0806b180 g     F .text	00000054 .hidden _nl_cleanup_ctype
080dbcc8 g     O .bss	00000004 _dl_tls_max_dtv_idx
080a08a0 g     F .text	000001e4 .hidden __mpn_extract_float128
080b0c40 g     O .rodata	000000a8 .hidden _nl_C_LC_CTYPE_map_toupper
080b0d60 g     O .rodata	0000004c .hidden _nl_C_LC_CTYPE_class_punct
0804e270 g     F .text	00000206 abort
080db980 g     O .bss	00000020 .hidden __libc_setlocale_lock
08048770 g     F .text	00000002 .hidden _dl_relocate_static_pie
0809f290 g     F .text	00000042 __sigjmp_save
0806e2c0 g     F .text	0000001b __stack_chk_fail
08069ad0 g     F .text	00000029 __strcasecmp_sse4_2
08050106 g     F .text	00000000 .hidden __x86.get_pc_thunk.dx
080a3ad0 g     F .text	000000a6 .hidden _dl_close
080dbce0 g     O .bss	00000200 _dl_static_dtv
080858b0 g     F .text	0000002b __printf_fp
080dbf40 g     O .bss	00000004 _dl_bind_not
080d9dac g     O .data.rel.ro	00000004 __libc_enable_secure
0808e960 g     F .text	00000150 _IO_wpadn
0807b980 g     F .text	00000070 _nl_postload_ctype
080a6940 g     F .text	000001fb .hidden __unordtf2
0806d380  w    F .text	0000059c tdelete
0808dfd0 g     F .text	00000143 _IO_fputs
08072eb0 g     F .text	000004c6 __gconv_transform_ucs4_internal
0806bfd0 g     F .text	0000005b __open_nocancel
080dbf44 g     O .bss	00000004 _dl_auxv
080481a8 g     F .init	00000000 _init
0809ebc0 g     F .text	000000e9 __libc_dlvsym
080b1000 g     O .rodata	00000044 .hidden _nl_C_LC_CTYPE_class_digit
080576e0 g     F .text	0000003f _IO_str_pbackfail
08051d10 g     F .text	0000018a _IO_wfile_xsputn
080dbfac g     O .bss	00000004 .hidden __gconv_max_path_elem_len
08056e80 g     F .text	00000002 _IO_default_imbue
0809f370 g     F .text	00000400 .hidden __mpn_divrem
0807c9d0  w    F .text	00000030 strtol
0809f250 g     F .text	00000035 __sigsetjmp
0806c1d0 g     F .text	0000006c __libc_lseek64
080a1460 g     F .text	00000089 .hidden __dlmopen
08090120  w  i   .text	00000027 strnlen
080af160 g     O .rodata	00000024 _dl_x86_platforms
0805e700  w  i   .text	00000032 rawmemchr
08093800  w    F .text	00000020 uname
0804add0 g     F .text	000002d2 .hidden _nl_find_domain
08056e50 g     F .text	00000006 _IO_default_read
080aaba0 g     F .text	0000002c .hidden __register_frame_table
080543f0  w    F .text	0000019a _IO_file_close_it
080bd7c8 g     O .rodata	00000004 __sys_nerr_internal
080bd7c8  w    O .rodata	00000004 _sys_nerr
080dbf48 g     O .bss	00000004 _dl_platform
080a0a90 g     F .text	00000227 _itowa
08056e90 g     F .text	00000013 _IO_iter_begin
080b1d80 g     O .rodata	00000400 .hidden _nl_C_LC_CTYPE_class32
08066f20 g     F .text	00000104 .hidden __strchr_sse2_bsf
0809d370 g     F .text	00000027 _dl_get_tls_static_info
08090150 g   i   .text	00000032 strrchr
080795e0 g     F .text	0000002a __gconv_destroy_spec
0807c9d0 g     F .text	00000030 __strtol
0807ba50 g     F .text	00000018 __ctype_tolower_loc
08049420 g     F .text	00000030 .hidden __libc_check_standard_fds
080db888  w    O .bss	00000004 __after_morecore_hook
0805ce00  w    F .text	00000381 calloc
080db314 g       __libc_atexit	00000000 .protected __start___libc_atexit
080a49d0 g     F .text	00000026 .hidden __setitimer
0805e6c0  w  i   .text	00000036 strcasecmp_l
080dbf90 g     O .bss	00000004 __libc_enable_secure_decided
0809e150 g     F .text	00000036 _dl_exception_free
08053880 g     F .text	00000026 _IO_file_stat
08070650 g     F .text	00000014 _dl_start
0805d430  w    F .text	000000de malloc_usable_size
0806d950  w    F .text	0000001a tdestroy
080aaa20 g     F .text	0000002a .hidden __register_frame_info_bases
08051b90 g     F .text	0000017a _IO_wfile_sync
0805cd80 g     F .text	00000077 __libc_pvalloc
0809dcf0 g     F .text	0000001e .hidden _dl_runtime_resolve
08067030 g     F .text	00000313 .hidden __rawmemchr_sse2
08090150  w  i   .text	00000032 rindex
08093e20 g     F .text	000001ff .hidden __readonly_area
080a4040 g     F .text	0000014b .hidden _dl_tlsdesc_resolve_rela_fixup
0806e4b0 g     F .text	00000020 __tunable_set_val
080858e0 g     F .text	00000023 .hidden __guess_grouping
0806c100  w    F .text	00000091 write
0805cd30 g     F .text	00000047 __libc_valloc
080b0b80 g     O .rodata	000000a8 .hidden _nl_C_LC_CTYPE_map_tolower
08090ab0 g     F .text	0000062f .hidden __strrchr_sse2
080abb70 g     F __libc_freeres_fn	000001f5 .hidden _nl_locale_subfreeres
080db8c0  w    O .bss	00000004 environ
080db900 g     O .bss	00000058 _dl_x86_cpu_features
0804a600 g     F .text	000007c8 .hidden __dcigettext
0804f8b0 g     F .text	00000029 fprintf
08098f50 g     F .text	000000a4 .hidden _dl_add_to_namespace_list
080ab3e0  w    F .text	00000161 dl_iterate_phdr
080db200 g     O __libc_IO_vtables	00000054 .hidden _IO_str_jumps
08057720 g     F .text	0000004e _IO_str_finish
0804d390 g     F .text	0000012c _nl_normalize_codeset
080db624 g     O .bss	00000001 .hidden __exit_funcs_done
08049970  w    F .text	0000001e dcgettext
080da068 g     O .data	00000004 _dl_tls_static_size
0809c420 g     F .text	0000002f .hidden _dl_debug_printf_c
08056e70 g     F .text	00000006 _IO_default_showmanyc
0806db80 g     F .text	000002ff __get_nprocs
08093bd0 g     F .text	0000004b .hidden __isatty
0806e2e0 g     F .text	00000066 .hidden __fortify_fail_abort
0806a8a0 g     F .text	00000025 .hidden __strcmp_ia32
080db560 g     O .bss	00000020 .hidden _nl_state_lock
080a1990 g     F .text	00000013 __profile_frequency
080dbf4c g     O .bss	00000004 _dl_lazy
0806e360 g     F .text	00000002 _dl_debug_state
08073f60 g     F .text	0000085a __gconv_transform_internal_ascii
080a16a0 g     F .text	000000ae .hidden __strspn_ia32
0805e680 g   i   .text	00000038 __stpcpy
0806ce50 g     F .text	0000009c __mmap64
08082f60 g     F .text	0000294f __printf_fp_l
080aad00 g     F .text	00000005 .hidden __deregister_frame_info
08057000 g     F .text	0000019a _IO_str_overflow
0806cf50  w    F .text	00000026 madvise
0805c270 g     F .text	000002c1 __malloc
08067570 g     F .text	00000048 __GI___strcasecmp_l
08093ac0 g     F .text	0000005b __openat64_nocancel
08096850 g     F .text	0000029a .hidden _dl_init_paths
0805c070 g     F .text	00000082 .hidden __malloc_fork_lock_parent
08053ab0 g     F .text	00000271 _IO_file_xsgetn
080565f0 g     F .text	00000300 _IO_cleanup
0804e1f0 g     F .text	00000032 .hidden __hash_string
080d9da4 g     O .data.rel.ro	00000004 _dl_argv
08055ea0 g     F .text	00000057 _IO_default_seekpos
08070690 g     F .text	00000359 __gconv_open
0805c870 g     F .text	000000db __free
080a8f90 g     F .text	000000ae .hidden _Unwind_Resume
080a47e0 g     F .text	0000002b .hidden __dlclose
080a9110 g     F .text	0000001d .hidden _Unwind_DeleteException
080daf14 g     O .data	00000002 __fpu_control
08076820 g     F .text	000008fa __gconv_transform_internal_ucs2
0806e070  w    F .text	00000032 mremap
0806cca0  w    F .text	00000026 __getrlimit
080543c0 g     F .text	0000002c _IO_new_do_write
0809ea00 g     F .text	00000015 .hidden _dl_tlsdesc_resolve_abs_plus_addend
0805ef10 g     F .text	00000578 .hidden __memset_sse2_rep
00000000 g       .tdata	00000004 .hidden _nl_current_LC_CTYPE
08093670 g     F .text	000000cc __readdir64
08052700  w    F .text	000002c1 _IO_file_underflow
0808e340  w    F .text	000002f8 getdelim
080790c0 g     F .text	00000030 .hidden __gconv_release_shlib
080d92e0 g     O .data.rel.ro	000000dc .hidden _nl_C_LC_MONETARY
0806c0d0 g     F .text	0000002e __read_nocancel
0804cda0 g     F .text	000005e7 _nl_make_l10nflist
08050000 g     F .text	000000f0 .hidden __fopen_internal
080560e0 g     F .text	000000a2 _IO_no_init
0805e740 g     F .text	0000015f __strchrnul
0809ee60 g     F .text	00000055 .hidden __libc_register_dl_open_hook
0808e810 g     F .text	00000148 _IO_padn
08054b50  w    F .text	00000204 _IO_file_overflow
08090210  w  i   .text	00000032 memchr
0808e640 g     F .text	00000199 _IO_getline_info
0806e2a0 g     F .text	0000001b __chk_fail
0808d1f0 g     F .text	000005c3 .hidden __parse_one_specmb
08093460 g     F .text	000000cc .hidden __readdir
0806bee0 g     F .text	00000026 ___fxstat64
080da49c g     O .data	00000004 stdin
0807d040 g     F .text	0000022c .hidden _itoa
0806d330  w    F .text	0000004f tfind
0809dd10 g     F .text	000000cd .hidden _dl_runtime_profile
08057800 g     F .text	00000017 _IO_str_init_static
080da498 g     O .data	00000004 .hidden _IO_stdout
08096090 g     F .text	000001a4 .hidden _dl_dst_substitute
080c0220 g     O .rodata	000000f0 .hidden _fpioconst_pow10
08050230 g     F .text	0000019b _IO_puts
080dbee0 g     O .bss	00000004 _dl_tls_dtv_slotinfo_list
080579f0 g     F .text	00000017 _dl_tunable_set_tcache_unsorted_limit
0809d460 g     F .text	0000034a _dl_allocate_tls_init
08070be0 g     F .text	00000061 .hidden __gconv_close
080929d0 g     F .text	000001b8 .hidden __wcrtomb
080da9a4 g     O .data	00000004 __progname
080dbf50 g     O .bss	00000004 _dl_sysinfo_map
08048730 g     F .text	00000000 _start
080aabd0 g     F .text	00000122 .hidden __deregister_frame_info_bases
080db318 g       __libc_atexit	00000000 .protected __stop___libc_atexit
080568f0 g     F .text	0000000e _IO_flush_all
0805e2f0 g     F .text	00000305 strstr
0804fc40 g     F .text	0000022e _IO_new_fclose
08056ed0 g     F .text	00000005 _IO_iter_file
08056380 g     F .text	00000267 _IO_flush_all_lockp
08056340 g     F .text	0000003f _IO_adjust_column
00000010 g       .tbss	00000004 .hidden __libc_errno
0804f5e0 g     F .text	000002c1 .hidden __correctly_grouped_prefixmb
080a6620 g     F .text	00000311 .hidden __lttf2
080705b0 g     F .text	0000009c __libc_init_first
08052330 g     F .text	0000002d .hidden _IO_vtable_check
0806c030  w    F .text	00000091 read
080dbf54 g     O .bss	00000004 _dl_inhibit_cache
080a3e70 g     F .text	00000084 .hidden _dl_tlsdesc_resolve_abs_plus_addend_fixup
080a0670 g     F .text	00000103 .hidden __mpn_extract_double
08060b90 g     F .text	000000b0 strncmp
080578d0 g     F .text	00000021 _dl_tunable_set_top_pad
080675f0 g     F .text	000024d2 .hidden __strcasecmp_l_ssse3
080d9880 g     O .data.rel.ro	00000070 .hidden _nl_C_LC_COLLATE
0804f8b0  w    F .text	00000029 _IO_fprintf
0804d4c0 g     F .text	0000021b _nl_explode_name
0808a590 g     F .text	000029a9 _IO_vfwprintf
0808f250 g     F .text	0000004a _IO_wdefault_doallocate
0809ea40 g     F .text	00000015 .hidden _dl_tlsdesc_resolve_rela
08092b90  w    F .text	000002fa wcsrtombs
0804ec40 g     F .text	0000020f .hidden __run_exit_handlers
0805c270 g     F .text	000002c1 __libc_malloc
080da998 g     O .data	00000004 .hidden __x86_data_cache_size
0805e8a0 g     F .text	00000668 .hidden __memset_sse2
08057900 g     F .text	00000017 _dl_tunable_set_perturb_byte
080927b0  w    F .text	00000074 wmemset
0806dfc0  w    F .text	0000003e get_avphys_pages
0805c170 g     F .text	00000097 .hidden __malloc_fork_unlock_child
08056bf0 g     F .text	0000002f _IO_marker_delta
0805c870 g     F .text	000000db __libc_free
0807c720  w    F .text	00000068 setenv
08053eb0 g     F .text	00000077 _IO_file_underflow_mmap
0808f760 g     F .text	0000006f _IO_sungetwc
080da9a4  w    O .data	00000004 program_invocation_short_name
08069b00 g     F .text	000004c6 .hidden __strcasecmp_l_sse4_2
080933c0 g     F .text	00000044 .hidden __opendir
08057850 g     F .text	00000012 _IO_str_count
080dc008 g     O __libc_freeres_ptrs	00000004 .hidden __printf_arginfo_table
080a2090 g     F .text	000001e8 .hidden _dl_open
0808d160  w    F .text	0000002d funlockfile
08052fc0 g     F .text	00000059 _IO_file_underflow_maybe_mmap
08092f40 g     F .text	000001f6 .hidden __wcslen_sse2
0805cd80 g     F .text	00000077 __pvalloc
0805c950 g     F .text	0000036d realloc
080b0f40 g     O .rodata	00000044 .hidden _nl_C_LC_CTYPE_class_space
08093850 g     F .text	0000000d .hidden __getegid
080dafc0 g     O __libc_IO_vtables	00000054 .hidden _IO_wfile_jumps_maybe_mmap
080a6150 g     F .text	00000059 .hidden _dl_check_all_versions
0806e370 g     F .text	0000007a .hidden _dl_debug_initialize
08090900 g     F .text	000000e2 .hidden __argz_create_sep
0805db90 g     F .text	00000044 __strdup
080dbee4 g     O .bss	00000001 _dl_tls_dtv_gaps
08070c50 g     F .text	00000025 .hidden __gconv_alias_compare
0804f060 g     F .text	00000029 __cxa_atexit
08060c40 g     F .text	000016ab .hidden __memcmp_ssse3
08092780 g     F .text	00000029 .hidden __wmemmove
08053f90  w    F .text	000001e2 _IO_file_xsputn
08093d00 g     F .text	00000033 .hidden __brk
080dafc0 g       __libc_IO_vtables	00000000 .protected __start___libc_IO_vtables
08093670  w    F .text	000000cc readdir64
080d9f00 g     O .data.rel.ro	00000034 .hidden _nl_C
0808f8a0 g     F .text	00000037 _IO_wmarker_delta
080db8e0 g     O .bss	00000008 _dl_hwcap2
08092e90  w    F .text	00000082 wcsnlen
08085910  w    F .text	000000d4 register_printf_specifier
0805d810 g     F .text	0000019a __libc_mallopt
08093dd0  w    F .text	00000045 towctrans
08048780 g     F .text	00000004 .hidden __x86.get_pc_thunk.bx
08056e40 g     F .text	00000006 _IO_default_stat
08054d60 g     F .text	000000fa _IO_new_file_sync
0805e600 g   i   .text	00000036 memcmp
080db0e0 g     O __libc_IO_vtables	00000054 .hidden _IO_file_jumps_maybe_mmap
080a17d0 g     F .text	000001b4 .hidden __profil
080a45e0 g     F .text	00000098 .hidden __mpn_add_n
0805d190  w    F .text	0000029c malloc_trim
080578a0 g     F .text	00000021 _dl_tunable_set_mmaps_max
0000000c g       .tdata	00000004 .hidden _nl_current_LC_NUMERIC
0804f100 g     F .text	000004b2 ____strtoul_l_internal
080b1780 g     O .rodata	00000600 .hidden _nl_C_LC_CTYPE_toupper
080a8dc0 g     F .text	00000126 .hidden _Unwind_RaiseException
0806be30 g     F .text	00000018 __sched_yield
0805e6c0 g   i   .text	00000036 __strcasecmp_l
080c3980 g     O .rodata	00000090 .hidden _itowa_lower_digits
08056be0 g     F .text	0000000f _IO_marker_difference
0809d9f0 g     F .text	00000188 .hidden _dl_get_origin
0807bdc0  w    F .text	00000033 sigaction
080dbf58 g     O .bss	00000004 _dl_phdr
0806a120 g     F .text	000000c6 .hidden __rawmemchr_ia32
0808f310 g     F .text	00000065 _IO_free_wbackup_area
080da4a4 g     O .data	00000004 .hidden __libc_malloc_initialized
0809c470 g     F .text	00000064 .hidden _dl_name_match_p
0807a750 g     F .text	00000052 .hidden _nl_remove_locale
0806cd70 g     F .text	0000003c __getpagesize
080bc620 g     O .rodata	000001a4 .hidden _itoa_base_table
08050110  w    F .text	0000011a fread
08070670 g     F .text	0000001c .hidden __syscall_error
080a4740 g     F .text	00000089 .hidden __dlopen
080556a0 g     F .text	00000058 _IO_free_backup_area
08093860 g     F .text	00000026 ___lxstat64
080d9400 g     O .data.rel.ro	000002a0 .hidden _nl_C_LC_TIME
08093140 g     F .text	0000006e .hidden __wcslen_ia32
080541c0  w    F .text	0000003b _IO_file_init
0806ccd0  w    F .text	0000009b sbrk
080bc7e0 g     O .rodata	00000024 _itoa_lower_digits
0806c3b0 g     F .text	00000079 __libc_close
0805db90  w    F .text	00000044 strdup
080d9f40 g     O .data.rel.ro	00000074 .hidden _nl_C_locobj
08055770 g     F .text	0000011a __underflow
08072a10 g     F .text	000000cc .hidden __gconv_get_builtin_trans
080daa00 g     O .data	00000004 _dl_nns
08093890 g     F .text	0000004d __fxstatat64
080da988 g     O .data	00000004 .hidden __x86_shared_cache_size
080a8c40 g     F .text	0000000c .hidden _Unwind_SetIP
08093530 g     F .text	0000007a __rewinddir
080496b0 g     F .text	0000009c __libc_csu_init
080d9da0 g     O .data.rel.ro	00000004 .hidden _dl_random
080db608 g     O .bss	00000004 __abort_msg
080a41f0 g     F .text	0000002d .hidden _dl_unmap
080dbf5c g     O .bss	00000004 _dl_scope_free_list
0806de80 g     F .text	000000f8 __get_nprocs_conf
08070d00 g     F .text	00000086 .hidden __gconv_release_step
0805daa0  w  i   .text	00000032 index
08049358 g     F .text	00000000 .hidden __x86.get_pc_thunk.bp
080500f0  w    F .text	00000016 fopen
080db31c g       .bss	00000000 __bss_start
0806bf10 g     F .text	000000be __libc_open
0808f100 g     F .text	000000e6 _IO_wdefault_xsputn
080747c0 g     F .text	00000b3c __gconv_transform_internal_utf8
08055ae0 g     F .text	00000057 _IO_default_uflow
0805e640 g   i   .text	00000032 memset
0806b110 g     F .text	00000029 .hidden __wmempcpy
0807cf30  w    F .text	0000001e __strtol_l
080488d4 g     F .text	00000113 main
0809c740 g     F .text	00000833 .hidden _dl_start_profile
080dbf60 g     O .bss	00000004 _dl_origin_path
08092e90 g     F .text	00000082 __wcsnlen
0805da10 g     F .text	0000005f __malloc_info
080d8714 g     O .data.rel.ro	00000010 .hidden __wcsmbs_gconv_fcts_c
00000002 g       *ABS*	00000000 _nl_current_LC_MONETARY_used
080d9000  w    O .data.rel.ro	0000021c _sys_errlist
0806a650 g     F .text	000001be .hidden __strchr_ia32
08054aa0 g     F .text	000000a7 _IO_new_file_finish
0806a550 g     F .text	0000000e __memmove_chk
080dbee8 g     O .bss	00000004 _dl_tls_generation
080dbfa0 g     O .bss	00000004 .hidden __gconv_lock
0806df80  w    F .text	0000003e get_phys_pages
0808a590  w    F .text	000029a9 vfwprintf
0806b140  w    F .text	0000003c mbsrtowcs
08054310 g     F .text	000000a7 _IO_new_file_attach
080bdd18 g     O .rodata	0000001f .hidden ___m128i_shift_right
0805d810  w    F .text	0000019a mallopt
0804fc40  w    F .text	0000022e fclose
0806e350 g     F .text	0000000e __fortify_fail
080dbf64 g     O .bss	00000004 _dl_clktck
0809e190 g     F .text	0000010a .hidden _dl_cache_libcmp
08099580 g     F .text	0000219f .hidden _dl_relocate_object
0805da10  w    F .text	0000005f malloc_info
08093c20  w    F .text	000000d7 tcgetattr
080d9000  w    O .data.rel.ro	0000021c sys_errlist
080dbf68 g     O .bss	00000004 _dl_dynamic_weak
0807ffc0 g     F .text	0000299b _IO_vfprintf_internal
080931b0 g     F .text	00000013 time
080933c0  w    F .text	00000044 opendir
0808f4d0 g     F .text	00000142 __wunderflow
08057990 g     F .text	00000035 _dl_tunable_set_tcache_max
0806a4d0 g     F .text	0000000e __memcpy_chk
08055890 g     F .text	0000012a __uflow
080aaad0 g     F .text	000000ad .hidden __register_frame_info_table_bases
08095ff0 g     F .text	00000091 .hidden _dl_dst_count
08049930 g     F .text	0000003a __assert_fail
080af4ee g     O .rodata	00000002 .hidden _nl_C_name
08055570 g     F .text	00000028 _IO_least_marker
08049c00 g     F .text	000009f2 .hidden _nl_find_msg
0808ed40 g     F .text	0000002a _IO_switch_to_wbackup_area
08056f70 g     F .text	00000029 _IO_list_resetlock
080af184 g     O .rodata	0000001b _dl_x86_hwcap_flags
08092f20  w    F .text	0000001f wcschrnul
08052360 g     F .text	000000a4 __fgets_unlocked
08058c70 g     F .text	0000006c _dl_tunable_set_mallopt_check
080a1d60 g     F .text	00000003 _dl_call_pltexit
080906a0 g     F .text	00000254 __memmem
080a4920 g     F .text	000000af .hidden __dlvsym
0806c1d0  w    F .text	0000006c llseek
08093b20 g     F .text	000000a9 __lseek
080ac424 g     O .rodata	00000012 _nl_default_dirname
080bc4b4 g     O .rodata	00000006 .hidden _nl_POSIX_name
0806d920 g     F .text	00000022 __twalk
0808e7e0 g     F .text	00000022 _IO_getline
08099400 g     F .text	00000046 .hidden _dl_allocate_static_tls
08062e80 g     F .text	0000184b .hidden __strcpy_ssse3
080488a5 g     F .text	0000002f copyData
0805dae0 g   i   .text	00000036 strcmp
0808f010 g     F .text	00000067 _IO_wdefault_uflow
0809f7d0 g     F .text	00000057 .hidden __mpn_rshift
080d97c0 g     O .data.rel.ro	0000002c .hidden _nl_C_LC_MEASUREMENT
08070ce0 g     F .text	00000011 __gconv_get_alias_db
0809ea60 g     F .text	00000015 .hidden _dl_tlsdesc_resolve_hold
080da060  w      .data	00000000 data_start
0808ff20 g     F .text	000000cc __libc_scratch_buffer_grow_preserve
08079f80 g     F .text	000007c7 .hidden _nl_find_locale
08090210 g   i   .text	00000032 __memchr
0806a8d0 g     F .text	000000ae .hidden __strcspn_ia32
0805c210 g     F .text	0000005b .hidden __malloc_check_init
080859f0  w    F .text	00000005 register_printf_function
0806b140 g     F .text	0000003c .hidden __mbsrtowcs
080dbff4 g     O .bss	00000004 .hidden __printf_function_table
0804f5c0  w    F .text	0000001e strtoul_l
0804ffa0 g     F .text	00000054 .hidden __fopen_maybe_mmap
08097450 g     F .text	0000021b _dl_rtld_di_serinfo
0806c460  w    F .text	0000083e getcwd
08093a00 g     F .text	000000b6 __libc_openat64
080dbf6c g     O .bss	00000004 _dl_sysinfo_dso
080927b0 g     F .text	00000074 __wmemset
080d9780 g     O .data.rel.ro	00000038 .hidden _nl_C_LC_TELEPHONE
0806e170 g     F .text	00000063 .hidden __libc_enable_asynccancel
080b0d00 g     O .rodata	0000004c .hidden _nl_C_LC_CTYPE_class_alnum
080aad10 g     F .text	00000032 .hidden __deregister_frame
080559c0 g     F .text	00000060 _IO_setb
080ab3e0 g     F .text	00000161 __dl_iterate_phdr
080ac228 g     F .fini	00000000 _fini
08087890 g     F .text	000000cc __register_printf_type
08054590  w    F .text	00000510 _IO_file_fopen
080a3b80 g     F .text	0000027d .hidden _dl_sort_maps
0806c1a0 g     F .text	0000002e __write_nocancel
080a11f0 g     F .text	00000066 .hidden __dladdr1
0804e800 g     F .text	0000032f __qsort_r
0805cd20  w    F .text	00000010 memalign
080622f0 g     F .text	00000b81 .hidden __memcmp_sse4_2
0806a5d0 g     F .text	00000022 __mempcpy
0809e9a0 g     F .text	0000003e .hidden _dl_unload_cache
0804f910  w    F .text	00000029 asprintf
08069fd0 g     F .text	00000150 .hidden __strcspn_sse42
080524b0 g     F .text	00000046 _IO_new_file_setbuf
0805dc80  w    F .text	00000191 strerror_r
08050b40 g     F .text	00000a05 _IO_wfile_seekoff
08092360 g     F .text	00000058 __strcasecmp_nonascii
080504a0 g     F .text	00000698 _IO_wfile_underflow
0806cf50 g     F .text	00000026 __madvise
08092b90 g     F .text	000002fa .hidden __wcsrtombs
0808de70 g     F .text	00000157 _IO_file_doallocate
0805db60 g   i   .text	00000027 strcspn
080788d0 g     F .text	0000009c .hidden __gconv_compare_alias_cache
080bc49c g     O .rodata	00000005 _libc_intl_domainname
080dbfb0 g     O .bss	00000004 .hidden __gconv_path_elem
080c0320 g     O .rodata	000035c0 .hidden __tens
0808f830 g     F .text	00000070 _IO_init_wmarker
08079820 g     F .text	00000754 setlocale
00000028 g       .tbss	00000004 __libc_tsd_CTYPE_B
0806e000 g     F .text	0000001d .hidden __getclktck
080a8cc0 g     F .text	00000008 .hidden _Unwind_GetTextRelBase
08053f30 g     F .text	00000056 _IO_file_read
080da494 g     O .data	00000004 stderr
0806ce50  w    F .text	0000009c mmap64
080b0e20 g     O .rodata	00000044 .hidden _nl_C_LC_CTYPE_class_blank
08093860 g     F .text	00000026 __lxstat64
08049450 g     F .text	00000259 __libc_setup_tls
080db1a0 g     O __libc_IO_vtables	00000054 _IO_file_jumps
0804f910 g     F .text	00000029 ___asprintf
080a17d0  w    F .text	000001b4 profil
080a1520  w    F .text	0000004e strsep
080579d0 g     F .text	0000001e _dl_tunable_set_tcache_count
0806c430 g     F .text	00000026 __close_nocancel
080daa24 g     O .data	00000004 _dl_init_static_tls
080646d0 g     F .text	0000186c .hidden __stpcpy_ssse3
080dbf00 g     O .bss	00000008 .hidden __new_exitfn_called
0806c360 g     F .text	00000047 __fcntl_nocancel
080a8c70 g     F .text	00000032 .hidden _Unwind_FindEnclosingFunction
080a1520 g     F .text	0000004e __strsep_g
0805cd30  w    F .text	00000047 valloc
08057770 g     F .text	0000008b _IO_str_init_static_internal
080ab620 g     F __libc_freeres_fn	00000055 .hidden _nl_finddomain_subfreeres
08093d40 g     F .text	00000082 __wctrans
080da9e0 g     O .data	00000004 _dl_stack_flags
080b0200 g     O .rodata	0000000d .hidden _nl_category_name_sizes
0809cf80 g     F .text	00000226 _dl_mcount
08093b20 g     F .text	000000a9 __libc_lseek
0809d200 g     F .text	0000010d .hidden _dl_next_tls_modid
0807d2f0 g     F .text	00000079 .hidden _fitoa
08087680 g     F .text	00000104 .hidden __handle_registered_modifier_mb
080500f0  w    F .text	00000016 _IO_fopen
0808ef80 g     F .text	0000008f _IO_wdefault_finish
0806f820 g     F .text	00000033 _dl_mcount_wrapper_check
08087890  w    F .text	000000cc register_printf_type
080538b0 g     F .text	000000a4 _IO_new_file_write
0805d510  w    F .text	0000010f mallinfo
080da494 g     O .data	00000004 .hidden _IO_stderr
0807ba10 g     F .text	00000018 __ctype_b_loc
0806e070 g     F .text	00000032 __mremap
08085a00 g     F .text	00001af7 .hidden __printf_fphex
080a8c50 g     F .text	00000008 .hidden _Unwind_GetLanguageSpecificData
080900d0 g     F .text	00000049 __strndup
080dbf70 g     O .bss	00000004 _dl_init_all_dirs
08066530 g     F .text	00000606 .hidden __stpcpy_sse2
0809d7b0 g     F .text	00000031 _dl_allocate_tls
080dbeec g     O .bss	00000004 _dl_tls_static_nelem
08070cc0 g     F .text	00000011 __gconv_get_modules_db
08093800 g     F .text	00000020 __uname
0808f6e0 g     F .text	00000077 _IO_sputbackwc
08093370 g     F .text	0000004c .hidden __opendirat
080725a0 g     F .text	0000046a .hidden __gconv_read_conf
0809ecb0 g     F .text	00000019 __libc_dlclose
0806d920  w    F .text	00000022 twalk
08071c50 g     F .text	00000099 .hidden __gconv_close_transform
0809d880 g     F .text	00000077 .hidden _dl_tls_get_addr_soft
08054310  w    F .text	000000a7 _IO_file_attach
08090900  w    F .text	000000e2 argz_create_sep
08067350 g     F .text	00000213 .hidden __rawmemchr_sse2_bsf
08057950 g     F .text	00000017 _dl_tunable_set_arena_max
0807c950 g     F .text	00000037 __libc_secure_getenv
080bd7c8 g     O .rodata	00000004 .hidden _sys_nerr_internal
080d93c0 g     O .data.rel.ro	0000003c .hidden _nl_C_LC_NUMERIC
08092780  w    F .text	00000029 wmemmove
0808f970 g     F .text	0000002a _IO_unsave_wmarkers
08054200 g     F .text	0000010f _IO_file_open
08096af0 g     F .text	00000954 .hidden _dl_map_object
080abd70 g     F __libc_freeres_fn	00000118 .hidden _nl_archive_subfreeres
00000004 g       .tdata	00000004 __libc_tsd_LOCALE
0808e1b0  w    F .text	00000187 fwrite
08056f30 g     F .text	0000003f _IO_list_unlock
0806c3b0 g     F .text	00000079 __close
0806bee0 g     F .text	00000026 __fxstat64
0809fb70 g     F .text	00000039 .hidden __mpn_mul_1
08093820 g     F .text	0000000d .hidden __getuid
080bc820 g     O .rodata	00000024 _itoa_upper_digits
080a8ef0 g     F .text	00000099 .hidden _Unwind_ForcedUnwind
080db31c g       __libc_thread_subfreeres	00000000 _edata
080da9c8 g     O .data	00000018 _dl_load_lock
0804e800  w    F .text	0000032f qsort_r
08055600 g     F .text	00000097 _IO_switch_to_get_mode
080dc010 g       __libc_freeres_ptrs	00000000 _end
080a19b0 g     F .text	00000184 .hidden _dl_fixup
080543c0  w    F .text	0000002c _IO_do_write
0807d270 g     F .text	00000079 .hidden _fitoa_word
08093740 g     F .text	000000be .hidden __fdopendir
080dbfc0 g     O .bss	00000034 .hidden _nl_locale_file_list
0808e340 g     F .text	000002f8 _IO_getdelim
08065f40 g     F .text	000005e5 .hidden __strcpy_sse2
08078dd0 g     F .text	0000002d .hidden __gconv_release_cache
0804fc40 g     F .text	0000022e __new_fclose
080da9e4 g     O .data	00000002 _dl_fpu_control
0808f380 g     F .text	00000142 __wuflow
0806ba60 g     F .text	000003d0 __sysconf
080da98c g     O .data	00000004 .hidden __x86_shared_cache_size_half
0807bdc0 g     F .text	00000033 __sigaction
0805ce00 g     F .text	00000381 __libc_calloc
080dba60 g     O .bss	00000004 __curbrk
08071870 g     F .text	00000117 .hidden __gconv_compare_alias
0808a590 g     F .text	000029a9 .hidden __vfwprintf
0806d330 g     F .text	0000004f __tfind
080daea0 g     O .data	00000074 .hidden _nl_global_locale
080dbf74 g     O .bss	00000004 _dl_verbose
08056240 g     F .text	0000000b _IO_default_seekoff
080af060 g     O .rodata	00000100 _dl_x86_cap_flags
0809c450 g     F .text	0000001e .hidden _dl_dprintf
08055a20 g     F .text	000000a7 _IO_doallocbuf
0809f080 g     F .text	00000064 _dl_signal_error
080dbf78 g     O .bss	00000004 _dl_phnum
08056900  w    F .text	00000237 _flushlbf
0809def0 g     F .text	00000254 _dl_exception_create_format
080d9fd0 g     O .data.rel.ro	00000004 .hidden __stack_prot
080bc540 g     O .rodata	00000023 .hidden __strtol_ul_rem_tab
080d9220 g     O .data.rel.ro	00000070 .hidden __libio_codecvt
080497a0 g     F .text	00000018 __errno_location
08093410 g     F .text	0000004c .hidden __closedir
08052070 g     F .text	00000280 .hidden __libc_message
0806db80  w    F .text	000002ff get_nprocs
080dbf7c g     O .bss	00000004 _dl_profile_map
080555d0 g     F .text	00000028 _IO_switch_to_backup_area
080a0d10 g     F .text	00000236 .hidden __dlerror
0804ee50 g     F .text	00000021 exit
080a8bb0 g     F .text	00000058 .hidden _Unwind_SetGR
080db88c  w    O .bss	00000004 __free_hook
08073380 g     F .text	000003cb __gconv_transform_internal_ucs4le
08054180 g     F .text	0000003b .hidden _IO_new_file_init_internal
08092560 g     F .text	000001b9 .hidden __strrchr_ia32
0806cef0 g     F .text	00000024 __munmap
00000024 g       .tbss	00000004 __libc_tsd_CTYPE_TOUPPER
0805d430 g     F .text	000000de __malloc_usable_size
08078010 g     F .text	0000048e __gconv_transliterate
080938e0  w    F .text	000000b6 __openat
080d9000 g     O .data.rel.ro	0000021c .hidden _sys_errlist_internal
0804f5c0  w    F .text	0000001e __strtoul_l
080da49c g     O .data	00000004 .hidden _IO_stdin
0808ed70 g     F .text	00000064 _IO_wsetb
080db020 g     O __libc_IO_vtables	00000054 .hidden _IO_wfile_jumps_mmap
080da074  w    O .data	00000004 .hidden DW.ref.__gcc_personality_v0
0804f8b0 g     F .text	00000029 __fprintf
08093d00  w    F .text	00000033 brk
08092360 g     F .text	00000058 __GI___strcasecmp
080d92a0 g     O .data.rel.ro	00000038 .hidden _nl_C_LC_MESSAGES
0807ffc0 g     F .text	0000299b _IO_vfprintf
0806b530 g     F .text	00000079 .hidden __wcsmbs_named_conv
0806ea80 g     F .text	000004cd .hidden _dl_aux_init
080db8e8 g     O .bss	00000008 _dl_hwcap
080c38e0 g     O .rodata	00000090 .hidden _itowa_upper_digits
0808e120 g     F .text	00000081 _IO_wfile_doallocate
080497c0 g     F .text	00000161 .hidden __assert_fail_base
080675c0 g     F .text	00000029 __strcasecmp_ssse3
080b0220 g     O .rodata	00000089 .hidden _nl_category_names
080938e0  w    F .text	000000b6 openat
080a4190 g     F .text	0000005b .hidden _dl_tlsdesc_resolve_hold_fixup
080bc4a4 g     O .rodata	0000000f .hidden _nl_C_codeset
08079290 g     F .text	00000349 __gconv_create_spec
080dbf80 g     O .bss	00000004 _dl_initfirst
0807bac0 g     F .text	00000097 .hidden __setfpucw
08056fa0 g     F .text	00000057 _IO_str_underflow
0807be00 g     F .text	000000ac __sigprocmask
0804e230 g     F .text	00000036 _setjmp
08052360  w    F .text	000000a4 fgets_unlocked
0807ba30 g     F .text	00000018 __ctype_toupper_loc
0808d160 g     F .text	0000002d .hidden __funlockfile
0805f490 g     F .text	0000146d .hidden __strcmp_ssse3
080ac244 g     O .rodata	00000004 _IO_stdin_used
0806b90c g     F .text	00000018 _exit
080da9b0 g     O .data	00000018 _dl_load_write_lock
0809e9e0 g     F .text	00000004 .hidden _dl_tlsdesc_return
0806a600 g     F .text	00000043 .hidden __memset_ia32
080931d0 g     F .text	00000100 .hidden __alloc_dir
080a14f0 g   i   .text	00000027 strspn
080a1750 g     F .text	0000002e .hidden __getdents64
080a8b40 g     F .text	00000051 .hidden _Unwind_GetGR
080ac438 g     O .rodata	00000009 .hidden _nl_default_default_domain
0806a1f0 g     F .text	000002d3 .hidden __memcmp_ia32
080dbf98 g     O .bss	00000004 .hidden __libc_argv
080da994 g     O .data	00000004 .hidden __x86_raw_data_cache_size_half
08048c60 g     F .text	000006f8 __libc_start_main
0806e110 g     F .text	0000002d .hidden __lll_lock_wait_private
0806a980 g     F .text	000000bb strlen
0806c1d0  w    F .text	0000006c lseek64
08056080 g     F .text	00000028 .hidden _IO_init_internal
0806bf10  w    F .text	000000be open
080da9a8  w    O .data	00000004 program_invocation_name
0809eb50 g     F .text	00000069 __libc_dlsym
0805c100 g     F .text	00000062 .hidden __malloc_fork_unlock_parent
080a2280 g     F .text	00000182 .hidden _dl_show_scope
0806c100 g     F .text	00000091 __libc_write
0806c2b0  w    F .text	000000ab __fcntl
080560b0 g     F .text	00000028 _IO_init
0804f0d0 g     F .text	00000030 __strtoul
08077740 g     F .text	000008cd __gconv_transform_internal_ucs2reverse
080b10c0 g     O .rodata	00000048 .hidden _nl_C_LC_CTYPE_class_lower
080dbf84 g     O .bss	00000004 _dl_all_dirs
080a1570 g     F .text	00000123 .hidden __strspn_sse42
0807c720 g     F .text	00000068 .hidden __setenv
0807c8b0 g     F .text	00000098 .hidden __clearenv
0805daa0 g   i   .text	00000032 strchr
0809d900 g     F .text	000000e8 .hidden _dl_add_to_slotinfo
0805c950 g     F .text	0000036d __realloc
080dbfa4 g     O .bss	00000004 .hidden __gconv_alias_db
08056eb0 g     F .text	00000003 _IO_iter_end
0805d810 g     F .text	0000019a __mallopt
0806a5c0 g     F .text	0000000e __mempcpy_chk
0808dfd0  w    F .text	00000143 fputs
0807beb0 g     F .text	000004c8 _quicksort
080a8cb0 g     F .text	00000008 .hidden _Unwind_GetDataRelBase
08067570 g     F .text	00000048 .hidden __strcasecmp_l_ia32
08052700 g     F .text	000002c1 _IO_new_file_underflow
080da060 g       .data	00000000 __data_start
080a0ff0 g     F .text	0000018b .hidden _dlerror_run
080a64d0 g     F .text	00000021 _dl_sym
080522f0 g     F .text	00000031 __libc_fatal
0806df80 g     F .text	0000003e __get_phys_pages
0806ccd0 g     F .text	0000009b __sbrk
0806cf20  w    F .text	00000026 mprotect
08056e30 g     F .text	0000000b _IO_default_seek
0806d380 g     F .text	0000059c __tdelete
0806f760 g     F .text	00000011 .hidden _dl_get_dl_main_map
080dc00c g     O __libc_freeres_ptrs	00000004 .hidden __printf_va_arg_table
080dbf0c g     O .bss	00000014 _r_debug
0805d620 g     F .text	000001e7 __malloc_stats
08093410  w    F .text	0000004c closedir
0808ede0 g     F .text	00000192 _IO_wdefault_pbackfail
080d9000 g     O .data.rel.ro	0000021c __sys_errlist_internal
080dbf88 g     O .bss	00000004 _dl_osversion
080da078 g     O .data	00000004 _IO_list_all
080909f0 g     F .text	000000bf .hidden __argz_add_sep
08054b50 g     F .text	00000204 _IO_new_file_overflow
0809eec0 g     F .text	00000081 __libc_dlopen_mode
0807c790 g     F .text	00000114 .hidden __unsetenv
08053090 g     F .text	000007e5 _IO_new_file_seekoff
08051ea0  w    F .text	000001cf vasprintf
08057970 g     F .text	00000017 _dl_tunable_set_arena_test
0809c360 g     F .text	0000008e .hidden _dl_sysdep_read_whole_file
0805e740  w    F .text	0000015f strchrnul
00000008 g       .tdata	00000004 .hidden _nl_current_LC_MONETARY
080939a0 g     F .text	0000005b __openat_nocancel
0806c2b0  w    F .text	000000ab fcntl
0806be30  w    F .text	00000018 sched_yield
080a4220 g     F .text	00000346 _dl_addr
0806dfc0 g     F .text	0000003e __get_avphys_pages
08087790 g     F .text	000000f8 .hidden __handle_registered_modifier_wc
080d96a0 g     O .data.rel.ro	00000030 .hidden _nl_C_LC_PAPER
0809f1f0 g     F .text	0000005f _dl_catch_error
08055360 g     F .text	00000012 _IO_un_link
080aab80 g     F .text	00000018 .hidden __register_frame_info_table
08052500 g     F .text	00000085 _IO_file_setbuf_mmap
080dad0c g     O .data	00000004 _dl_make_stack_executable_hook
080dbf8c g     O .bss	00000004 _dl_inhibit_rpath
0806de80  w    F .text	000000f8 get_nprocs_conf
0805cd20  w    F .text	00000010 aligned_alloc
08056cd0 g     F .text	0000015d _IO_default_pbackfail
080aaa50 g     F .text	00000027 .hidden __register_frame_info
0809e9f0 g     F .text	0000000b .hidden _dl_tlsdesc_undefweak
0805d9b0  w    F .text	0000005f posix_memalign
080929d0  w    F .text	000001b8 wcrtomb
080da9e8 g     O .data	00000004 _dl_correct_cache_id
0806e0b0 g     F .text	00000020 .hidden __sysinfo
080500f0 g     F .text	00000016 __new_fopen
0806c3b0  w    F .text	00000079 close
080daa20 g     O .data	00000004 _dl_sysinfo
08092750 g     F .text	00000029 .hidden __wmemcpy
08056ec0 g     F .text	00000008 _IO_iter_next
080a2cc0 g     F .text	00000e0d .hidden _dl_close_worker
080da9f0 g     O .data	00000004 _dl_pagesize
0805cd30 g     F .text	00000047 __valloc
080da500  w    O .data	00000004 __memalign_hook
08093830 g     F .text	0000000d .hidden __geteuid
0807ffc0 g     F .text	0000299b vfprintf
080da080 g     O .data	00000098 _IO_2_1_stderr_
080da9a8 g     O .data	00000004 __progname_full
0806f860 g     F .text	00000c3b .hidden _dl_tunable_set_hwcaps
080555a0 g     F .text	00000026 _IO_switch_to_main_get_area
0806e140 g     F .text	00000025 .hidden __lll_unlock_wake_private
0807bb60 g     F .text	000000ee raise
08056c20 g     F .text	0000007f _IO_seekmark
080b1060 g     O .rodata	00000048 .hidden _nl_C_LC_CTYPE_class_alpha
0805c870 g     F .text	000000db free
08093dd0 g     F .text	00000045 __towctrans
0807be00  w    F .text	000000ac sigprocmask
08055fc0 g     F .text	000000b1 _IO_old_init
080db140 g     O __libc_IO_vtables	00000054 .hidden _IO_file_jumps_mmap
080a1180 g     F .text	00000033 .hidden __libc_register_dlfcn_hook
080a4aa0 g     F .text	00000d22 .hidden _dl_map_object_deps
08092290 g     F .text	000000c4 .hidden __strnlen_ia32
080d9800 g     O .data.rel.ro	00000064 .hidden _nl_C_LC_IDENTIFICATION
080daa40 g     O .data	0000004c _dl_ns
0807ae10 g     F .text	00000b68 .hidden _nl_load_locale_from_archive
08093d40  w    F .text	00000082 wctrans
0806b0d0 g     F .text	00000035 .hidden __cache_sysconf


