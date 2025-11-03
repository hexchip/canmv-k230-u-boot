/* Copyright (c) 2025, Canaan Bright Sight Co., Ltd
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __K230_ATAG_H__
#define __K230_ATAG_H__

#include <common.h>
#include <asm/types.h>

/* ATAG tag definitions */
#define ATAG_NONE		0x00000000
#define ATAG_CORE       0x54410001
/* K230-specific ATAG extensions */
#define ATAG_K230_DDR_SIZE	0x54410002	/* K230 DDR size information */
#define ATAG_K230_RTAPP		0x54410003	/* K230 RTAPP preload information */

struct tag_core {
    u32 flags;
};

/* K230-specific ATAG structures */
struct tag_k230_ddr_size {
	u64 ddr_size;		/* DDR size in bytes */
};

struct tag_k230_rtapp {
    u64 size;
	u64 load_address;	/* RTAPP load address */
};

/* ATAG tag header */
struct tag_header {
	u32 size;
	u32 tag;
};

/* Generic ATAG structure */
struct tag {
	struct tag_header hdr;
	union {
        struct tag_core             core;
		struct tag_k230_ddr_size	k230_ddr;
		struct tag_k230_rtapp		k230_rtapp;
	} u;
};

/* Tag list definitions */
#define tag_next(t)	((struct tag *)((u32 *)(t) + (t)->hdr.size))
#define tag_size(type)	((sizeof(struct tag_header) + sizeof(struct type)) >> 2)

/* Memory layout for ATAG area */
#define K230_ATAG_BASE		(CONFIG_RTSMART_OPENSIB_MEMORY_SIZE - 0x4000)	/* 128K - 16K */
#define K230_ATAG_MAX_SIZE	(CONFIG_RTSMART_OPENSIB_MEMORY_SIZE - 0x10)	/* 128K - 16B */

/* Function prototypes */
void setup_start_tag(void);
void setup_k230_ddr_size_tag(uint64_t ddr_size);
void setup_k230_rtapp_tag(uint64_t size, uint64_t load_address);
void setup_end_tag(void);

#endif /* __K230_ATAG_H__ */
