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

#include <common.h>
#include <asm/io.h>
#include <linux/kernel.h>
#include "k230_atag.h"
#include "board_common.h"

/* Global ATAG pointer */
static struct tag *params;

void setup_start_tag(void)
{
	params = (struct tag *)K230_ATAG_BASE;

	/* Clear the ATAG area first */
	memset((void *)K230_ATAG_BASE, 0, K230_ATAG_MAX_SIZE - K230_ATAG_BASE);

	params->hdr.tag = ATAG_CORE;
	params->hdr.size = tag_size(tag_core);

	params->u.core.flags = 0;

	params = tag_next(params);
}

void setup_k230_ddr_size_tag(uint64_t ddr_size)
{
	params->hdr.tag = ATAG_K230_DDR_SIZE;
	params->hdr.size = tag_size(tag_k230_ddr_size);

	params->u.k230_ddr.ddr_size = ddr_size;

	params = tag_next(params);
}

void setup_k230_rtapp_tag(uint64_t size, uint64_t load_address)
{
	params->hdr.tag = ATAG_K230_RTAPP;
	params->hdr.size = tag_size(tag_k230_rtapp);

	params->u.k230_rtapp.size = size;
	params->u.k230_rtapp.load_address = load_address;

	params = tag_next(params);
}

void setup_end_tag(void)
{
	struct tag *tag;
	u32 total_size = 0;

	/* Setup END tag */
	params->hdr.tag = ATAG_NONE;
	params->hdr.size = 0;

	/* Calculate total ATAG size for cache flush by walking through all tags */
	tag = (struct tag *)K230_ATAG_BASE;
	while (tag->hdr.tag != ATAG_NONE) {
		total_size += tag->hdr.size * sizeof(u32);
		tag = tag_next(tag);

		/* Safety check to prevent infinite loop */
		if ((ulong)tag >= K230_ATAG_MAX_SIZE) {
			printf("ATAG: Safety check triggered during size calculation\n");
			break;
		}
	}

	/* Add size for the final END tag (header only) */
	total_size += sizeof(struct tag_header);

	/* Flush cache to ensure all tags are written to memory */
	flush_cache((ulong)K230_ATAG_BASE, total_size);
}
