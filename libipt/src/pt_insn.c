/*
 * Copyright (c) 2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "pt_insn.h"

#include "intel-pt.h"


int pt_insn_changes_cpl(const struct pt_insn *insn,
			const struct pt_insn_ext *iext)
{
	(void) insn;

	if (!iext)
		return 0;

	switch (iext->iclass) {
	default:
		return 0;

	case PTI_INST_INT:
	case PTI_INST_INT3:
	case PTI_INST_INT1:
	case PTI_INST_INTO:
	case PTI_INST_IRET:
	case PTI_INST_SYSCALL:
	case PTI_INST_SYSENTER:
	case PTI_INST_SYSEXIT:
	case PTI_INST_SYSRET:
		return 1;
	}
}

int pt_insn_changes_cr3(const struct pt_insn *insn,
			const struct pt_insn_ext *iext)
{
	(void) insn;

	if (!iext)
		return 0;

	switch (iext->iclass) {
	default:
		return 0;

	case PTI_INST_MOV_CR3:
		return 1;
	}
}

int pt_insn_is_branch(const struct pt_insn *insn,
		      const struct pt_insn_ext *iext)
{
	(void) iext;

	if (!insn)
		return 0;

	switch (insn->iclass) {
	default:
		return 0;

	case ptic_call:
	case ptic_return:
	case ptic_jump:
	case ptic_cond_jump:
	case ptic_far_call:
	case ptic_far_return:
	case ptic_far_jump:
		return 1;
	}
}

int pt_insn_is_far_branch(const struct pt_insn *insn,
			  const struct pt_insn_ext *iext)
{
	(void) iext;

	if (!insn)
		return 0;

	switch (insn->iclass) {
	default:
		return 0;

	case ptic_far_call:
	case ptic_far_return:
	case ptic_far_jump:
		return 1;
	}
}

int pt_insn_binds_to_pip(const struct pt_insn *insn,
			 const struct pt_insn_ext *iext)
{
	if (!iext)
		return 0;

	switch (iext->iclass) {
	default:
		return pt_insn_is_far_branch(insn, iext);

	case PTI_INST_MOV_CR3:
	case PTI_INST_VMLAUNCH:
	case PTI_INST_VMRESUME:
		return 1;
	}
}

int pt_insn_binds_to_vmcs(const struct pt_insn *insn,
			  const struct pt_insn_ext *iext)
{
	if (!iext)
		return 0;

	switch (iext->iclass) {
	default:
		return pt_insn_is_far_branch(insn, iext);

	case PTI_INST_VMPTRLD:
	case PTI_INST_VMLAUNCH:
	case PTI_INST_VMRESUME:
		return 1;
	}
}

int pt_insn_next_ip(uint64_t *pip, const struct pt_insn *insn,
		    const struct pt_insn_ext *iext)
{
	uint64_t ip;

	if (!insn || !iext)
		return -pte_internal;

	ip = insn->ip + insn->size;

	switch (insn->iclass) {
	case ptic_other:
		break;

	case ptic_call:
	case ptic_jump:
		if (iext->variant.branch.is_direct) {
			ip += iext->variant.branch.displacement;
			break;
		}

		/* Fall through. */
	default:
		return -pte_bad_query;

	case ptic_error:
		return -pte_bad_insn;
	}

	if (pip)
		*pip = ip;

	return 0;
}
