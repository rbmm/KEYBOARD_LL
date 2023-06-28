
; struct KHS *__cdecl log__fnHkINLPKBDLLHOOKSTRUCT(struct KHS *)
extern ?log__fnHkINLPKBDLLHOOKSTRUCT@@YAPEAUKHS@@PEAU1@@Z : PROC

extern __imp___fnHkINLPKBDLLHOOKSTRUCT:QWORD

.code


; __int64 __cdecl hook__fnHkINLPKBDLLHOOKSTRUCT(struct KHS *,unsigned long)

?hook__fnHkINLPKBDLLHOOKSTRUCT@@YA_JPEAUKHS@@@Z proc
	sub rsp,40
	call ?log__fnHkINLPKBDLLHOOKSTRUCT@@YAPEAUKHS@@PEAU1@@Z
	add rsp,40
	mov rcx,rax
	jmp __imp___fnHkINLPKBDLLHOOKSTRUCT
?hook__fnHkINLPKBDLLHOOKSTRUCT@@YA_JPEAUKHS@@@Z endp

end