.686
.model flat

; struct KHS *__fastcall log__fnHkINLPKBDLLHOOKSTRUCT(struct KHS *)
extern ?log__fnHkINLPKBDLLHOOKSTRUCT@@YIPAUKHS@@PAU1@@Z : PROC
extern ___imp___fnHkINLPKBDLLHOOKSTRUCT:DWORD
.code

; long __stdcall hook__fnHkINLPKBDLLHOOKSTRUCT(struct KHS *)

?hook__fnHkINLPKBDLLHOOKSTRUCT@@YGJPAUKHS@@@Z proc
	mov ecx,[esp+4]
	call ?log__fnHkINLPKBDLLHOOKSTRUCT@@YIPAUKHS@@PAU1@@Z
	jmp ___imp___fnHkINLPKBDLLHOOKSTRUCT
?hook__fnHkINLPKBDLLHOOKSTRUCT@@YGJPAUKHS@@@Z endp

end