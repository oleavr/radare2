DIST ?= /home/oleavr/src/frida-tools/apps/tracer/node_modules/@frida/react-use-r2/dist

r2.wasm: r2.c
	emcc \
		r2.c \
		-Oz \
		-I../libr/include -I../shlr/sdb/include \
		-L../libr -lr \
		-o r2.mjs \
		--emit-tsd=r2.d.ts \
		-sEXPORTED_RUNTIME_METHODS=ccall,cwrap,UTF8ToString \
		-sEXPORTED_FUNCTIONS=_main,_r2_open,_r2_execute,_free \
		-sASYNCIFY \
		-sASYNCIFY_STACK_SIZE=16384
	cp r2.mjs r2.d.ts r2.wasm $(DIST)
